"""Transport-layer tests: in-memory mTLS, JWS sign/verify, response decoding.

Network is fully mocked via httpx.MockTransport. No requests reach the
internet — these tests run offline and run fast.
"""

from __future__ import annotations

import base64
import os
import ssl
import warnings
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from furs_fiscal import (
    FURS_PRODUCTION_ENDPOINT,
    FURS_TEST_ENDPOINT,
    FURSBusinessPremiseError,
    FURSCertificateError,
    FURSConnectionError,
    FURSResponseChainNotVerifiedWarning,
    FURSResponseError,
    FURSSchemaError,
    FURSServerError,
    FURSSignatureError,
    FURSSystemError,
    FURSTLSVerificationDisabledWarning,
)
from furs_fiscal.exceptions import from_furs_error
from furs_fiscal.transport import (
    FURS_TLS_CIPHERS,
    Connector,
    _load_ssl_context_with_client_cert,
)
from tests.conftest import P12_PASSWORD


def _build_response_signing_cert(key: rsa.RSAPrivateKey) -> x509.Certificate:
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "FURS-RESPONSE-TEST"),
        ]
    )
    now = datetime.now(tz=timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )


def _make_response_token(
    payload: dict,
    signer_key: rsa.RSAPrivateKey,
    signer_cert: x509.Certificate | None,
) -> str:
    headers: dict = {"alg": "RS256"}
    if signer_cert is not None:
        x5c = base64.b64encode(
            signer_cert.public_bytes(serialization.Encoding.DER)
        ).decode("ascii")
        headers["x5c"] = [x5c]
    return jwt.encode(payload, key=signer_key, headers=headers, algorithm="RS256")


# ---------------------------------------------------------------------------
# SSL context loader
# ---------------------------------------------------------------------------


def test_in_memory_cert_loader_does_not_leave_temp_files(p12_data_and_key, tmp_path):
    """The loader writes PEM to mkstemp briefly; after load_cert_chain returns,
    no PEM file should remain on disk."""
    p12_data, _ = p12_data_and_key
    before = set(os.listdir("/tmp"))
    ctx, key, cert = _load_ssl_context_with_client_cert(
        p12_data=p12_data, p12_password=P12_PASSWORD, verify_tls=True
    )
    after = set(os.listdir("/tmp"))
    leaked = {f for f in after - before if f.endswith(".pem")}
    assert not leaked, f"loader leaked {leaked}"
    assert ctx is not None
    assert isinstance(key, rsa.RSAPrivateKey)
    assert cert.subject.rfc4514_string()


def test_ssl_context_pins_tls12_minimum_and_aead_ciphers(p12_data_and_key):
    """Spec sec. 2 requires TLS 1.2+; sec. 6.2 restricts TLS 1.2 cipher suites
    to the AEAD ECDHE/DHE-RSA subset present in both the test (6.2.1) and
    production (6.2.2) lists. Both must be applied regardless of whether
    verify_tls is True, False, or a CA bundle path.
    """
    p12_data, _ = p12_data_and_key

    # Cover the str-path branch in _load_ssl_context_with_client_cert.
    # ssl.create_default_context(cafile=...) requires a real PEM file; the
    # system trust store is the simplest one we can rely on cross-platform.
    system_cafile = ssl.get_default_verify_paths().cafile
    if not system_cafile or not os.path.exists(system_cafile):
        pytest.skip("system CA bundle not available for cafile-branch coverage")

    for verify_tls in (True, False, system_cafile):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSTLSVerificationDisabledWarning)
            ctx, _, _ = _load_ssl_context_with_client_cert(
                p12_data=p12_data, p12_password=P12_PASSWORD, verify_tls=verify_tls
            )
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        # Every active TLS 1.2 cipher must be ECDHE-RSA / DHE-RSA + AESGCM.
        # Names follow OpenSSL conventions ("ECDHE-RSA-AES128-GCM-SHA256"
        # etc.). TLS 1.3 ciphers (TLS_AES_*_GCM_SHA*) are configured
        # separately and not filtered by set_ciphers(). The cipher string in
        # transport.py uses ``+aRSA`` to drop ECDSA / DSS-keyed AEAD suites
        # that are unreachable against the FURS RSA cert anyway; assert that
        # explicitly so a future widening of FURS_TLS_CIPHERS cannot silently
        # let them through.
        tls12_names: list[str] = []
        for cipher in ctx.get_ciphers():
            name = cipher["name"]
            if name.startswith("TLS_"):
                continue  # TLS 1.3 — separate negotiation
            tls12_names.append(name)
            assert "GCM" in name, f"non-AEAD TLS 1.2 cipher leaked through: {name}"
            assert name.startswith(("ECDHE-RSA-", "DHE-RSA-")), (
                f"non-RSA-PFS TLS 1.2 cipher leaked through: {name}"
            )
            assert "-DSS-" not in name and "-ECDSA-" not in name, (
                f"non-RSA-keyed TLS 1.2 cipher leaked through: {name}"
            )
        # And as a positive check: the spec intersection is exactly the four
        # RSA AEAD suites. If OpenSSL silently drops one (eg. a build with
        # 128-bit AES disabled), the handshake against FURS will fail in
        # production; surface it here instead.
        assert set(tls12_names) == {
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-GCM-SHA384",
        }, f"unexpected TLS 1.2 cipher set: {sorted(tls12_names)}"


# ---------------------------------------------------------------------------
# Cipher list rotation surveillance — same yellow-then-red pattern used for
# the FURS-published cert expiry checks in tests/test_real_cert.py. Spec
# sec. 6.2.2 v3.2 is documented as "active until 12.5.2026". When the
# production list rotates, FURS_TLS_CIPHERS must be re-verified against the
# successor list (6.2.2 v3.3+) before the rotation date or handshakes will
# silently break.
#
# When this turns yellow:
#   1. Pull the latest TehnicnaDokumentacijaVer*.pdf and read sec. 6.2.2.
#   2. Confirm the intersection with sec. 6.2.1 still includes all four
#      AEAD ECDHE/DHE-RSA suites currently selected by FURS_TLS_CIPHERS.
#   3. If the new list drops one, update FURS_TLS_CIPHERS and the comment
#      above it. If the new list is broader, just bump the constant below.
# ---------------------------------------------------------------------------

CIPHER_LIST_ROTATION_WARNING_DAYS = 30
FURS_PROD_CIPHER_LIST_ACTIVE_UNTIL = datetime(2026, 5, 12, tzinfo=timezone.utc)


def test_furs_tls_cipher_list_rotation_surveillance():
    """Surveillance: emit a UserWarning if the FURS production cipher list
    (spec sec. 6.2.2) rotates within ``CIPHER_LIST_ROTATION_WARNING_DAYS``
    days; fail outright once the rotation date has passed so the next CI
    run reminds the maintainer to re-verify FURS_TLS_CIPHERS against the
    successor spec list. The constant being surveilled is imported and
    referenced here so a rename will trip this test, not silently bypass
    it.
    """
    assert FURS_TLS_CIPHERS  # constant must exist; renames must update us
    days_left = (
        FURS_PROD_CIPHER_LIST_ACTIVE_UNTIL - datetime.now(tz=timezone.utc)
    ).days
    assert days_left > 0, (
        "FURS production cipher list (spec sec. 6.2.2) rotated "
        f"{-days_left} day(s) ago "
        f"(active_until={FURS_PROD_CIPHER_LIST_ACTIVE_UNTIL.date().isoformat()}). "
        "Re-verify FURS_TLS_CIPHERS against the successor list in the "
        "current TehnicnaDokumentacijaVer*.pdf and bump "
        "FURS_PROD_CIPHER_LIST_ACTIVE_UNTIL."
    )
    if days_left < CIPHER_LIST_ROTATION_WARNING_DAYS:
        warnings.warn(
            "FURS production cipher list (spec sec. 6.2.2) rotates in "
            f"{days_left} day(s) "
            f"(active_until={FURS_PROD_CIPHER_LIST_ACTIVE_UNTIL.date().isoformat()}) "
            "— re-verify FURS_TLS_CIPHERS against the successor list before "
            "the rotation date.",
            UserWarning,
            stacklevel=2,
        )


def test_disabled_tls_warns(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _load_ssl_context_with_client_cert(
            p12_data=p12_data, p12_password=P12_PASSWORD, verify_tls=False
        )
    assert any(
        issubclass(w.category, FURSTLSVerificationDisabledWarning) for w in caught
    )


# ---------------------------------------------------------------------------
# Connector construction guards
# ---------------------------------------------------------------------------


def test_connector_rejects_verify_true_without_pinned_key(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    with pytest.raises(ValueError, match="requires furs_response_public_key"):
        Connector(
            p12_data=p12_data,
            p12_password=P12_PASSWORD,
            production=False,
            verify_furs_response=True,
        )


def test_connector_rejects_invalid_verify_mode(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    with pytest.raises(ValueError, match="must be True, False, or 'x5c-untrusted'"):
        Connector(
            p12_data=p12_data,
            p12_password=P12_PASSWORD,
            production=False,
            verify_furs_response="garbage",  # type: ignore[arg-type]
        )


def test_connector_endpoint_selection(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    test = Connector(p12_data=p12_data, p12_password=P12_PASSWORD, production=False)
    prod = Connector(p12_data=p12_data, p12_password=P12_PASSWORD, production=True)
    try:
        assert test._endpoint == FURS_TEST_ENDPOINT
        assert prod._endpoint == FURS_PRODUCTION_ENDPOINT
    finally:
        test.close()
        prod.close()


def test_connector_jws_header_includes_cert_metadata(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    conn = Connector(p12_data=p12_data, p12_password=P12_PASSWORD, production=False)
    try:
        header = conn._jws_header()
        assert header["alg"] == "RS256"
        assert "subject_name" in header and "C=SI" in header["subject_name"]
        assert "issuer_name" in header
        assert isinstance(header["serial"], int)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Mocked HTTP exchanges
# ---------------------------------------------------------------------------


def _connector_with_mock_transport(
    p12_data: bytes,
    handler,
    *,
    verify_furs_response="x5c-untrusted",
    furs_response_public_key=None,
) -> Connector:
    return Connector(
        p12_data=p12_data,
        p12_password=P12_PASSWORD,
        production=False,
        verify_furs_response=verify_furs_response,
        furs_response_public_key=furs_response_public_key,
        transport=httpx.MockTransport(handler),
    )


def test_post_decodes_x5c_signed_response(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response_cert = _build_response_signing_cert(response_key)
    expected_payload = {"InvoiceResponse": {"UniqueInvoiceID": "EOR-XYZ"}}
    response_token = _make_response_token(expected_payload, response_key, response_cert)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            decoded = conn.post(path="v1/cash_registers/invoices", payload={"x": 1})
        assert decoded == expected_payload
        assert any(
            issubclass(w.category, FURSResponseChainNotVerifiedWarning) for w in caught
        )
    finally:
        conn.close()


def test_post_raises_schema_error_on_s002_envelope(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response_cert = _build_response_signing_cert(response_key)
    response_token = _make_response_token(
        {
            "InvoiceResponse": {
                "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                "Error": {
                    "ErrorCode": "S002",
                    "ErrorMessage": "JSON schema mismatch",
                },
            }
        },
        response_key,
        response_cert,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            with pytest.raises(FURSSchemaError) as exc:
                conn.post(path="v1/cash_registers/invoices", payload={"x": 1})
        assert exc.value.code == "S002"
    finally:
        conn.close()


def test_post_raises_signature_error_on_s003(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response_cert = _build_response_signing_cert(response_key)
    response_token = _make_response_token(
        {
            "InvoiceResponse": {
                "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                "Error": {"ErrorCode": "S003", "ErrorMessage": "bad sig"},
            }
        },
        response_key,
        response_cert,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            with pytest.raises(FURSSignatureError):
                conn.post(path="v1/cash_registers/invoices", payload={})
    finally:
        conn.close()


def test_post_raises_certificate_error_on_s004(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response_cert = _build_response_signing_cert(response_key)
    response_token = _make_response_token(
        {
            "InvoiceResponse": {
                "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                "Error": {"ErrorCode": "S004", "ErrorMessage": "unknown cert"},
            }
        },
        response_key,
        response_cert,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            with pytest.raises(FURSCertificateError):
                conn.post(path="v1/cash_registers/invoices", payload={})
    finally:
        conn.close()


@pytest.mark.parametrize(
    "code,expected_cls,is_retryable",
    [
        ("S001", FURSSchemaError, False),
        ("S002", FURSSchemaError, False),
        # Case-insensitive (production has sent lower-case).
        ("s002", FURSSchemaError, False),
        ("S003", FURSSignatureError, False),
        ("S004", FURSCertificateError, False),
        ("S005", FURSCertificateError, False),  # tax-number / cert mismatch
        ("S006", FURSBusinessPremiseError, False),  # premise not registered
        ("S007", FURSCertificateError, False),  # cert revoked
        ("S008", FURSCertificateError, False),  # cert expired
        ("S100", FURSSystemError, True),  # transient server-side
        ("S999", FURSServerError, False),  # unknown → catch-all
    ],
)
def test_from_furs_error_maps_spec_section_4_codes(code, expected_cls, is_retryable):
    """Spec sec. 4 enumerates S001..S008 and S100. Each must resolve to the
    most specific exception class in the hierarchy so callers can branch
    without parsing strings, and ``is_retryable`` must be True only for the
    codes documented as transient server-side conditions.
    """
    err = from_furs_error(code, "msg")
    assert isinstance(err, expected_cls)
    assert err.code == code
    assert err.message == "msg"
    assert err.is_retryable is is_retryable


def test_post_handles_non_200_status(p12_data_and_key):
    p12_data, _ = p12_data_and_key

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="Server unavailable")

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with pytest.raises(FURSConnectionError, match="HTTP 503"):
            conn.post(path="v1/cash_registers/invoices", payload={})
    finally:
        conn.close()


def test_post_handles_missing_token_in_body(p12_data_and_key):
    p12_data, _ = p12_data_and_key

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with pytest.raises(FURSConnectionError, match="valid JSON envelope"):
            conn.post(path="v1/cash_registers/invoices", payload={})
    finally:
        conn.close()


def test_x5c_untrusted_rejects_token_without_x5c_header(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response_token = _make_response_token(
        {"InvoiceResponse": {"UniqueInvoiceID": "X"}}, response_key, signer_cert=None
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with pytest.raises(FURSConnectionError, match="x5c"):
            conn.post(path="v1/cash_registers/invoices", payload={})
    finally:
        conn.close()


def test_x5c_untrusted_rejects_expired_certificate(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired")]))
        .public_key(response_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2000, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2001, 1, 1, tzinfo=timezone.utc))
        .sign(response_key, hashes.SHA256())
    )
    response_token = _make_response_token(
        {"InvoiceResponse": {}}, response_key, expired_cert
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with pytest.raises(FURSConnectionError, match="validity window"):
            conn.post(path="v1/cash_registers/invoices", payload={})
    finally:
        conn.close()


def test_x5c_untrusted_rejects_signature_from_different_key(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _build_response_signing_cert(cert_key)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Sign with other_key but advertise cert_key in x5c → signature must fail.
    response_token = _make_response_token({"InvoiceResponse": {}}, other_key, cert)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with pytest.raises(FURSConnectionError, match="signature"):
            conn.post(path="v1/cash_registers/invoices", payload={})
    finally:
        conn.close()


def test_pinned_key_mode_rejects_response_signed_by_other_key(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    pinned_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pinned_pub = pinned_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response_token = _make_response_token(
        {"InvoiceResponse": {}}, other_key, signer_cert=None
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    conn = _connector_with_mock_transport(
        p12_data,
        handler,
        verify_furs_response=True,
        furs_response_public_key=pinned_pub,
    )
    try:
        with pytest.raises(FURSConnectionError, match="JWS verification failed"):
            conn.post(path="v1/cash_registers/invoices", payload={})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Echo (spec sec. 3.3 / 9.7 / 9.8) — plain JSON, not JWS
# ---------------------------------------------------------------------------


def test_echo_round_trip_does_not_sign_request(p12_data_and_key):
    """Echo must POST plain ``{"EchoRequest": ...}`` (no JWS) and parse
    plain ``{"EchoResponse": ...}`` back."""
    p12_data, _ = p12_data_and_key
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = request.read()
        return httpx.Response(200, json={"EchoResponse": "furs"})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        result = conn.echo(path="v1/cash_registers/echo", message="furs")
    finally:
        conn.close()

    assert result == "furs"
    assert seen["path"].endswith("/v1/cash_registers/echo")
    body = seen["body"].decode("utf-8")
    assert '"EchoRequest"' in body
    # The JWS path produces ``{"token":"<dot>.<dot>.<dot>"}``; the echo
    # path must not.
    assert '"token"' not in body


def test_echo_raises_on_non_200(p12_data_and_key):
    p12_data, _ = p12_data_and_key

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="busy")

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with pytest.raises(FURSConnectionError, match="503"):
            conn.echo(path="v1/cash_registers/echo", message="furs")
    finally:
        conn.close()


def test_echo_raises_on_missing_field(p12_data_and_key):
    p12_data, _ = p12_data_and_key

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with pytest.raises(FURSConnectionError, match="EchoResponse"):
            conn.echo(path="v1/cash_registers/echo", message="furs")
    finally:
        conn.close()


def test_echo_raises_on_non_string_field(p12_data_and_key):
    p12_data, _ = p12_data_and_key

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"EchoResponse": 123})

    conn = _connector_with_mock_transport(p12_data, handler)
    try:
        with pytest.raises(FURSConnectionError, match="not a string"):
            conn.echo(path="v1/cash_registers/echo", message="furs")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Retry policy — only retries on transient failures (S100, 5xx, 408, 429,
# httpx.RequestError). Schema / signature / cert errors are deterministic
# and never retried.
# ---------------------------------------------------------------------------


def _connector_with_retry(
    p12_data: bytes, handler, *, retries: int
) -> Connector:
    return Connector(
        p12_data=p12_data,
        p12_password=P12_PASSWORD,
        production=False,
        retries=retries,
        retry_backoff=0.0,  # no real sleep in tests
        transport=httpx.MockTransport(handler),
    )


def _ok_response_token() -> str:
    response_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response_cert = _build_response_signing_cert(response_key)
    return _make_response_token(
        {"InvoiceResponse": {"UniqueInvoiceID": "EOR-OK"}},
        response_key,
        response_cert,
    )


def _s100_response_token() -> str:
    response_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response_cert = _build_response_signing_cert(response_key)
    return _make_response_token(
        {
            "InvoiceResponse": {
                "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                "Error": {"ErrorCode": "S100", "ErrorMessage": "transient"},
            }
        },
        response_key,
        response_cert,
    )


def _s001_response_token() -> str:
    response_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response_cert = _build_response_signing_cert(response_key)
    return _make_response_token(
        {
            "InvoiceResponse": {
                "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                "Error": {"ErrorCode": "S001", "ErrorMessage": "schema"},
            }
        },
        response_key,
        response_cert,
    )


def test_retry_recovers_after_s100(p12_data_and_key):
    """S100 is the canonical retryable FURS error (sec. 4)."""
    p12_data, _ = p12_data_and_key
    calls = {"n": 0}
    bad = _s100_response_token()
    good = _ok_response_token()

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        token = bad if calls["n"] == 1 else good
        return httpx.Response(200, json={"token": token})

    conn = _connector_with_retry(p12_data, handler, retries=2)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            decoded = conn.post(
                path="v1/cash_registers/invoices", payload={"x": 1}
            )
    finally:
        conn.close()
    assert calls["n"] == 2
    assert decoded["InvoiceResponse"]["UniqueInvoiceID"] == "EOR-OK"


def test_retry_does_not_retry_s001(p12_data_and_key):
    """Schema errors are deterministic: a retry would just repeat the failure."""
    p12_data, _ = p12_data_and_key
    calls = {"n": 0}
    bad = _s001_response_token()

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"token": bad})

    conn = _connector_with_retry(p12_data, handler, retries=5)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            with pytest.raises(FURSSchemaError):
                conn.post(path="v1/cash_registers/invoices", payload={"x": 1})
    finally:
        conn.close()
    assert calls["n"] == 1


def test_retry_recovers_after_5xx(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    calls = {"n": 0}
    good = _ok_response_token()

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, text="busy")
        return httpx.Response(200, json={"token": good})

    conn = _connector_with_retry(p12_data, handler, retries=2)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            decoded = conn.post(
                path="v1/cash_registers/invoices", payload={"x": 1}
            )
    finally:
        conn.close()
    assert calls["n"] == 2
    assert decoded["InvoiceResponse"]["UniqueInvoiceID"] == "EOR-OK"


def test_retry_does_not_retry_4xx(p12_data_and_key):
    """Generic 4xx is not retried — the request is malformed and re-sending
    won't help. (408 / 429 are retried elsewhere.)"""
    p12_data, _ = p12_data_and_key
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(400, text="bad request")

    conn = _connector_with_retry(p12_data, handler, retries=5)
    try:
        with pytest.raises(FURSConnectionError, match="400"):
            conn.post(path="v1/cash_registers/invoices", payload={"x": 1})
    finally:
        conn.close()
    assert calls["n"] == 1


def test_retry_recovers_after_request_error(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    calls = {"n": 0}
    good = _ok_response_token()

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(200, json={"token": good})

    conn = _connector_with_retry(p12_data, handler, retries=2)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            decoded = conn.post(
                path="v1/cash_registers/invoices", payload={"x": 1}
            )
    finally:
        conn.close()
    assert calls["n"] == 2
    assert decoded["InvoiceResponse"]["UniqueInvoiceID"] == "EOR-OK"


def test_retry_429_and_408_are_retryable(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    good = _ok_response_token()
    for transient_status in (408, 429):
        calls = {"n": 0}

        def handler(request: httpx.Request, status=transient_status) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(status, text="slow down")
            return httpx.Response(200, json={"token": good})

        conn = _connector_with_retry(p12_data, handler, retries=1)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
                conn.post(path="v1/cash_registers/invoices", payload={"x": 1})
        finally:
            conn.close()
        assert calls["n"] == 2, f"status {transient_status} should retry"


def test_retry_exhaustion_raises_last_error(p12_data_and_key):
    """After all retries are spent, the most recent transient error surfaces."""
    p12_data, _ = p12_data_and_key
    calls = {"n": 0}
    bad = _s100_response_token()

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"token": bad})

    conn = _connector_with_retry(p12_data, handler, retries=2)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            with pytest.raises(FURSSystemError):
                conn.post(path="v1/cash_registers/invoices", payload={"x": 1})
    finally:
        conn.close()
    # 1 initial attempt + 2 retries = 3 total
    assert calls["n"] == 3


def test_retries_default_is_zero(p12_data_and_key):
    """Library default keeps the legacy single-attempt behaviour."""
    p12_data, _ = p12_data_and_key
    conn = Connector(
        p12_data=p12_data, p12_password=P12_PASSWORD, production=False
    )
    try:
        assert conn._retries == 0
    finally:
        conn.close()


def test_connector_rejects_negative_retries(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    with pytest.raises(ValueError, match="retries must be >= 0"):
        Connector(
            p12_data=p12_data,
            p12_password=P12_PASSWORD,
            production=False,
            retries=-1,
        )


def test_connector_rejects_negative_backoff(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    with pytest.raises(ValueError, match="retry_backoff must be >= 0"):
        Connector(
            p12_data=p12_data,
            p12_password=P12_PASSWORD,
            production=False,
            retry_backoff=-0.1,
        )


def test_echo_does_not_retry(p12_data_and_key):
    """Echo is a connectivity probe — auto-retry would mask the failure
    that the caller is trying to detect."""
    p12_data, _ = p12_data_and_key
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, text="busy")

    conn = Connector(
        p12_data=p12_data,
        p12_password=P12_PASSWORD,
        production=False,
        retries=5,  # would retry post() — but echo() bypasses the loop
        retry_backoff=0.0,
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(FURSConnectionError, match="503"):
            conn.echo(path="v1/cash_registers/echo", message="furs")
    finally:
        conn.close()
    assert calls["n"] == 1
