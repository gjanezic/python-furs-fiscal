"""Transport-layer tests: in-memory mTLS, JWS sign/verify, response decoding.

Network is fully mocked via httpx.MockTransport. No requests reach the
internet — these tests run offline and run fast.
"""

from __future__ import annotations

import base64
import os
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
    FURSCertificateError,
    FURSConnectionError,
    FURSResponseChainNotVerifiedWarning,
    FURSResponseError,
    FURSSchemaError,
    FURSSignatureError,
    FURSTLSVerificationDisabledWarning,
)
from furs_fiscal.transport import (
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
