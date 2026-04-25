"""End-to-end tests using the real FURS-issued *TESTNO PODJETJE 1211* p12.

The synthetic in-memory cert in ``conftest.py`` proves the API surface works,
but the FURS production cert chain has quirks the synthetic cert hides:

  * the p12 is wrapped with ``pbeWithSHA1And40BitRC2-CBC`` (legacy PBE)
  * the issuer DN is the live ``Tax CA Test`` CA (not a self-signed test cert)
  * the certificate carries ``digital_signature`` only — no ``key_encipherment``,
    no ``key_agreement`` — so any code path that demands a TLS-cipher key usage
    breaks here even when the synthetic cert passes
  * the subject DN includes a ``serialNumber=2`` RDN which has tripped DN
    parsers in the past

These tests load the cert and exercise the **whole** signing/transport
pipeline against an httpx ``MockTransport`` so they run offline and fast,
then assert that the data the library would put on the wire matches what
FURS expects (correct subject DN in the JWS header, correct content-type,
correct payload shape, ZOI deterministic & round-trippable).

If the cert file is not present the tests are skipped — external
contributors without the cert can still run the rest of the suite.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import tempfile
import warnings
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from furs_fiscal import (
    Address,
    BPIdentifier,
    BusinessPremise,
    FURSClient,
    FURSResponseChainNotVerifiedWarning,
    Invoice,
    InvoiceIdentifier,
    PropertyID,
    RealEstateBP,
    SoftwareSupplier,
    TaxesPerSeller,
    VATAmount,
    calculate_zoi,
    load_furs_certificate,
    load_response_public_key,
)
from furs_fiscal.exceptions import FURSConnectionError
from furs_fiscal.models import LJUBLJANA
from furs_fiscal.transport import _load_ssl_context_with_client_cert

# ---------------------------------------------------------------------------
# Fixture: real FURS *TESTNO PODJETJE 1211* p12
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_CERTS_DIR = _REPO_ROOT / "specs" / "test_certs"
PROD_CERTS_DIR = _REPO_ROOT / "specs" / "prod_certs"

REAL_P12_PATH = TEST_CERTS_DIR / "10492682-2.p12"
REAL_P12_PASSWORD = "DQHTBI591V00"  # FURS-published test material — not a secret.
REAL_P12_TAX_NUMBER = 10492682

# FURS-published certs (public material) for the *test* environment.
TEST_DAVPOTRAC_CER = TEST_CERTS_DIR / "DavPotRacTEST.cer"
TEST_BLAGAJNE_CER = TEST_CERTS_DIR / "blagajne-test.fu.gov.si.cer"
TEST_SIGOV_CA = TEST_CERTS_DIR / "sigov-ca2.xcert.crt"
TEST_SI_TRUST_ROOT = TEST_CERTS_DIR / "si-trust-root.crt"
TEST_TLS_BUNDLE = TEST_CERTS_DIR / "sigov-ca-bundle.pem"

# FURS-published certs for the *production* environment.
PROD_DAVPOTRAC_CER = PROD_CERTS_DIR / "DavPotRac_2025.cer"
PROD_BLAGAJNE_CER = PROD_CERTS_DIR / "blagajne.fu.gov.si_2025.cer"
PROD_SIGOV_CA = PROD_CERTS_DIR / "sigov-ca2.xcert.crt"
PROD_SI_TRUST_ROOT = PROD_CERTS_DIR / "si-trust-root.crt"
PROD_TLS_BUNDLE = PROD_CERTS_DIR / "sigov-ca-bundle.pem"


@pytest.fixture(scope="module")
def real_p12_data() -> bytes:
    if not REAL_P12_PATH.exists():
        pytest.skip(
            f"real FURS test cert not present at {REAL_P12_PATH} — see "
            "specs/test_certs/README.md to obtain it."
        )
    return REAL_P12_PATH.read_bytes()


# ---------------------------------------------------------------------------
# Helper: forge a FURS-style x5c-signed response token so x5c-untrusted accepts it
# ---------------------------------------------------------------------------


def _signed_response_token(payload: dict) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=timezone.utc)
    # Use timedelta(±365d) instead of replace(year=...) — the latter
    # blows up on Feb-29 of a leap year because Feb 29 of the prior /
    # next year doesn't exist.
    one_year = timedelta(days=365)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "blagajne-test.fu.gov.si")])
        )
        .issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "blagajne-test.fu.gov.si")])
        )
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - one_year)
        .not_valid_after(now + one_year)
        .sign(key, hashes.SHA256())
    )
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
    return jwt.encode(payload, key=key, headers={"x5c": [x5c]}, algorithm="RS256")


# ---------------------------------------------------------------------------
# 1. PKCS#12 load — the real cert is encrypted with legacy PBE
# ---------------------------------------------------------------------------


def test_real_p12_loads_via_cryptography(real_p12_data):
    """The cert is wrapped with pbeWithSHA1And40BitRC2-CBC (OpenSSL needs
    -legacy). cryptography handles it without ceremony — proving we don't
    need to install a fallback PBE provider."""
    ctx, key, cert = _load_ssl_context_with_client_cert(
        p12_data=real_p12_data,
        p12_password=REAL_P12_PASSWORD,
        verify_tls=True,
    )
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048

    subject = cert.subject.rfc4514_string()
    assert "CN=TESTNO PODJETJE 1211" in subject
    assert "OU=10492682" in subject  # tax number embedded in the subject
    assert cert.issuer.rfc4514_string() == "CN=Tax CA Test,O=state-institutions,C=SI"


def test_real_p12_load_does_not_leak_pem_files(
    real_p12_data, tmp_path, monkeypatch
):
    """Private-key material on disk is the worst possible failure mode
    for this library. ``ssl.SSLContext.load_cert_chain`` requires file
    paths so a brief mkstemp window is unavoidable — but the loader is
    expected to ``os.unlink`` both files in its ``finally`` block.

    Pin ``TMPDIR`` to a per-test directory so we can list it before/after
    without race conditions from parallel workers or other processes,
    and so the test runs unchanged on macOS / Linux / Windows."""
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    before = set(tmp_path.iterdir())
    _load_ssl_context_with_client_cert(
        p12_data=real_p12_data,
        p12_password=REAL_P12_PASSWORD,
        verify_tls=True,
    )
    after = set(tmp_path.iterdir())

    leftover = [p for p in (after - before) if p.suffix == ".pem"]
    assert not leftover, f"loader leaked PEMs to {tmp_path}: {leftover!r}"


def test_real_p12_rejects_wrong_password(real_p12_data):
    with pytest.raises(ValueError):
        _load_ssl_context_with_client_cert(
            p12_data=real_p12_data,
            p12_password="wrong-password",
            verify_tls=True,
        )


# ---------------------------------------------------------------------------
# 2. ZOI — the only place where the real RSA key visibly matters offline
# ---------------------------------------------------------------------------


def test_zoi_with_real_key_is_deterministic_and_pkcs1v15(real_p12_data):
    """ZOI uses RSA-PKCS#1v1.5 → deterministic → repeated calls match.
    Verifies the signature with the cert's public key end-to-end so we
    catch any ZOI input-string regression against a *real* cert."""
    ctx, key, cert = _load_ssl_context_with_client_cert(
        p12_data=real_p12_data,
        p12_password=REAL_P12_PASSWORD,
        verify_tls=True,
    )
    issued = datetime(2026, 4, 25, 8, 30, 0, tzinfo=timezone.utc)
    args = dict(
        private_key=key,
        tax_number=REAL_P12_TAX_NUMBER,
        issued_date=issued,
        invoice_number="11",
        business_premise_id="BP1",
        electronic_device_id="B1",
        invoice_amount=Decimal("19.15"),
    )
    a = calculate_zoi(**args)
    b = calculate_zoi(**args)
    assert a == b
    assert len(a) == 32

    # Reconstruct the exact bytes the library signed and verify against the
    # cert's public key — proves the ZOI input string the library builds
    # matches what FURS will recompute server-side.
    issued_lj = issued.astimezone(LJUBLJANA)
    content = (
        f"{REAL_P12_TAX_NUMBER}"
        f"{issued_lj.strftime('%d.%m.%Y %H:%M:%S')}"
        f"11BP1B119.15"
    ).encode("utf-8")
    # PKCS1v15 is deterministic, so we can resign and compare the MD5 of the
    # signature directly.
    sig = key.sign(content, padding.PKCS1v15(), hashes.SHA256())
    assert hashlib.md5(sig).hexdigest() == a

    # And the cert's public key validates that signature.
    cert.public_key().verify(sig, content, padding.PKCS1v15(), hashes.SHA256())


# ---------------------------------------------------------------------------
# 3. JWS payload — what the library would actually put on the wire
# ---------------------------------------------------------------------------


def _client_with_handler(p12_data: bytes, handler) -> FURSClient:
    return FURSClient(
        p12_data=p12_data,
        p12_password=REAL_P12_PASSWORD,
        production=False,
        transport=httpx.MockTransport(handler),
    )


def test_jws_header_uses_real_cert_metadata(real_p12_data):
    """The JWS header FURS validates carries the *real* subject_name /
    issuer_name / serial. Anything but the live values fails server-side."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured["token"] = body["token"]
        return httpx.Response(
            200,
            json={
                "token": _signed_response_token(
                    {
                        "InvoiceResponse": {
                            "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                            "UniqueInvoiceID": "EOR-OFFLINE",
                        }
                    }
                )
            },
        )

    client = _client_with_handler(real_p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            client.submit_invoice(_real_invoice())
    finally:
        client.close()

    header = jwt.get_unverified_header(captured["token"])
    assert header["alg"] == "RS256"
    assert "CN=TESTNO PODJETJE 1211" in header["subject_name"]
    assert "OU=10492682" in header["subject_name"]
    assert header["issuer_name"] == "CN=Tax CA Test,O=state-institutions,C=SI"
    # FURS validates the serial against the cert it has on file for this VAT
    # number; matching the real one is the whole point.
    assert header["serial"] == 4831614050775426776


def test_jws_signature_round_trips_through_real_cert_pubkey(real_p12_data):
    """Decode the token the library produces using the cert's public key —
    proves we sign with the matching private key, not a stale fixture."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured["token"] = body["token"]
        return httpx.Response(
            200,
            json={
                "token": _signed_response_token(
                    {
                        "InvoiceResponse": {
                            "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                            "UniqueInvoiceID": "EOR-OFFLINE",
                        }
                    }
                )
            },
        )

    client = _client_with_handler(real_p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            client.submit_invoice(_real_invoice())
    finally:
        client.close()

    pub_pem = client.certificate.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    decoded = jwt.decode(captured["token"], key=pub_pem, algorithms=["RS256"])
    invoice_request = decoded["InvoiceRequest"]
    assert invoice_request["Invoice"]["TaxNumber"] == REAL_P12_TAX_NUMBER
    assert invoice_request["Invoice"]["InvoiceAmount"] == 19.15


# ---------------------------------------------------------------------------
# 4. Full request shape — sanity-check the wire payload one last time
# ---------------------------------------------------------------------------


def _real_invoice() -> Invoice:
    issued = datetime(2026, 4, 25, 8, 30, 0, tzinfo=timezone.utc)
    return Invoice(
        tax_number=REAL_P12_TAX_NUMBER,
        issue_date_time=issued,
        numbering_structure="B",
        invoice_identifier=InvoiceIdentifier(
            business_premise_id="BP1",
            electronic_device_id="B1",
            invoice_number="11",
        ),
        invoice_amount=Decimal("19.15"),
        payment_amount=Decimal("19.15"),
        taxes_per_seller=[
            TaxesPerSeller(
                vat=[
                    VATAmount(
                        tax_rate=Decimal("22"),
                        taxable_amount=Decimal("15.70"),
                        tax_amount=Decimal("3.45"),
                    )
                ]
            )
        ],
        protected_id="34905bcff14b381039af2e9d7eee54bb",
    )


def test_invoice_payload_uses_real_tax_number(real_p12_data):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured["token"] = body["token"]
        return httpx.Response(
            200,
            json={
                "token": _signed_response_token(
                    {
                        "InvoiceResponse": {
                            "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                            "UniqueInvoiceID": "EOR-1",
                        }
                    }
                )
            },
        )

    client = _client_with_handler(real_p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            eor = client.submit_invoice(_real_invoice())
        assert eor == "EOR-1"
    finally:
        client.close()

    payload = jwt.decode(captured["token"], options={"verify_signature": False})
    inv = payload["InvoiceRequest"]["Invoice"]
    assert inv["TaxNumber"] == REAL_P12_TAX_NUMBER
    assert inv["IssueDateTime"] == "2026-04-25T10:30:00"  # converted to Ljubljana
    assert inv["NumberingStructure"] == "B"
    assert inv["InvoiceIdentifier"] == {
        "BusinessPremiseID": "BP1",
        "ElectronicDeviceID": "B1",
        "InvoiceNumber": "11",
    }
    assert inv["TaxesPerSeller"] == [
        {"VAT": [{"TaxRate": 22.0, "TaxableAmount": 15.70, "TaxAmount": 3.45}]}
    ]
    assert inv["ProtectedID"] == "34905bcff14b381039af2e9d7eee54bb"


def test_business_premise_payload_uses_real_tax_number(real_p12_data):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured["token"] = body["token"]
        return httpx.Response(
            200,
            json={
                "token": _signed_response_token(
                    {
                        "BusinessPremiseResponse": {
                            "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                        }
                    }
                )
            },
        )

    bp = BusinessPremise(
        tax_number=REAL_P12_TAX_NUMBER,
        business_premise_id="BP1",
        bp_identifier=BPIdentifier(
            real_estate_bp=RealEstateBP(
                property_id=PropertyID(
                    cadastral_number=365,
                    building_number=12,
                    building_section_number=3,
                ),
                address=Address(
                    street="Tržaška cesta",
                    house_number="24",
                    house_number_additional="B",
                    community="Ljubljana",
                    city="Ljubljana",
                    postal_code="1000",
                ),
            )
        ),
        validity_date=date(2026, 4, 25),
        software_supplier=[SoftwareSupplier(tax_number=24564444)],
        special_notes="real-cert offline test",
    )

    client = _client_with_handler(real_p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            decoded = client.submit_business_premise(bp)
        assert "BusinessPremiseResponse" in decoded
    finally:
        client.close()

    payload = jwt.decode(captured["token"], options={"verify_signature": False})
    bpreq = payload["BusinessPremiseRequest"]["BusinessPremise"]
    assert bpreq["TaxNumber"] == REAL_P12_TAX_NUMBER
    assert bpreq["BusinessPremiseID"] == "BP1"
    assert bpreq["BPIdentifier"]["RealEstateBP"]["PropertyID"]["CadastralNumber"] == 365


# ---------------------------------------------------------------------------
# 5. FURS-published certs (test + prod) — load and sanity-check
# ---------------------------------------------------------------------------


def _load_furs_cer(path: Path) -> x509.Certificate:
    """Skip-aware wrapper around :func:`furs_fiscal.load_furs_certificate`.

    External contributors without the FURS-published material can still
    run the rest of the suite; this just skips the cert-specific tests.
    """
    if not path.exists():
        pytest.skip(f"FURS-published cert not present at {path}")
    return load_furs_certificate(path)


@pytest.mark.parametrize(
    "path,expected_cn",
    [
        (TEST_DAVPOTRAC_CER, "DavPotRacTEST"),
        (TEST_BLAGAJNE_CER, "blagajne-test.fu.gov.si"),
        (TEST_SIGOV_CA, "SIGOV-CA"),
        (TEST_SI_TRUST_ROOT, "SI-TRUST Root"),
        (PROD_DAVPOTRAC_CER, "DavPotRac"),
        (PROD_BLAGAJNE_CER, "blagajne.fu.gov.si"),
        (PROD_SIGOV_CA, "SIGOV-CA"),
        (PROD_SI_TRUST_ROOT, "SI-TRUST Root"),
    ],
)
def test_furs_published_cert_loads_and_has_expected_cn(path: Path, expected_cn: str):
    """All eight FURS-published certs (4 test + 4 prod) load via the
    library's only crypto dependency and carry the published CN."""
    cert = _load_furs_cer(path)
    cns = [
        a.value
        for a in cert.subject
        if a.oid.dotted_string == "2.5.4.3"  # CN
    ]
    assert expected_cn in cns, f"{path} CN={cns}, expected {expected_cn}"


@pytest.mark.parametrize(
    "bundle_path",
    [TEST_TLS_BUNDLE, PROD_TLS_BUNDLE],
)
def test_tls_bundle_contains_intermediate_and_root(bundle_path: Path):
    """The bundle Python's ssl module will load must contain SIGOV-CA
    (intermediate) followed by SI-TRUST Root (the trust anchor)."""
    if not bundle_path.exists():
        pytest.skip(f"bundle not present at {bundle_path}")
    pem = bundle_path.read_text()
    assert pem.count("-----BEGIN CERTIFICATE-----") == 2

    # ssl.SSLContext.load_verify_locations() is the path the library
    # actually exercises — make sure it accepts the bundle without error.
    ctx = ssl.create_default_context(cafile=str(bundle_path))
    assert ctx is not None


def test_test_tls_bundle_validates_test_blagajne_cert():
    """Use the test trust bundle to validate the published
    ``blagajne-test.fu.gov.si`` cert — proves the bundle and the server
    cert agree on a chain."""
    bundle_pem = TEST_TLS_BUNDLE.read_bytes()
    server_cert = _load_furs_cer(TEST_BLAGAJNE_CER)

    # Walk the bundle, find the issuer of the server cert, verify the
    # issuer's signature on the server cert. If the bundle is wrong, this
    # raises InvalidSignature.
    pem_re = re.compile(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
    )
    chain = [
        x509.load_pem_x509_certificate(m.group(0))
        for m in pem_re.finditer(bundle_pem)
    ]
    issuer = next(
        (c for c in chain if c.subject == server_cert.issuer), None
    )
    assert issuer is not None, (
        f"server cert issuer {server_cert.issuer.rfc4514_string()!r} "
        f"not present in {bundle_path}"
    )
    issuer.public_key().verify(
        server_cert.signature,
        server_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        server_cert.signature_hash_algorithm,
    )


# ---------------------------------------------------------------------------
# 6. Pinned-response mode using the *real* FURS public key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "davpotrac_path,env",
    [(TEST_DAVPOTRAC_CER, "test"), (PROD_DAVPOTRAC_CER, "prod")],
)
def test_pinned_response_key_rejects_responses_signed_by_other_keys(
    real_p12_data, davpotrac_path: Path, env: str
):
    """``verify_furs_response=True`` with the published ``DavPotRac*.cer``
    public key MUST reject a JWS signed by anything else.

    Half of the load-bearing security work in this library: the pinned
    public key is what makes the connection MITM-resistant. If the wrong
    key were silently accepted, an attacker who could MITM TLS would also
    pass response-signature verification.
    """
    if not davpotrac_path.exists():
        pytest.skip(f"FURS-published cert not present at {davpotrac_path}")
    pinned_pub = load_response_public_key(davpotrac_path)

    # Sign a fake response with a *different* RSA key — this is what an
    # attacker-controlled response would look like.
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake_response = jwt.encode(
        {"InvoiceResponse": {"UniqueInvoiceID": "EOR-FAKE"}},
        key=other_key,
        algorithm="RS256",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": fake_response})

    client = FURSClient(
        p12_data=real_p12_data,
        p12_password=REAL_P12_PASSWORD,
        production=False,
        verify_furs_response=True,
        furs_response_public_key=pinned_pub,
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(FURSConnectionError, match="JWS verification failed"):
            client.submit_invoice(_real_invoice())
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 7. Live FURS test endpoint — opt-in via env var, *fully* MITM-resistant
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("FURS_LIVE_TEST"),
    reason="set FURS_LIVE_TEST=1 to hit blagajne-test.fu.gov.si:9002",
)
def test_live_register_business_premise_against_furs_test_endpoint(real_p12_data):
    """Round-trip a business-premise registration through the *real* FURS
    test endpoint, in fully-secure mode:

    * ``verify_tls`` pinned to the bundled SIGOV-CA / SI-TRUST chain
    * ``verify_furs_response=True`` pinned to the published
      ``DavPotRacTEST.cer`` public key

    This is the strongest mode the library supports. If FURS rotates
    either cert, this test fails the day after the rotation — exactly
    when you want it to.
    """
    if not TEST_TLS_BUNDLE.exists() or not TEST_DAVPOTRAC_CER.exists():
        pytest.skip(
            "specs/test_certs/sigov-ca-bundle.pem and DavPotRacTEST.cer "
            "are required for the fully-pinned live test"
        )

    pinned_pub = load_response_public_key(TEST_DAVPOTRAC_CER)

    bp = BusinessPremise(
        tax_number=REAL_P12_TAX_NUMBER,
        business_premise_id="REALBP1",
        bp_identifier=BPIdentifier(premise_type="A"),
        validity_date=date.today(),
        software_supplier=[SoftwareSupplier(tax_number=24564444)],
        special_notes="python-furs-fiscal live integration test (pinned)",
    )
    with FURSClient(
        p12_data=real_p12_data,
        p12_password=REAL_P12_PASSWORD,
        production=False,
        request_timeout=30.0,
        verify_tls=str(TEST_TLS_BUNDLE),
        verify_furs_response=True,
        furs_response_public_key=pinned_pub,
    ) as client:
        decoded = client.submit_business_premise(bp)
    assert "BusinessPremiseResponse" in decoded
    assert "Error" not in decoded["BusinessPremiseResponse"]


# ---------------------------------------------------------------------------
# 8. Expiry surveillance — yellow CI before FURS rotates a cert
# ---------------------------------------------------------------------------
#
# When a FURS-published cert is within CERT_EXPIRY_WARNING_DAYS of its
# notAfter, the relevant test below emits a UserWarning instead of failing.
# pytest surfaces these in its end-of-run "warnings summary", which most
# CI dashboards render as yellow. Once the cert actually expires the test
# fails red — by then refreshing the material is no longer optional.
#
# Workflow when one of these turns yellow::
#
#     make refresh-test-certs                    # for *TEST_*.cer / TEST_TLS_BUNDLE
#     make refresh-prod-certs PROD_YEAR=<YYYY>   # for *PROD_*.cer / PROD_TLS_BUNDLE
#
# then commit the updated files in ``specs/{test,prod}_certs/`` and
# update ``test_furs_published_cert_loads_and_has_expected_cn`` if FURS
# changed any CN in the rotation.

CERT_EXPIRY_WARNING_DAYS = 30


def _cert_not_valid_after_utc(cert: x509.Certificate) -> datetime:
    # Mirror the safe pattern used in furs_fiscal/transport.py so this
    # works on both cryptography <42 and >=42.
    return getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
        tzinfo=timezone.utc
    )


def _check_expiry(label: str, expires: datetime, refresh_hint: str) -> None:
    days_left = (expires - datetime.now(tz=timezone.utc)).days
    assert days_left > 0, (
        f"{label} EXPIRED {-days_left} days ago "
        f"(notAfter={expires.isoformat()}). {refresh_hint}"
    )
    if days_left < CERT_EXPIRY_WARNING_DAYS:
        warnings.warn(
            f"{label} expires in {days_left} days "
            f"(notAfter={expires.isoformat()}) — {refresh_hint}",
            UserWarning,
            stacklevel=2,
        )


@pytest.mark.parametrize(
    "path,refresh_target",
    [
        (TEST_DAVPOTRAC_CER, "make refresh-test-certs"),
        (TEST_BLAGAJNE_CER, "make refresh-test-certs"),
        (TEST_SIGOV_CA, "make refresh-test-certs"),
        (TEST_SI_TRUST_ROOT, "make refresh-test-certs"),
        (PROD_DAVPOTRAC_CER, "make refresh-prod-certs PROD_YEAR=<YYYY>"),
        (PROD_BLAGAJNE_CER, "make refresh-prod-certs PROD_YEAR=<YYYY>"),
        (PROD_SIGOV_CA, "make refresh-prod-certs PROD_YEAR=<YYYY>"),
        (PROD_SI_TRUST_ROOT, "make refresh-prod-certs PROD_YEAR=<YYYY>"),
    ],
)
def test_furs_published_cert_expiry(path: Path, refresh_target: str):
    """Surveillance: emit a warning if a FURS-published cert expires
    within ``CERT_EXPIRY_WARNING_DAYS`` days; fail outright if it has
    already expired. Skipped if the cert file is not checked out."""
    cert = _load_furs_cer(path)
    _check_expiry(
        label=path.name,
        expires=_cert_not_valid_after_utc(cert),
        refresh_hint=f"refresh via `{refresh_target}`",
    )


def test_real_p12_client_cert_expiry(real_p12_data):
    """Surveillance for the FURS test-environment client p12. Unlike the
    public certs, this one cannot be re-fetched with curl — it is FURS-
    issued material for *TESTNO PODJETJE 1211*. When this turns yellow,
    download the new p12 from the eDavki technical-specifications page
    and update REAL_P12_PASSWORD / the serial assertion in
    ``test_jws_header_uses_real_cert_metadata`` if either changed."""
    _, _, cert = _load_ssl_context_with_client_cert(
        p12_data=real_p12_data,
        p12_password=REAL_P12_PASSWORD,
        verify_tls=True,
    )
    _check_expiry(
        label="10492682-2.p12 (TESTNO PODJETJE 1211)",
        expires=_cert_not_valid_after_utc(cert),
        refresh_hint="re-issue via FURS eDavki and replace specs/test_certs/10492682-2.p12",
    )
