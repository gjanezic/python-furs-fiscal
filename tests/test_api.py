"""High-level FURSClient tests against a mock httpx transport.

Exercises the full submit_invoice / submit_business_premise / batch flow
including per-record FURSBatchError handling.
"""

from __future__ import annotations

import base64
import warnings
from datetime import date, datetime, timezone
from decimal import Decimal

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from furs_fiscal import (
    BPIdentifier,
    BusinessPremise,
    FURSBatchError,
    FURSClient,
    FURSResponseChainNotVerifiedWarning,
    FURSSchemaError,
    Invoice,
    InvoiceIdentifier,
    SoftwareSupplier,
    TaxesPerSeller,
    VATAmount,
)
from tests.conftest import P12_PASSWORD


def _signed_response_token(payload: dict) -> tuple[str, rsa.RSAPrivateKey]:
    """Produce an x5c-signed JWS that x5c-untrusted mode will accept."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FURS")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FURS")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(tz=timezone.utc))
        .not_valid_after(datetime(2099, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
    return jwt.encode(payload, key=key, headers={"x5c": [x5c]}, algorithm="RS256"), key


def _client_with_handler(p12_data: bytes, handler) -> FURSClient:
    return FURSClient(
        p12_data=p12_data,
        p12_password=P12_PASSWORD,
        production=False,
        transport=httpx.MockTransport(handler),
    )


def _make_invoice(invoice_number: str = "11", invoice_amount: str = "19.15") -> Invoice:
    return Invoice(
        tax_number=10039856,
        issue_date_time=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
        numbering_structure="B",
        invoice_identifier=InvoiceIdentifier(
            business_premise_id="BP1",
            electronic_device_id="B1",
            invoice_number=invoice_number,
        ),
        invoice_amount=Decimal(invoice_amount),
        payment_amount=Decimal(invoice_amount),
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


# ---------------------------------------------------------------------------
# Single-record submit
# ---------------------------------------------------------------------------


def test_submit_invoice_returns_eor(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_token, _ = _signed_response_token(
        {
            "InvoiceResponse": {
                "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                "UniqueInvoiceID": "EOR-CLIENT-1",
            }
        }
    )
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = request.content
        return httpx.Response(200, json={"token": response_token})

    client = _client_with_handler(p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            eor = client.submit_invoice(_make_invoice())
        assert eor == "EOR-CLIENT-1"
        assert "/v1/cash_registers/invoices" in captured["url"]
    finally:
        client.close()


def test_submit_invoice_propagates_furs_schema_error(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_token, _ = _signed_response_token(
        {
            "InvoiceResponse": {
                "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                "Error": {"ErrorCode": "S002", "ErrorMessage": "JSON schema mismatch"},
            }
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    client = _client_with_handler(p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            with pytest.raises(FURSSchemaError):
                client.submit_invoice(_make_invoice())
    finally:
        client.close()


def test_submit_business_premise_returns_decoded_envelope(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_token, _ = _signed_response_token(
        {
            "BusinessPremiseResponse": {
                "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
            }
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    client = _client_with_handler(p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            decoded = client.submit_business_premise(
                BusinessPremise(
                    tax_number=10039856,
                    business_premise_id="BP1",
                    bp_identifier=BPIdentifier(premise_type="A"),
                    validity_date=date(2026, 4, 25),
                    software_supplier=[SoftwareSupplier(tax_number=24564444)],
                )
            )
        assert "BusinessPremiseResponse" in decoded
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------


def test_submit_invoice_batch_returns_per_record_eors(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_token, _ = _signed_response_token(
        {
            "InvoiceListResponse": {
                "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                "InvoiceListReply": {
                    "RecordReply": [
                        {
                            "RecordNumber": 1,
                            "ProtectedID": "34905bcff14b381039af2e9d7eee54bb",
                            "UniqueInvoiceID": "EOR-1",
                        },
                        {
                            "RecordNumber": 2,
                            "ProtectedID": "34905bcff14b381039af2e9d7eee54bc",
                            "UniqueInvoiceID": "EOR-2",
                        },
                    ]
                },
            }
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    client = _client_with_handler(p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            replies = client.submit_invoice_batch(
                [_make_invoice("11"), _make_invoice("12")]
            )
        assert replies == {
            1: {"ProtectedID": "34905bcff14b381039af2e9d7eee54bb", "UniqueInvoiceID": "EOR-1"},
            2: {"ProtectedID": "34905bcff14b381039af2e9d7eee54bc", "UniqueInvoiceID": "EOR-2"},
        }
    finally:
        client.close()


def test_submit_invoice_batch_raises_with_per_record_errors(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    response_token, _ = _signed_response_token(
        {
            "InvoiceListResponse": {
                "Header": {"MessageID": "x", "DateTime": "2026-04-25T10:00:00"},
                "InvoiceListReply": {
                    "RecordReply": [
                        {
                            "RecordNumber": 1,
                            "ProtectedID": "34905bcff14b381039af2e9d7eee54bb",
                            "UniqueInvoiceID": "EOR-1",
                        },
                        {
                            "RecordNumber": 2,
                            "Error": {
                                "ErrorCode": "S002",
                                "ErrorMessage": "bad record",
                            },
                        },
                    ]
                },
            }
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": response_token})

    client = _client_with_handler(p12_data, handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
            with pytest.raises(FURSBatchError) as exc:
                client.submit_invoice_batch(
                    [_make_invoice("11"), _make_invoice("12")]
                )
        # Successful records preserved on the exception so callers can mark
        # them as done before retrying the failures.
        assert 1 in exc.value.successes
        assert exc.value.successes[1]["UniqueInvoiceID"] == "EOR-1"
        assert 2 in exc.value.record_errors
        assert isinstance(exc.value.record_errors[2], FURSSchemaError)
    finally:
        client.close()


def test_submit_invoice_batch_rejects_single_invoice(p12_data_and_key):
    p12_data, _ = p12_data_and_key

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not have been called")

    client = _client_with_handler(p12_data, handler)
    try:
        with pytest.raises(ValueError, match="2..500"):
            client.submit_invoice_batch([_make_invoice("11")])
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Convenience: ZOI/printable on the client wraps the underlying private key
# ---------------------------------------------------------------------------


def test_calculate_zoi_uses_client_private_key(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    client = FURSClient(p12_data=p12_data, p12_password=P12_PASSWORD, production=False)
    try:
        zoi = client.calculate_zoi(
            tax_number=10039856,
            issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            invoice_number="11",
            business_premise_id="BP1",
            electronic_device_id="B1",
            invoice_amount=Decimal("19.15"),
        )
        assert len(zoi) == 32
    finally:
        client.close()


def test_client_context_manager_closes(p12_data_and_key):
    p12_data, _ = p12_data_and_key
    with FURSClient(
        p12_data=p12_data, p12_password=P12_PASSWORD, production=False
    ) as client:
        assert client is not None
    # After __exit__ the underlying httpx client should be closed.
    assert client._connector._client.is_closed
