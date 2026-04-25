"""High-level FURS client.

Single entry point for application code. Wraps :class:`Connector`, exposes
typed submit methods that take pydantic models, and converts FURS-side errors
into the granular exception hierarchy.

Typical usage::

    from datetime import datetime, timezone
    from decimal import Decimal
    from pathlib import Path

    from furs_fiscal import (
        FURSClient,
        Invoice,
        InvoiceIdentifier,
        TaxesPerSeller,
        VATAmount,
    )

    client = FURSClient(
        p12_data=Path("client.p12").read_bytes(),
        p12_password="secret",
        production=False,
    )

    issued = datetime.now(tz=timezone.utc)
    zoi = client.calculate_zoi(
        tax_number=10039856,
        issued_date=issued,
        invoice_number="11",
        business_premise_id="BP1",
        electronic_device_id="B1",
        invoice_amount=Decimal("19.15"),
    )

    invoice = Invoice(
        tax_number=10039856,
        issue_date_time=issued,
        numbering_structure="B",
        invoice_identifier=InvoiceIdentifier(
            business_premise_id="BP1", electronic_device_id="B1", invoice_number="11"
        ),
        invoice_amount=Decimal("19.15"),
        payment_amount=Decimal("19.15"),
        taxes_per_seller=[
            TaxesPerSeller(vat=[
                VATAmount(tax_rate=Decimal("22"), taxable_amount=Decimal("15.70"), tax_amount=Decimal("3.45")),
            ])
        ],
        protected_id=zoi,
    )
    eor = client.submit_invoice(invoice)
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

import httpx

from .exceptions import (
    FURSBatchError,
    FURSResponseError,
    from_furs_error,
)
from .models import (
    BusinessPremise,
    Identifier,
    Invoice,
    InvoiceNumberStr,
    SalesBookInvoice,
    TaxNumber,
    ZOIHex,
    wrap_business_premise,
    wrap_business_premise_batch,
    wrap_invoice,
    wrap_invoice_batch,
    wrap_sales_book_invoice,
)
from .transport import Connector, VerifyMode
from .zoi import calculate_zoi as _calculate_zoi
from .zoi import prepare_printable as _prepare_printable

# FURS endpoint paths (spec sec. 6.1).
PATH_INVOICE = "v1/cash_registers/invoices"
PATH_INVOICE_BATCH = "v1/cash_registers_batch/invoices"
PATH_BUSINESS_PREMISE = "v1/cash_registers/invoices/register"
PATH_BUSINESS_PREMISE_BATCH = "v1/cash_registers_batch/invoices/register"


class FURSClient:
    """Application-facing client for the FURS fiscal-verification web service."""

    def __init__(
        self,
        *,
        p12_data: bytes,
        p12_password: str,
        production: bool,
        request_timeout: float = 10.0,
        verify_tls: bool | str = True,
        verify_furs_response: VerifyMode = "x5c-untrusted",
        furs_response_public_key: bytes | str | None = None,
        proxy: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._connector = Connector(
            p12_data=p12_data,
            p12_password=p12_password,
            production=production,
            request_timeout=request_timeout,
            verify_tls=verify_tls,
            verify_furs_response=verify_furs_response,
            furs_response_public_key=furs_response_public_key,
            proxy=proxy,
            transport=transport,
        )

    # -- Lifecycle ------------------------------------------------------------

    def close(self) -> None:
        self._connector.close()

    def __enter__(self) -> FURSClient:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    # -- ZOI helpers ----------------------------------------------------------

    def calculate_zoi(
        self,
        *,
        tax_number: TaxNumber,
        issued_date: datetime,
        invoice_number: InvoiceNumberStr,
        business_premise_id: Identifier,
        electronic_device_id: Identifier,
        invoice_amount: Decimal,
    ) -> str:
        return _calculate_zoi(
            private_key=self._connector.private_key,
            tax_number=tax_number,
            issued_date=issued_date,
            invoice_number=invoice_number,
            business_premise_id=business_premise_id,
            electronic_device_id=electronic_device_id,
            invoice_amount=invoice_amount,
        )

    @staticmethod
    def prepare_printable(
        *,
        tax_number: TaxNumber,
        zoi: ZOIHex,
        issued_date: datetime,
    ) -> str:
        return _prepare_printable(
            tax_number=tax_number, zoi=zoi, issued_date=issued_date
        )

    # -- Single-record submissions -------------------------------------------

    def submit_invoice(self, invoice: Invoice) -> str:
        """POST a single invoice and return the FURS-issued EOR (UniqueInvoiceID)."""
        decoded = self._connector.post(
            path=PATH_INVOICE, payload=wrap_invoice(invoice)
        )
        return decoded["InvoiceResponse"]["UniqueInvoiceID"]

    def submit_sales_book_invoice(self, invoice: SalesBookInvoice) -> str:
        """POST a pre-numbered-invoice-book invoice and return the EOR."""
        decoded = self._connector.post(
            path=PATH_INVOICE, payload=wrap_sales_book_invoice(invoice)
        )
        return decoded["InvoiceResponse"]["UniqueInvoiceID"]

    def submit_business_premise(self, premise: BusinessPremise) -> dict[str, Any]:
        """POST business-premise registration. Returns the (header-only) reply."""
        return self._connector.post(
            path=PATH_BUSINESS_PREMISE, payload=wrap_business_premise(premise)
        )

    # -- Batch submissions ----------------------------------------------------

    def submit_invoice_batch(self, invoices: list[Invoice]) -> dict[int, dict[str, Any]]:
        """POST a 2..500-record invoice batch.

        Returns a dict mapping ``RecordNumber`` to its reply
        (``{ProtectedID, UniqueInvoiceID}``).

        Raises :class:`FURSBatchError` when one or more records have an
        ``Error`` block. The batch-wide ``Error`` envelope (spec sec. 6.2)
        is converted to the appropriate :class:`FURSResponseError` subclass
        by the transport layer.
        """
        decoded = self._connector.post(
            path=PATH_INVOICE_BATCH, payload=wrap_invoice_batch(invoices)
        )
        return self._collect_record_replies(
            decoded["InvoiceListResponse"]["InvoiceListReply"]["RecordReply"]
        )

    def submit_business_premise_batch(
        self, premises: list[BusinessPremise]
    ) -> dict[str, Any]:
        """POST a 2..500-record business-premise batch."""
        return self._connector.post(
            path=PATH_BUSINESS_PREMISE_BATCH,
            payload=wrap_business_premise_batch(premises),
        )

    @staticmethod
    def _collect_record_replies(
        record_replies: list[dict[str, Any]],
    ) -> dict[int, dict[str, Any]]:
        """Split per-record replies into successes / failures.

        Returns the success dict on the all-OK path. If any record carries an
        ``Error`` block, raises :class:`FURSBatchError` instead — the partial
        successes are accessible via ``exc.successes`` so callers can persist
        completed EORs without resubmitting them.
        """
        successes: dict[int, dict[str, Any]] = {}
        failures: dict[int, FURSResponseError] = {}
        for reply in record_replies:
            number = reply["RecordNumber"]
            err = reply.get("Error")
            if err:
                failures[number] = from_furs_error(
                    err["ErrorCode"], err["ErrorMessage"]
                )
            else:
                successes[number] = {
                    "ProtectedID": reply.get("ProtectedID"),
                    "UniqueInvoiceID": reply.get("UniqueInvoiceID"),
                }
        if failures:
            raise FURSBatchError(record_errors=failures, successes=successes)
        return successes
