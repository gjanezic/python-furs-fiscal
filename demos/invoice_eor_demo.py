"""Submit an electronic-device invoice and print the EOR.

2.0 replacement for the legacy 1.x demo. Constructs an :class:`Invoice`
with multiple VAT rates plus a reference to two prior invoices, signs +
posts it via :class:`FURSClient`, and prints the FURS-issued EOR
(``UniqueInvoiceID``).

This demo uses the bundled demo p12, which is **not** registered on the
FURS test server. Calling ``submit_invoice`` will therefore fail at the
network layer (TLS handshake) or with ``FURSCertificateError`` if FURS
sees an unknown cert serial. To exercise the full round-trip against
the live FURS test endpoint use ``demos/real_test_cert_demo.py``.

Run::

    python -m demos.invoice_eor_demo
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from furs_fiscal import (
    FURSClient,
    Invoice,
    InvoiceIdentifier,
    ReferenceInvoice,
    TaxesPerSeller,
    VATAmount,
)

P12_CERT_PATH = Path(__file__).parent / "demo_podjetje.p12"
P12_CERT_PASS = "Geslo123#"
TAX_NUMBER = 10039856
BP_ID = "BP105"
DEVICE_ID = "B1"


def main() -> int:
    with FURSClient(
        p12_data=P12_CERT_PATH.read_bytes(),
        p12_password=P12_CERT_PASS,
        production=False,
    ) as client:
        issued = datetime.now(tz=timezone.utc)

        zoi = client.calculate_zoi(
            tax_number=TAX_NUMBER,
            issued_date=issued,
            invoice_number="11",
            business_premise_id=BP_ID,
            electronic_device_id=DEVICE_ID,
            invoice_amount=Decimal("66.71"),
        )
        print(f"ZOI: {zoi}")

        # One seller (the issuer), three VAT rates: 22%, 9.5%, 5%.
        # SellerTaxNumber is omitted — it's only required for additional
        # sellers, never for the issuer.
        own_taxes = TaxesPerSeller(
            vat=[
                VATAmount(
                    tax_rate=Decimal("22"),
                    taxable_amount=Decimal("23.14"),
                    tax_amount=Decimal("5.09"),
                ),
                VATAmount(
                    tax_rate=Decimal("9.5"),
                    taxable_amount=Decimal("35.14"),
                    tax_amount=Decimal("3.34"),
                ),
                VATAmount(
                    tax_rate=Decimal("5"),
                    taxable_amount=Decimal("10.00"),
                    tax_amount=Decimal("0.50"),
                ),
            ]
        )

        # Reference two earlier invoices on the same premise/device.
        reference_invoices = [
            ReferenceInvoice(
                reference_invoice_identifier=InvoiceIdentifier(
                    business_premise_id=BP_ID,
                    electronic_device_id=DEVICE_ID,
                    invoice_number=str(n),
                ),
                reference_invoice_issue_date_time=issued,
            )
            for n in (9, 10)
        ]

        invoice = Invoice(
            tax_number=TAX_NUMBER,
            issue_date_time=issued,
            numbering_structure="B",
            invoice_identifier=InvoiceIdentifier(
                business_premise_id=BP_ID,
                electronic_device_id=DEVICE_ID,
                invoice_number="11",
            ),
            invoice_amount=Decimal("66.71"),
            payment_amount=Decimal("66.71"),
            taxes_per_seller=[own_taxes],
            operator_tax_number=12345678,
            reference_invoice=reference_invoices,
            protected_id=zoi,
        )

        eor = client.submit_invoice(invoice)
        print(f"EOR: {eor}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
