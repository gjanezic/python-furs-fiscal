"""Submit a pre-numbered-invoice-book (vezana knjiga) invoice.

2.0 replacement for the legacy 1.x demo. Builds a
:class:`SalesBookInvoice` with a sales-book identifier
(``InvoiceNumber`` + ``SetNumber`` + ``SerialNumber``), submits it via
:class:`FURSClient`, and prints the FURS-issued EOR.

Per spec sec. 3.1 (R_4.x): the sales-book invoice has no
``OperatorTaxNumber`` field. ``IssueDate`` is a date (no time
component) and the schema does not allow ``NumberingStructure``,
``ProtectedID``, or ``ReferenceInvoice`` either — those are
electronic-device-only.

Run::

    python -m demos.sales_book_invoice_eor_demo
"""

from __future__ import annotations

import sys
from datetime import date
from decimal import Decimal
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from furs_fiscal import (
    FURSClient,
    SalesBookIdentifier,
    SalesBookInvoice,
    TaxesPerSeller,
    VATAmount,
)

P12_CERT_PATH = Path(__file__).parent / "demo_podjetje.p12"
P12_CERT_PASS = "Geslo123#"
TAX_NUMBER = 10039856
BP_ID = "BP105"


def main() -> int:
    with FURSClient(
        p12_data=P12_CERT_PATH.read_bytes(),
        p12_password=P12_CERT_PASS,
        production=False,
    ) as client:
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

        invoice = SalesBookInvoice(
            tax_number=TAX_NUMBER,
            issue_date=date.today(),
            sales_book_identifier=SalesBookIdentifier(
                invoice_number="612",
                set_number="03",
                serial_number="5001-0001018",
            ),
            business_premise_id=BP_ID,
            invoice_amount=Decimal("66.71"),
            payment_amount=Decimal("66.71"),
            taxes_per_seller=[own_taxes],
        )

        eor = client.submit_sales_book_invoice(invoice)
        print(f"EOR: {eor}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
