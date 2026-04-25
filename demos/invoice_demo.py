"""ZOI + printable QR/Code-128 payload — no network call.

2.0 replacement for the legacy 1.x demo. Loads the bundled demo p12,
calculates a ZOI, and renders the 60-digit QR / Code-128 / PDF-417
payload that goes on the printed receipt. This demo is fully offline:
no FURS endpoint is contacted.

Run::

    python -m demos.invoice_demo
    # or
    python demos/invoice_demo.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from furs_fiscal import FURSClient

P12_CERT_PATH = Path(__file__).parent / "demo_podjetje.p12"
P12_CERT_PASS = "Geslo123#"
TAX_NUMBER = 10039856


def main() -> int:
    """Calculate a ZOI for the invoice ``11/BP101/B1`` and print the QR payload.

    The receipt uses the layout ``<InvoiceNumber>/<BusinessPremiseID>/<ElectronicDeviceID>``:

    * ``11`` — sequential invoice number
    * ``BP101`` — business premise mark
    * ``B1`` — electronic device mark
    """
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
            business_premise_id="BP101",
            electronic_device_id="B1",
            invoice_amount=Decimal("19.15"),
        )
        print(f"ZOI: {zoi}")

        printable = client.prepare_printable(
            tax_number=TAX_NUMBER, zoi=zoi, issued_date=issued
        )
        print(f"QR/Code128/PDF417 payload (60 digits): {printable}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
