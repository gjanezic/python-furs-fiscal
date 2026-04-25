"""Register an immovable + a movable business premise.

2.0 replacement for the legacy 1.x demo. Builds two
:class:`BusinessPremise` objects — one with cadastral data and street
address (``RealEstateBP``), one type-A movable (``PremiseType="A"``) —
and submits them via :class:`FURSClient`.

The bundled demo p12 is **not** registered on the FURS test server, so
``submit_business_premise`` will fail at the TLS handshake or with
``FURSCertificateError``. The end-to-end round-trip lives in
``demos/real_test_cert_demo.py``.

Run::

    python -m demos.business_premise_demo
"""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from furs_fiscal import (
    Address,
    BPIdentifier,
    BusinessPremise,
    FURSClient,
    PropertyID,
    RealEstateBP,
    SoftwareSupplier,
)

P12_CERT_PATH = Path(__file__).parent / "demo_podjetje.p12"
P12_CERT_PASS = "Geslo123#"
TAX_NUMBER = 10039856
SOFTWARE_SUPPLIER_TAX_NUMBER = 24564444


def register_immovable(client: FURSClient) -> None:
    """Register an immovable premise at Trzaska cesta 24A, Ljubljana."""
    bp = BusinessPremise(
        tax_number=TAX_NUMBER,
        business_premise_id="BP105",
        bp_identifier=BPIdentifier(
            real_estate_bp=RealEstateBP(
                property_id=PropertyID(
                    cadastral_number=112,
                    building_number=11,
                    building_section_number=1,
                ),
                address=Address(
                    street="Trzaska cesta",
                    house_number="24",
                    house_number_additional="A",
                    community="Ljubljana",
                    city="Ljubljana",
                    postal_code="1000",
                ),
            )
        ),
        validity_date=date.today() - timedelta(days=360),
        software_supplier=[
            SoftwareSupplier(tax_number=SOFTWARE_SUPPLIER_TAX_NUMBER)
        ],
    )
    decoded = client.submit_business_premise(bp)
    msg_id = decoded["BusinessPremiseResponse"]["Header"]["MessageID"]
    print(f"Immovable BP105 registered (MessageID={msg_id})")


def register_movable(client: FURSClient) -> None:
    """Register a movable type-A premise (vehicle / portable stand).

    Movable types per spec sec. 3.2.1 / P_5.2:
      * ``A`` — movable object (vehicle, portable stand)
      * ``B`` — object at a permanent location (market stand, kiosk)
      * ``C`` — individual electronic device with no other premise
    """
    bp = BusinessPremise(
        tax_number=TAX_NUMBER,
        business_premise_id="MOB1",
        bp_identifier=BPIdentifier(premise_type="A"),
        validity_date=date.today() - timedelta(days=60),
        software_supplier=[
            SoftwareSupplier(tax_number=SOFTWARE_SUPPLIER_TAX_NUMBER)
        ],
    )
    decoded = client.submit_business_premise(bp)
    msg_id = decoded["BusinessPremiseResponse"]["Header"]["MessageID"]
    print(f"Movable MOB1 registered (MessageID={msg_id})")


def main() -> int:
    with FURSClient(
        p12_data=P12_CERT_PATH.read_bytes(),
        p12_password=P12_CERT_PASS,
        production=False,
    ) as client:
        register_immovable(client)
        register_movable(client)
    return 0


if __name__ == "__main__":
    sys.exit(main())
