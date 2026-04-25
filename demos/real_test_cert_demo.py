"""End-to-end demo against the FURS test endpoint, fully MITM-resistant.

This is the 2.0-API replacement for the legacy 1.x demos in this directory.
It uses three pieces of FURS-published material in ``specs/test_certs/``:

  * ``10492682-2.p12`` — *TESTNO PODJETJE 1211* client cert (mTLS + JWS)
  * ``sigov-ca-bundle.pem`` — SIGOV-CA + SI-TRUST Root, used to pin the
    server-side TLS chain (``verify_tls``)
  * ``DavPotRacTEST.cer`` — FURS response signing public key, pinned via
    ``verify_furs_response=True``

…to:

  1. register a movable business premise (type ``A``) on the FURS test
     server, then
  2. submit a single invoice for that premise and print the EOR, then
  3. print the printable QR / Code-128 payload that goes on the receipt.

The demo defaults to the strongest mode the library supports: TLS
verification pinned against the SIGOV-CA chain, and FURS response
signature pinned against ``DavPotRacTEST.cer``. No system trust store, no
``x5c-untrusted`` warning, no insecure escape hatch unless asked.

It hits the live FURS test endpoint at
``https://blagajne-test.fu.gov.si:9002`` so it requires network egress.

Run::

    python -m demos.real_test_cert_demo
    # or
    python demos/real_test_cert_demo.py

Environment switches::

    # Switch to the production endpoint with the production cert+pubkey.
    FURS_PRODUCTION=1
    # Required in production mode (test mode defaults to TESTNO PODJETJE 1211).
    FURS_TAX_NUMBER=12345678
    # Override the client cert / password.
    FURS_CLIENT_P12=/path/to/cert.p12
    FURS_CLIENT_P12_PASSWORD=...
    # Override the TLS bundle (default: specs/{test,prod}_certs/sigov-ca-bundle.pem).
    FURS_CA_BUNDLE=/path/to/sigov.pem
    # Override the response-signing pubkey (default: DavPotRacTEST.cer / DavPotRac_2025.cer).
    FURS_RESPONSE_PUBKEY=/path/to/DavPotRac.cer
    # Last-resort: drop server TLS verification AND fall back to x5c-untrusted
    # response verification. Demo prints a warning when this is on.
    FURS_INSECURE=1

The legacy ``FURS_TEST_P12`` / ``FURS_TEST_P12_PASSWORD`` / ``FURS_TEST_CA_BUNDLE``
names are still accepted as aliases for one release.

See ``specs/test_certs/README.md`` for cert provenance and license.
"""

from __future__ import annotations

import os
import sys
import warnings
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

# Allow ``python demos/real_test_cert_demo.py`` from the project root without
# an editable install. ``python -m demos.real_test_cert_demo`` works too.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from furs_fiscal import (
    BPIdentifier,
    BusinessPremise,
    FURSClient,
    FURSResponseChainNotVerifiedWarning,
    Invoice,
    InvoiceIdentifier,
    SoftwareSupplier,
    TaxesPerSeller,
    VATAmount,
    load_response_public_key,
)

# ---------------------------------------------------------------------------
# Defaults (test environment is the demo's primary target)
# ---------------------------------------------------------------------------

TEST_DEFAULTS = {
    "endpoint": "https://blagajne-test.fu.gov.si:9002",
    "client_p12": _REPO_ROOT / "specs" / "test_certs" / "10492682-2.p12",
    "client_password": "DQHTBI591V00",  # FURS-published — not a secret.
    "tax_number": 10492682,
    "ca_bundle": _REPO_ROOT / "specs" / "test_certs" / "sigov-ca-bundle.pem",
    "response_pubkey_cer": _REPO_ROOT / "specs" / "test_certs" / "DavPotRacTEST.cer",
}

PROD_DEFAULTS = {
    "endpoint": "https://blagajne.fu.gov.si:9003",
    # No production client p12 ships with the library — the user supplies
    # their own via FURS_TEST_P12 / FURS_TEST_P12_PASSWORD.
    "client_p12": None,
    "client_password": None,
    "tax_number": None,
    "ca_bundle": _REPO_ROOT / "specs" / "prod_certs" / "sigov-ca-bundle.pem",
    "response_pubkey_cer": _REPO_ROOT / "specs" / "prod_certs" / "DavPotRac_2025.cer",
}

BP_ID = "REALBP1"
DEVICE_ID = "B1"


def _env(*names: str) -> str | None:
    """Return the first non-empty value for any of the given env-var names.

    Used to accept the new (``FURS_CLIENT_P12``...) names while still
    honouring the legacy (``FURS_TEST_P12``...) ones for one release.
    """
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _resolve_environment() -> dict:
    production = bool(os.environ.get("FURS_PRODUCTION"))
    base = PROD_DEFAULTS if production else TEST_DEFAULTS
    insecure = bool(os.environ.get("FURS_INSECURE"))

    p12_path_env = _env("FURS_CLIENT_P12", "FURS_TEST_P12")
    p12_path = Path(p12_path_env) if p12_path_env else base["client_p12"]
    p12_password = (
        _env("FURS_CLIENT_P12_PASSWORD", "FURS_TEST_P12_PASSWORD")
        or base["client_password"]
    )

    ca_bundle_env = _env("FURS_CA_BUNDLE", "FURS_TEST_CA_BUNDLE")
    ca_bundle = Path(ca_bundle_env) if ca_bundle_env else base["ca_bundle"]

    response_pubkey_env = os.environ.get("FURS_RESPONSE_PUBKEY")
    response_pubkey_path = (
        Path(response_pubkey_env) if response_pubkey_env else base["response_pubkey_cer"]
    )

    tax_number_env = os.environ.get("FURS_TAX_NUMBER")
    tax_number = (
        int(tax_number_env) if tax_number_env else base["tax_number"]
    )

    if production and not p12_path:
        raise SystemExit(
            "FURS_PRODUCTION=1 requires FURS_CLIENT_P12 and "
            "FURS_CLIENT_P12_PASSWORD (no production client cert ships "
            "with this repo)."
        )
    if production and not tax_number:
        raise SystemExit(
            "FURS_PRODUCTION=1 requires FURS_TAX_NUMBER (the VAT number "
            "embedded in your production client cert)."
        )
    if not p12_path or not Path(p12_path).exists():
        raise SystemExit(
            f"PKCS#12 file not found at {p12_path}. Set FURS_CLIENT_P12 "
            "to override."
        )
    if not insecure:
        missing = [
            str(p)
            for p in (ca_bundle, response_pubkey_path)
            if not p.exists()
        ]
        if missing:
            raise SystemExit(
                "FURS-published trust material missing: "
                f"{', '.join(missing)}. Re-fetch from edavki.durs.si or "
                "pass FURS_INSECURE=1 to fall back to x5c-untrusted + "
                "system TLS."
            )

    return {
        "production": production,
        "endpoint": base["endpoint"],
        "p12_path": Path(p12_path),
        "p12_password": p12_password,
        "tax_number": tax_number,
        "ca_bundle": ca_bundle,
        "response_pubkey_path": response_pubkey_path,
        "insecure": insecure,
    }


def _make_client(env: dict) -> FURSClient:
    if env["insecure"]:
        warnings.simplefilter("ignore", FURSResponseChainNotVerifiedWarning)
        return FURSClient(
            p12_data=env["p12_path"].read_bytes(),
            p12_password=env["p12_password"],
            production=env["production"],
            request_timeout=30.0,
            verify_tls=False,
            verify_furs_response="x5c-untrusted",
        )
    return FURSClient(
        p12_data=env["p12_path"].read_bytes(),
        p12_password=env["p12_password"],
        production=env["production"],
        request_timeout=30.0,
        verify_tls=str(env["ca_bundle"]),
        verify_furs_response=True,
        furs_response_public_key=load_response_public_key(
            env["response_pubkey_path"]
        ),
    )


def register_business_premise(client: FURSClient, *, tax_number: int) -> None:
    """Register a movable type-A premise. Idempotent on the FURS test
    server — re-registering the same ID with the same data is fine."""
    bp = BusinessPremise(
        tax_number=tax_number,
        business_premise_id=BP_ID,
        bp_identifier=BPIdentifier(premise_type="A"),
        validity_date=date.today(),
        software_supplier=[SoftwareSupplier(tax_number=tax_number)],
        special_notes="python-furs-fiscal real-cert demo",
    )
    decoded = client.submit_business_premise(bp)
    header = decoded["BusinessPremiseResponse"]["Header"]
    print(
        f"  registered BP {BP_ID!r} "
        f"(MessageID={header['MessageID']}, DateTime={header['DateTime']})"
    )


def submit_one_invoice(client: FURSClient, *, tax_number: int, invoice_number: str) -> None:
    issued = datetime.now(tz=timezone.utc)

    zoi = client.calculate_zoi(
        tax_number=tax_number,
        issued_date=issued,
        invoice_number=invoice_number,
        business_premise_id=BP_ID,
        electronic_device_id=DEVICE_ID,
        invoice_amount=Decimal("19.15"),
    )
    print(f"  ZOI: {zoi}")

    invoice = Invoice(
        tax_number=tax_number,
        issue_date_time=issued,
        numbering_structure="B",
        invoice_identifier=InvoiceIdentifier(
            business_premise_id=BP_ID,
            electronic_device_id=DEVICE_ID,
            invoice_number=invoice_number,
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
        protected_id=zoi,
    )
    eor = client.submit_invoice(invoice)
    printable = client.prepare_printable(
        tax_number=tax_number, zoi=zoi, issued_date=issued
    )
    print(f"  EOR: {eor}")
    print(f"  printable (QR/Code-128 payload, 60 digits): {printable}")


def main() -> int:
    env = _resolve_environment()

    print(f"Endpoint:   {env['endpoint']}")
    print(f"Client p12: {env['p12_path']}")
    if env["insecure"]:
        print("verify_tls: DISABLED (FURS_INSECURE=1)")
        print("verify_furs_response: x5c-untrusted (FURS_INSECURE=1)")
    else:
        print(f"verify_tls: pinned to {env['ca_bundle']}")
        print(f"verify_furs_response: pinned to {env['response_pubkey_path']}")
    print()

    with _make_client(env) as client:
        print("[1/2] Registering business premise...")
        register_business_premise(client, tax_number=env["tax_number"])
        print()
        print("[2/2] Submitting invoice...")
        # Use full epoch seconds (10 digits, well under FURS's 20-char
        # InvoiceNumber limit) so reruns never collide with the FURS
        # test-server's (BP_ID, device, invoice_number) uniqueness key.
        invoice_number = str(int(datetime.now().timestamp()))
        submit_one_invoice(
            client, tax_number=env["tax_number"], invoice_number=invoice_number
        )

    print()
    print("OK — round-trip complete against FURS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
