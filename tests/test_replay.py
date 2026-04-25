"""Replay the official signed FURS examples and assert that the library
produces an equivalent payload.

Each official ``specs/examples/*.txt`` file contains a JWS token. We decode
it, build the same logical request via the pydantic models, and compare the
resulting JSON dicts. This is the strongest skladnost test: if it passes,
our wire format is byte-equivalent to FURS' own examples (modulo Header
fields which are always per-message).

Also runs full JSON Schema validation against
``specs/schemas/FiscalVerificationSchema.json`` on the library output.
"""

from __future__ import annotations

import base64
import json
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest

try:
    import jsonschema
    from jsonschema.validators import extend
except ImportError:  # pragma: no cover
    jsonschema = None

from furs_fiscal import (
    Address,
    BPIdentifier,
    BusinessPremise,
    Geolocation,
    Invoice,
    InvoiceIdentifier,
    PropertyID,
    RealEstateBP,
    SalesBookIdentifier,
    SalesBookInvoice,
    SoftwareSupplier,
    TaxesPerSeller,
    VATAmount,
    VendingMachine,
    wrap_business_premise,
    wrap_business_premise_batch,
    wrap_invoice,
    wrap_sales_book_invoice,
)
from furs_fiscal.models import LJUBLJANA

REPO = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO / "specs" / "schemas" / "FiscalVerificationSchema.json"
SCHEMA_BATCH_PATH = REPO / "specs" / "schemas" / "FiscalVerificationSchemaBatch.json"
EXAMPLES = REPO / "specs" / "examples"

pytestmark = [
    pytest.mark.skipif(jsonschema is None, reason="jsonschema not installed"),
    pytest.mark.skipif(
        not EXAMPLES.is_dir() or not any(EXAMPLES.glob("*.txt")),
        reason="specs/examples not present (sdist install or partial clone)",
    ),
    pytest.mark.skipif(
        not SCHEMA_PATH.is_file() or not SCHEMA_BATCH_PATH.is_file(),
        reason="specs/schemas not present",
    ),
]


def _decode_official_token(path: Path) -> dict:
    raw = path.read_text().strip()
    token = json.loads(raw)["token"] if raw.startswith("{") else raw
    payload_b64 = token.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def _strip_header(envelope: dict) -> dict:
    """Drop the per-message Header so payloads can be compared structurally."""
    out = {}
    for top_key, top_val in envelope.items():
        cleaned = {k: v for k, v in top_val.items() if k != "Header"}
        out[top_key] = cleaned
    return out


# ---------------------------------------------------------------------------
# JSON Schema cross-check
# ---------------------------------------------------------------------------


def _floats_to_decimal(obj):
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _floats_to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_floats_to_decimal(v) for v in obj]
    return obj


def _decimals_to_float(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: _decimals_to_float(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decimals_to_float(v) for v in obj]
    return obj


def _decimal_aware_validator(schema):
    type_checker = jsonschema.Draft4Validator.TYPE_CHECKER.redefine(
        "number",
        lambda checker, instance: isinstance(instance, (int, float, Decimal))
        and not isinstance(instance, bool),
    )
    Validator = extend(jsonschema.Draft4Validator, type_checker=type_checker)
    return Validator(schema)


def _validate_against_schema(payload: dict, schema_path: Path = SCHEMA_PATH) -> None:
    schema = json.loads(schema_path.read_text(), parse_float=Decimal)
    jsonschema.Draft4Validator.check_schema(_decimals_to_float(schema))
    _decimal_aware_validator(schema).validate(_floats_to_decimal(payload))


# ---------------------------------------------------------------------------
# Replay: invoice from electronic device (PrimerDokumentacijaRacunJsonPodpisanToken)
# ---------------------------------------------------------------------------


def test_replay_official_invoice_example():
    """Spec sec. 9.1 — invoice via electronic device, two VAT lines + operator."""
    expected = _decode_official_token(
        EXAMPLES / "PrimerDokumentacijaRacunJsonPodpisanToken.txt"
    )

    invoice = Invoice(
        tax_number=99999862,
        issue_date_time=datetime(2015, 8, 7, 13, 5, 24, tzinfo=LJUBLJANA),
        numbering_structure="B",
        invoice_identifier=InvoiceIdentifier(
            business_premise_id="TRGOVINA1",
            electronic_device_id="BLAG2",
            invoice_number="145",
        ),
        invoice_amount=Decimal("66.71"),
        payment_amount=Decimal("1047.76"),
        taxes_per_seller=[
            TaxesPerSeller(
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
                ]
            )
        ],
        operator_tax_number=12345678,
        protected_id="34905bcff14b381039af2e9d7eee54bb",
    )
    actual = wrap_invoice(invoice)

    assert _strip_header(actual) == _strip_header(expected)
    _validate_against_schema(actual)


# ---------------------------------------------------------------------------
# Replay: sales-book invoice (vezana knjiga)
# ---------------------------------------------------------------------------


def test_replay_official_sales_book_invoice_example():
    """Spec sec. 9.2 — invoice from a pre-numbered invoice book."""
    expected = _decode_official_token(
        EXAMPLES / "PrimerDokumentacijaRacunVezanaKnjigaJsonPodpisanToken.txt"
    )

    invoice = SalesBookInvoice(
        tax_number=99999862,
        issue_date=date(2016, 4, 10),
        sales_book_identifier=SalesBookIdentifier(
            invoice_number="612",
            set_number="03",
            serial_number="5001-0001018",
        ),
        business_premise_id="TRGOVINA1",
        invoice_amount=Decimal("1060.06"),
        returns_amount=Decimal("12.30"),
        payment_amount=Decimal("1047.76"),
        taxes_per_seller=[
            TaxesPerSeller(
                vat=[
                    VATAmount(
                        tax_rate=Decimal("22"),
                        taxable_amount=Decimal("36.89"),
                        tax_amount=Decimal("8.12"),
                    ),
                    VATAmount(
                        tax_rate=Decimal("9.5"),
                        taxable_amount=Decimal("56.53"),
                        tax_amount=Decimal("5.37"),
                    ),
                ],
                other_taxes_amount=Decimal("53.89"),
                exempt_vat_taxable_amount=Decimal("142.87"),
                reverse_vat_taxable_amount=Decimal("67.34"),
                nontaxable_amount=Decimal("43.87"),
                special_tax_rules_amount=Decimal("87.23"),
            ),
            TaxesPerSeller(
                seller_tax_number=82730341,
                vat=[
                    VATAmount(
                        tax_rate=Decimal("22"),
                        taxable_amount=Decimal("37.42"),
                        tax_amount=Decimal("8.23"),
                    ),
                    VATAmount(
                        tax_rate=Decimal("9.5"),
                        taxable_amount=Decimal("88.99"),
                        tax_amount=Decimal("8.45"),
                    ),
                ],
                other_taxes_amount=Decimal("65.53"),
                exempt_vat_taxable_amount=Decimal("45.38"),
                reverse_vat_taxable_amount=Decimal("54.83"),
                nontaxable_amount=Decimal("245.14"),
                special_tax_rules_amount=Decimal("3.98"),
            ),
        ],
    )
    actual = wrap_sales_book_invoice(invoice)

    assert _strip_header(actual) == _strip_header(expected)
    _validate_against_schema(actual)


# ---------------------------------------------------------------------------
# Replay: business premise registration (real estate)
# ---------------------------------------------------------------------------


def test_replay_official_business_premise_example():
    expected = _decode_official_token(
        EXAMPLES / "PrimerDokumentacijaPrijavaProstoraJsonPodpisanToken.txt"
    )

    bp = BusinessPremise(
        tax_number=99999862,
        business_premise_id="36CF",
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
        validity_date=date(1990, 8, 25),
        closing_tag="Z",
        software_supplier=[SoftwareSupplier(tax_number=24564444)],
        special_notes="Primer prijave poslovnega prostora",
    )
    actual = wrap_business_premise(bp)
    assert _strip_header(actual) == _strip_header(expected)
    _validate_against_schema(actual)


# ---------------------------------------------------------------------------
# Replay: vending machine via geolocation
# ---------------------------------------------------------------------------


def test_replay_official_vending_machine_geolocation_example():
    expected = _decode_official_token(EXAMPLES / "PP_vm_longlat.txt")

    bp = BusinessPremise(
        tax_number=85505102,
        business_premise_id="VendingMJsonLL",
        bp_identifier=BPIdentifier(
            vending_machine=VendingMachine(
                vending_premise_type="E",
                geolocation=Geolocation(
                    latitude=Decimal("23.456789"),
                    longitude=Decimal("456.456789"),
                ),
            )
        ),
        validity_date=date(2018, 10, 15),
        software_supplier=[SoftwareSupplier(tax_number=12345678)],
        special_notes="1",
    )
    actual = wrap_business_premise(bp)
    assert _strip_header(actual) == _strip_header(expected)
    _validate_against_schema(actual)


# ---------------------------------------------------------------------------
# Replay: business premise BATCH (BBP_2)
# ---------------------------------------------------------------------------


def test_replay_official_business_premise_batch_example():
    expected = _decode_official_token(EXAMPLES / "BBP_2.txt")

    bp1 = BusinessPremise(
        tax_number=85505102,
        business_premise_id="mb1",
        bp_identifier=BPIdentifier(
            vending_machine=VendingMachine(
                vending_premise_type="D",
                address=Address(
                    street="Testna ulica",
                    house_number="1",
                    community="Ljubljana",
                    city="Ljubljana",
                    postal_code="1000",
                ),
            )
        ),
        validity_date=date(2025, 7, 7),
        software_supplier=[SoftwareSupplier(tax_number=85505102)],
        special_notes="Primer 1",
    )
    bp2 = BusinessPremise(
        tax_number=85505102,
        business_premise_id="mb2",
        bp_identifier=BPIdentifier(
            vending_machine=VendingMachine(
                vending_premise_type="E",
                geolocation=Geolocation(
                    latitude=Decimal("23.456789"),
                    longitude=Decimal("456.456789"),
                ),
            )
        ),
        validity_date=date(2025, 7, 7),
        software_supplier=[SoftwareSupplier(tax_number=85505102)],
        special_notes="Primer 2",
    )
    actual = wrap_business_premise_batch([bp1, bp2])

    # Strip the batch envelope's header and per-record validity date string —
    # the official sample uses "2025-07-07T08:55:52" (date-time) for ValidityDate
    # while we emit "2025-07-07" (date-only). Both are accepted by FURS per
    # spec text P_6.0; canonicalise both sides to date for the comparison.
    def _canonicalise(env):
        bpr = env["BusinessPremiseListRequest"]
        records = bpr["BusinessPremiseList"]["RecordInfo"]
        out_records = []
        for r in records:
            bp = dict(r["BusinessPremise"])
            vd = bp.get("ValidityDate", "")
            bp["ValidityDate"] = vd[:10]  # take only YYYY-MM-DD portion
            out_records.append({"RecordNumber": r["RecordNumber"], "BusinessPremise": bp})
        return {
            "BusinessPremiseListRequest": {
                "BusinessPremiseList": {"RecordInfo": out_records}
            }
        }

    assert _canonicalise(actual) == _canonicalise(expected)
    # Schema validation against the batch schema.
    _validate_against_schema(actual, schema_path=SCHEMA_BATCH_PATH)
