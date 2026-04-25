import json
from datetime import datetime, timezone
from decimal import Decimal

import pytest

try:
    import jsonschema
    from jsonschema.validators import extend
except ImportError:  # pragma: no cover - dependency is declared, skip only for incomplete local envs.
    jsonschema = None

from furs_fiscal.api import (
    FURSBusinessPremiseAPI,
    FURSInvoiceAPI,
    TaxesPerSeller,
    TYPE_MOVABLE_PREMISE_A,
    TYPE_VENDING_MACHINE_E,
)


pytestmark = pytest.mark.skipif(jsonschema is None, reason="jsonschema is not installed")


def _floats_to_decimal(obj):
    """Recursively convert float values to Decimal so jsonschema's multipleOf
    check uses exact decimal arithmetic instead of IEEE-754 floats. Without
    this, perfectly valid amounts like 66.71 fail multipleOf 0.01 because
    float(66.71) is not an exact multiple of float(0.01).

    Booleans are left alone (Python bool is a subclass of int).
    """
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _floats_to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_floats_to_decimal(v) for v in obj]
    return obj


def _decimal_aware_validator(schema):
    """Build a Draft 4 validator that recognises Decimal as a JSON number type.

    Decimal already participates in jsonschema's multipleOf check correctly
    (Fraction(Decimal('66.71')) is exact); we only need the type checker to
    accept it as a "number".
    """
    type_checker = jsonschema.Draft4Validator.TYPE_CHECKER.redefine(
        "number",
        lambda checker, instance: isinstance(instance, (int, float, Decimal))
        and not isinstance(instance, bool),
    )
    Validator = extend(jsonschema.Draft4Validator, type_checker=type_checker)
    return Validator(schema)


def _decimals_to_float(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: _decimals_to_float(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decimals_to_float(v) for v in obj]
    return obj


def validate_official_payload(payload, schema_path='specs/schemas/FiscalVerificationSchema.json'):
    with open(schema_path) as schema_file:
        # parse_float=Decimal keeps multipleOf operands as Decimal so the
        # validator's `instance / dB` works with the Decimal-converted payload.
        schema = json.load(schema_file, parse_float=Decimal)
    # check_schema needs floats for its own meta-schema; convert back for that step.
    jsonschema.Draft4Validator.check_schema(_decimals_to_float(schema))
    _decimal_aware_validator(schema).validate(_floats_to_decimal(payload))


def build_invoice_api():
    api = object.__new__(FURSInvoiceAPI)
    api.sent = None

    def fake_send_request(path, data):
        api.sent = data
        return {'InvoiceResponse': {'UniqueInvoiceID': 'EOR-123'}}

    api._send_request = fake_send_request
    return api


def build_business_premise_api():
    api = object.__new__(FURSBusinessPremiseAPI)
    api.sent = None

    def fake_send_request(path, data):
        api.sent = data
        return {'BusinessPremiseResponse': {}}

    api._send_request = fake_send_request
    return api


def tax_spec():
    taxes = TaxesPerSeller(non_taxable_amount=Decimal('0.00'))
    taxes.add_vat_amount(Decimal('22.00'), Decimal('23.14'), Decimal('5.09'))
    taxes.add_flat_rate_compensation(Decimal('8.00'), Decimal('10.00'), Decimal('0.80'))
    return taxes


def test_electronic_invoice_payload_validates_against_official_schema():
    api = build_invoice_api()

    api.get_invoice_eor(
        zoi='34905bcff14b381039af2e9d7eee54bb',
        tax_number=99999862,
        issued_date=datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc),
        invoice_number='145',
        business_premise_id='TRGOVINA1',
        electronic_device_id='BLAG2',
        invoice_amount=Decimal('66.71'),
        taxes_per_seller=tax_spec(),
        operator_tax_number=12345678,
        special_notes='schema test',
    )

    validate_official_payload(api.sent)


def test_sales_book_invoice_payload_validates_against_official_schema():
    api = build_invoice_api()

    api.get_sales_book_invoice_eor(
        tax_number=99999862,
        issued_date=datetime(2026, 4, 25, tzinfo=timezone.utc),
        invoice_number='145',
        business_premise_id='TRGOVINA1',
        set_number='03',
        serial_number='5001-0001018',
        invoice_amount=Decimal('66.71'),
        taxes_per_seller=tax_spec(),
        special_notes='schema test',
    )

    validate_official_payload(api.sent)


def test_immovable_business_premise_payload_validates_against_official_schema():
    api = build_business_premise_api()

    api.register_immovable_business_premise(
        tax_number=99999862,
        premise_id='TRGOVINA1',
        real_estate_cadastral_number=1,
        real_estate_building_number=2,
        real_estate_building_section_number=3,
        street='Slovenska cesta',
        house_number='24',
        house_number_additional=None,
        community='Ljubljana',
        city='Ljubljana',
        postal_code='1000',
        validity_date=datetime(2026, 4, 25, tzinfo=timezone.utc),
        software_supplier_tax_number=24564444,
        special_notes='schema test',
    )

    validate_official_payload(api.sent)


def test_movable_business_premise_payload_validates_against_official_schema():
    api = build_business_premise_api()

    api.register_movable_business_premise(
        tax_number=99999862,
        premise_id='MOBILE1',
        movable_type=TYPE_MOVABLE_PREMISE_A,
        validity_date=datetime(2026, 4, 25, tzinfo=timezone.utc),
        software_supplier_tax_number=24564444,
        special_notes='schema test',
    )

    validate_official_payload(api.sent)


def test_vending_machine_payload_validates_against_official_schema():
    api = build_business_premise_api()

    api.register_vending_machine_business_premise(
        tax_number=99999862,
        premise_id='VM1',
        vending_machine_type=TYPE_VENDING_MACHINE_E,
        validity_date=datetime(2026, 4, 25, tzinfo=timezone.utc),
        software_supplier_tax_number=24564444,
        latitude=Decimal('46.056946'),
        longitude=Decimal('14.505751'),
        special_notes='schema test',
    )

    validate_official_payload(api.sent)


def test_schema_validator_still_rejects_more_than_two_decimal_places():
    """The Decimal-aware validator was added to fix a false negative on valid
    amounts like 66.71. Make sure it still catches actual multipleOf 0.01
    violations (e.g. 66.715) — otherwise the conversion would have silently
    suppressed the schema rule entirely, and we'd have traded one bug for a
    much worse one."""
    # Build a hand-crafted payload that bypasses the normal _normalize_amount
    # validation in production code; we want to feed an invalid amount
    # straight to the validator.
    payload = {
        'InvoiceRequest': {
            'Header': {
                'MessageID': '11111111-1111-1111-1111-111111111111',
                'DateTime': '2026-04-25T10:00:00',
            },
            'Invoice': {
                'TaxNumber': 99999862,
                'IssueDateTime': '2026-04-25T10:00:00',
                'NumberingStructure': 'B',
                'InvoiceIdentifier': {
                    'BusinessPremiseID': 'TRGOVINA1',
                    'ElectronicDeviceID': 'BLAG2',
                    'InvoiceNumber': '145',
                },
                # Three decimal places — should violate multipleOf 0.01.
                'InvoiceAmount': Decimal('66.715'),
                'PaymentAmount': Decimal('66.71'),
                'ProtectedID': '34905bcff14b381039af2e9d7eee54bb',
                'TaxesPerSeller': [{'NontaxableAmount': Decimal('66.71')}],
            }
        }
    }

    with pytest.raises(jsonschema.ValidationError):
        validate_official_payload(payload)

