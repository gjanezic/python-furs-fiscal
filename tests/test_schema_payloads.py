import json
from datetime import datetime, timezone
from decimal import Decimal

import pytest

try:
    import jsonschema
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


def validate_official_payload(payload, schema_path='specs/schemas/FiscalVerificationSchema.json'):
    with open(schema_path) as schema_file:
        schema = json.load(schema_file)
    jsonschema.Draft4Validator.check_schema(schema)
    jsonschema.Draft4Validator(schema).validate(payload)


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

