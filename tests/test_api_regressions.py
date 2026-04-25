import os
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.x509.oid import NameOID

from furs_fiscal.api import FURSBusinessPremiseAPI, FURSInvoiceAPI, TaxesPerSeller
from furs_fiscal.connector import Connector, FURS_TEST_ENDPOINT
from furs_fiscal.exceptions import ConnectionException

P12_CERT_PASSWORD = 'test-password'


class DummyP12:
    def __init__(self, key):
        self.key = key


class DummyConnector:
    def __init__(self, key):
        self.p12 = DummyP12(key)


def build_invoice_api():
    api = object.__new__(FURSInvoiceAPI)
    api.sent = None

    def fake_send_request(path, data):
        api.sent = data
        return {'InvoiceResponse': {'UniqueInvoiceID': 'EOR-123'}}

    api._send_request = fake_send_request
    return api


def build_p12_buffer(password=P12_CERT_PASSWORD):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'SI'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'test-institutions'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'TEST CERTIFICATE'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    return serialize_key_and_certificates(
        name=b'test-certificate',
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')),
    )


def build_test_certificate_connector():
    return Connector(
        p12_path=None,
        p12_password=P12_CERT_PASSWORD,
        p12_buffer=build_p12_buffer(),
        production=False,
        request_timeout=1.0,
    )


def test_calculate_zoi_is_deterministic():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    api = object.__new__(FURSInvoiceAPI)
    api.connector = DummyConnector(key)
    issued_date = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)

    first = api.calculate_zoi(10039856, issued_date, '11', 'BP105', 'B1', Decimal('19.15'))
    second = api.calculate_zoi(10039856, issued_date, '11', 'BP105', 'B1', Decimal('19.15'))

    assert first == second
    assert len(first) == 32


def test_generated_certificate_loads_and_calculates_deterministic_zoi():
    connector = build_test_certificate_connector()
    api = object.__new__(FURSInvoiceAPI)
    api.connector = connector
    issued_date = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)

    try:
        first = api.calculate_zoi(10492682, issued_date, '11', 'BP105', 'B1', Decimal('19.15'))
        second = api.calculate_zoi(10492682, issued_date, '11', 'BP105', 'B1', Decimal('19.15'))

        assert first == second
        assert len(first) == 32
    finally:
        cert_name = connector.cert_temp.name
        pkey_name = connector.pkey_temp.name
        connector.close()
        assert not os.path.exists(cert_name)
        assert not os.path.exists(pkey_name)


def test_generated_certificate_jwt_signs_payload_with_expected_header():
    connector = build_test_certificate_connector()
    try:
        header = connector._get_jws_header()
        token = connector._jwt_sign(
            header=header,
            payload={'EchoRequest': 'ping'},
        )
        decoded_header = jwt.get_unverified_header(token)
        decoded_payload = jwt.decode(token, options={"verify_signature": False})

        assert decoded_header['alg'] == 'RS256'
        assert decoded_header['subject_name'] == header['subject_name']
        assert decoded_header['issuer_name'] == header['issuer_name']
        assert decoded_header['serial'] == header['serial']
        assert decoded_payload == {'EchoRequest': 'ping'}
    finally:
        connector.close()


def test_generated_certificate_connector_uses_test_endpoint():
    connector = build_test_certificate_connector()
    try:
        assert connector.endpoint == FURS_TEST_ENDPOINT
        assert os.path.exists(connector.cert_temp.name)
        assert os.path.exists(connector.pkey_temp.name)
    finally:
        connector.close()


def test_invoice_payload_preserves_zero_values_and_decimals():
    api = build_invoice_api()
    tax = TaxesPerSeller(non_taxable_amount=Decimal('0.00'), special_tax_rules_amount=Decimal('1.20'))
    tax.add_vat_amount(tax_rate=Decimal('22.00'), tax_base=Decimal('0.00'), tax_amount=Decimal('0.00'))

    eor = api.get_invoice_eor(
        zoi='abc123',
        tax_number=10039856,
        issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
        invoice_number='11',
        business_premise_id='BP105',
        electronic_device_id='B1',
        invoice_amount=Decimal('66.70'),
        payment_amount=Decimal('0.00'),
        returns_amount=Decimal('0.00'),
        taxes_per_seller=tax,
        operator_tax_number=12345678,
    )

    invoice = api.sent['InvoiceRequest']['Invoice']
    tax_payload = invoice['TaxesPerSeller'][0]
    assert eor == 'EOR-123'
    assert invoice['InvoiceAmount'] == 66.7
    assert invoice['PaymentAmount'] == 0
    assert invoice['ReturnsAmount'] == 0
    assert tax_payload['NontaxableAmount'] == 0
    assert tax_payload['SpecialTaxRulesAmount'] == 1.2
    assert tax_payload['VAT'][0]['TaxableAmount'] == 0
    assert tax_payload['VAT'][0]['TaxAmount'] == 0


def test_invoice_datetime_preserves_local_wall_time_without_timezone_suffix():
    api = build_invoice_api()
    local_issued_at = datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    local_reference_at = datetime(2026, 4, 24, 9, 30, 0, tzinfo=timezone(timedelta(hours=2)))

    api.get_invoice_eor(
        zoi='abc123',
        tax_number=10039856,
        issued_date=local_issued_at,
        invoice_number='11',
        business_premise_id='BP105',
        electronic_device_id='B1',
        invoice_amount=Decimal('66.70'),
        reference_invoice_number='10',
        reference_invoice_business_premise_id='BP105',
        reference_invoice_electronic_device_id='B1',
        reference_invoice_issued_date=local_reference_at,
    )

    invoice = api.sent['InvoiceRequest']['Invoice']
    reference = invoice['ReferenceInvoice'][0]
    assert invoice['IssueDateTime'] == '2026-04-25T10:00:00'
    assert not invoice['IssueDateTime'].endswith('Z')
    assert reference['ReferenceInvoiceIssueDateTime'] == '2026-04-24T09:30:00'
    assert not reference['ReferenceInvoiceIssueDateTime'].endswith('Z')


def test_invoice_rejects_too_many_decimal_places():
    api = build_invoice_api()

    with pytest.raises(ValueError, match='at most 2 decimal places'):
        api.get_invoice_eor(
            zoi='abc123',
            tax_number=10039856,
            issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            invoice_number='11',
            business_premise_id='BP105',
            electronic_device_id='B1',
            invoice_amount=Decimal('66.701'),
        )


def test_invoice_rejects_conflicting_operator_fields():
    api = build_invoice_api()

    with pytest.raises(ValueError, match='mutually exclusive'):
        api.get_invoice_eor(
            zoi='abc123',
            tax_number=10039856,
            issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            invoice_number='11',
            business_premise_id='BP105',
            electronic_device_id='B1',
            invoice_amount=Decimal('66.70'),
            operator_tax_number=12345678,
            foreign_operator=True,
        )


def test_invoice_rejects_mismatched_reference_invoice_lists():
    api = build_invoice_api()

    with pytest.raises(ValueError, match='same length'):
        api.get_invoice_eor(
            zoi='abc123',
            tax_number=10039856,
            issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            invoice_number='11',
            business_premise_id='BP105',
            electronic_device_id='B1',
            invoice_amount=Decimal('66.70'),
            reference_invoice_number=['10', '11'],
            reference_invoice_business_premise_id=['BP105'],
            reference_invoice_electronic_device_id=['B1', 'B1'],
            reference_invoice_issued_date=[datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc), datetime(2026, 4, 25, 8, 1, 0, tzinfo=timezone.utc)],
        )


def test_sales_book_reference_date_is_date_only():
    api = build_invoice_api()

    api.get_sales_book_invoice_eor(
        tax_number=10039856,
        issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
        invoice_number='612',
        business_premise_id='BP105',
        set_number='03',
        serial_number='5001-0001018',
        invoice_amount=Decimal('66.70'),
        reference_sales_book_number='611',
        reference_sales_book_set_number='03',
        reference_sales_book_serial_number='5001-0001017',
        reference_sales_book_issued_date=datetime(2026, 4, 24, 8, 0, 0, tzinfo=timezone.utc),
    )

    reference = api.sent['InvoiceRequest']['SalesBookInvoice']['ReferenceSalesBook'][0]
    assert reference['ReferenceSalesBookIssueDate'] == '2026-04-24'


def test_software_supplier_tax_number_still_wins_over_foreign_name():
    message = FURSBusinessPremiseAPI._build_common_message_body(
        tax_number=10039856,
        premise_id='BP105',
        validity_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
        software_supplier_tax_number=24564444,
        foreign_software_supplier_name='Foreign Supplier',
        special_notes='No notes',
        close=False,
    )

    assert message['BusinessPremiseRequest']['BusinessPremise']['SoftwareSupplier'] == [{'TaxNumber': 24564444}]


def test_connection_exception_code_is_not_tuple():
    exc = ConnectionException(code=500, message='error')

    assert exc.code == 500


def test_connector_close_removes_temp_files():
    connector = object.__new__(Connector)
    cert_temp = tempfile.NamedTemporaryFile(delete=False)
    pkey_temp = tempfile.NamedTemporaryFile(delete=False)
    connector.cert_temp = cert_temp
    connector.pkey_temp = pkey_temp
    cert_name = cert_temp.name
    pkey_name = pkey_temp.name

    connector.close()

    assert not os.path.exists(cert_name)
    assert not os.path.exists(pkey_name)
    assert connector.cert_temp is None
    assert connector.pkey_temp is None
