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
    # Use a relative validity window so the test cert never expires under us.
    now = datetime.now(tz=timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
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
        zoi='34905bcff14b381039af2e9d7eee54bb',
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
    tax = TaxesPerSeller(non_taxable_amount=Decimal('0.00'))

    api.get_invoice_eor(
        zoi='34905bcff14b381039af2e9d7eee54bb',
        tax_number=10039856,
        issued_date=local_issued_at,
        invoice_number='11',
        business_premise_id='BP105',
        electronic_device_id='B1',
        invoice_amount=Decimal('66.70'),
        taxes_per_seller=tax,
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
    tax = TaxesPerSeller(non_taxable_amount=Decimal('0.00'))

    with pytest.raises(ValueError, match='at most 2 decimal places'):
        api.get_invoice_eor(
            zoi='34905bcff14b381039af2e9d7eee54bb',
            tax_number=10039856,
            issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            invoice_number='11',
            business_premise_id='BP105',
            electronic_device_id='B1',
            invoice_amount=Decimal('66.701'),
            taxes_per_seller=tax,
        )


def test_invoice_rejects_conflicting_operator_fields():
    api = build_invoice_api()
    tax = TaxesPerSeller(non_taxable_amount=Decimal('0.00'))

    with pytest.raises(ValueError, match='mutually exclusive'):
        api.get_invoice_eor(
            zoi='34905bcff14b381039af2e9d7eee54bb',
            tax_number=10039856,
            issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            invoice_number='11',
            business_premise_id='BP105',
            electronic_device_id='B1',
            invoice_amount=Decimal('66.70'),
            taxes_per_seller=tax,
            operator_tax_number=12345678,
            foreign_operator=True,
        )


def test_invoice_rejects_mismatched_reference_invoice_lists():
    api = build_invoice_api()
    tax = TaxesPerSeller(non_taxable_amount=Decimal('0.00'))

    with pytest.raises(ValueError, match='same length'):
        api.get_invoice_eor(
            zoi='34905bcff14b381039af2e9d7eee54bb',
            tax_number=10039856,
            issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            invoice_number='11',
            business_premise_id='BP105',
            electronic_device_id='B1',
            invoice_amount=Decimal('66.70'),
            taxes_per_seller=tax,
            reference_invoice_number=['10', '11'],
            reference_invoice_business_premise_id=['BP105'],
            reference_invoice_electronic_device_id=['B1', 'B1'],
            reference_invoice_issued_date=[datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc), datetime(2026, 4, 25, 8, 1, 0, tzinfo=timezone.utc)],
        )


def test_sales_book_reference_date_is_date_only():
    api = build_invoice_api()
    tax = TaxesPerSeller(non_taxable_amount=Decimal('0.00'))

    api.get_sales_book_invoice_eor(
        tax_number=10039856,
        issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
        invoice_number='612',
        business_premise_id='BP105',
        set_number='03',
        serial_number='5001-0001018',
        invoice_amount=Decimal('66.70'),
        taxes_per_seller=tax,
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


def test_software_supplier_requires_tax_number_or_foreign_name():
    with pytest.raises(ValueError, match='software_supplier_tax_number'):
        FURSBusinessPremiseAPI._build_common_message_body(
            tax_number=10039856,
            premise_id='BP105',
            validity_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            software_supplier_tax_number=None,
            foreign_software_supplier_name=None,
            special_notes='No notes',
            close=False,
        )


def test_connection_exception_code_is_not_tuple():
    exc = ConnectionException(code=500, message='error')

    assert exc.code == 500


def test_pkey_temp_file_is_not_world_or_group_readable():
    """The private-key file must not leak to other users on the box. POSIX
    ``mkstemp`` (used internally by NamedTemporaryFile) creates files with
    mode 0o600, but a future refactor that switches to plain ``open`` would
    silently regress that. Fail loudly if anything other than the owner can
    read or write the key file. POSIX-only by design — Windows uses ACLs."""
    if os.name != 'posix':
        pytest.skip('POSIX-only file mode check')
    connector = build_test_certificate_connector()
    try:
        mode = os.stat(connector.pkey_temp.name).st_mode
        # Group + other bits should be zero.
        assert mode & 0o077 == 0, oct(mode)
    finally:
        connector.close()


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


def test_connector_accepts_configurable_tls_verification():
    connector = build_test_certificate_connector()
    try:
        assert connector.verify_tls is False
    finally:
        connector.close()


def test_invoice_rejects_missing_taxes_per_seller():
    api = build_invoice_api()

    with pytest.raises(ValueError, match='taxes_per_seller'):
        api.get_invoice_eor(
            zoi='34905bcff14b381039af2e9d7eee54bb',
            tax_number=10039856,
            issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            invoice_number='11',
            business_premise_id='BP105',
            electronic_device_id='B1',
            invoice_amount=Decimal('66.70'),
        )


def test_calculate_zoi_rejects_amount_with_more_than_two_decimals():
    """ZOI must be derived from the same numeric value sent in InvoiceAmount.
    Silently rounding 66.715 to 66.72 would produce a ZOI that does not match
    the value FURS receives, breaking server-side verification."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    api = object.__new__(FURSInvoiceAPI)
    api.connector = DummyConnector(key)
    issued_date = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)

    with pytest.raises(ValueError, match='at most 2 decimal places'):
        api.calculate_zoi(10039856, issued_date, '11', 'BP105', 'B1', Decimal('66.715'))


def test_submit_invoice_batch_rejects_sales_book_invoice_payloads():
    """The official FiscalVerificationSchemaBatch.json only defines InvoiceType
    for batch records; SalesBookInvoiceType is not allowed. Earlier code wrapped
    SalesBookInvoice as Invoice, producing payloads that FURS rejects with
    'Additional properties are not allowed (BusinessPremiseID, IssueDate, ...)'."""
    api = object.__new__(FURSInvoiceAPI)
    api._send_request = lambda path, data: None  # would not be reached

    sales_book_payload = {
        'InvoiceRequest': {
            'Header': {'MessageID': 'irrelevant', 'DateTime': '2026-04-25T08:00:00'},
            'SalesBookInvoice': {'TaxNumber': 10039856},
        }
    }
    invoice_payload = {
        'InvoiceRequest': {
            'Header': {'MessageID': 'irrelevant', 'DateTime': '2026-04-25T08:00:00'},
            'Invoice': {'TaxNumber': 10039856},
        }
    }

    with pytest.raises(ValueError, match='SalesBookInvoice payloads cannot be submitted'):
        api.submit_invoice_batch([invoice_payload, sales_book_payload])

    # Bare top-level SalesBookInvoice key path is also rejected.
    bare_sales_book = {'SalesBookInvoice': {'TaxNumber': 10039856}}
    with pytest.raises(ValueError, match='SalesBookInvoice payloads cannot be submitted'):
        api.submit_invoice_batch([invoice_payload, bare_sales_book])


def test_submit_invoice_batch_forwards_valid_invoice_payloads():
    """Counterpart to the rejection test: two valid Invoice payloads should
    reach _send_request wrapped in the official InvoiceListRequest envelope
    with sequential RecordNumber values starting at 1."""
    api = object.__new__(FURSInvoiceAPI)
    captured = {}

    def fake_send_request(path, data):
        captured['path'] = path
        captured['data'] = data
        return {'InvoiceListResponse': {}}

    api._send_request = fake_send_request

    invoice_one = {
        'InvoiceRequest': {
            'Header': {'MessageID': 'irrelevant', 'DateTime': '2026-04-25T08:00:00'},
            'Invoice': {'TaxNumber': 10039856, 'InvoiceAmount': 1.00},
        }
    }
    # Mix InvoiceRequest-wrapped and bare-Invoice forms to exercise both branches.
    invoice_two = {'Invoice': {'TaxNumber': 10039856, 'InvoiceAmount': 2.00}}

    response = api.submit_invoice_batch([invoice_one, invoice_two])

    assert response == {'InvoiceListResponse': {}}
    record_infos = captured['data']['InvoiceListRequest']['InvoiceList']['RecordInfo']
    assert [r['RecordNumber'] for r in record_infos] == [1, 2]
    assert record_infos[0]['Invoice'] == invoice_one['InvoiceRequest']['Invoice']
    assert record_infos[1]['Invoice'] == invoice_two['Invoice']
    assert 'Header' in captured['data']['InvoiceListRequest']


def test_verify_furs_response_true_without_key_is_rejected_at_construction():
    """verify_furs_response=True is the MITM-resistant mode and only makes
    sense with a pinned public key. Constructing without one used to silently
    fall through to x5c-based verification — that mode is now opt-in via the
    'x5c-untrusted' string instead."""
    from furs_fiscal.base_api import FURSBaseAPI

    with pytest.raises(ValueError, match='requires furs_response_public_key'):
        FURSBaseAPI(
            p12_path=None,
            p12_password=P12_CERT_PASSWORD,
            p12_buffer=build_p12_buffer(),
            production=False,
            verify_furs_response=True,
        )


def test_decode_furs_token_rejects_expired_x5c_certificate():
    """In x5c-untrusted mode the certificate is extracted from the response
    itself, so anything an attacker can substitute is fair game — but at
    minimum we must refuse a cert that is outside its validity window."""
    import base64 as _base64

    from cryptography.hazmat.primitives.serialization import Encoding
    from furs_fiscal.base_api import FURSBaseAPI
    from furs_fiscal.exceptions import ConnectionException

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'SI'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'EXPIRED-FURS-RESPONSE-TEST'),
    ])
    expired_before = datetime(2000, 1, 1, tzinfo=timezone.utc)
    expired_after = datetime(2001, 1, 1, tzinfo=timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(expired_before)
        .not_valid_after(expired_after)
        .sign(key, hashes.SHA256())
    )
    x5c_value = _base64.b64encode(cert.public_bytes(Encoding.DER)).decode('ascii')
    token = jwt.encode(
        {'InvoiceResponse': {'UniqueInvoiceID': 'EOR-X'}},
        key=key,
        algorithm='RS256',
        headers={'x5c': [x5c_value]},
    )

    api = object.__new__(FURSBaseAPI)
    api.verify_furs_response = 'x5c-untrusted'
    api.furs_response_public_key = None

    with pytest.raises(ConnectionException, match='validity window'):
        api._decode_furs_token(token)


def test_sales_book_reference_rejects_list_inputs_with_clear_message():
    """Sales-book references only allow scalar values per spec R_4.13–R_4.16.
    Earlier code accepted lists silently and only failed deep inside the regex
    validator with an opaque 'invalid format' error."""
    api = build_invoice_api()
    tax = TaxesPerSeller(non_taxable_amount=Decimal('0.00'))

    with pytest.raises(ValueError, match='must be scalar values'):
        api.get_sales_book_invoice_eor(
            tax_number=10039856,
            issued_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            invoice_number='612',
            business_premise_id='BP105',
            set_number='03',
            serial_number='5001-0001018',
            invoice_amount=Decimal('66.70'),
            taxes_per_seller=tax,
            reference_sales_book_number=['611', '610'],
            reference_sales_book_set_number='03',
            reference_sales_book_serial_number='5001-0001017',
            reference_sales_book_issued_date=datetime(2026, 4, 24, 8, 0, 0, tzinfo=timezone.utc),
        )


def test_connector_emits_warning_when_tls_verification_disabled():
    """The FURS spec requires verifying the SIGOV-CA chain. Disabling
    verification (the legacy default) must surface a warning so callers do
    not silently ship MITM-vulnerable clients."""
    import warnings as _warnings

    from furs_fiscal.connector import FURSTLSVerificationDisabledWarning

    with _warnings.catch_warnings(record=True) as caught:
        _warnings.simplefilter('always')
        connector = build_test_certificate_connector()
        try:
            assert any(
                issubclass(w.category, FURSTLSVerificationDisabledWarning)
                for w in caught
            ), 'expected FURSTLSVerificationDisabledWarning'
        finally:
            connector.close()


def test_decode_furs_token_extracts_signing_certificate_from_x5c_header():
    """When verify_furs_response='x5c-untrusted', the signing certificate
    must be extracted from the JWS x5c header per spec sec. 8.1. A
    FURSResponseChainNotVerifiedWarning is emitted because the chain is
    not validated against a pinned trust anchor."""
    import base64 as _base64
    import warnings as _warnings

    from cryptography.hazmat.primitives.serialization import Encoding
    from furs_fiscal.base_api import FURSBaseAPI, FURSResponseChainNotVerifiedWarning

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'SI'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'FURS-RESPONSE-TEST'),
    ])
    now = datetime.now(tz=timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    x5c_value = _base64.b64encode(cert.public_bytes(Encoding.DER)).decode('ascii')
    token = jwt.encode(
        {'InvoiceResponse': {'UniqueInvoiceID': 'EOR-X'}},
        key=key,
        algorithm='RS256',
        headers={'x5c': [x5c_value]},
    )

    api = object.__new__(FURSBaseAPI)
    api.verify_furs_response = 'x5c-untrusted'
    api.furs_response_public_key = None

    with _warnings.catch_warnings(record=True) as caught:
        _warnings.simplefilter('always')
        decoded = api._decode_furs_token(token)

    assert decoded == {'InvoiceResponse': {'UniqueInvoiceID': 'EOR-X'}}
    assert any(
        issubclass(w.category, FURSResponseChainNotVerifiedWarning)
        for w in caught
    ), 'expected FURSResponseChainNotVerifiedWarning when verifying via x5c'
