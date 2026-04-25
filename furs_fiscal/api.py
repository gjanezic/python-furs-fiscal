import hashlib
import re
import uuid
import datetime
from decimal import Decimal, InvalidOperation

import pytz

from furs_fiscal.base_api import FURSBaseAPI


TYPE_MOVABLE_PREMISE_A = 'A'
TYPE_MOVABLE_PREMISE_B = 'B'
TYPE_MOVABLE_PREMISE_C = 'C'

TYPE_VENDING_MACHINE_D = 'D'
TYPE_VENDING_MACHINE_E = 'E'
TYPE_VENDING_MACHINE_F = 'F'

NUMBERING_STRUCTURE_CENTRAL = 'C'
NUMBERING_STRUCTURE_DEVICE = 'B'

REGISTER_BUSINESS_UNIT_PATH = 'v1/cash_registers/invoices/register'
REGISTER_BUSINESS_UNIT_BATCH_PATH = 'v1/cash_registers_batch/invoices/register'
INVOICE_ISSUE_PATH = 'v1/cash_registers/invoices'
INVOICE_ISSUE_BATCH_PATH = 'v1/cash_registers_batch/invoices'

_IDENTIFIER_RE = re.compile(r'^[0-9a-zA-Z]{1,20}$')
_INVOICE_NUMBER_RE = re.compile(r'^[1-9][0-9]{0,19}$')
_ZOI_RE = re.compile(r'^[0-9a-fA-F]{32}$')


def _format_datetime(value):
    return value.strftime("%Y-%m-%dT%H:%M:%S")


def _format_date(value):
    # FURS spec text (R_3.0.x, R_4.15, BusinessPremise ValidityDate) uses "YYYY-MM-DD".
    # The official JSON Schema annotates these fields as `format: date-time`, but the
    # signed JSON examples in specs/examples/ confirm date-only strings are accepted.
    return value.strftime("%Y-%m-%d")


def _validate_text(value, field_name, min_length=1, max_length=None, pattern=None):
    if not isinstance(value, str):
        raise ValueError("%s must be a string" % field_name)
    if len(value) < min_length:
        raise ValueError("%s must contain at least %s characters" % (field_name, min_length))
    if max_length is not None and len(value) > max_length:
        raise ValueError("%s must contain at most %s characters" % (field_name, max_length))
    if pattern is not None and not pattern.match(value):
        raise ValueError("%s has invalid format" % field_name)
    return value


def _validate_identifier(value, field_name):
    return _validate_text(value, field_name, max_length=20, pattern=_IDENTIFIER_RE)


def _validate_invoice_number(value, field_name='invoice_number'):
    return _validate_text(str(value), field_name, max_length=20, pattern=_INVOICE_NUMBER_RE)


def _validate_sales_book_set_number(value, field_name='set_number'):
    return _validate_text(str(value), field_name, min_length=2, max_length=2)


def _validate_sales_book_serial_number(value, field_name='serial_number'):
    return _validate_text(str(value), field_name, min_length=12, max_length=12)


def _validate_tax_number(value, field_name='tax_number'):
    if isinstance(value, bool):
        raise ValueError("%s must be an 8-digit integer" % field_name)
    try:
        tax_number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("%s must be an 8-digit integer" % field_name) from exc
    if tax_number < 10000000 or tax_number > 99999999:
        raise ValueError("%s must be an 8-digit integer between 10000000 and 99999999" % field_name)
    return tax_number


def _validate_postal_code(value):
    return _validate_text(str(value), 'postal_code', min_length=4, max_length=4)


def _normalize_decimal_number(value, max_decimals=2, minimum=None, maximum=None, field_name='Decimal number'):
    if value is None:
        return None

    try:
        decimal_value = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("%s fields must be valid numeric values" % field_name) from exc

    if not decimal_value.is_finite():
        raise ValueError("%s fields must be finite numeric values" % field_name)

    quant = Decimal(1).scaleb(-max_decimals)
    try:
        quantized = decimal_value.quantize(quant)
    except InvalidOperation as exc:
        raise ValueError("%s fields must be valid numeric values" % field_name) from exc

    if decimal_value != quantized:
        raise ValueError("%s fields support at most %s decimal places" % (field_name, max_decimals))

    if minimum is not None and quantized <= Decimal(str(minimum)):
        raise ValueError("%s fields must be greater than %s" % (field_name, minimum))
    if maximum is not None and quantized >= Decimal(str(maximum)):
        raise ValueError("%s fields must be less than %s" % (field_name, maximum))

    if quantized == quantized.to_integral_value():
        return int(quantized)
    return float(quantized)


def _normalize_amount(value):
    return _normalize_decimal_number(value,
                                     max_decimals=2,
                                     minimum='-100000000000000',
                                     maximum='100000000000000',
                                     field_name='Amount')


def _normalize_tax_rate(value):
    return _normalize_decimal_number(value,
                                     max_decimals=2,
                                     minimum='-99999.01',
                                     maximum='99999.01',
                                     field_name='Tax rate')


def _normalize_geolocation(value, max_abs, field_name):
    return _normalize_decimal_number(value,
                                     max_decimals=6,
                                     minimum=str(-max_abs - Decimal('0.000001')),
                                     maximum=str(max_abs + Decimal('0.000001')),
                                     field_name=field_name)


def _ensure_taxes_per_seller_list(taxes_per_seller, required=True):
    if taxes_per_seller is None:
        taxes_per_seller = []
    elif isinstance(taxes_per_seller, TaxesPerSeller):
        taxes_per_seller = [taxes_per_seller]
    elif not isinstance(taxes_per_seller, list):
        raise ValueError("Parameter taxes_per_seller should be a list of TaxesPerSeller objects")

    if not all(isinstance(tax_per_seller, TaxesPerSeller) for tax_per_seller in taxes_per_seller):
        raise ValueError("Parameter taxes_per_seller should contain only TaxesPerSeller objects")
    if required and len(taxes_per_seller) == 0:
        raise ValueError("Parameter taxes_per_seller must contain at least one TaxesPerSeller object")
    return taxes_per_seller


def _validate_reference_invoice_lists(reference_invoice_number,
                                      reference_invoice_business_premise_id,
                                      reference_invoice_electronic_device_id,
                                      reference_invoice_issued_date):
    reference_fields = [
        reference_invoice_business_premise_id,
        reference_invoice_electronic_device_id,
        reference_invoice_issued_date,
    ]

    if reference_invoice_number is None:
        if any(field is not None for field in reference_fields):
            raise ValueError("Reference invoice fields must be provided together")
        return

    if isinstance(reference_invoice_number, list):
        if len(reference_invoice_number) == 0:
            raise ValueError("Reference invoice lists must not be empty")
        if not all(isinstance(field, list) for field in reference_fields):
            raise ValueError("Reference invoice fields must all be lists when reference_invoice_number is a list")
        reference_count = len(reference_invoice_number)
        if not all(len(field) == reference_count for field in reference_fields):
            raise ValueError("Reference invoice field lists must have the same length")
    elif any(field is None or isinstance(field, list) for field in reference_fields):
        raise ValueError("Reference invoice fields must be scalar values provided together")


def _validate_reference_sales_book_fields(reference_sales_book_number,
                                          reference_sales_book_set_number,
                                          reference_sales_book_serial_number,
                                          reference_sales_book_issued_date):
    secondary_fields = [
        reference_sales_book_set_number,
        reference_sales_book_serial_number,
        reference_sales_book_issued_date,
    ]
    if reference_sales_book_number is None and all(field is None for field in secondary_fields):
        return
    all_fields = [reference_sales_book_number] + secondary_fields
    if any(isinstance(field, list) for field in all_fields):
        raise ValueError("Reference sales book fields must be scalar values; lists are not supported")
    if reference_sales_book_number is None or any(field is None for field in secondary_fields):
        raise ValueError("Reference sales book fields must be provided together")


def _build_reference_invoice_list(reference_invoice_number,
                                  reference_invoice_business_premise_id,
                                  reference_invoice_electronic_device_id,
                                  reference_invoice_issued_date):
    _validate_reference_invoice_lists(reference_invoice_number,
                                      reference_invoice_business_premise_id,
                                      reference_invoice_electronic_device_id,
                                      reference_invoice_issued_date)
    if reference_invoice_number is None:
        return []

    if isinstance(reference_invoice_number, list):
        return [{
            'ReferenceInvoiceIdentifier': {
                'BusinessPremiseID': _validate_identifier(reference_invoice_business_premise_id[i], 'reference_invoice_business_premise_id'),
                'ElectronicDeviceID': _validate_identifier(reference_invoice_electronic_device_id[i], 'reference_invoice_electronic_device_id'),
                'InvoiceNumber': _validate_invoice_number(reference_invoice_number[i], 'reference_invoice_number')
            },
            'ReferenceInvoiceIssueDateTime': _format_datetime(reference_invoice_issued_date[i])
        } for i in range(0, len(reference_invoice_number))]

    return [{
        'ReferenceInvoiceIdentifier': {
            'BusinessPremiseID': _validate_identifier(reference_invoice_business_premise_id, 'reference_invoice_business_premise_id'),
            'ElectronicDeviceID': _validate_identifier(reference_invoice_electronic_device_id, 'reference_invoice_electronic_device_id'),
            'InvoiceNumber': _validate_invoice_number(reference_invoice_number, 'reference_invoice_number')
        },
        'ReferenceInvoiceIssueDateTime': _format_datetime(reference_invoice_issued_date)
    }]


def _build_reference_sales_book_list(reference_sales_book_number,
                                     reference_sales_book_set_number,
                                     reference_sales_book_serial_number,
                                     reference_sales_book_issued_date):
    _validate_reference_sales_book_fields(reference_sales_book_number,
                                          reference_sales_book_set_number,
                                          reference_sales_book_serial_number,
                                          reference_sales_book_issued_date)
    if reference_sales_book_number is None:
        return []
    return [{
        'ReferenceSalesBookIdentifier': {
            'InvoiceNumber': _validate_invoice_number(reference_sales_book_number, 'reference_sales_book_number'),
            'SetNumber': _validate_sales_book_set_number(reference_sales_book_set_number, 'reference_sales_book_set_number'),
            'SerialNumber': _validate_sales_book_serial_number(reference_sales_book_serial_number, 'reference_sales_book_serial_number')
        },
        'ReferenceSalesBookIssueDate': _format_date(reference_sales_book_issued_date)
    }]


class FURSBusinessPremiseAPI(FURSBaseAPI):
    """
    FURSBusinessPremiseAPI allows you to register business unit to FURS prior to issuing any invoices.
    """
    def register_immovable_business_premise(self,
                                            tax_number,
                                            premise_id,
                                            real_estate_cadastral_number,
                                            real_estate_building_number,
                                            real_estate_building_section_number,
                                            street,
                                            house_number,
                                            house_number_additional,
                                            community,
                                            city,
                                            postal_code,
                                            validity_date,
                                            software_supplier_tax_number=None,
                                            foreign_software_supplier_name=None,
                                            special_notes='No notes',
                                            close=False):
        message = FURSBusinessPremiseAPI._build_common_message_body(**locals())
        business_premise = message['BusinessPremiseRequest']['BusinessPremise']
        bpi_identifier = business_premise['BPIdentifier']

        address = {
            'Street': _validate_text(street, 'street', max_length=100),
            'HouseNumber': _validate_text(house_number, 'house_number', max_length=10),
            'Community': _validate_text(community, 'community', max_length=100),
            'City': _validate_text(city, 'city', max_length=100),
            'PostalCode': _validate_postal_code(postal_code)
        }
        if house_number_additional not in ('', None):
            address['HouseNumberAdditional'] = _validate_text(house_number_additional, 'house_number_additional', max_length=10)

        bpi_identifier['RealEstateBP'] = {
            'Address': address,
            'PropertyID': {
                'CadastralNumber': _normalize_decimal_number(real_estate_cadastral_number, 0, minimum='-1', maximum='10000', field_name='CadastralNumber'),
                'BuildingNumber': _normalize_decimal_number(real_estate_building_number, 0, minimum='-1', maximum='100000', field_name='BuildingNumber'),
                'BuildingSectionNumber': _normalize_decimal_number(real_estate_building_section_number, 0, minimum='-1', maximum='10000', field_name='BuildingSectionNumber')
            }
        }

        self._send_request(path=REGISTER_BUSINESS_UNIT_PATH, data=message)
        return True

    def register_movable_business_premise(self,
                                          tax_number,
                                          premise_id,
                                          movable_type,
                                          validity_date,
                                          software_supplier_tax_number=None,
                                          foreign_software_supplier_name=None,
                                          special_notes='No notes',
                                          close=False):
        message = FURSBusinessPremiseAPI._build_common_message_body(**locals())
        bpi_identifier = message['BusinessPremiseRequest']['BusinessPremise']['BPIdentifier']

        if movable_type not in (TYPE_MOVABLE_PREMISE_A, TYPE_MOVABLE_PREMISE_B, TYPE_MOVABLE_PREMISE_C):
            raise ValueError("movable_type must be one of A, B or C")
        bpi_identifier['PremiseType'] = movable_type

        self._send_request(path=REGISTER_BUSINESS_UNIT_PATH, data=message)
        return True

    def register_vending_machine_business_premise(self,
                                                  tax_number,
                                                  premise_id,
                                                  vending_machine_type,
                                                  validity_date,
                                                  software_supplier_tax_number=None,
                                                  foreign_software_supplier_name=None,
                                                  street=None,
                                                  house_number=None,
                                                  house_number_additional=None,
                                                  community=None,
                                                  city=None,
                                                  postal_code=None,
                                                  latitude=None,
                                                  longitude=None,
                                                  special_notes='No notes',
                                                  close=False):
        """
        Register a FURS v3.2 vending-machine business premise.
        Provide either a full address or latitude/longitude geolocation.
        """
        message = FURSBusinessPremiseAPI._build_common_message_body(**locals())
        bpi_identifier = message['BusinessPremiseRequest']['BusinessPremise']['BPIdentifier']

        if vending_machine_type not in (TYPE_VENDING_MACHINE_D, TYPE_VENDING_MACHINE_E, TYPE_VENDING_MACHINE_F):
            raise ValueError("vending_machine_type must be one of D, E or F")

        vending_machine = {'VPremiseType': vending_machine_type}
        has_address = all(value is not None for value in (street, house_number, community, city, postal_code))
        has_geolocation = latitude is not None or longitude is not None

        if has_address and has_geolocation:
            raise ValueError("Provide either vending-machine address or geolocation, not both")
        if has_address:
            address = {
                'Street': _validate_text(street, 'street', max_length=100),
                'HouseNumber': _validate_text(house_number, 'house_number', max_length=10),
                'Community': _validate_text(community, 'community', max_length=100),
                'City': _validate_text(city, 'city', max_length=100),
                'PostalCode': _validate_postal_code(postal_code)
            }
            if house_number_additional not in ('', None):
                address['HouseNumberAdditional'] = _validate_text(house_number_additional, 'house_number_additional', max_length=10)
            vending_machine['Address'] = address
        elif latitude is not None and longitude is not None:
            vending_machine['Geolocation'] = {
                'Latitude': _normalize_geolocation(latitude, Decimal('99.999999'), 'Latitude'),
                'Longitude': _normalize_geolocation(longitude, Decimal('999.999999'), 'Longitude')
            }
        else:
            raise ValueError("Vending-machine registration requires either full address or latitude and longitude")

        bpi_identifier['VendingMachine'] = vending_machine
        self._send_request(path=REGISTER_BUSINESS_UNIT_PATH, data=message)
        return True

    def register_business_premises_batch(self, business_premise_messages):
        """
        Submit already-built BusinessPremise payload dictionaries through the FURS batch endpoint.
        """
        if not isinstance(business_premise_messages, list) or len(business_premise_messages) < 2:
            raise ValueError("business_premise_messages must contain at least two items for batch submission")
        if len(business_premise_messages) > 500:
            raise ValueError("business_premise_messages must contain at most 500 items")
        record_infos = []
        for index, message in enumerate(business_premise_messages, start=1):
            if 'BusinessPremiseRequest' in message:
                business_premise = message['BusinessPremiseRequest']['BusinessPremise']
            elif 'BusinessPremise' in message:
                business_premise = message['BusinessPremise']
            else:
                business_premise = message
            record_infos.append({'RecordNumber': index, 'BusinessPremise': business_premise})
        batch_message = {
            'BusinessPremiseListRequest': {
                'Header': FURSBusinessPremiseAPI._prepare_business_premise_request_header(),
                'BusinessPremiseList': {'RecordInfo': record_infos}
            }
        }
        self._send_request(path=REGISTER_BUSINESS_UNIT_BATCH_PATH, data=batch_message)
        return True

    @staticmethod
    def _prepare_business_premise_request_header():
        return {
            "MessageID": str(uuid.uuid4()),
            "DateTime": _format_datetime(datetime.datetime.now())
        }

    @staticmethod
    def _prepare_software_supplier_json(software_supplier_tax_number=None, foreign_software_supplier_name=None):
        if software_supplier_tax_number:
            return {'TaxNumber': _validate_tax_number(software_supplier_tax_number, 'software_supplier_tax_number')}
        if foreign_software_supplier_name:
            return {'NameForeign': _validate_text(foreign_software_supplier_name, 'foreign_software_supplier_name', max_length=1000)}
        raise ValueError("Either software_supplier_tax_number or foreign_software_supplier_name must be provided")

    @staticmethod
    def _build_common_message_body(*args, **kwargs):
        business_premise = {
            'TaxNumber': _validate_tax_number(kwargs['tax_number']),
            'BusinessPremiseID': _validate_identifier(kwargs['premise_id'], 'premise_id'),
            'ValidityDate': _format_date(kwargs['validity_date']),
            'SoftwareSupplier': [
                FURSBusinessPremiseAPI._prepare_software_supplier_json(kwargs['software_supplier_tax_number'],
                                                                       kwargs['foreign_software_supplier_name'])
            ],
            'BPIdentifier': {}
        }
        special_notes = kwargs.get('special_notes')
        if special_notes:
            business_premise['SpecialNotes'] = _validate_text(special_notes, 'special_notes', max_length=1000)
        if kwargs.get('close', False):
            business_premise['ClosingTag'] = 'Z'
        return {
            'BusinessPremiseRequest': {
                'Header': FURSBusinessPremiseAPI._prepare_business_premise_request_header(),
                'BusinessPremise': business_premise
            }
        }


class TaxesPerSeller:
    def __init__(self,
                 other_taxes_amount=None,
                 exempt_vat_taxable_amount=None,
                 reverse_vat_taxable_amount=None,
                 non_taxable_amount=None,
                 special_tax_rules_amount=None,
                 seller_tax_number=None):
        self.other_taxes_amount = other_taxes_amount
        self.exempt_vat_taxable_amount = exempt_vat_taxable_amount
        self.reverse_vat_taxable_amount = reverse_vat_taxable_amount
        self.non_taxable_amount = non_taxable_amount
        self.special_tax_rules_amount = special_tax_rules_amount
        self.seller_tax_number = seller_tax_number
        self.vat_amounts = []
        self.flat_rate_compensations = []

    def add_vat_amount(self, tax_rate, tax_base, tax_amount):
        self.vat_amounts.append({
            'TaxRate': _normalize_tax_rate(tax_rate),
            'TaxableAmount': _normalize_amount(tax_base),
            'TaxAmount': _normalize_amount(tax_amount)
        })

    def add_flat_rate_compensation(self, flat_rate_rate, flat_rate_taxable_amount, flat_rate_amount):
        self.flat_rate_compensations.append({
            'FlatRateRate': _normalize_tax_rate(flat_rate_rate),
            'FlatRateTaxableAmount': _normalize_amount(flat_rate_taxable_amount),
            'FlatRateAmount': _normalize_amount(flat_rate_amount)
        })

    def build_json(self):
        tax_spec = {}
        if self.seller_tax_number:
            tax_spec['SellerTaxNumber'] = _validate_tax_number(self.seller_tax_number, 'seller_tax_number')
        if len(self.vat_amounts) > 0:
            tax_spec['VAT'] = self.vat_amounts
        if len(self.flat_rate_compensations) > 0:
            tax_spec['FlatRateCompensation'] = self.flat_rate_compensations
        if self.non_taxable_amount is not None:
            tax_spec['NontaxableAmount'] = _normalize_amount(self.non_taxable_amount)
        if self.reverse_vat_taxable_amount is not None:
            tax_spec['ReverseVATTaxableAmount'] = _normalize_amount(self.reverse_vat_taxable_amount)
        if self.exempt_vat_taxable_amount is not None:
            tax_spec['ExemptVATTaxableAmount'] = _normalize_amount(self.exempt_vat_taxable_amount)
        if self.other_taxes_amount is not None:
            tax_spec['OtherTaxesAmount'] = _normalize_amount(self.other_taxes_amount)
        if self.special_tax_rules_amount is not None:
            tax_spec['SpecialTaxRulesAmount'] = _normalize_amount(self.special_tax_rules_amount)
        if not tax_spec:
            raise ValueError("TaxesPerSeller must contain at least one tax amount field")
        return tax_spec


class FURSInvoiceAPI(FURSBaseAPI):

    def __init__(self, *args, **kwargs):
        FURSBaseAPI.__init__(self, *args, **kwargs)

    def calculate_zoi(self,
                      tax_number,
                      issued_date,
                      invoice_number,
                      business_premise_id,
                      electronic_device_id,
                      invoice_amount,
                      date_format='%d.%m.%Y %H:%M:%S'):
        """
        Calculate ZOI - Protective Mark of the Invoice Issuer.
        Defaults to the date format used by the FURS v3.2 implementation examples.

        ``invoice_amount`` is validated through the same rules as the invoice
        payload (max 2 decimal places); this prevents silent rounding that
        would make the ZOI inconsistent with the InvoiceAmount sent to FURS.
        """
        # Validate-only: _normalize_amount raises ValueError if invoice_amount
        # has too many decimals or is otherwise unacceptable. The validated
        # value isn't reused — quantize() below is just a defensive 0.01
        # zero-pad ('66.7' -> '66.70') for the hashed string.
        _normalize_amount(invoice_amount)
        content = "%s%s%s%s%s%s" % (_validate_tax_number(tax_number),
                                    issued_date.strftime(date_format),
                                    _validate_invoice_number(invoice_number),
                                    _validate_identifier(business_premise_id, 'business_premise_id'),
                                    _validate_identifier(electronic_device_id, 'electronic_device_id'),
                                    Decimal(str(invoice_amount)).quantize(Decimal('0.01')))
        return hashlib.md5(self._sign(content=content)).hexdigest()

    def prepare_printable(self, tax_number, zoi, issued_date, timezone='Europe/Ljubljana'):
        if not _ZOI_RE.match(zoi):
            raise ValueError("zoi must be a 32-character hexadecimal string")
        tax_number = _validate_tax_number(tax_number)
        if issued_date.tzinfo:
            tz = pytz.timezone(timezone)
            issued_date = issued_date.astimezone(tz)

        zoi_base10 = str(int(zoi, 16)).zfill(39)
        date_str = issued_date.strftime('%y%m%d%H%M%S')
        data = zoi_base10 + str(tax_number) + date_str
        control = str(sum(map(int, data)) % 10)
        return data + control

    def get_invoice_eor(self,
                        zoi,
                        tax_number,
                        issued_date,
                        invoice_number,
                        business_premise_id,
                        electronic_device_id,
                        invoice_amount,
                        taxes_per_seller=None,
                        payment_amount=None,
                        customer_vat_number=None,
                        returns_amount=None,
                        operator_tax_number=None,
                        foreign_operator=False,
                        subsequent_submit=False,
                        reference_invoice_number=None,
                        reference_invoice_business_premise_id=None,
                        reference_invoice_electronic_device_id=None,
                        reference_invoice_issued_date=None,
                        reference_sales_book_number=None,
                        reference_sales_book_set_number=None,
                        reference_sales_book_serial_number=None,
                        reference_sales_book_issued_date=None,
                        numbering_structure=NUMBERING_STRUCTURE_DEVICE,
                        special_notes=''):
        if operator_tax_number is not None and foreign_operator:
            raise ValueError("operator_tax_number and foreign_operator=True are mutually exclusive")

        taxes_per_seller = _ensure_taxes_per_seller_list(taxes_per_seller)
        message = self._build_common_message_body(**locals())
        invoice = message['InvoiceRequest']['Invoice']

        for tax_per_seller in taxes_per_seller:
            invoice['TaxesPerSeller'].append(tax_per_seller.build_json())

        if customer_vat_number:
            invoice['CustomerVATNumber'] = _validate_text(customer_vat_number, 'customer_vat_number', max_length=20)
        if returns_amount is not None:
            invoice['ReturnsAmount'] = _normalize_amount(returns_amount)
        if operator_tax_number is not None:
            invoice['OperatorTaxNumber'] = _validate_tax_number(operator_tax_number, 'operator_tax_number')
        if foreign_operator:
            invoice['ForeignOperator'] = True
        if subsequent_submit:
            invoice['SubsequentSubmit'] = True

        reference_invoices = _build_reference_invoice_list(reference_invoice_number,
                                                           reference_invoice_business_premise_id,
                                                           reference_invoice_electronic_device_id,
                                                           reference_invoice_issued_date)
        if reference_invoices:
            invoice['ReferenceInvoice'] = reference_invoices

        reference_sales_books = _build_reference_sales_book_list(reference_sales_book_number,
                                                                 reference_sales_book_set_number,
                                                                 reference_sales_book_serial_number,
                                                                 reference_sales_book_issued_date)
        if reference_sales_books:
            invoice['ReferenceSalesBook'] = reference_sales_books

        if special_notes:
            invoice['SpecialNotes'] = _validate_text(special_notes, 'special_notes', min_length=0, max_length=1000)

        response = self._send_request(path=INVOICE_ISSUE_PATH, data=message)
        return response['InvoiceResponse']['UniqueInvoiceID']

    @staticmethod
    def _prepare_invoice_request_header():
        return {
            "MessageID": str(uuid.uuid4()),
            "DateTime": _format_datetime(datetime.datetime.now())
        }

    @staticmethod
    def _build_common_message_body(*args, **kwargs):
        numbering_structure = kwargs['numbering_structure']
        if numbering_structure not in (NUMBERING_STRUCTURE_DEVICE, NUMBERING_STRUCTURE_CENTRAL):
            raise ValueError("numbering_structure must be B or C")
        if not _ZOI_RE.match(kwargs['zoi']):
            raise ValueError("zoi must be a 32-character hexadecimal string")
        return {
            'InvoiceRequest': {
                'Header': FURSInvoiceAPI._prepare_invoice_request_header(),
                'Invoice': {
                    'TaxNumber': _validate_tax_number(kwargs['tax_number']),
                    'IssueDateTime': _format_datetime(kwargs['issued_date']),
                    'NumberingStructure': numbering_structure,
                    'InvoiceIdentifier': {
                        'BusinessPremiseID': _validate_identifier(kwargs['business_premise_id'], 'business_premise_id'),
                        'ElectronicDeviceID': _validate_identifier(kwargs['electronic_device_id'], 'electronic_device_id'),
                        'InvoiceNumber': _validate_invoice_number(kwargs['invoice_number'])
                    },
                    'InvoiceAmount': _normalize_amount(kwargs['invoice_amount']),
                    'PaymentAmount': _normalize_amount(kwargs['payment_amount']) if kwargs['payment_amount'] is not None else _normalize_amount(kwargs['invoice_amount']),
                    'ProtectedID': kwargs['zoi'],
                    'TaxesPerSeller': [],
                }
            }
        }

    def get_sales_book_invoice_eor(self,
                                   tax_number,
                                   issued_date,
                                   invoice_number,
                                   business_premise_id,
                                   set_number,
                                   serial_number,
                                   invoice_amount,
                                   taxes_per_seller=None,
                                   payment_amount=None,
                                   customer_vat_number=None,
                                   returns_amount=None,
                                   operator_tax_number=None,
                                   reference_invoice_number=None,
                                   reference_invoice_business_premise_id=None,
                                   reference_invoice_electronic_device_id=None,
                                   reference_invoice_issued_date=None,
                                   reference_sales_book_number=None,
                                   reference_sales_book_set_number=None,
                                   reference_sales_book_serial_number=None,
                                   reference_sales_book_issued_date=None,
                                   special_notes=''):
        taxes_per_seller = _ensure_taxes_per_seller_list(taxes_per_seller)
        message = self._build_common_sales_book_message_body(**locals())
        sales_book_invoice = message['InvoiceRequest']['SalesBookInvoice']

        for tax_per_seller in taxes_per_seller:
            sales_book_invoice['TaxesPerSeller'].append(tax_per_seller.build_json())

        if customer_vat_number:
            sales_book_invoice['CustomerVATNumber'] = _validate_text(customer_vat_number, 'customer_vat_number', max_length=20)
        if returns_amount is not None:
            sales_book_invoice['ReturnsAmount'] = _normalize_amount(returns_amount)
        if operator_tax_number is not None:
            # The official schema for SalesBookInvoice does not include OperatorTaxNumber.
            raise ValueError("operator_tax_number is not supported for SalesBookInvoice payloads by the official JSON schema")

        reference_invoices = _build_reference_invoice_list(reference_invoice_number,
                                                           reference_invoice_business_premise_id,
                                                           reference_invoice_electronic_device_id,
                                                           reference_invoice_issued_date)
        if reference_invoices:
            sales_book_invoice['ReferenceInvoice'] = reference_invoices

        reference_sales_books = _build_reference_sales_book_list(reference_sales_book_number,
                                                                 reference_sales_book_set_number,
                                                                 reference_sales_book_serial_number,
                                                                 reference_sales_book_issued_date)
        if reference_sales_books:
            sales_book_invoice['ReferenceSalesBook'] = reference_sales_books

        if special_notes:
            sales_book_invoice['SpecialNotes'] = _validate_text(special_notes, 'special_notes', min_length=0, max_length=1000)

        response = self._send_request(path=INVOICE_ISSUE_PATH, data=message)
        return response['InvoiceResponse']['UniqueInvoiceID']

    @staticmethod
    def _build_common_sales_book_message_body(*args, **kwargs):
        return {
            'InvoiceRequest': {
                'Header': FURSInvoiceAPI._prepare_invoice_request_header(),
                'SalesBookInvoice': {
                    'TaxNumber': _validate_tax_number(kwargs['tax_number']),
                    'IssueDate': _format_date(kwargs['issued_date']),
                    'SalesBookIdentifier': {
                        'InvoiceNumber': _validate_invoice_number(kwargs['invoice_number']),
                        'SetNumber': _validate_sales_book_set_number(kwargs['set_number']),
                        'SerialNumber': _validate_sales_book_serial_number(kwargs['serial_number']),
                    },
                    'BusinessPremiseID': _validate_identifier(kwargs['business_premise_id'], 'business_premise_id'),
                    'InvoiceAmount': _normalize_amount(kwargs['invoice_amount']),
                    'PaymentAmount': _normalize_amount(kwargs['payment_amount']) if kwargs['payment_amount'] is not None else _normalize_amount(kwargs['invoice_amount']),
                    'TaxesPerSeller': [],
                }
            }
        }

    def submit_invoice_batch(self, invoice_messages):
        """
        Submit already-built Invoice payload dictionaries through the FURS batch endpoint.

        The batch endpoint only accepts electronic-device invoices; SalesBookInvoice
        payloads are rejected by the official ``FiscalVerificationSchemaBatch.json``
        (RecordInfoType.items.Invoice references InvoiceType only). Use the
        single-message :meth:`get_sales_book_invoice_eor` for sales-book invoices.

        The full FURS response dict is returned. **Callers must inspect each
        record's reply** — per-record EORs and per-record ``Error`` blocks are
        nested under ``InvoiceListResponse.InvoiceListReply.RecordReply``.
        ``submit_invoice_batch`` only raises automatically for a batch-wide
        ``Error`` returned by :meth:`_check_for_errors`; a batch where some
        records succeed and others fail will return normally, and silently
        ignoring per-record errors will leave failed records un-fiscalised.
        """
        if not isinstance(invoice_messages, list) or len(invoice_messages) < 2:
            raise ValueError("invoice_messages must contain at least two items for batch submission")
        if len(invoice_messages) > 500:
            raise ValueError("invoice_messages must contain at most 500 items")
        record_infos = []
        for index, message in enumerate(invoice_messages, start=1):
            if 'InvoiceRequest' in message:
                invoice_request = message['InvoiceRequest']
                if 'SalesBookInvoice' in invoice_request:
                    raise ValueError(
                        "SalesBookInvoice payloads cannot be submitted via the FURS batch endpoint "
                        "(item %d). Use get_sales_book_invoice_eor() instead." % index
                    )
                if 'Invoice' not in invoice_request:
                    raise ValueError(
                        "Item %d has InvoiceRequest without an Invoice payload" % index
                    )
                record_infos.append({'RecordNumber': index, 'Invoice': invoice_request['Invoice']})
            elif 'SalesBookInvoice' in message:
                raise ValueError(
                    "SalesBookInvoice payloads cannot be submitted via the FURS batch endpoint "
                    "(item %d). Use get_sales_book_invoice_eor() instead." % index
                )
            elif 'Invoice' in message:
                record_infos.append({'RecordNumber': index, 'Invoice': message['Invoice']})
            else:
                raise ValueError(
                    "Each invoice batch item must contain InvoiceRequest or Invoice (item %d)" % index
                )
        batch_message = {
            'InvoiceListRequest': {
                'Header': FURSInvoiceAPI._prepare_invoice_request_header(),
                'InvoiceList': {'RecordInfo': record_infos}
            }
        }
        response = self._send_request(path=INVOICE_ISSUE_BATCH_PATH, data=batch_message)
        return response
