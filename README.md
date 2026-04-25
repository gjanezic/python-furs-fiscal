# python-furs-fiscal

[![Join the chat at https://gitter.im/boris-savic/python-furs-fiscal](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/boris-savic/python-furs-fiscal?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
Python library for simplified communication with  FURS (Finančna uprava Republike Slovenije).



## Installation

    $ pip install furs_fiscal

## Quick Start


### Registering Immovable Business Premise

Registering new Business Premises is simple. But you will need to obtain certain information
from your client such as:

 * Real Estate Cadastral Number
 * Real Estate Building Number
 * Real Estate Building Section Number

One thing you should also keep in mind is your premise address - if your premise is located at **Trzaska cesta 24A** you will need to pass house number **24** and additional number **A** as separate parameters.
If your street does not have additional house number/letter just pass None.

```python
from furs_fiscal.api import FURSBusinessPremiseAPI

api = FURSBusinessPremiseAPI(p12_path='my_cert.p12',
                             p12_password='cert_pass',
                             production=True, request_timeout=2.0)

api.register_immovable_business_premise(tax_number=10039856,
                                        premise_id='BP101',
                                        real_estate_cadastral_number=112,
                                        real_estate_building_number=11,
                                        real_estate_building_section_number=1,
                                        street='Trzaska cesta',
                                        house_number='24',
                                        house_number_additional='A',
                                        community='Ljubljana',
                                        city='Ljubljana',
                                        postal_code='1000',
                                        validity_date=datetime.now() - timedelta(days=60),
                                        software_supplier_tax_number=24564444,
                                        foreign_software_supplier_name=None,
                                        special_notes='/')
```

**NOTE**: As of 23.11.2015 FURS does require you to send some kind of Special note to them. Empty string will raise
invalid JSON on their side.

### Registering Movable Business Premise

In order to register Movable Business Premise you will need to define one of three types:

 * **TYPE_MOVABLE_PREMISE_A**: Movable object such as vehicle, movable stand etc.
 * **TYPE_MOVABLE_PREMISE_B**: Object at permanent location such as news stand, market stand etc.
 * **TYPE_MOVABLE_PREMISE_C**: Individual electronic device in cases when the company does not use other business premises


```python
from furs_fiscal.api import FURSBusinessPremiseAPI, TYPE_MOVABLE_PREMISE_A

api = FURSBusinessPremiseAPI(p12_path='my_cert.p12',
                             p12_password='cert_pass',
                             production=True,
                             request_timeout=2.0)

api.register_movable_business_premise(tax_number=10039856,
                                      premise_id='BP102',
                                      movable_type=TYPE_MOVABLE_PREMISE_A,
                                      validity_date=datetime.now() - timedelta(days=60),
                                      software_supplier_tax_number=24564444,
                                      foreign_software_supplier_name=None,
                                      special_notes='')

```

### Calculate Invoice ZOI - Protected ID

At the end of every Invoice your should print ZOI (Protected ID). To obtain it follow the next procedure:

```python
from furs_fiscal.api import FURSInvoiceAPI

api = FURSInvoiceAPI(p12_path='my_cert.p12',
                     p12_password='cert_pass',
                     production=False,
                     request_timeout=1.0)

date_issued = datetime.now()

zoi = api.calculate_zoi(tax_number=10039856,
                        issued_date=date_issued,
                        invoice_number='11',
                        business_premise_id='BP101',
                        electronic_device_id='B1',
                        invoice_amount=Decimal('19.15'))

```

### Generate Data for QR/Code128/PDF417

You're supposed to print QR Code/Code128 or PDF 417 on every invoice after the ZOI. To obtain the data for QR/Code128/PDF417 perform the following method call on **FURSInvoiceAPI** object.

```python
qr_data = api.prepare_printable(tax_number=10039856,
                                zoi=zoi,
                                issued_date=date_issued)
```

### Get EOR From FURS

To obtain FURS EOR code - UniqueID, you'll have to call the following method. It provides several other parameters,
for issuing invoice storno and special tax rules. Please read the full documentation.

```python
from decimal import Decimal

# In most cases there will be just one seller - company that issues the invoice.
# For some cases you may need to include more sellers. In that case,
# do not forget to set seller_tax_number for the other sellers.
seller_one = TaxesPerSeller(other_taxes_amount=None,
                            exempt_vat_taxable_amount=None,
                            reverse_vat_taxable_amount=None,
                            non_taxable_amount=Decimal('0.00'),
                            special_tax_rules_amount=None,
                            seller_tax_number=None)

seller_one.add_vat_amount(tax_rate=Decimal('22.00'),
                          tax_base=Decimal('23.14'),
                          tax_amount=Decimal('5.09'))
seller_one.add_vat_amount(tax_rate=Decimal('9.50'),
                          tax_base=Decimal('35.14'),
                          tax_amount=Decimal('3.34'))
# 5% VAT - for books etc.
seller_one.add_vat_amount(tax_rate=Decimal('5.00'),
                          tax_base=Decimal('10.00'),
                          tax_amount=Decimal('0.50'))

eor = api.get_invoice_eor(zoi=zoi,
                          tax_number=10039856,
                          issued_date=date_issued,
                          invoice_number='11',
                          business_premise_id='BP101',
                          electronic_device_id='B1',
                          invoice_amount=Decimal('66.71'),
                          payment_amount=Decimal('0.00'),
                          returns_amount=Decimal('0.00'),
                          taxes_per_seller=seller_one,  # Single TaxesPerSeller or a list is supported.
                          operator_tax_number=12345678)
```

Invoice and tax amount fields accept numeric values, including `Decimal` instances. Values are validated to be finite, to contain at most two decimal places, and to fit the official FURS JSON-schema ranges before JSON serialization. Explicit zero amounts are preserved in generated payloads, so `payment_amount=Decimal('0.00')`, `returns_amount=Decimal('0.00')`, and zero-valued tax fields are sent to FURS. `taxes_per_seller` is required and must contain at least one `TaxesPerSeller` instance.

`operator_tax_number` and `foreign_operator=True` are mutually exclusive. Reference invoice fields can be passed as scalar values for a single reference, or as parallel lists of equal length for multiple references. Electronic invoices also support references to pre-numbered invoice-book invoices through `reference_sales_book_*` fields. `SpecialNotes` is included whenever a non-empty value is provided.

Invoice issue/reference datetimes and request header timestamps are formatted as `YYYY-MM-DDTHH:MM:SS` without a `Z` suffix or offset. Business premise validity dates and sales-book dates are formatted as `YYYY-MM-DD`.

FURS v3.2 additions are supported for vending-machine business premises via `register_vending_machine_business_premise()`, flat-rate compensation via `TaxesPerSeller.add_flat_rate_compensation()`, and batch submission via `submit_invoice_batch()` and `register_business_premises_batch()`. Batch methods expect already-built payload dictionaries and submit them to the official `cash_registers_batch` endpoints.

TLS server verification is configurable through `verify_tls`: keep the legacy default `False`, pass `True` to use the system CA store, or pass a CA bundle path for SIGOV-CA/SI-TRUST pinning. FURS response JWS verification can be enabled with `verify_furs_response=True` and `furs_response_public_key`; by default responses are decoded without signature verification for backwards compatibility.

### Certificate Temporary Files

`Connector` writes certificate and private-key material from the `.p12` file into temporary PEM files because `requests` requires filesystem paths for mutual TLS client certificates. Call `close()` when you are finished with an API instance to remove those temporary files:

```python
api = FURSInvoiceAPI(p12_path='my_cert.p12',
                     p12_password='cert_pass',
                     production=False,
                     request_timeout=1.0)
try:
    # Use the API here.
    pass
finally:
    api.close()
```

The API classes and the underlying `Connector` also support context-manager cleanup.

## Running Tests

Regression tests are available under `tests/`. After installing test dependencies, run:

```bash
python -m pytest tests/test_api_regressions.py
python -m pytest tests/test_schema_payloads.py
```

## Contributing

This library should be sufficient to integrate into your software as is, but there is still some work that needs to be done.

You can contribute in one of the following areas:

 * Detailed documentation
 * More examples for various use-cases
 * Additional FURS API regression tests
 * Packaging and CI improvements

## Contact

**Boris Savic**

 * Twitter: [@zitko](https://twitter.com/zitko)
 * Email: boris70@gmail.com




