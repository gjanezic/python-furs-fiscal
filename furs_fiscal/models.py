"""Pydantic models for the FURS v3.2 wire format.

Validation rules come directly from ``specs/schemas/FiscalVerificationSchema.json``
and ``specs/schemas/FiscalVerificationSchemaBatch.json``, plus the Slovene/EN
text in ``specs/TehnicnaDokumentacijaVer3.2.txt``. Field aliases match the
official JSON keys; the Pythonic snake_case attribute names are exposed to
callers and never sent over the wire.

The models double as both **input** (caller constructs them) and **wire**
representation (``model_dump(by_alias=True)`` produces the JSON FURS expects).

Design choices:
  - Amounts and tax rates are ``Decimal`` only — float input is rejected.
  - Datetimes must be timezone-aware and are auto-converted to Europe/Ljubljana
    before formatting (FURS spec uses local Slovenian wall time).
  - Round-trip safety: amounts that lose cents in IEEE-754 are rejected.
  - Pydantic ``extra='forbid'`` matches the schema's ``additionalProperties: false``.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    field_validator,
    model_validator,
)

LJUBLJANA = ZoneInfo("Europe/Ljubljana")

# ---------------------------------------------------------------------------
# Amount / TaxRate — Decimal-only, IEEE-754-safe
# ---------------------------------------------------------------------------

_AMOUNT_QUANT = Decimal("0.01")
_AMOUNT_LIMIT = Decimal("100000000000000")  # exclusive per schema
_TAX_RATE_LIMIT = Decimal("99999")  # inclusive per schema


def _coerce_to_decimal(value: Any) -> Decimal:
    """Reject ``float`` (silent precision loss); accept ``Decimal``, ``int``, ``str``."""
    if isinstance(value, bool):
        raise ValueError("bool is not a valid numeric value")
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, str):
        try:
            return Decimal(value)
        except (ValueError, ArithmeticError) as exc:
            raise ValueError(f"invalid decimal string: {value!r}") from exc
    raise ValueError(
        f"amount must be Decimal, int, or str (got {type(value).__name__}); "
        "float is rejected to avoid silent IEEE-754 precision loss"
    )


def _check_amount(value: Decimal) -> Decimal:
    if not value.is_finite():
        raise ValueError("amount must be finite")
    quantized = value.quantize(_AMOUNT_QUANT)
    if quantized != value:
        raise ValueError(f"amount supports at most 2 decimal places (got {value})")
    if quantized <= -_AMOUNT_LIMIT or quantized >= _AMOUNT_LIMIT:
        raise ValueError(
            f"amount {quantized} outside FURS schema range (exclusive ±{_AMOUNT_LIMIT})"
        )
    # IEEE-754 round-trip safety: at the upper end (~1e14), float64 silently
    # drops the cents. The truncated payload would then disagree with the ZOI
    # input string, breaking server-side verification.
    if Decimal(repr(float(quantized))) != quantized:
        raise ValueError(
            f"amount {quantized} cannot be represented exactly as IEEE-754 double; "
            "reduce magnitude"
        )
    return quantized


def _serialize_amount(value: Decimal) -> float:
    return float(value)


Amount = Annotated[
    Decimal,
    BeforeValidator(_coerce_to_decimal),
    AfterValidator(_check_amount),
    PlainSerializer(_serialize_amount, return_type=float),
]


def _check_tax_rate(value: Decimal) -> Decimal:
    if not value.is_finite():
        raise ValueError("tax rate must be finite")
    quantized = value.quantize(_AMOUNT_QUANT)
    if quantized != value:
        raise ValueError(f"tax rate supports at most 2 decimal places (got {value})")
    if quantized < -_TAX_RATE_LIMIT or quantized > _TAX_RATE_LIMIT:
        raise ValueError(
            f"tax rate {quantized} outside FURS schema range (inclusive ±{_TAX_RATE_LIMIT})"
        )
    return quantized


TaxRate = Annotated[
    Decimal,
    BeforeValidator(_coerce_to_decimal),
    AfterValidator(_check_tax_rate),
    PlainSerializer(_serialize_amount, return_type=float),
]


def _check_geo(value: Decimal, *, max_abs: Decimal) -> Decimal:
    if not value.is_finite():
        raise ValueError("geolocation must be finite")
    quantized = value.quantize(Decimal("0.000001"))
    if quantized != value:
        raise ValueError("geolocation supports at most 6 decimal places")
    if quantized < -max_abs or quantized > max_abs:
        raise ValueError(f"geolocation outside ±{max_abs}")
    return quantized


def _check_latitude(value: Decimal) -> Decimal:
    return _check_geo(value, max_abs=Decimal("99.999999"))


def _check_longitude(value: Decimal) -> Decimal:
    return _check_geo(value, max_abs=Decimal("999.999999"))


Latitude = Annotated[
    Decimal,
    BeforeValidator(_coerce_to_decimal),
    AfterValidator(_check_latitude),
    PlainSerializer(_serialize_amount, return_type=float),
]
Longitude = Annotated[
    Decimal,
    BeforeValidator(_coerce_to_decimal),
    AfterValidator(_check_longitude),
    PlainSerializer(_serialize_amount, return_type=float),
]


# ---------------------------------------------------------------------------
# Datetime / date — tz-aware required, auto-convert to Ljubljana
# ---------------------------------------------------------------------------


def _to_ljubljana_datetime(value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(f"expected datetime, got {type(value).__name__}")
    if value.tzinfo is None:
        raise ValueError(
            "datetime must be timezone-aware so it can be unambiguously "
            "converted to Europe/Ljubljana for FURS"
        )
    return value.astimezone(LJUBLJANA)


def _serialize_datetime(value: datetime) -> str:
    # FURS spec text R_2.0 / R_3.2: YYYY-MM-DDTHH:MM:SS, no timezone suffix.
    return value.strftime("%Y-%m-%dT%H:%M:%S")


FURSDateTime = Annotated[
    datetime,
    BeforeValidator(_to_ljubljana_datetime),
    PlainSerializer(_serialize_datetime, return_type=str),
]


def _to_ljubljana_date(value: Any) -> date:
    if isinstance(value, datetime):
        return _to_ljubljana_datetime(value).date()
    if isinstance(value, date):
        return value
    raise ValueError(f"expected date or datetime, got {type(value).__name__}")


def _serialize_date(value: date) -> str:
    return value.strftime("%Y-%m-%d")


FURSDate = Annotated[
    date,
    BeforeValidator(_to_ljubljana_date),
    PlainSerializer(_serialize_date, return_type=str),
]

# ---------------------------------------------------------------------------
# Primitive constraints from the JSON Schema
# ---------------------------------------------------------------------------

TaxNumber = Annotated[int, Field(ge=10000000, le=99999999)]

# R_3.4.1 / R_3.4.2: alphanumeric, 1..20.
Identifier = Annotated[
    str,
    StringConstraints(min_length=1, max_length=20, pattern=r"^[0-9a-zA-Z]+$"),
]
# R_3.4.3: numeric, no leading zero.
InvoiceNumberStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=20, pattern=r"^[1-9][0-9]{0,19}$"),
]
SetNumber = Annotated[str, StringConstraints(min_length=2, max_length=2)]
SerialNumber = Annotated[str, StringConstraints(min_length=12, max_length=12)]
PostalCode = Annotated[str, StringConstraints(min_length=4, max_length=4)]
SpecialNotesStr = Annotated[str, StringConstraints(min_length=1, max_length=1000)]
ZOIHex = Annotated[
    str,
    StringConstraints(min_length=32, max_length=32, pattern=r"^[0-9a-fA-F]{32}$"),
]
NameForeignStr = Annotated[str, StringConstraints(min_length=1, max_length=1000)]


def _check_premise_count(value: Decimal | int, *, max_value: int) -> int:
    """CadastralNumber / BuildingNumber / BuildingSectionNumber — non-negative integer.

    Schema: ``type: number, minimum: 0, maximum: <bound>``. We keep them as
    ``int`` because the example payload uses integer JSON literals.
    """
    if isinstance(value, bool):
        raise ValueError("bool is not a valid premise count")
    if isinstance(value, int):
        n = value
    elif isinstance(value, Decimal):
        if value != value.to_integral_value():
            raise ValueError("premise count must be an integer")
        n = int(value)
    elif isinstance(value, str):
        n = int(value)
    else:
        raise ValueError(f"expected int, got {type(value).__name__}")
    if n < 0 or n > max_value:
        raise ValueError(f"premise count {n} outside [0, {max_value}]")
    return n


def _cadastral(value: Any) -> int:
    return _check_premise_count(value, max_value=9999)


def _building(value: Any) -> int:
    return _check_premise_count(value, max_value=99999)


def _building_section(value: Any) -> int:
    return _check_premise_count(value, max_value=9999)


CadastralNumber = Annotated[int, BeforeValidator(_cadastral)]
BuildingNumber = Annotated[int, BeforeValidator(_building)]
BuildingSectionNumber = Annotated[int, BeforeValidator(_building_section)]


# ---------------------------------------------------------------------------
# Base model — extra='forbid' mirrors schema additionalProperties: false
# ---------------------------------------------------------------------------


class FURSModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        validate_by_name=True,
        str_strip_whitespace=False,
    )

    def to_wire(self) -> dict[str, Any]:
        """Return the dict that should be JSON-encoded into the JWS payload."""
        return self.model_dump(by_alias=True, exclude_none=True)


# ---------------------------------------------------------------------------
# Header (shared between every request envelope)
# ---------------------------------------------------------------------------


def _new_message_id() -> str:
    return str(uuid.uuid4())


def _now_ljubljana() -> datetime:
    return datetime.now(tz=LJUBLJANA)


class Header(FURSModel):
    """Request envelope header (R_1.0 + R_2.0 / P_1.0 + P_2.0)."""

    message_id: Annotated[
        str,
        StringConstraints(
            min_length=36,
            max_length=36,
            pattern=r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$",
        ),
    ] = Field(default_factory=_new_message_id, alias="MessageID")
    date_time: FURSDateTime = Field(default_factory=_now_ljubljana, alias="DateTime")


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------


class InvoiceIdentifier(FURSModel):
    business_premise_id: Identifier = Field(alias="BusinessPremiseID")
    electronic_device_id: Identifier = Field(alias="ElectronicDeviceID")
    invoice_number: InvoiceNumberStr = Field(alias="InvoiceNumber")


class SalesBookIdentifier(FURSModel):
    invoice_number: InvoiceNumberStr = Field(alias="InvoiceNumber")
    set_number: SetNumber = Field(alias="SetNumber")
    serial_number: SerialNumber = Field(alias="SerialNumber")


# ---------------------------------------------------------------------------
# Tax structures
# ---------------------------------------------------------------------------


class VATAmount(FURSModel):
    tax_rate: TaxRate = Field(alias="TaxRate")
    taxable_amount: Amount = Field(alias="TaxableAmount")
    tax_amount: Amount = Field(alias="TaxAmount")


class FlatRateCompensation(FURSModel):
    flat_rate_rate: TaxRate = Field(alias="FlatRateRate")
    flat_rate_taxable_amount: Amount = Field(alias="FlatRateTaxableAmount")
    flat_rate_amount: Amount = Field(alias="FlatRateAmount")


class TaxesPerSeller(FURSModel):
    """One per-seller tax breakdown.

    Schema does not require any specific field, but FURS spec text R_3.9
    expects at least one meaningful entry. We enforce that locally.
    """

    seller_tax_number: TaxNumber | None = Field(default=None, alias="SellerTaxNumber")
    vat: list[VATAmount] | None = Field(default=None, alias="VAT")
    flat_rate_compensation: list[FlatRateCompensation] | None = Field(
        default=None, alias="FlatRateCompensation"
    )
    other_taxes_amount: Amount | None = Field(default=None, alias="OtherTaxesAmount")
    exempt_vat_taxable_amount: Amount | None = Field(
        default=None, alias="ExemptVATTaxableAmount"
    )
    reverse_vat_taxable_amount: Amount | None = Field(
        default=None, alias="ReverseVATTaxableAmount"
    )
    nontaxable_amount: Amount | None = Field(default=None, alias="NontaxableAmount")
    special_tax_rules_amount: Amount | None = Field(
        default=None, alias="SpecialTaxRulesAmount"
    )

    @model_validator(mode="after")
    def _at_least_one_field(self) -> TaxesPerSeller:
        meaningful = (
            self.vat,
            self.flat_rate_compensation,
            self.other_taxes_amount,
            self.exempt_vat_taxable_amount,
            self.reverse_vat_taxable_amount,
            self.nontaxable_amount,
            self.special_tax_rules_amount,
        )
        if all(field is None for field in meaningful):
            raise ValueError(
                "TaxesPerSeller must contain at least one tax field "
                "(VAT, FlatRateCompensation, OtherTaxesAmount, ExemptVATTaxableAmount, "
                "ReverseVATTaxableAmount, NontaxableAmount, or SpecialTaxRulesAmount)"
            )
        if self.vat is not None and not (1 <= len(self.vat) <= 1000):
            raise ValueError("VAT must contain 1..1000 entries")
        if self.flat_rate_compensation is not None and not (
            1 <= len(self.flat_rate_compensation) <= 1000
        ):
            raise ValueError("FlatRateCompensation must contain 1..1000 entries")
        return self


# ---------------------------------------------------------------------------
# Reference invoice / sales book
# ---------------------------------------------------------------------------


class ReferenceInvoice(FURSModel):
    reference_invoice_identifier: InvoiceIdentifier = Field(
        alias="ReferenceInvoiceIdentifier"
    )
    reference_invoice_issue_date_time: FURSDateTime = Field(
        alias="ReferenceInvoiceIssueDateTime"
    )


class ReferenceSalesBook(FURSModel):
    reference_sales_book_identifier: SalesBookIdentifier = Field(
        alias="ReferenceSalesBookIdentifier"
    )
    reference_sales_book_issue_date: FURSDate = Field(alias="ReferenceSalesBookIssueDate")


# ---------------------------------------------------------------------------
# Invoice (electronic device)
# ---------------------------------------------------------------------------

NumberingStructure = Literal["B", "C"]


class Invoice(FURSModel):
    """Invoice issued via an electronic device — R_3.x."""

    tax_number: TaxNumber = Field(alias="TaxNumber")
    issue_date_time: FURSDateTime = Field(alias="IssueDateTime")
    numbering_structure: NumberingStructure = Field(alias="NumberingStructure")
    invoice_identifier: InvoiceIdentifier = Field(alias="InvoiceIdentifier")
    customer_vat_number: Annotated[
        str, StringConstraints(min_length=1, max_length=20)
    ] | None = Field(default=None, alias="CustomerVATNumber")
    invoice_amount: Amount = Field(alias="InvoiceAmount")
    returns_amount: Amount | None = Field(default=None, alias="ReturnsAmount")
    payment_amount: Amount = Field(alias="PaymentAmount")
    taxes_per_seller: list[TaxesPerSeller] = Field(
        alias="TaxesPerSeller", min_length=1, max_length=1000
    )
    operator_tax_number: TaxNumber | None = Field(default=None, alias="OperatorTaxNumber")
    foreign_operator: bool | None = Field(default=None, alias="ForeignOperator")
    protected_id: ZOIHex = Field(alias="ProtectedID")
    subsequent_submit: bool | None = Field(default=None, alias="SubsequentSubmit")
    reference_invoice: list[ReferenceInvoice] | None = Field(
        default=None, alias="ReferenceInvoice", min_length=1, max_length=1000
    )
    reference_sales_book: list[ReferenceSalesBook] | None = Field(
        default=None, alias="ReferenceSalesBook", min_length=1, max_length=1000
    )
    special_notes: SpecialNotesStr | None = Field(default=None, alias="SpecialNotes")

    @model_validator(mode="after")
    def _operator_exclusive(self) -> Invoice:
        # Spec sec. 3 + R_3.10/R_3.11: operator is either local (tax number)
        # or foreign — never both. Sending both is a local validation error
        # because FURS rejects it as schema mismatch (s002).
        if self.operator_tax_number is not None and self.foreign_operator:
            raise ValueError(
                "operator_tax_number and foreign_operator=True are mutually exclusive"
            )
        return self


# ---------------------------------------------------------------------------
# SalesBookInvoice (pre-numbered invoice book) — R_4.x
# ---------------------------------------------------------------------------


class SalesBookInvoice(FURSModel):
    tax_number: TaxNumber = Field(alias="TaxNumber")
    issue_date: FURSDate = Field(alias="IssueDate")
    sales_book_identifier: SalesBookIdentifier = Field(alias="SalesBookIdentifier")
    business_premise_id: Identifier = Field(alias="BusinessPremiseID")
    customer_vat_number: Annotated[
        str, StringConstraints(min_length=1, max_length=20)
    ] | None = Field(default=None, alias="CustomerVATNumber")
    invoice_amount: Amount = Field(alias="InvoiceAmount")
    returns_amount: Amount | None = Field(default=None, alias="ReturnsAmount")
    payment_amount: Amount = Field(alias="PaymentAmount")
    taxes_per_seller: list[TaxesPerSeller] = Field(
        alias="TaxesPerSeller", min_length=1, max_length=1000
    )
    reference_invoice: list[ReferenceInvoice] | None = Field(
        default=None, alias="ReferenceInvoice", min_length=1, max_length=1000
    )
    reference_sales_book: list[ReferenceSalesBook] | None = Field(
        default=None, alias="ReferenceSalesBook", min_length=1, max_length=1000
    )
    special_notes: SpecialNotesStr | None = Field(default=None, alias="SpecialNotes")


# ---------------------------------------------------------------------------
# Invoice request envelope
# ---------------------------------------------------------------------------


class InvoiceRequest(FURSModel):
    header: Header = Field(default_factory=Header, alias="Header")
    invoice: Invoice | None = Field(default=None, alias="Invoice")
    sales_book_invoice: SalesBookInvoice | None = Field(
        default=None, alias="SalesBookInvoice"
    )

    @model_validator(mode="after")
    def _exactly_one(self) -> InvoiceRequest:
        present = sum(
            1 for f in (self.invoice, self.sales_book_invoice) if f is not None
        )
        if present != 1:
            raise ValueError(
                "InvoiceRequest must contain exactly one of Invoice or SalesBookInvoice"
            )
        return self


def wrap_invoice(invoice: Invoice) -> dict[str, Any]:
    return {"InvoiceRequest": InvoiceRequest(invoice=invoice).to_wire()}


def wrap_sales_book_invoice(invoice: SalesBookInvoice) -> dict[str, Any]:
    return {"InvoiceRequest": InvoiceRequest(sales_book_invoice=invoice).to_wire()}


# ---------------------------------------------------------------------------
# Business premise structures (P_x.x)
# ---------------------------------------------------------------------------


class Address(FURSModel):
    street: Annotated[str, StringConstraints(min_length=1, max_length=100)] = Field(
        alias="Street"
    )
    house_number: Annotated[str, StringConstraints(min_length=1, max_length=10)] = Field(
        alias="HouseNumber"
    )
    house_number_additional: Annotated[
        str, StringConstraints(min_length=1, max_length=10)
    ] | None = Field(default=None, alias="HouseNumberAdditional")
    community: Annotated[str, StringConstraints(min_length=1, max_length=100)] = Field(
        alias="Community"
    )
    city: Annotated[str, StringConstraints(min_length=1, max_length=100)] = Field(
        alias="City"
    )
    postal_code: PostalCode = Field(alias="PostalCode")


class PropertyID(FURSModel):
    cadastral_number: CadastralNumber = Field(alias="CadastralNumber")
    building_number: BuildingNumber = Field(alias="BuildingNumber")
    building_section_number: BuildingSectionNumber = Field(alias="BuildingSectionNumber")


class RealEstateBP(FURSModel):
    property_id: PropertyID = Field(alias="PropertyID")
    address: Address = Field(alias="Address")


class Geolocation(FURSModel):
    latitude: Latitude = Field(alias="Latitude")
    longitude: Longitude = Field(alias="Longitude")


class VendingMachine(FURSModel):
    vending_premise_type: Literal["D", "E", "F"] = Field(alias="VPremiseType")
    address: Address | None = Field(default=None, alias="Address")
    geolocation: Geolocation | None = Field(default=None, alias="Geolocation")

    @model_validator(mode="after")
    def _exactly_one_location(self) -> VendingMachine:
        if (self.address is None) == (self.geolocation is None):
            raise ValueError(
                "VendingMachine must specify exactly one of Address or Geolocation"
            )
        return self


PremiseType = Literal["A", "B", "C"]


class BPIdentifier(FURSModel):
    real_estate_bp: RealEstateBP | None = Field(default=None, alias="RealEstateBP")
    premise_type: PremiseType | None = Field(default=None, alias="PremiseType")
    vending_machine: VendingMachine | None = Field(default=None, alias="VendingMachine")

    @model_validator(mode="after")
    def _exactly_one(self) -> BPIdentifier:
        present = sum(
            1
            for f in (self.real_estate_bp, self.premise_type, self.vending_machine)
            if f is not None
        )
        if present != 1:
            raise ValueError(
                "BPIdentifier must specify exactly one of RealEstateBP, "
                "PremiseType, or VendingMachine"
            )
        return self


class SoftwareSupplier(FURSModel):
    tax_number: TaxNumber | None = Field(default=None, alias="TaxNumber")
    name_foreign: NameForeignStr | None = Field(default=None, alias="NameForeign")

    @model_validator(mode="after")
    def _exactly_one(self) -> SoftwareSupplier:
        if (self.tax_number is None) == (self.name_foreign is None):
            raise ValueError(
                "SoftwareSupplier must specify exactly one of TaxNumber or NameForeign"
            )
        return self


class BusinessPremise(FURSModel):
    tax_number: TaxNumber = Field(alias="TaxNumber")
    business_premise_id: Identifier = Field(alias="BusinessPremiseID")
    bp_identifier: BPIdentifier = Field(alias="BPIdentifier")
    validity_date: FURSDate = Field(alias="ValidityDate")
    closing_tag: Literal["Z"] | None = Field(default=None, alias="ClosingTag")
    software_supplier: list[SoftwareSupplier] = Field(
        alias="SoftwareSupplier", min_length=1
    )
    special_notes: SpecialNotesStr | None = Field(default=None, alias="SpecialNotes")


class BusinessPremiseRequest(FURSModel):
    header: Header = Field(default_factory=Header, alias="Header")
    business_premise: BusinessPremise = Field(alias="BusinessPremise")


def wrap_business_premise(bp: BusinessPremise) -> dict[str, Any]:
    return {
        "BusinessPremiseRequest": BusinessPremiseRequest(business_premise=bp).to_wire()
    }


# ---------------------------------------------------------------------------
# Batch envelopes
# ---------------------------------------------------------------------------


class _InvoiceRecordInfo(FURSModel):
    record_number: Annotated[int, Field(ge=1, le=500)] = Field(alias="RecordNumber")
    invoice: Invoice = Field(alias="Invoice")


class _BPRecordInfo(FURSModel):
    # Spec asymmetry: BPRecordNumberType is 1..1000 in the schema even though
    # BusinessPremiseList itself is capped at maxItems=500. We keep the field
    # bound spec-faithful (1..1000); list-size enforcement happens in
    # wrap_business_premise_batch below.
    record_number: Annotated[int, Field(ge=1, le=1000)] = Field(alias="RecordNumber")
    business_premise: BusinessPremise = Field(alias="BusinessPremise")


class _InvoiceList(FURSModel):
    record_info: list[_InvoiceRecordInfo] = Field(
        alias="RecordInfo", min_length=2, max_length=500
    )


class _BusinessPremiseList(FURSModel):
    record_info: list[_BPRecordInfo] = Field(
        alias="RecordInfo", min_length=2, max_length=500
    )


class InvoiceListRequest(FURSModel):
    header: Header = Field(default_factory=Header, alias="Header")
    invoice_list: _InvoiceList = Field(alias="InvoiceList")


class BusinessPremiseListRequest(FURSModel):
    header: Header = Field(default_factory=Header, alias="Header")
    business_premise_list: _BusinessPremiseList = Field(alias="BusinessPremiseList")


def wrap_invoice_batch(invoices: list[Invoice]) -> dict[str, Any]:
    if len(invoices) < 2 or len(invoices) > 500:
        raise ValueError(
            f"invoice batch must contain 2..500 records (got {len(invoices)})"
        )
    records = [
        _InvoiceRecordInfo(record_number=i, invoice=inv)
        for i, inv in enumerate(invoices, start=1)
    ]
    return {
        "InvoiceListRequest": InvoiceListRequest(
            invoice_list=_InvoiceList(record_info=records)
        ).to_wire()
    }


def wrap_business_premise_batch(premises: list[BusinessPremise]) -> dict[str, Any]:
    if len(premises) < 2 or len(premises) > 500:
        raise ValueError(
            f"business premise batch must contain 2..500 records (got {len(premises)})"
        )
    records = [
        _BPRecordInfo(record_number=i, business_premise=bp)
        for i, bp in enumerate(premises, start=1)
    ]
    return {
        "BusinessPremiseListRequest": BusinessPremiseListRequest(
            business_premise_list=_BusinessPremiseList(record_info=records)
        ).to_wire()
    }
