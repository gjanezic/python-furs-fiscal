"""Pydantic model validation tests."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from furs_fiscal import (
    Address,
    BPIdentifier,
    BusinessPremise,
    FlatRateCompensation,
    Geolocation,
    Header,
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
    wrap_invoice_batch,
    wrap_sales_book_invoice,
)
from furs_fiscal.models import LJUBLJANA


# ---------------------------------------------------------------------------
# Amount / TaxRate validation
# ---------------------------------------------------------------------------


def _make_minimal_invoice(**overrides) -> Invoice:
    base = dict(
        tax_number=10039856,
        issue_date_time=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
        numbering_structure="B",
        invoice_identifier=InvoiceIdentifier(
            business_premise_id="BP1",
            electronic_device_id="B1",
            invoice_number="11",
        ),
        invoice_amount=Decimal("19.15"),
        payment_amount=Decimal("19.15"),
        taxes_per_seller=[TaxesPerSeller(nontaxable_amount=Decimal("0.00"))],
        protected_id="34905bcff14b381039af2e9d7eee54bb",
    )
    base.update(overrides)
    return Invoice(**base)


class TestAmountValidation:
    def test_decimal_amount_accepted(self):
        inv = _make_minimal_invoice(invoice_amount=Decimal("66.71"))
        assert inv.invoice_amount == Decimal("66.71")

    def test_int_amount_accepted(self):
        inv = _make_minimal_invoice(invoice_amount=20)
        assert inv.invoice_amount == Decimal("20.00")

    def test_str_amount_accepted(self):
        inv = _make_minimal_invoice(invoice_amount="66.71")
        assert inv.invoice_amount == Decimal("66.71")

    def test_float_amount_rejected(self):
        # Float is the headline footgun: silent IEEE-754 conversion. Reject hard.
        with pytest.raises(ValidationError, match="float is rejected"):
            _make_minimal_invoice(invoice_amount=66.71)

    def test_three_decimal_places_rejected(self):
        with pytest.raises(ValidationError, match="at most 2 decimal places"):
            _make_minimal_invoice(invoice_amount=Decimal("66.715"))

    def test_amount_at_ieee754_loss_threshold_rejected(self):
        """At the schema's exclusive ±100T limit, float64 silently drops cents.
        The truncated payload would not match the ZOI input → reject upfront."""
        with pytest.raises(ValidationError, match="IEEE-754"):
            _make_minimal_invoice(invoice_amount=Decimal("99999999999999.99"))

    def test_realistic_high_value_accepted(self):
        inv = _make_minimal_invoice(invoice_amount=Decimal("1234567890123.45"))
        assert inv.invoice_amount == Decimal("1234567890123.45")

    def test_amount_at_or_above_schema_max_rejected(self):
        with pytest.raises(ValidationError, match="outside FURS schema range"):
            _make_minimal_invoice(invoice_amount=Decimal("100000000000000.00"))

    def test_zero_amount_accepted_and_serialized_as_float(self):
        inv = _make_minimal_invoice(payment_amount=Decimal("0.00"))
        wire = wrap_invoice(inv)
        assert wire["InvoiceRequest"]["Invoice"]["PaymentAmount"] == 0.0

    def test_serialized_value_is_float_for_two_decimal_amounts(self):
        inv = _make_minimal_invoice(invoice_amount=Decimal("66.71"))
        wire = wrap_invoice(inv)
        assert wire["InvoiceRequest"]["Invoice"]["InvoiceAmount"] == 66.71

    @given(st.decimals(min_value=Decimal("-999999999.99"), max_value=Decimal("999999999.99"), places=2, allow_nan=False))
    @settings(max_examples=50)
    def test_property_amounts_round_trip_within_safe_range(self, amount: Decimal):
        # Skip values pydantic's Decimal coercion would mangle (e.g. signed zero).
        if not amount.is_finite():
            return
        inv = _make_minimal_invoice(invoice_amount=amount, payment_amount=amount)
        wire = wrap_invoice(inv)
        assert wire["InvoiceRequest"]["Invoice"]["InvoiceAmount"] == float(amount)


class TestTaxRate:
    def test_tax_rate_at_inclusive_boundary_accepted(self):
        TaxesPerSeller(
            vat=[
                VATAmount(
                    tax_rate=Decimal("99999"),
                    taxable_amount=Decimal("1.00"),
                    tax_amount=Decimal("0.10"),
                )
            ]
        )

    def test_tax_rate_just_above_boundary_rejected(self):
        with pytest.raises(ValidationError):
            VATAmount(
                tax_rate=Decimal("99999.01"),
                taxable_amount=Decimal("1.00"),
                tax_amount=Decimal("0.10"),
            )


# ---------------------------------------------------------------------------
# Datetime / date validation
# ---------------------------------------------------------------------------


class TestDateTimes:
    def test_naive_datetime_rejected_for_invoice(self):
        with pytest.raises(ValidationError, match="timezone-aware"):
            _make_minimal_invoice(issue_date_time=datetime(2026, 4, 25, 10, 0, 0))

    def test_aware_datetime_converted_to_ljubljana_in_payload(self):
        # 08:00 UTC on 25 April is 10:00 CEST.
        inv = _make_minimal_invoice(
            issue_date_time=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
        )
        wire = wrap_invoice(inv)
        assert wire["InvoiceRequest"]["Invoice"]["IssueDateTime"] == "2026-04-25T10:00:00"

    def test_already_ljubljana_aware_datetime_round_trips(self):
        dt = datetime(2026, 4, 25, 10, 0, 0, tzinfo=LJUBLJANA)
        inv = _make_minimal_invoice(issue_date_time=dt)
        wire = wrap_invoice(inv)
        assert wire["InvoiceRequest"]["Invoice"]["IssueDateTime"] == "2026-04-25T10:00:00"

    def test_validity_date_serialised_as_date_only(self):
        bp = BusinessPremise(
            tax_number=10039856,
            business_premise_id="BP1",
            bp_identifier=BPIdentifier(premise_type="A"),
            validity_date=date(2026, 4, 25),
            software_supplier=[SoftwareSupplier(tax_number=24564444)],
        )
        wire = wrap_business_premise(bp)
        assert wire["BusinessPremiseRequest"]["BusinessPremise"]["ValidityDate"] == "2026-04-25"

    def test_validity_date_from_aware_datetime_drops_time_in_ljubljana(self):
        # 23:30 UTC on 24 April is 01:30 CEST on 25 April. Date should be 25.
        bp = BusinessPremise(
            tax_number=10039856,
            business_premise_id="BP1",
            bp_identifier=BPIdentifier(premise_type="A"),
            validity_date=datetime(2026, 4, 24, 23, 30, 0, tzinfo=timezone.utc),
            software_supplier=[SoftwareSupplier(tax_number=24564444)],
        )
        wire = wrap_business_premise(bp)
        assert wire["BusinessPremiseRequest"]["BusinessPremise"]["ValidityDate"] == "2026-04-25"


# ---------------------------------------------------------------------------
# Identifiers, tax number, ZOI
# ---------------------------------------------------------------------------


class TestIdentifierConstraints:
    def test_invoice_number_with_leading_zero_rejected(self):
        with pytest.raises(ValidationError):
            InvoiceIdentifier(
                business_premise_id="BP1",
                electronic_device_id="B1",
                invoice_number="011",
            )

    def test_business_premise_id_non_alphanumeric_rejected(self):
        with pytest.raises(ValidationError):
            InvoiceIdentifier(
                business_premise_id="BP-1",
                electronic_device_id="B1",
                invoice_number="11",
            )

    @pytest.mark.parametrize("tn", [9999999, 100000000, -1, "abc"])
    def test_tax_number_out_of_range(self, tn):
        with pytest.raises(ValidationError):
            _make_minimal_invoice(tax_number=tn)

    def test_protected_id_must_be_32_hex_chars(self):
        with pytest.raises(ValidationError):
            _make_minimal_invoice(protected_id="not-hex")

    def test_set_number_must_be_exactly_2_chars(self):
        with pytest.raises(ValidationError):
            SalesBookIdentifier(invoice_number="11", set_number="3", serial_number="0001-0001012")

    def test_serial_number_must_be_exactly_12_chars(self):
        with pytest.raises(ValidationError):
            SalesBookIdentifier(invoice_number="11", set_number="03", serial_number="too-short")


# ---------------------------------------------------------------------------
# TaxesPerSeller composition rules
# ---------------------------------------------------------------------------


class TestTaxesPerSeller:
    def test_empty_taxes_per_seller_rejected(self):
        with pytest.raises(ValidationError, match="at least one tax field"):
            TaxesPerSeller()

    def test_only_seller_tax_number_is_not_enough(self):
        with pytest.raises(ValidationError, match="at least one tax field"):
            TaxesPerSeller(seller_tax_number=10039856)

    def test_flat_rate_compensation_supported(self):
        tps = TaxesPerSeller(
            flat_rate_compensation=[
                FlatRateCompensation(
                    flat_rate_rate=Decimal("8"),
                    flat_rate_taxable_amount=Decimal("100.00"),
                    flat_rate_amount=Decimal("8.00"),
                )
            ]
        )
        assert tps.flat_rate_compensation[0].flat_rate_rate == Decimal("8")

    def test_zero_amount_in_tax_breakdown_preserved(self):
        tps = TaxesPerSeller(nontaxable_amount=Decimal("0.00"))
        wire = tps.to_wire()
        assert wire == {"NontaxableAmount": 0.0}


# ---------------------------------------------------------------------------
# Operator mutual exclusion
# ---------------------------------------------------------------------------


class TestOperatorRules:
    def test_operator_tax_number_and_foreign_operator_mutually_exclusive(self):
        with pytest.raises(ValidationError, match="mutually exclusive"):
            _make_minimal_invoice(operator_tax_number=12345678, foreign_operator=True)

    def test_only_operator_tax_number_ok(self):
        inv = _make_minimal_invoice(operator_tax_number=12345678)
        assert inv.operator_tax_number == 12345678

    def test_only_foreign_operator_ok(self):
        inv = _make_minimal_invoice(foreign_operator=True)
        assert inv.foreign_operator is True


# ---------------------------------------------------------------------------
# Sales-book invoice (no operator field, date-only IssueDate)
# ---------------------------------------------------------------------------


class TestSalesBookInvoice:
    def test_basic_payload_has_date_only_issue_date(self):
        inv = SalesBookInvoice(
            tax_number=10039856,
            issue_date=datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc),
            sales_book_identifier=SalesBookIdentifier(
                invoice_number="11", set_number="03", serial_number="5001-0001018"
            ),
            business_premise_id="BP1",
            invoice_amount=Decimal("19.15"),
            payment_amount=Decimal("19.15"),
            taxes_per_seller=[TaxesPerSeller(nontaxable_amount=Decimal("0.00"))],
        )
        wire = wrap_sales_book_invoice(inv)
        sbi = wire["InvoiceRequest"]["SalesBookInvoice"]
        assert sbi["IssueDate"] == "2026-04-25"
        assert "OperatorTaxNumber" not in sbi  # not in schema

    def test_operator_tax_number_field_does_not_exist(self):
        # Schema for SalesBookInvoice does not include OperatorTaxNumber. The
        # pydantic model should reject any attempt to set one.
        with pytest.raises(ValidationError):
            SalesBookInvoice(
                tax_number=10039856,
                issue_date=date(2026, 4, 25),
                sales_book_identifier=SalesBookIdentifier(
                    invoice_number="11", set_number="03", serial_number="5001-0001018"
                ),
                business_premise_id="BP1",
                invoice_amount=Decimal("19.15"),
                payment_amount=Decimal("19.15"),
                taxes_per_seller=[TaxesPerSeller(nontaxable_amount=Decimal("0.00"))],
                operator_tax_number=12345678,  # type: ignore[call-arg]
            )


# ---------------------------------------------------------------------------
# Business premise variants
# ---------------------------------------------------------------------------


class TestBusinessPremise:
    def test_immovable_with_address_and_property(self):
        bp = BusinessPremise(
            tax_number=10039856,
            business_premise_id="BP1",
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
                        community="Ljubljana",
                        city="Ljubljana",
                        postal_code="1000",
                    ),
                )
            ),
            validity_date=date(2026, 4, 25),
            software_supplier=[SoftwareSupplier(tax_number=24564444)],
        )
        wire = wrap_business_premise(bp)
        prop = wire["BusinessPremiseRequest"]["BusinessPremise"]["BPIdentifier"][
            "RealEstateBP"
        ]["PropertyID"]
        assert prop == {
            "CadastralNumber": 365,
            "BuildingNumber": 12,
            "BuildingSectionNumber": 3,
        }

    def test_movable_premise_type(self):
        bp = BusinessPremise(
            tax_number=10039856,
            business_premise_id="BP2",
            bp_identifier=BPIdentifier(premise_type="A"),
            validity_date=date(2026, 4, 25),
            software_supplier=[SoftwareSupplier(tax_number=24564444)],
        )
        assert bp.bp_identifier.premise_type == "A"

    def test_vending_with_geolocation(self):
        bp = BusinessPremise(
            tax_number=10039856,
            business_premise_id="VM1",
            bp_identifier=BPIdentifier(
                vending_machine=VendingMachine(
                    vending_premise_type="E",
                    geolocation=Geolocation(
                        latitude=Decimal("46.056946"),
                        longitude=Decimal("14.505751"),
                    ),
                )
            ),
            validity_date=date(2026, 4, 25),
            software_supplier=[SoftwareSupplier(tax_number=24564444)],
        )
        wire = wrap_business_premise(bp)
        vm = wire["BusinessPremiseRequest"]["BusinessPremise"]["BPIdentifier"][
            "VendingMachine"
        ]
        assert vm["VPremiseType"] == "E"
        assert vm["Geolocation"] == {"Latitude": 46.056946, "Longitude": 14.505751}

    def test_vending_with_both_address_and_geolocation_rejected(self):
        with pytest.raises(ValidationError, match="exactly one"):
            VendingMachine(
                vending_premise_type="D",
                address=Address(
                    street="x",
                    house_number="1",
                    community="x",
                    city="x",
                    postal_code="1000",
                ),
                geolocation=Geolocation(
                    latitude=Decimal("46.0"), longitude=Decimal("14.5")
                ),
            )

    def test_bp_identifier_must_pick_exactly_one(self):
        with pytest.raises(ValidationError, match="exactly one"):
            BPIdentifier()  # nothing
        with pytest.raises(ValidationError, match="exactly one"):
            BPIdentifier(
                premise_type="A",
                vending_machine=VendingMachine(
                    vending_premise_type="D",
                    geolocation=Geolocation(
                        latitude=Decimal("46.0"), longitude=Decimal("14.5")
                    ),
                ),
            )

    def test_software_supplier_requires_tax_or_foreign(self):
        with pytest.raises(ValidationError, match="exactly one"):
            SoftwareSupplier()
        with pytest.raises(ValidationError, match="exactly one"):
            SoftwareSupplier(tax_number=24564444, name_foreign="dual")


# ---------------------------------------------------------------------------
# Batch envelope wrappers
# ---------------------------------------------------------------------------


class TestBatch:
    def test_invoice_batch_too_small(self):
        inv = _make_minimal_invoice()
        with pytest.raises(ValueError, match="2..500"):
            wrap_invoice_batch([inv])

    def test_invoice_batch_record_numbering(self):
        envelope = wrap_invoice_batch([_make_minimal_invoice() for _ in range(3)])
        records = envelope["InvoiceListRequest"]["InvoiceList"]["RecordInfo"]
        assert [r["RecordNumber"] for r in records] == [1, 2, 3]

    def test_business_premise_batch_record_numbering(self):
        bp = BusinessPremise(
            tax_number=10039856,
            business_premise_id="BP1",
            bp_identifier=BPIdentifier(premise_type="A"),
            validity_date=date(2026, 4, 25),
            software_supplier=[SoftwareSupplier(tax_number=24564444)],
        )
        envelope = wrap_business_premise_batch([bp, bp])
        records = envelope["BusinessPremiseListRequest"]["BusinessPremiseList"][
            "RecordInfo"
        ]
        assert [r["RecordNumber"] for r in records] == [1, 2]


# ---------------------------------------------------------------------------
# Header default behaviour
# ---------------------------------------------------------------------------


class TestHeader:
    def test_default_message_id_is_uuid_format(self):
        h = Header()
        wire = h.to_wire()
        assert len(wire["MessageID"]) == 36

    def test_default_datetime_in_ljubljana_tz(self):
        h = Header()
        # Should not be naive after model conversion
        assert h.date_time.tzinfo is not None
