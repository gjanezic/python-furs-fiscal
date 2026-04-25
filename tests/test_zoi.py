"""ZOI calculation + printable QR payload tests.

Covers:
  * Determinism (PKCS#1 v1.5 deterministic signing → same input → same ZOI)
  * Input validation (tax number, identifier patterns, amount precision)
  * Naive datetime rejection
  * Printable timestamp uses Europe/Ljubljana wall time
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from furs_fiscal import calculate_zoi, prepare_printable
from furs_fiscal.models import LJUBLJANA


def test_zoi_is_deterministic(rsa_key):
    issued = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
    args = dict(
        private_key=rsa_key,
        tax_number=10039856,
        issued_date=issued,
        invoice_number="11",
        business_premise_id="BP1",
        electronic_device_id="B1",
        invoice_amount=Decimal("19.15"),
    )
    a = calculate_zoi(**args)
    b = calculate_zoi(**args)
    assert a == b
    assert len(a) == 32
    assert all(c in "0123456789abcdef" for c in a)


def test_zoi_changes_when_amount_changes(rsa_key):
    issued = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
    base = dict(
        private_key=rsa_key,
        tax_number=10039856,
        issued_date=issued,
        invoice_number="11",
        business_premise_id="BP1",
        electronic_device_id="B1",
    )
    a = calculate_zoi(**base, invoice_amount=Decimal("19.15"))
    b = calculate_zoi(**base, invoice_amount=Decimal("19.16"))
    assert a != b


def test_zoi_changes_when_tz_offset_changes(rsa_key):
    """Same wall-clock instant in Ljubljana, different source timezone — ZOI must
    be the same because the canonical form is Europe/Ljubljana wall time."""
    utc = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
    lj = datetime(2026, 4, 25, 10, 0, 0, tzinfo=LJUBLJANA)  # same instant
    args = dict(
        private_key=rsa_key,
        tax_number=10039856,
        invoice_number="11",
        business_premise_id="BP1",
        electronic_device_id="B1",
        invoice_amount=Decimal("19.15"),
    )
    a = calculate_zoi(**args, issued_date=utc)
    b = calculate_zoi(**args, issued_date=lj)
    assert a == b


def test_zoi_rejects_naive_datetime(rsa_key):
    naive = datetime(2026, 4, 25, 8, 0, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        calculate_zoi(
            private_key=rsa_key,
            tax_number=10039856,
            issued_date=naive,
            invoice_number="11",
            business_premise_id="BP1",
            electronic_device_id="B1",
            invoice_amount=Decimal("19.15"),
        )


def test_zoi_rejects_invoice_amount_with_3_decimals(rsa_key):
    issued = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="at most 2 decimal places"):
        calculate_zoi(
            private_key=rsa_key,
            tax_number=10039856,
            issued_date=issued,
            invoice_number="11",
            business_premise_id="BP1",
            electronic_device_id="B1",
            invoice_amount=Decimal("19.155"),
        )


def test_zoi_rejects_invalid_invoice_number_with_leading_zero(rsa_key):
    issued = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="leading zero"):
        calculate_zoi(
            private_key=rsa_key,
            tax_number=10039856,
            issued_date=issued,
            invoice_number="011",
            business_premise_id="BP1",
            electronic_device_id="B1",
            invoice_amount=Decimal("19.15"),
        )


def test_zoi_rejects_out_of_range_tax_number(rsa_key):
    issued = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="8-digit"):
        calculate_zoi(
            private_key=rsa_key,
            tax_number=999,
            issued_date=issued,
            invoice_number="11",
            business_premise_id="BP1",
            electronic_device_id="B1",
            invoice_amount=Decimal("19.15"),
        )


def test_zoi_uses_two_decimal_amount_in_signed_string(rsa_key):
    """Decimal('66.7') must produce the same ZOI as Decimal('66.70'), because
    both are quantized to 66.70 before signing per the spec."""
    issued = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
    base = dict(
        private_key=rsa_key,
        tax_number=10039856,
        issued_date=issued,
        invoice_number="11",
        business_premise_id="BP1",
        electronic_device_id="B1",
    )
    a = calculate_zoi(**base, invoice_amount=Decimal("66.7"))
    b = calculate_zoi(**base, invoice_amount=Decimal("66.70"))
    assert a == b


# ---------------------------------------------------------------------------
# prepare_printable
# ---------------------------------------------------------------------------


def test_prepare_printable_total_length_60_chars():
    zoi = "34905bcff14b381039af2e9d7eee54bb"
    issued = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
    out = prepare_printable(tax_number=10039856, zoi=zoi, issued_date=issued)
    # 39 (zoi base10) + 8 (tax) + 12 (yymmddHHMMSS) + 1 (luhn) = 60
    assert len(out) == 60
    assert out.isdigit()


def test_prepare_printable_naive_datetime_rejected():
    zoi = "34905bcff14b381039af2e9d7eee54bb"
    naive = datetime(2026, 4, 25, 8, 0, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        prepare_printable(tax_number=10039856, zoi=zoi, issued_date=naive)


def test_prepare_printable_uses_ljubljana_wall_time():
    zoi = "34905bcff14b381039af2e9d7eee54bb"
    # 08:00 UTC on 25 April → 10:00 CEST.
    issued = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
    out = prepare_printable(tax_number=10039856, zoi=zoi, issued_date=issued)
    # Last 13 chars before Luhn = yymmddHHMMSS in Ljubljana.
    assert out[-13:-1] == "260425100000"


def test_prepare_printable_rejects_non_hex_zoi():
    issued = datetime(2026, 4, 25, 8, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="hexadecimal"):
        prepare_printable(tax_number=10039856, zoi="not-hex", issued_date=issued)
