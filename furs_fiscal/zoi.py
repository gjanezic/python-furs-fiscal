"""ZOI (Zaščitna oznaka izdajatelja računa) calculation and printable QR data.

Pure functions — no Connector or HTTP dependency. Pass in the loaded RSA
private key (from ``cryptography``) directly. The signing key is the same
mTLS client certificate key used for JWS signing.

Algorithm per spec sec. 10:

    ZOI = MD5(RSA-SHA256-PKCS1v15(
        TaxNumber + IssueDateTime + InvoiceNumber +
        BusinessPremiseID + ElectronicDeviceID + InvoiceAmount,
        private_key,
    ))

Returned as a 32-character lower-case hex string.

* IssueDateTime is formatted as ``dd.MM.yyyy HH:mm:ss`` per the .NET reference
  in ``specs/BlagajneSample/.../ZOI.cs`` and the spec text.
* InvoiceAmount is the Decimal-quantized amount with two decimals
  (``66.71``, never ``66.7`` or ``66``). The same value goes into the JSON
  payload, so server-side ZOI verification matches.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from decimal import Decimal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .models import (
    Identifier,
    InvoiceNumberStr,
    TaxNumber,
    ZOIHex,
    _check_amount,
    _coerce_to_decimal,
    _to_ljubljana_datetime,
)

_AMOUNT_QUANT = Decimal("0.01")
_ZOI_DATE_FORMAT = "%d.%m.%Y %H:%M:%S"

_INVOICE_NUMBER_RE = re.compile(r"^[1-9][0-9]{0,19}$")
_IDENTIFIER_RE = re.compile(r"^[0-9a-zA-Z]{1,20}$")
_ZOI_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def calculate_zoi(
    *,
    private_key: RSAPrivateKey,
    tax_number: TaxNumber,
    issued_date: datetime,
    invoice_number: InvoiceNumberStr,
    business_premise_id: Identifier,
    electronic_device_id: Identifier,
    invoice_amount: Decimal,
) -> str:
    """Compute the 32-character hex ZOI for an invoice.

    All inputs are validated identically to the JSON payload, so callers
    cannot accidentally produce a ZOI that disagrees with what they later
    submit. ``issued_date`` must be timezone-aware.
    """
    # Run the same validation pydantic models would: tz-aware dt, in-range
    # tax/identifier/invoice_number, valid Decimal amount.
    if not isinstance(tax_number, int) or not (10000000 <= tax_number <= 99999999):
        raise ValueError("tax_number must be an 8-digit integer (10000000..99999999)")
    issued_dt_lju = _to_ljubljana_datetime(issued_date)
    amount = _check_amount(_coerce_to_decimal(invoice_amount))

    if not _INVOICE_NUMBER_RE.match(str(invoice_number)):
        raise ValueError("invoice_number must be digits only, no leading zero")
    if not _IDENTIFIER_RE.match(str(business_premise_id)):
        raise ValueError("business_premise_id must be alphanumeric, 1..20 chars")
    if not _IDENTIFIER_RE.match(str(electronic_device_id)):
        raise ValueError("electronic_device_id must be alphanumeric, 1..20 chars")

    content = "{tax}{issued}{invoice}{premise}{device}{amount}".format(
        tax=tax_number,
        issued=issued_dt_lju.strftime(_ZOI_DATE_FORMAT),
        invoice=invoice_number,
        premise=business_premise_id,
        device=electronic_device_id,
        amount=amount.quantize(_AMOUNT_QUANT),
    )

    signature = private_key.sign(
        data=content.encode("utf-8"),
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA256(),
    )
    return hashlib.md5(signature).hexdigest()


def prepare_printable(
    *,
    tax_number: TaxNumber,
    zoi: ZOIHex,
    issued_date: datetime,
) -> str:
    """Build the printable QR / Code-128 / PDF-417 payload.

    Format: 39-digit decimal ZOI || 8-digit tax number || yymmddHHMMSS ||
    Luhn check digit (``sum(digits) mod 10``) — total 60 digits.

    ``issued_date`` MUST be timezone-aware. It is converted to Europe/Ljubljana
    before formatting per spec.
    """
    if not _ZOI_RE.match(zoi):
        raise ValueError("zoi must be a 32-character hexadecimal string")
    if not isinstance(tax_number, int) or not (10000000 <= tax_number <= 99999999):
        raise ValueError("tax_number must be an 8-digit integer (10000000..99999999)")
    issued_dt_lju = _to_ljubljana_datetime(issued_date)

    zoi_base10 = str(int(zoi, 16)).zfill(39)
    date_str = issued_dt_lju.strftime("%y%m%d%H%M%S")
    data = zoi_base10 + str(tax_number) + date_str
    control = str(sum(map(int, data)) % 10)
    return data + control
