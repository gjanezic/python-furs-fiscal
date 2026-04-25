# python-furs-fiscal

Typed, modern Python client for the **Slovenian FURS** (Finančna uprava Republike Slovenije) v3.2 fiscal-verification web service. Targets the official [`TehnicnaDokumentacijaVer3.2.pdf`](https://www.datoteke.fu.gov.si/dpr/files/TehnicnaDokumentacijaVer3.2.pdf) and the JSON schemas published alongside it.

> **2.0 is a complete rewrite.** It has different installation, different API shape, different defaults, and different behaviour from 1.x. See **[Migrating from 1.x](#migrating-from-1x)** at the bottom if you are upgrading.

## Features

* **Pydantic-typed wire models** — payloads are constructed and validated by models that mirror `FiscalVerificationSchema*.json` exactly. Wrong field names, missing required fields, out-of-range values, or malformed identifiers are rejected before any HTTP traffic.
* **Decimal-only money** — `float` is rejected to eliminate silent IEEE-754 precision loss. Amounts that cannot round-trip through `float64` (i.e. close to the schema's ±100 trillion limit) are also rejected so the on-the-wire payload always matches the ZOI input.
* **Timezone-aware datetimes everywhere** — naive datetimes are rejected. All datetimes are auto-converted to `Europe/Ljubljana` before formatting per FURS spec.
* **Minimised on-disk key exposure** — PEMs are written to `mkstemp` (mode `0600`) only for the duration of `ssl.SSLContext.load_cert_chain`, then immediately unlinked. After that brief window the key material lives only in the SSLContext for the connector's lifetime. (Fully memory-only mTLS is not possible with stdlib `ssl`, which requires file paths.)
* **Secure-by-default** — `verify_tls=True` and `verify_furs_response='x5c-untrusted'` are the defaults. The strongest mode (`verify_furs_response=True` with a pinned public key) is one parameter away.
* **Granular exception hierarchy** — `FURSSchemaError` (S001/S002), `FURSSignatureError` (S003), `FURSCertificateError` (S004/S005/S007/S008 — unknown / tax-number mismatch / revoked / expired), `FURSBusinessPremiseError` (S006), `FURSSystemError` (S100, carries `is_retryable=True`), `FURSServerError` (catch-all for unmodelled codes), `FURSBatchError` (with per-record `record_errors` and `successes`), `FURSConnectionError`, `FURSValidationError`. Catch what you can act on.
* **Built-in retry on transient failures** — pass `retries=N` (and optional `retry_backoff=0.5`) to `FURSClient` to auto-retry only the failures that justify it: `httpx.RequestError`, HTTP 5xx / 408 / 429, and `FURSSystemError` (S100). Schema, signature, certificate, and 4xx errors are never retried — they're deterministic. Default is `retries=0`.
* **Replay-tested against the official FURS samples** — `tests/test_replay.py` decodes every signed example in `specs/examples/`, builds the same payload via the library, and asserts byte equivalence (modulo the per-message Header) plus JSON Schema validation.

## Installation

    pip install furs_fiscal

Requires Python 3.10+. Dependencies: `cryptography`, `PyJWT`, `httpx`, `pydantic`. (`jsonschema` and `hypothesis` are dev-only.)

## Quick Start

```python
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from furs_fiscal import (
    FURSClient,
    Invoice,
    InvoiceIdentifier,
    TaxesPerSeller,
    VATAmount,
)

with FURSClient(
    p12_data=Path("client.p12").read_bytes(),
    p12_password="cert-password",
    production=False,                  # use the FURS test endpoint
    verify_tls=True,                    # system CA store; pass a path for SIGOV-CA pinning
    verify_furs_response="x5c-untrusted",
) as client:

    issued = datetime.now(tz=timezone.utc)

    zoi = client.calculate_zoi(
        tax_number=10039856,
        issued_date=issued,
        invoice_number="11",
        business_premise_id="BP1",
        electronic_device_id="B1",
        invoice_amount=Decimal("19.15"),
    )

    invoice = Invoice(
        tax_number=10039856,
        issue_date_time=issued,
        numbering_structure="B",
        invoice_identifier=InvoiceIdentifier(
            business_premise_id="BP1",
            electronic_device_id="B1",
            invoice_number="11",
        ),
        invoice_amount=Decimal("19.15"),
        payment_amount=Decimal("19.15"),
        taxes_per_seller=[
            TaxesPerSeller(vat=[
                VATAmount(
                    tax_rate=Decimal("22"),
                    taxable_amount=Decimal("15.70"),
                    tax_amount=Decimal("3.45"),
                ),
            ]),
        ],
        protected_id=zoi,
    )

    eor = client.submit_invoice(invoice)

    qr_data = client.prepare_printable(
        tax_number=10039856, zoi=zoi, issued_date=issued
    )
```

## Registering Business Premises

### Immovable premise (with property ID + address)

```python
from datetime import date
from furs_fiscal import (
    Address, BPIdentifier, BusinessPremise, PropertyID, RealEstateBP,
    SoftwareSupplier,
)

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
                house_number_additional="B",
                community="Ljubljana",
                city="Ljubljana",
                postal_code="1000",
            ),
        )
    ),
    validity_date=date.today(),
    software_supplier=[SoftwareSupplier(tax_number=24564444)],
    special_notes="Glavna trgovina",
)
client.submit_business_premise(bp)
```

### Movable premise (type A/B/C)

```python
bp = BusinessPremise(
    tax_number=10039856,
    business_premise_id="MOB1",
    bp_identifier=BPIdentifier(premise_type="A"),
    validity_date=date.today(),
    software_supplier=[SoftwareSupplier(tax_number=24564444)],
)
client.submit_business_premise(bp)
```

### Vending machine (type D/E/F, address OR geolocation)

```python
from furs_fiscal import Geolocation, VendingMachine

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
    validity_date=date.today(),
    software_supplier=[SoftwareSupplier(tax_number=24564444)],
)
client.submit_business_premise(bp)
```

## Sales-Book Invoices (vezana knjiga)

```python
from furs_fiscal import SalesBookIdentifier, SalesBookInvoice

sbi = SalesBookInvoice(
    tax_number=10039856,
    issue_date=date.today(),
    sales_book_identifier=SalesBookIdentifier(
        invoice_number="612", set_number="03", serial_number="5001-0001018",
    ),
    business_premise_id="BP1",
    invoice_amount=Decimal("19.15"),
    payment_amount=Decimal("19.15"),
    taxes_per_seller=[TaxesPerSeller(nontaxable_amount=Decimal("0.00"))],
)
eor = client.submit_sales_book_invoice(sbi)
```

`SalesBookInvoice` does **not** support `OperatorTaxNumber` (the official schema does not allow it for sales-book payloads).

## Batch Submission

```python
from furs_fiscal import FURSBatchError

try:
    successes = client.submit_invoice_batch([invoice_1, invoice_2, ...])
    # successes: dict[int, {"ProtectedID": str, "UniqueInvoiceID": str}]
except FURSBatchError as exc:
    for record_no, err in exc.record_errors.items():
        log.error("record %d failed: %s", record_no, err)
    for record_no, ok in exc.successes.items():
        mark_done(record_no, ok["UniqueInvoiceID"])  # don't resubmit these
```

A batch must contain 2..500 records. The transport layer raises a `FURSBatchError` whenever any record reply contains an `Error` block; successful records remain accessible on the exception so callers can persist the EORs without resubmitting.

`submit_business_premise_batch(premises)` returns the response `Header` (`{MessageID, DateTime}`) — premise batches have no per-record reply in the schema, they either succeed wholesale or raise `FURSResponseError`.

## Subsequent Submit (Offline-Then-Catch-Up)

When a register prints a receipt without a live FURS connection, the EOR can't appear on the printed receipt — but the ZOI (calculated locally) can, and is what FURS later cross-verifies. Submit the same payload retroactively with `SubsequentSubmit=true`:

```python
# Same Invoice you built when the receipt was printed — same ZOI in
# protected_id, same issue_date_time, same invoice_number. The helper
# only flips SubsequentSubmit; do not change anything else.
eor = client.submit_invoice_subsequent(invoice)
```

The flag corresponds to spec R_3.13. The helper does not mutate the input — it `model_copy`s with `subsequent_submit=True` and submits.

## Closing a Business Premise

`ClosingTag='Z'` (P_7.0) permanently retires a `BusinessPremiseID`. After FURS accepts the closure, further invoices against that ID will return `FURSBusinessPremiseError` (S006).

```python
# Build the same BusinessPremise you registered originally — FURS
# requires the full record, not just the ID.
client.close_business_premise(bp)
```

## Echo (Connectivity Check)

A plain JSON ping that exercises mTLS but not JWS. Useful as a fast health check.

```python
assert client.echo("furs") == "furs"
```

`echo()` deliberately bypasses the retry loop — its purpose IS to surface a failed connection, not paper over one.

## Retries on Transient Failures

```python
client = FURSClient(
    p12_data=...,
    p12_password=...,
    production=False,
    retries=3,            # 1 initial + up to 3 retries
    retry_backoff=0.5,    # exponential: 0.5s, 1.0s, 2.0s
)
```

Retried: `httpx.RequestError` (DNS/TCP/TLS/timeout), HTTP 5xx, HTTP 408, HTTP 429, and `FURSSystemError` (S100). Not retried: schema (S001/S002), signature (S003), certificate (S004/S005/S007/S008), business-premise (S006), `FURSBatchError`, and generic 4xx — those are deterministic and a fresh attempt would just repeat the same failure.

## Security: TLS and FURS Response Verification

### `verify_tls`

| Value          | Behaviour                                                                                  |
|----------------|--------------------------------------------------------------------------------------------|
| `True`         | (default) System CA store.                                                                  |
| `str` (path)   | Pin against a CA bundle file. Recommended for production with the SIGOV-CA chain.           |
| `False`        | Disable verification. Emits `FURSTLSVerificationDisabledWarning`. Use only for offline tests. |

### `verify_furs_response`

| Value              | Behaviour                                                                                                                                                                                                       |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `'x5c-untrusted'`  | (default) Verifies the response signature with the certificate embedded in the JWS `x5c` header. Validity window is checked; chain is **not**. Emits `FURSResponseChainNotVerifiedWarning`. Only signature self-consistency. |
| `True`             | Verifies against `furs_response_public_key` (required). The constructor raises `ValueError` if no key is supplied. The only MITM-resistant mode.                                                                |
| `False`            | Skips signature verification entirely. Discouraged.                                                                                                                                                              |

For real MITM protection in production, combine `verify_tls=<sigov-ca-path>` with `verify_furs_response=True` plus the published FURS response signing public key.

## Exception Hierarchy

```
FURSError
├── FURSValidationError            — local validation failed (also a ValueError)
├── FURSConnectionError            — transport / decode failure
├── FURSResponseError              — FURS returned an Error envelope
│   ├── FURSSchemaError            — S001 / S002
│   ├── FURSSignatureError         — S003
│   ├── FURSCertificateError       — S004 / S005 / S007 / S008
│   │                                (unknown / tax-number mismatch /
│   │                                 revoked / expired digital cert)
│   ├── FURSBusinessPremiseError   — S006 (premise not registered)
│   ├── FURSSystemError            — S100 (transient, is_retryable=True)
│   └── FURSServerError            — every other code
└── FURSBatchError                 — one or more records in a batch failed
                                     (record_errors: dict[int, FURSResponseError],
                                      successes:     dict[int, {ProtectedID, UniqueInvoiceID}])
```

`FURSResponseError.is_retryable` is `False` by default and `True` on
`FURSSystemError`. Retry middleware can branch on that attribute without
having to maintain its own list of error codes.

> **Behaviour change in 2.1**: in 2.0, only S004 raised
> `FURSCertificateError` and S005/S007/S008 fell through to
> `FURSServerError`. They now all raise `FURSCertificateError`, and S006
> raises the new `FURSBusinessPremiseError` (also previously
> `FURSServerError`), and S100 raises the new `FURSSystemError`. Code
> that catches `FURSServerError` to handle these specifically must move
> to the new classes; code that catches the broader `FURSResponseError`
> is unaffected.

## ZOI and Printable QR/Code-128 Data

```python
zoi = client.calculate_zoi(
    tax_number=10039856,
    issued_date=datetime.now(tz=timezone.utc),
    invoice_number="11",
    business_premise_id="BP1",
    electronic_device_id="B1",
    invoice_amount=Decimal("19.15"),
)
printable = client.prepare_printable(
    tax_number=10039856, zoi=zoi, issued_date=datetime.now(tz=timezone.utc)
)
```

Both inputs MUST be timezone-aware. `prepare_printable` converts to `Europe/Ljubljana` per spec; `calculate_zoi` uses the same conversion so the ZOI matches the value FURS later receives in the JSON payload.

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite (156 tests; 154 offline + 2 live, the live ones gated behind `FURS_LIVE_TEST=1`) covers:

* **Models** — pydantic validation, IEEE-754 round-trip safety, datetime conversion, mutual-exclusion rules, batch envelope construction. Property-based tests via `hypothesis`.
* **ZOI** — determinism, validation, Europe/Ljubljana wall-time semantics.
* **Transport** — in-memory mTLS, TLS 1.2 floor + AEAD-RSA cipher pinning (spec sec. 2 / 6.2), x5c response verification (good cert / expired cert / wrong key / missing header), pinned-key mode, error-code → exception routing for S001..S008/S100 (case-insensitive), echo round-trip, retry policy (S100 + 5xx + 408/429 + `httpx.RequestError`; deterministic errors and 4xx are NOT retried).
* **API** — full submit flows over `httpx.MockTransport`, batch handling with per-record errors, `submit_invoice_subsequent` / `close_business_premise` helpers, business-premise batch envelope validation.
* **Replay** — every official signed example in `specs/examples/` is decoded, rebuilt by the library, and compared structurally + validated against `specs/schemas/FiscalVerificationSchema*.json`.
* **Real-cert surveillance** — yellow-warns ahead of FURS-published cert rotations and ahead of the documented production-cipher-list rotation (2026-05-12); fails red after the date so CI nags the maintainer to refresh.
* **Live FURS test endpoint** (opt-in: `FURS_LIVE_TEST=1`) — round-trips an `EchoRequest` and a business-premise registration through `blagajne-test.fu.gov.si:9002` in the strongest mode the library supports.

## Migrating from 1.x

| 1.x                                              | 2.0                                                                                            |
|--------------------------------------------------|------------------------------------------------------------------------------------------------|
| `FURSInvoiceAPI(p12_path=..., p12_password=...)` | `FURSClient(p12_data=Path(...).read_bytes(), p12_password=...)`                                |
| `FURSBusinessPremiseAPI`                         | Same `FURSClient` — call `submit_business_premise(bp)`                                          |
| `api.get_invoice_eor(...)` (positional kwargs)   | Build `Invoice(...)` from typed fields, then `client.submit_invoice(invoice)`                   |
| `api.get_sales_book_invoice_eor(...)`            | Build `SalesBookInvoice(...)`, then `client.submit_sales_book_invoice(sbi)`                     |
| `register_immovable_business_premise(...)` etc.  | Build `BusinessPremise(... bp_identifier=BPIdentifier(real_estate_bp=...))`                     |
| `TaxesPerSeller.add_vat_amount(...)`             | `TaxesPerSeller(vat=[VATAmount(...)])` — pure pydantic construction                              |
| `verify_tls=False` default                       | `verify_tls=True` default; pass `False` only with a warning                                     |
| `verify_furs_response=False` default             | `verify_furs_response='x5c-untrusted'` default                                                  |
| `requests` + persistent on-disk client cert tempfiles | `httpx` + `ssl.SSLContext` loaded via `mkstemp` (0600) and unlinked immediately after `load_cert_chain` |
| `from furs_fiscal.exceptions import FURSException` | `from furs_fiscal import FURSResponseError, FURSSchemaError, ...` (granular subclasses)         |
| `pyOpenSSL`, `pytz` dependencies                 | Dropped — `cryptography`-only, stdlib `zoneinfo`                                                |
| Python 2/3 support                               | Python 3.10+                                                                                    |
| Float / int amounts accepted                     | `Decimal`, `int`, or `str` only. Float raises `FURSValidationError`/`ValidationError`.          |
| Naive datetimes accepted                         | All datetimes must be timezone-aware. Auto-converted to `Europe/Ljubljana`.                     |
| Per-record batch errors silently ignored         | `FURSBatchError` raised; `record_errors` and `successes` dicts on the exception                 |

## License

MIT — see [LICENSE](LICENSE).
