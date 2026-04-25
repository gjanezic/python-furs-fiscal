"""FURS exception hierarchy.

The hierarchy lets callers catch broad failure classes (network, validation,
server error) or specific FURS error codes (S001..S008, S100 per spec sec. 4)
without parsing strings.

    FURSError
    ├── FURSValidationError            — local validation failed before sending
    ├── FURSConnectionError            — transport / decode failure
    ├── FURSResponseError              — FURS returned an Error envelope
    │   ├── FURSSchemaError            — S001 / S002 schema mismatch
    │   ├── FURSSignatureError         — S003 invalid digital signature
    │   ├── FURSCertificateError       — S004 unknown / S005 tax-number
    │   │                                 mismatch / S007 revoked /
    │   │                                 S008 expired digital certificate
    │   ├── FURSBusinessPremiseError   — S006 business premise not registered
    │   ├── FURSSystemError            — S100 server-side processing error
    │   │                                 (typically transient, retryable)
    │   └── FURSServerError            — anything else FURS sends
    └── FURSBatchError                 — one or more records in a batch failed
"""

from __future__ import annotations


class FURSError(Exception):
    """Base class for every error raised by the library."""


class FURSValidationError(FURSError, ValueError):
    """Local validation rejected an input before any HTTP traffic happened.

    Subclasses :class:`ValueError` so existing callers that catch
    ``ValueError`` keep working when the validation moved into pydantic.
    """


class FURSConnectionError(FURSError):
    """Transport-layer failure: DNS, TCP, TLS, timeout, malformed JWT, etc.

    Pass the original exception as ``__cause__`` (``raise ... from exc``)
    when re-raising from the transport layer.

    ``code`` uses a transport-side namespace distinct from FURS-side codes on
    :class:`FURSResponseError`:

    * Transport codes are ALL_CAPS string literals or stringified HTTP status
      codes: ``"REQUEST_FAILED"``, ``"INVALID_RESPONSE"``,
      ``"INVALID_SIGNATURE"``, ``"MISSING_RESPONSE_PUBLIC_KEY"``,
      ``"503"``, ...
    * FURS-side codes (on :class:`FURSResponseError`) follow the spec form
      ``"S001"`` / ``"S002"`` / ``"S003"`` / ``"S004"`` / ...

    Catch on the exception class — only inspect ``code`` for logging or
    fine-grained branching within a handler.
    """

    def __init__(self, message: str, *, code: str | None = None) -> None:
        self.code = code
        super().__init__(message)


class FURSResponseError(FURSError):
    """FURS returned a structured ``Error`` element in the response envelope.

    See spec sec. 4 for the official error code table.

    The ``is_retryable`` class attribute lets consumers branch on
    retryability without an ``isinstance`` ladder. It defaults to
    ``False`` because most FURS error codes (schema mismatch, bad
    signature, unknown cert, …) are deterministic — retrying without
    fixing the underlying cause is wasted traffic. Subclasses that
    represent transient server-side conditions override this to ``True``
    (see :class:`FURSSystemError`).
    """

    is_retryable: bool = False

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


class FURSSchemaError(FURSResponseError):
    """S001 / S002 — message did not validate against the FURS XML/JSON schema."""


class FURSSignatureError(FURSResponseError):
    """S003 — JWS / XMLDSig signature on the request was invalid."""


class FURSCertificateError(FURSResponseError):
    """Certificate-binding failures.

    Covers S004 (unknown certificate), S005 (tax number in the message does
    not match the tax number on the digital certificate), S007 (digital
    certificate revoked), and S008 (digital certificate expired).
    """


class FURSBusinessPremiseError(FURSResponseError):
    """S006 — data about the business premise have not been submitted.

    The premise referenced by the invoice is not registered with FURS, or
    has been marked closed (ClosingTag=Z). The caller usually wants to
    register / re-register the premise and retry the invoice.
    """


class FURSSystemError(FURSResponseError):
    """S100 — system error at processing of the message (typically transient).

    Distinct from :class:`FURSServerError` because S100 is documented as a
    server-side processing failure that callers may safely retry, whereas
    other unmapped codes may indicate persistent issues. Carries
    ``is_retryable = True`` so retry middleware can branch without
    pattern-matching on the code.
    """

    is_retryable: bool = True


class FURSServerError(FURSResponseError):
    """Catch-all for FURS error codes the library does not model explicitly."""


_ERROR_CODE_MAP: dict[str, type[FURSResponseError]] = {
    "S001": FURSSchemaError,
    "S002": FURSSchemaError,
    "S003": FURSSignatureError,
    "S004": FURSCertificateError,
    "S005": FURSCertificateError,
    "S006": FURSBusinessPremiseError,
    "S007": FURSCertificateError,
    "S008": FURSCertificateError,
    "S100": FURSSystemError,
}


def from_furs_error(code: str, message: str) -> FURSResponseError:
    """Build the most specific :class:`FURSResponseError` subclass for ``code``.

    Codes are case-insensitive; the spec uses upper-case but production has
    occasionally returned lower-case (``s002``).
    """
    cls = _ERROR_CODE_MAP.get(code.upper(), FURSServerError)
    return cls(code, message)


class FURSBatchError(FURSError):
    """One or more records in a batch submission failed.

    ``record_errors`` maps the per-record ``RecordNumber`` to its
    :class:`FURSResponseError`. The successful records are still available
    in ``successes`` (mapping ``RecordNumber`` to the per-record reply
    dictionary, which contains ``ProtectedID`` and ``UniqueInvoiceID``).
    """

    def __init__(
        self,
        record_errors: dict[int, FURSResponseError],
        successes: dict[int, dict] | None = None,
    ) -> None:
        self.record_errors = record_errors
        self.successes = successes or {}
        failed = ", ".join(str(n) for n in sorted(record_errors))
        super().__init__(f"{len(record_errors)} record(s) failed: {failed}")
