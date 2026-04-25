"""python-furs-fiscal — typed Python client for the Slovenian FURS v3.2 fiscal API."""

from __future__ import annotations

from .api import FURSClient
from .exceptions import (
    FURSBatchError,
    FURSCertificateError,
    FURSConnectionError,
    FURSError,
    FURSResponseError,
    FURSSchemaError,
    FURSServerError,
    FURSSignatureError,
    FURSValidationError,
)
from .models import (
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
    ReferenceInvoice,
    ReferenceSalesBook,
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
from .transport import (
    FURS_PRODUCTION_ENDPOINT,
    FURS_TEST_ENDPOINT,
    FURSResponseChainNotVerifiedWarning,
    FURSTLSVerificationDisabledWarning,
)
from .trust import load_furs_certificate, load_response_public_key
from .zoi import calculate_zoi, prepare_printable

__version__ = "2.0.0"

__all__ = [
    "__version__",
    # Client
    "FURSClient",
    # Endpoints / warnings
    "FURS_PRODUCTION_ENDPOINT",
    "FURS_TEST_ENDPOINT",
    "FURSResponseChainNotVerifiedWarning",
    "FURSTLSVerificationDisabledWarning",
    # Models
    "Address",
    "BPIdentifier",
    "BusinessPremise",
    "FlatRateCompensation",
    "Geolocation",
    "Header",
    "Invoice",
    "InvoiceIdentifier",
    "PropertyID",
    "RealEstateBP",
    "ReferenceInvoice",
    "ReferenceSalesBook",
    "SalesBookIdentifier",
    "SalesBookInvoice",
    "SoftwareSupplier",
    "TaxesPerSeller",
    "VATAmount",
    "VendingMachine",
    "wrap_business_premise",
    "wrap_business_premise_batch",
    "wrap_invoice",
    "wrap_invoice_batch",
    "wrap_sales_book_invoice",
    # ZOI
    "calculate_zoi",
    "prepare_printable",
    # Trust material helpers
    "load_furs_certificate",
    "load_response_public_key",
    # Exceptions
    "FURSError",
    "FURSValidationError",
    "FURSConnectionError",
    "FURSResponseError",
    "FURSSchemaError",
    "FURSSignatureError",
    "FURSCertificateError",
    "FURSServerError",
    "FURSBatchError",
]
