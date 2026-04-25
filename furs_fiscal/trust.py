"""Helpers for loading FURS-published trust material.

FURS hands out the response-signing certificate (``DavPotRac*.cer``) and
the SI-TRUST chain (``sigov-ca2.xcert.crt``, ``si-trust-root.crt``) in a
mix of PEM and DER encodings depending on the file. The functions here
hide that quirk so the demo, the tests, and downstream callers all do the
same thing in one line.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization

PathLike = Union[str, Path]


def load_furs_certificate(path: PathLike) -> x509.Certificate:
    """Load a FURS- or SI-TRUST-published X.509 certificate.

    Accepts both PEM (``*.cer`` files in the FURS distribution) and DER
    (``*.crt`` files from si-trust.gov.si). Tries PEM first, falls back
    to DER, so callers don't need to track the encoding.
    """
    raw = Path(path).read_bytes()
    try:
        return x509.load_pem_x509_certificate(raw)
    except ValueError:
        return x509.load_der_x509_certificate(raw)


def load_response_public_key(path: PathLike) -> bytes:
    """Return the SubjectPublicKeyInfo PEM from a FURS response-signing cert.

    The library's ``furs_response_public_key=`` parameter wants the
    public key by itself (PEM-encoded SPKI), not the wrapping cert.
    Pass this helper's return value straight into
    :class:`furs_fiscal.FURSClient` together with
    ``verify_furs_response=True``::

        client = FURSClient(
            ...,
            verify_furs_response=True,
            furs_response_public_key=load_response_public_key(
                "specs/prod_certs/DavPotRac_2025.cer"
            ),
        )
    """
    cert = load_furs_certificate(path)
    return cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


__all__ = [
    "load_furs_certificate",
    "load_response_public_key",
]
