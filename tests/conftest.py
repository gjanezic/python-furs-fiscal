"""Shared fixtures: in-memory test PKCS#12 client cert, dummy connector."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
)
from cryptography.x509.oid import NameOID

P12_PASSWORD = "test-password"


def _build_p12_with_key() -> tuple[bytes, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SI"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "test-institutions"),
            x509.NameAttribute(NameOID.COMMON_NAME, "TEST CERTIFICATE"),
        ]
    )
    now = datetime.now(tz=timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    p12 = serialize_key_and_certificates(
        name=b"test-certificate",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            P12_PASSWORD.encode("utf-8")
        ),
    )
    return p12, key


@pytest.fixture(scope="session")
def p12_data_and_key() -> tuple[bytes, rsa.RSAPrivateKey]:
    return _build_p12_with_key()


@pytest.fixture
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
