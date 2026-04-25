"""HTTP transport for FURS using httpx + minimised on-disk key exposure.

Differences from the 1.x ``Connector``:

* **Minimised on-disk key exposure.** The PKCS#12 private key is touched on
  disk only briefly: PEMs are written to ``mkstemp`` (mode ``0600``) for the
  duration of ``ssl.SSLContext.load_cert_chain`` — which requires file paths
  — then immediately unlinked. After load, the key material lives only in
  the SSLContext for the connector's lifetime. The 1.x pattern of
  ``NamedTemporaryFile(delete=False)`` leaving PEMs on disk for the entire
  connector lifetime is gone.
* **Secure-by-default TLS.** ``verify_tls`` defaults to ``True`` (system CA
  store). Passing ``False`` is supported only with an explicit warning so
  the legacy escape hatch stays available for offline tests.
* **Secure-by-default response verification.** ``verify_furs_response``
  defaults to ``'x5c-untrusted'`` — the response signature is checked using
  the cert embedded in the ``x5c`` JWS header. That is signature
  self-consistency only; pair with ``verify_tls`` against the SIGOV-CA bundle
  for real MITM protection. Set to ``True`` with a pinned
  ``furs_response_public_key`` for the strongest mode.
"""

from __future__ import annotations

import base64
import os
import ssl
import tempfile
import warnings
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

from .exceptions import (
    FURSConnectionError,
    from_furs_error,
)

FURS_TEST_ENDPOINT = "https://blagajne-test.fu.gov.si:9002"
FURS_PRODUCTION_ENDPOINT = "https://blagajne.fu.gov.si:9003"

# Recognised values for verify_furs_response.
VerifyMode = Literal[True, False, "x5c-untrusted"]


class FURSTLSVerificationDisabledWarning(UserWarning):
    """Emitted when the connector is constructed with TLS verification disabled."""


class FURSResponseChainNotVerifiedWarning(UserWarning):
    """Emitted when a response is verified via the x5c header without a trust anchor."""


def _load_ssl_context_with_client_cert(
    *,
    p12_data: bytes,
    p12_password: str,
    verify_tls: bool | str,
) -> tuple[ssl.SSLContext, RSAPrivateKey, x509.Certificate]:
    """Return ``(ssl_ctx, private_key, certificate)`` with mTLS configured.

    The client-cert PEMs are written to ``mkstemp`` files (mode ``0600``)
    **only** for the duration of :meth:`ssl.SSLContext.load_cert_chain` —
    which requires file paths — then unlinked. The key material lives only
    in the SSLContext after that. There is a brief on-disk window during
    load; fully memory-only mTLS is not possible with stdlib ``ssl``.
    """
    p12 = load_pkcs12(p12_data, password=p12_password.encode("utf-8"))
    cert = p12.cert.certificate
    key = p12.key

    if verify_tls is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        warnings.warn(
            "FURS connector created with TLS verification disabled. The FURS "
            "spec requires verifying the server certificate against the "
            "SIGOV-CA chain. Pass verify_tls=True or a CA bundle path.",
            FURSTLSVerificationDisabledWarning,
            stacklevel=3,
        )
    elif isinstance(verify_tls, str):
        ctx = ssl.create_default_context(cafile=verify_tls)
    else:
        ctx = ssl.create_default_context()

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
    key_fd, key_path = tempfile.mkstemp(suffix=".pem")
    try:
        os.write(cert_fd, cert_pem)
        os.write(key_fd, key_pem)
        os.close(cert_fd)
        cert_fd = -1
        os.close(key_fd)
        key_fd = -1
        ctx.load_cert_chain(cert_path, key_path)
    finally:
        for fd in (cert_fd, key_fd):
            if fd >= 0:
                os.close(fd)
        for path in (cert_path, key_path):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    return ctx, key, cert


class Connector:
    """Low-level HTTP client. Application code should use :class:`FURSClient`."""

    def __init__(
        self,
        *,
        p12_data: bytes,
        p12_password: str,
        production: bool,
        request_timeout: float = 10.0,
        verify_tls: bool | str = True,
        verify_furs_response: VerifyMode = "x5c-untrusted",
        furs_response_public_key: bytes | str | None = None,
        proxy: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if verify_furs_response is True and furs_response_public_key is None:
            raise ValueError(
                "verify_furs_response=True requires furs_response_public_key. "
                "Use verify_furs_response='x5c-untrusted' for the looser default mode."
            )
        if verify_furs_response not in (True, False, "x5c-untrusted"):
            raise ValueError(
                "verify_furs_response must be True, False, or 'x5c-untrusted'"
            )

        self._endpoint = (
            FURS_PRODUCTION_ENDPOINT if production else FURS_TEST_ENDPOINT
        )
        self._verify_furs_response = verify_furs_response
        self._furs_response_public_key = furs_response_public_key

        ssl_ctx, key, cert = _load_ssl_context_with_client_cert(
            p12_data=p12_data, p12_password=p12_password, verify_tls=verify_tls
        )
        self.private_key: RSAPrivateKey = key
        self.certificate: x509.Certificate = cert
        if transport is not None:
            # Test injection: when a transport is supplied, the SSLContext is
            # not consulted by httpx, but we still load the p12 above so
            # private_key / certificate are available for JWS signing.
            self._client = httpx.Client(
                base_url=self._endpoint,
                transport=transport,
                timeout=request_timeout,
                headers={"Content-Type": "application/json; charset=UTF-8"},
            )
        else:
            self._client = httpx.Client(
                base_url=self._endpoint,
                verify=ssl_ctx,
                timeout=request_timeout,
                proxy=proxy,
                headers={"Content-Type": "application/json; charset=UTF-8"},
            )

    # -- Lifecycle ------------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Connector:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    # -- JWS sign / send / verify --------------------------------------------

    def _jws_header(self) -> dict[str, Any]:
        cert = self.certificate
        return {
            "alg": "RS256",
            "subject_name": cert.subject.rfc4514_string(),
            "issuer_name": cert.issuer.rfc4514_string(),
            "serial": cert.serial_number,
        }

    def post(self, *, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Sign ``payload`` as a JWS, POST to ``path``, return the decoded reply.

        Raises :class:`FURSConnectionError` on transport / decode failure and
        :class:`FURSResponseError` on a FURS error envelope.
        """
        token = jwt.encode(
            payload,
            key=self.private_key,
            headers=self._jws_header(),
            algorithm="RS256",
        )
        try:
            response = self._client.post(path, json={"token": token})
        except httpx.RequestError as exc:
            raise FURSConnectionError(str(exc), code="REQUEST_FAILED") from exc

        if response.status_code != 200:
            raise FURSConnectionError(
                f"HTTP {response.status_code}: {response.text[:500]}",
                code=str(response.status_code),
            )

        try:
            body = response.json()
            response_token = body["token"]
        except (ValueError, KeyError) as exc:
            raise FURSConnectionError(
                "FURS response did not contain a valid JSON envelope with a token",
                code="INVALID_RESPONSE",
            ) from exc

        decoded = self._decode_response_token(response_token)
        self._raise_if_error_envelope(decoded)
        return decoded

    # -- Response signature verification --------------------------------------

    def _decode_response_token(self, token: str) -> dict[str, Any]:
        if self._verify_furs_response is False:
            return jwt.decode(token, options={"verify_signature": False})

        if self._verify_furs_response is True:
            try:
                return jwt.decode(
                    token,
                    key=self._furs_response_public_key,
                    algorithms=["RS256"],
                )
            except jwt.PyJWTError as exc:
                raise FURSConnectionError(
                    f"FURS response JWS verification failed: {exc}",
                    code="INVALID_SIGNATURE",
                ) from exc

        # 'x5c-untrusted'
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise FURSConnectionError(
                f"FURS response JWT could not be parsed: {exc}",
                code="INVALID_RESPONSE",
            ) from exc

        x5c = header.get("x5c")
        if not x5c:
            raise FURSConnectionError(
                "FURS response JWT lacks an 'x5c' header; cannot verify in "
                "x5c-untrusted mode",
                code="MISSING_RESPONSE_PUBLIC_KEY",
            )
        try:
            cert_der = base64.b64decode(x5c[0])
            cert = x509.load_der_x509_certificate(cert_der)
        except (ValueError, IndexError, TypeError) as exc:
            raise FURSConnectionError(
                "FURS response x5c header could not be decoded",
                code="INVALID_RESPONSE",
            ) from exc

        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(
            tzinfo=timezone.utc
        )
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
            tzinfo=timezone.utc
        )
        now = datetime.now(tz=timezone.utc)
        if now < not_before or now > not_after:
            raise FURSConnectionError(
                "FURS response x5c certificate is outside its validity window",
                code="INVALID_RESPONSE",
            )

        warnings.warn(
            "FURS response verified via x5c header only — the certificate chain "
            "was NOT validated against SIGOV-CA. Pair with verify_tls against the "
            "SIGOV-CA bundle, or pass verify_furs_response=True with a pinned key, "
            "for real MITM protection.",
            FURSResponseChainNotVerifiedWarning,
            stacklevel=4,
        )
        try:
            return jwt.decode(token, key=cert.public_key(), algorithms=["RS256"])
        except jwt.PyJWTError as exc:
            raise FURSConnectionError(
                f"FURS response JWS signature did not match x5c key: {exc}",
                code="INVALID_SIGNATURE",
            ) from exc

    @staticmethod
    def _raise_if_error_envelope(decoded: dict[str, Any]) -> None:
        if not decoded:
            raise FURSConnectionError(
                "FURS response envelope is empty",
                code="INVALID_RESPONSE",
            )
        envelope = decoded[next(iter(decoded))]
        error = envelope.get("Error") if isinstance(envelope, dict) else None
        if error:
            raise from_furs_error(error["ErrorCode"], error["ErrorMessage"])
