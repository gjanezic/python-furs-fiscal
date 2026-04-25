import base64
import datetime
import warnings

import jwt

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from requests.exceptions import RequestException, Timeout
from requests import codes

from furs_fiscal.connector import Connector
from furs_fiscal.exceptions import ConnectionException, ConnectionTimedOutException, FURSException


VERIFY_FURS_RESPONSE_X5C_UNTRUSTED = 'x5c-untrusted'


class FURSResponseChainNotVerifiedWarning(UserWarning):
    """Emitted when FURS response signature is verified using a certificate
    extracted from the response itself (``x5c`` JWS header) without an
    independent trust anchor. The certificate chain is NOT verified against
    SIGOV-CA, so an attacker who can MITM the connection could forge responses
    by substituting both the JWT and the embedded ``x5c`` certificate. This
    mode is therefore essentially "signature self-consistency" and offers no
    real MITM protection on its own — pair it with TLS verification against
    the SIGOV-CA chain, or supply ``furs_response_public_key`` for a pinned
    trust anchor.
    """


class FURSBaseAPI(object):
    def __init__(self,
                 p12_path,
                 p12_password,
                 p12_buffer=None,
                 production=True,
                 request_timeout=2.0,
                 proxy=None,
                 verify_tls=False,
                 furs_response_public_key=None,
                 verify_furs_response=False):
        """
        ``verify_furs_response`` accepted values:

        - ``False`` (default): do not verify the response signature.
        - ``True``: verify against ``furs_response_public_key`` (required).
          Raises ``ValueError`` if no key is provided. This is the only
          MITM-resistant verification mode.
        - ``'x5c-untrusted'``: verify the response signature using the
          certificate embedded in the JWS ``x5c`` header. Cert dates are
          checked but the certificate chain is NOT validated against any
          trust anchor, so this provides only signature self-consistency
          and offers no real MITM protection on its own. Pair with proper
          TLS verification (``verify_tls`` set to a SIGOV-CA bundle) before
          relying on this in production.
        """
        if verify_furs_response is True and furs_response_public_key is None:
            raise ValueError(
                "verify_furs_response=True requires furs_response_public_key. "
                "Pass verify_furs_response='x5c-untrusted' to opt into the "
                "weaker x5c-header verification mode (see FURSResponseChainNotVerifiedWarning)."
            )
        if (verify_furs_response not in (False, True, VERIFY_FURS_RESPONSE_X5C_UNTRUSTED)):
            raise ValueError(
                "verify_furs_response must be False, True, or 'x5c-untrusted'"
            )

        self.connector = Connector(p12_path=p12_path,
                                   p12_password=p12_password,
                                   p12_buffer=p12_buffer,
                                   production=production,
                                   request_timeout=request_timeout,
                                   proxy=proxy,
                                   verify_tls=verify_tls)
        self.furs_response_public_key = furs_response_public_key
        self.verify_furs_response = verify_furs_response

    def close(self):
        self.connector.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def is_server_accessible(self):
        """
        Check if FURS server is accessible. Will return False if server responds with anything else
        than HTTP Code: 200 or if the request timeouts.

        :return: (boolean) True for ok, False if there was a problem accessing server.
        """
        try:
            return self.connector.send_echo().status_code == codes.ok
        except Timeout as e:
            return False
        except RequestException:
            return False

    def _send_request(self, path, data):
        """
        Sends request to the FURS Server and decodes response.

        :param path: (string) Server path
        :param data: (dict) Data to be sent
        :return: (dict) Received response

        :raises:
            ConnectionTimedOutException: If connection timed out
            ConnectionException: If FURS responded with status code different than 200
            FURSException: If server responded with error
        """
        try:
            response = self.connector.post(path=path, json=data)

            if response.status_code == codes.ok:
                try:
                    token = response.json()['token']
                    server_response = self._decode_furs_token(token)
                except (ValueError, KeyError, jwt.PyJWTError) as e:
                    raise ConnectionException(code='INVALID_RESPONSE',
                                              message='FURS response did not contain a valid token') from e
                return self._check_for_errors(server_response)
            else:
                raise ConnectionException(code=response.status_code,
                                          message=response.text)

        except Timeout as e:
            raise ConnectionTimedOutException(e)
        except RequestException as e:
            raise ConnectionException(code='REQUEST_FAILED', message=str(e)) from e

    def _decode_furs_token(self, token):
        """
        Decode and (optionally) verify the JWT returned by FURS.

        Behaviour by ``verify_furs_response`` value:

        - ``False``: signature is NOT verified.
        - ``True``: verify against ``furs_response_public_key`` (RS256). The
          constructor enforces that a key was supplied.
        - ``'x5c-untrusted'``: extract the signing certificate from the JWS
          ``x5c`` header per FURS spec sec. 8.1, check its validity dates,
          then verify the signature with its public key. A
          ``FURSResponseChainNotVerifiedWarning`` is emitted because no trust
          anchor is checked.
        """
        if self.verify_furs_response is False:
            return jwt.decode(token, options={"verify_signature": False})

        if self.verify_furs_response is True:
            return jwt.decode(token, key=self.furs_response_public_key, algorithms=['RS256'])

        # 'x5c-untrusted' mode.
        header = jwt.get_unverified_header(token)
        x5c = header.get('x5c')
        if not x5c:
            raise ConnectionException(
                code='MISSING_RESPONSE_PUBLIC_KEY',
                message='FURS response x5c-untrusted verification requires an x5c header '
                        'on the response token',
            )
        try:
            cert_der = base64.b64decode(x5c[0])
            cert = x509.load_der_x509_certificate(cert_der)
        except (ValueError, IndexError, TypeError) as exc:
            raise ConnectionException(
                code='INVALID_RESPONSE',
                message='FURS response x5c header could not be decoded',
            ) from exc

        # Validity-window check. cryptography deprecated the naive properties
        # in favour of the *_utc variants; fall back for older releases.
        not_before = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        if now < not_before or now > not_after:
            raise ConnectionException(
                code='INVALID_RESPONSE',
                message='FURS response x5c certificate is outside its validity window',
            )

        warnings.warn(
            "Verifying FURS response signature with certificate extracted from the "
            "response itself; certificate chain is NOT verified against SIGOV-CA. "
            "This mode protects only against accidental corruption, not MITM. "
            "Use verify_furs_response=True with a pinned furs_response_public_key "
            "for MITM-resistant verification.",
            FURSResponseChainNotVerifiedWarning,
            stacklevel=3,
        )
        return jwt.decode(token, key=cert.public_key(), algorithms=['RS256'])

    def _check_for_errors(self, server_response):
        """
        Check if server response contains FURS Error message and raise FURSException if it does
        :param server_response: (dict) FURS Server response data
        :return: server_response: (dict) FURS Server response data

        :raises
            FURSException: If response contains error
        """
        if server_response[list(server_response.keys())[0]].get('Error', None):
            raise FURSException(code=server_response[list(server_response.keys())[0]]['Error']['ErrorCode'],
                                message=server_response[list(server_response.keys())[0]]['Error']['ErrorMessage'])

        return server_response

    def _sign(self, content, algorithm=hashes.SHA256()):
        return self.connector.p12.key.sign(data=bytes(content, 'utf-8'),
                                           padding=padding.PKCS1v15(),
                                           algorithm=algorithm)
