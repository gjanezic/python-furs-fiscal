import os
import tempfile
import warnings

import requests
import jwt

from OpenSSL import crypto
from OpenSSL.crypto import X509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12


FURS_TEST_ENDPOINT = 'https://blagajne-test.fu.gov.si:9002'
FURS_PRODUCTION_ENDPOINT = 'https://blagajne.fu.gov.si:9003'


class FURSTLSVerificationDisabledWarning(UserWarning):
    """Emitted when the connector is constructed with TLS verification disabled.

    The FURS technical specification mandates two-way TLS with verification of
    the server certificate against the SIGOV-CA chain. Disabling verification
    leaves the channel vulnerable to MITM attacks. Pass a CA bundle path or
    ``verify_tls=True`` to silence this warning.
    """

# TODO - we should add all the certificates to trusted CA's to make this work.
# TODO - for now we'll just keep it to verify=False...
# FURS_TEST_CERT = os.path.join(os.path.dirname(__file__), 'certs/test-tls.cer')
# FURS_PRODUCTION_CERT = os.path.join(os.path.dirname(__file__), 'certs/blagajne.fu.gov.si.cer')


class Connector(object):
    """
    Connector performs all the communication with the FURS server.

    """
    def __init__(self,
                 p12_path,
                 p12_password,
                 p12_buffer=None,
                 production=True,
                 request_timeout=2,
                 proxy=None,
                 verify_tls=False,
                 disable_tls_warnings=True):
        """
        Initializes and loads certs to memory.

        :param p12_path: (string) Path to the .p12 file for current client
        :param p12_password: (string) Password for the .p12 file
        :param p12_buffer: (string) Buffer of the .p12 file
        :param production: (boolean) Should we use FURS Production server of Test server
        :param request_timeout: (float) How long should we wait for the request to timeout
        :param proxy: (dict) Specify proxy details if you need one, for example: {"http": "http://localhost:3128", "https": "http://localhost:3128"}
        :param verify_tls: ``False`` (legacy default) or any other falsy value
                           except ``None`` disables verification. ``True`` uses
                           the system CA bundle. A string path pins to a CA
                           bundle (e.g. SIGOV-CA). ``None`` falls back to
                           ``requests`` defaults (REQUESTS_CA_BUNDLE env var or
                           system CAs — i.e. verification is enabled).
        :param disable_tls_warnings: Disable urllib3 warnings when verification
                                     is disabled.
        :return: None
        """
        self.p12_path = p12_path
        self.p12_buffer = p12_buffer
        self.endpoint = FURS_PRODUCTION_ENDPOINT if production else FURS_TEST_ENDPOINT
        # self.cert = FURS_PRODUCTION_CERT if production else FURS_TEST_CERT

        self.p12 = None
        self.cert_temp = None
        self.pkey_temp = None

        self.request_timeout = request_timeout

        self.proxy = proxy
        self.verify_tls = verify_tls
        # Any falsy value other than None disables verification in `requests`
        # (False, 0, ''). None means "use REQUESTS_CA_BUNDLE/system CAs", which
        # is fine. Catch the dangerous-but-falsy variants too, not just False.
        if not verify_tls and verify_tls is not None:
            warnings.warn(
                "FURS connector created with TLS verification disabled. The FURS spec "
                "requires verifying the server certificate against the SIGOV-CA chain. "
                "Pass verify_tls=True or a CA bundle path to enable verification.",
                FURSTLSVerificationDisabledWarning,
                stacklevel=2,
            )
            if disable_tls_warnings:
                requests.packages.urllib3.disable_warnings()

        # self.furs_cert = open(self.cert, 'rt').read()
        # load certificate...
        self._load_p12(p12_password)

    def _load_p12(self, p12_password):
        """
        Load .p12 cert to memory

        :param p12_password: (string) password for the .p12 file
        :return: None
        """
        if self.p12_buffer is None:
            with open(self.p12_path, 'rb') as p12_file:
                self.p12_buffer = p12_file.read()
        self.p12 = load_pkcs12(self.p12_buffer, password=bytes(p12_password, 'utf-8'))
        self._store_temp_files()

    def _store_temp_files(self):
        """
        Requests library requires string path to PKey and Cert - therefore we save those into
        temporary files on the file system.

        ``tempfile.NamedTemporaryFile`` already creates files with mode 0o600 on
        POSIX (via ``mkstemp``), so no explicit ``chmod`` is needed.

        :return: None
        """
        self.cert_temp = tempfile.NamedTemporaryFile(delete=False)
        self.cert_temp.write(crypto.dump_certificate(crypto.FILETYPE_PEM, X509.from_cryptography(self.p12.cert.certificate)))
        self.cert_temp.flush()
        self.cert_temp.close()

        self.pkey_temp = tempfile.NamedTemporaryFile(delete=False)
        self.pkey_temp.write(self.p12.key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
        self.pkey_temp.flush()
        self.pkey_temp.close()

    def close(self):
        """
        Remove temporary certificate and private key files created for requests.

        :return: None
        """
        for temp_file_attr in ('cert_temp', 'pkey_temp'):
            temp_file = getattr(self, temp_file_attr, None)
            if temp_file is None:
                continue
            try:
                if not temp_file.closed:
                    temp_file.close()
            finally:
                try:
                    os.unlink(temp_file.name)
                except FileNotFoundError:
                    pass
                setattr(self, temp_file_attr, None)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def _get_jws_header(self):
        """
        Prepare JWS Header dictionary based on the client certificate data.

        :return: (dict) JWS header
        """
        jws_header = {
            'alg': 'RS256',
            'subject_name': self.p12.cert.certificate.subject.rfc4514_string(),
            'issuer_name': self.p12.cert.certificate.issuer.rfc4514_string(),
            'serial': self.p12.cert.certificate.serial_number
        }

        return jws_header

    def _jwt_sign(self, header, payload, algorithm='RS256'):
        """
        Perform JWT signature of the header and payload.

        :param header: (dict) JWS header dictionary
        :param payload: (dict) content to sign
        :param algorithm: (string) which algorithm to use. Default: 'RS256'
        :return: (string) Signed base64 encoded content
        """
        return jwt.encode(payload,
                          key=self.p12.key,
                          headers=header,
                          algorithm=algorithm)

    def post(self, path, json):
        """
        Perform POST request to the FURS server for a given path endpoint. This wrapper will
        prepare JWS header and sign the message according to the JWT specification.

        :param path: (string) path to the endpoint e.g 'v1/cash_registers/invoices'
        :param json: (dict) data to send
        :return: response object
        """
        data = {
            'token': self._jwt_sign(header=self._get_jws_header(),
                                    payload=json)
        }

        return requests.post(url='%s/%s' % (self.endpoint, path),
                             json=data,
                             cert=(self.cert_temp.name, self.pkey_temp.name),
                             verify=self.verify_tls,
                             headers=self._prepare_headers(),
                             timeout=self.request_timeout,
                             proxies=self.proxy)

    def send_echo(self, message='ping'):
        """
        Sends echo request to the FURS server. Echo request does not perform any type of
        message signing, therefore it should not be used to validate the client certificate.
        Instead it's commonly used to determine if the FURS server is accessible.

        :param message: (string) a message to send to FURS.
        :return: response object
        """
        data = {
            'EchoRequest': message,
        }

        return requests.post(url='%s/%s' % (self.endpoint, 'v1/cash_registers/echo'),
                             json=data,
                             cert=(self.cert_temp.name, self.pkey_temp.name),
                             verify=self.verify_tls,
                             headers=self._prepare_headers(),
                             timeout=self.request_timeout,
                             proxies=self.proxy)

    def _prepare_headers(self):
        """
        Prepare request header so that the FURS server will accept our request.

        :return: (dict) request header
        """
        return {'Content-Type': 'application/json; charset=UTF-8'}
