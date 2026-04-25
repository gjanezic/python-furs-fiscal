# FURS production-environment certificates

Public material published by FURS / SI-TRUST for the *production*
fiscal-verification endpoint at `https://blagajne.fu.gov.si:9003`.

There is **no** client p12 in this directory — production client certs
are issued by FURS to the integrator's own VAT number and are obtained
out of band. The library accepts them via `FURSClient(p12_data=...,
p12_password=...)`.

| File                            | Purpose                                                                       | Source |
|---------------------------------|-------------------------------------------------------------------------------|--------|
| `blagajne.fu.gov.si_2025.cer`   | Server-side TLS cert for the production endpoint. Reference only.             | `https://www.datoteke.fu.gov.si/dpr/files/blagajne.fu.gov.si_2025.cer` |
| `DavPotRac_2025.cer`            | FURS response-signing public key. Used as `verify_furs_response=True` pin.   | `https://www.datoteke.fu.gov.si/dpr/files/DavPotRac_2025.cer` |
| `sigov-ca2.xcert.crt`           | Intermediate CA — `SIGOV-CA` (DER, identical to test).                        | `https://www.si-trust.gov.si/assets/si-trust-root/povezovalni-podrejeni/sigovca-2/sigov-ca2.xcert.crt` |
| `si-trust-root.crt`             | Root CA — `SI-TRUST Root` (DER, identical to test).                           | `https://www.si-trust.gov.si/assets/si-trust-root/korensko-potrdilo/si-trust-root.crt` |
| `sigov-ca-bundle.pem`           | `sigov-ca2 + si-trust-root` PEM concatenation for `verify_tls=<path>`.        | Built locally via `openssl x509 -inform DER -outform PEM`. |

The `_2025` filename suffix on the FURS-published server / signing
certs is FURS's convention — these are rotated approximately yearly,
so refresh them annually (and refresh
`tests/test_real_cert.py::test_furs_published_cert_loads_and_has_expected_cn`
expectations if a CN ever changes).

See `specs/test_certs/README.md` for re-fetch commands; the production
files use the same hosts.

## Recommended production wiring

```python
from pathlib import Path
from furs_fiscal import FURSClient, load_response_public_key

PROD_CERTS = Path("specs/prod_certs")

client = FURSClient(
    p12_data=Path("/secure/myco.p12").read_bytes(),
    p12_password="...",
    production=True,
    verify_tls=str(PROD_CERTS / "sigov-ca-bundle.pem"),
    verify_furs_response=True,
    furs_response_public_key=load_response_public_key(
        PROD_CERTS / "DavPotRac_2025.cer"
    ),
)
```

This is the strongest configuration the library supports: every byte on
the wire is verified against material FURS published, both for the TLS
chain and for the JWS response signature.
