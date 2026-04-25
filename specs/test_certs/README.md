# FURS test-environment certificates

All material in this directory is **public** — published by FURS (or
SI-TRUST) for integrators developing against the test fiscal-verification
endpoint at `https://blagajne-test.fu.gov.si:9002`. Nothing here is a
secret. Tracked in git so the demo and the integration tests pin
against the right keys out of the box.

| File                                | Purpose                                                                               | Source |
|-------------------------------------|---------------------------------------------------------------------------------------|--------|
| `10492682-2.p12`                    | Client cert (mTLS + JWS signing) for *TESTNO PODJETJE 1211*. Password: `DQHTBI591V00` | FURS-issued; legacy PBE (RC2-40-CBC). |
| `blagajne-test.fu.gov.si.cer`       | Server-side TLS cert for the test endpoint. Reference only.                           | `https://www.datoteke.fu.gov.si/dpr/files/blagajne-test.fu.gov.si.cer` |
| `DavPotRacTEST.cer`                 | FURS response-signing public key. Used as `verify_furs_response=True` pin.           | `https://www.datoteke.fu.gov.si/dpr/files/DavPotRacTEST.cer` |
| `sigov-ca2.xcert.crt`               | Intermediate CA — `SIGOV-CA` (DER).                                                   | `https://www.si-trust.gov.si/assets/si-trust-root/povezovalni-podrejeni/sigovca-2/sigov-ca2.xcert.crt` |
| `si-trust-root.crt`                 | Root CA — `SI-TRUST Root` (DER).                                                      | `https://www.si-trust.gov.si/assets/si-trust-root/korensko-potrdilo/si-trust-root.crt` |
| `sigov-ca-bundle.pem`               | `sigov-ca2 + si-trust-root` concatenated as PEM, ready for `verify_tls=<path>`.       | Built locally via `openssl x509 -inform DER -outform PEM`. |

## Legacy PBE on the client p12

`10492682-2.p12` is encrypted with `pbeWithSHA1And40BitRC2-CBC`, which
the OpenSSL 3 CLI rejects by default. Inspecting it from the shell needs
the `-legacy` provider:

```bash
openssl pkcs12 -info -nokeys -in 10492682-2.p12 -legacy
```

The Python loader uses `cryptography`'s PKCS#12 parser, which handles
the legacy PBE without any extra flag — so the demo and tests do not
need OpenSSL CLI at all. If FURS issues a future test p12 with a
modern PBE, this note can go.

## Why both `*.cer` and a separate `sigov-ca-bundle.pem`?

* The CAs ship as **DER** (`*.crt`); Python's `ssl` module wants a PEM
  bundle for `cafile=`. We convert and concatenate once into
  `sigov-ca-bundle.pem` so the demo and tests can pin in one line.
* `DavPotRacTEST.cer` is consumed differently — the client extracts the
  *public key* (`SubjectPublicKeyInfo`) and passes it as
  `furs_response_public_key=...` for `verify_furs_response=True`.

## Re-fetching

These files don't change often, but FURS rotates server and signing
certs occasionally (e.g. the production server cert is rotated yearly,
hence `_2025` suffix). The test endpoint cert (`blagajne-test.fu.gov.si.cer`)
and the response-signing cert (`DavPotRacTEST.cer`) follow the same
rough cadence. When that happens:

1. Re-fetch the new files (commands below).
2. The CN of the response-signing cert may change (e.g. `DavPotRacTEST`
   could become `DavPotRacTEST_2026`); update the
   `tests/test_real_cert.py::test_furs_published_cert_loads_and_has_expected_cn`
   parametrize block to match.
3. The serial number of `10492682-2.p12` is asserted in
   `test_jws_header_uses_real_cert_metadata` — if FURS reissues the
   *TESTNO PODJETJE 1211* p12, update that assertion too.

To re-fetch:

```bash
cd specs/test_certs/
curl -fsSLO https://www.datoteke.fu.gov.si/dpr/files/blagajne-test.fu.gov.si.cer
curl -fsSLO https://www.datoteke.fu.gov.si/dpr/files/DavPotRacTEST.cer
curl -fsSLO https://www.si-trust.gov.si/assets/si-trust-root/povezovalni-podrejeni/sigovca-2/sigov-ca2.xcert.crt
curl -fsSLO https://www.si-trust.gov.si/assets/si-trust-root/korensko-potrdilo/si-trust-root.crt

# Rebuild the PEM bundle.
openssl x509 -in sigov-ca2.xcert.crt   -inform DER -outform PEM \
  > sigov-ca-bundle.pem
openssl x509 -in si-trust-root.crt     -inform DER -outform PEM \
  >> sigov-ca-bundle.pem
```

The published index lives at:
<https://edavki.durs.si/edavkiportal/openportal/CommonPages/Opdynp/PageD.aspx?category=dpr_teh_spec>
("Digitalna potrdila" section).

## Production

The same set of files for the production endpoint
(`https://blagajne.fu.gov.si:9003`) ships in `specs/prod_certs/`. The
production client p12 is **not** committed — that's something each
integrator obtains from FURS for their own VAT number.

## License / use

Public-sector material published for technical-integration purposes; no
restrictions on bundling for development tooling. The client p12 is
test-only and **must not** be reused for production.
