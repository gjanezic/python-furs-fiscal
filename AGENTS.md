# AGENTS.md

This file provides guidance to agents when working with code in this repository.

- Official primary sources for FURS/eDavki technical specifications are the technical-specifications page at https://edavki.durs.si/edavkiportal/openportal/CommonPages/Opdynp/PageD.aspx?category=dpr_teh_spec and the direct PDF technical documentation at https://www.datoteke.fu.gov.si/dpr/files/TehnicnaDokumentacijaVer3.2.pdf. For any future question, task, or implementation involving technical specifications, request structures, certificates, signing, eDavki/FURS communication, or related integrations, consult these sources first, verify that the information is current, and clearly separate facts from official documentation from agent inferences or recommendations.
- A local copy of the FURS v3.2 PDF is stored at `specs/TehnicnaDokumentacijaVer3.2.pdf`, with a searchable `pdftotext -layout` extract at `specs/TehnicnaDokumentacijaVer3.2.txt` and regeneration notes in `specs/README.md`; use the local text extract for fast searches, but verify currency against the official page/PDF before relying on it.
- No test runner is configured and `tests/` only has an empty package marker; for single-test work use direct pytest only after adding tests, e.g. `python -m pytest tests/test_api.py::test_name`.
- Packaging is legacy setuptools only (`setup.py` plus `setup.cfg` metadata); build checks should use `python setup.py sdist bdist_wheel` if `wheel` is installed.
- Runtime deps are intentionally minimal: `requirements.txt` pins `PyJWT==2.8.0`, while `setup.py` allows `PyJWT>=2.8.0`; keep compatibility with PyJWT 2.x return types.
- Core flow: public APIs in `furs_fiscal/api.py` build FURS JSON envelopes, `FURSBaseAPI._send_request()` signs/posts through `Connector`, then decodes the returned JWT without verifying the FURS signature.
- `Connector` writes certificate and private key material from `.p12`/buffer into `NamedTemporaryFile(delete=False)` because `requests` needs file paths; account for leaked temp files in long-running processes/tests.
- TLS verification is deliberately disabled globally and per request (`verify=False` plus disabled urllib3 warnings); do not “fix” this casually without adding FURS CA handling.
- FURS date formats vary by message type: invoice issue/reference datetimes and request header `DateTime` use `YYYY-MM-DDTHH:MM:SS` without a timezone suffix per `specs/TehnicnaDokumentacijaVer3.2.txt`; business premise validity and sales-book issue dates use `%Y-%m-%d`.
- `TaxesPerSeller.build_json()` omits fields based on truthiness, so zero-valued amounts are dropped; preserve or test this behavior before changing tax serialization.
- API defaults contain mutable `taxes_per_seller=[]`; avoid mutating it and prefer `None` only with compatibility care.
- Demos rely on running from `demos/` because `P12_CERT_PATH = 'demo_podjetje.p12'` is relative.
