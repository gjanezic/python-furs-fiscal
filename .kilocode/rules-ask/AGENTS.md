# Project Documentation Rules (Non-Obvious Only)

- For explanatory or documentation work involving FURS/eDavki technical specifications, request structures, certificates, signing, communication, or related integrations, first consult the official technical-specifications page at https://edavki.durs.si/edavkiportal/openportal/CommonPages/Opdynp/PageD.aspx?category=dpr_teh_spec and the direct PDF technical documentation at https://www.datoteke.fu.gov.si/dpr/files/TehnicnaDokumentacijaVer3.2.pdf; verify currency and clearly distinguish official-documentation facts from agent inferences or recommendations.
- Use `specs/TehnicnaDokumentacijaVer3.2.txt` for quick local citation/search of the FURS v3.2 spec; the source PDF is `specs/TehnicnaDokumentacijaVer3.2.pdf`, but always verify currentness against the official page/PDF for specification-sensitive answers.
- `README.md` states tests are planned, matching the empty `tests/` package; do not infer an existing test suite or CI workflow from the directory name.
- `demos/` are the most complete usage reference, but their certificate path is relative to `demos/`, not repository root.
- The package includes `furs_fiscal/certs/test_certificate.pem` via `package_data`, but connector code currently does not use bundled CA certs; it posts with `verify=False`.
- Invoice numbering constants are FURS protocol values: central numbering is `'C'`, device numbering is `'B'`, and the default is device numbering.
