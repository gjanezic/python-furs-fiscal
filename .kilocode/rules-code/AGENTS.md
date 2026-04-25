# Project Coding Rules (Non-Obvious Only)

- For implementation work involving FURS/eDavki technical specifications, request structures, certificates, signing, communication, or related integrations, first consult the official technical-specifications page at https://edavki.durs.si/edavkiportal/openportal/CommonPages/Opdynp/PageD.aspx?category=dpr_teh_spec and the direct PDF technical documentation at https://www.datoteke.fu.gov.si/dpr/files/TehnicnaDokumentacijaVer3.2.pdf; verify currency and distinguish official-documentation facts from implementation recommendations.
- Use `specs/TehnicnaDokumentacijaVer3.2.txt` as the repository-local searchable extract of the FURS v3.2 PDF (`specs/TehnicnaDokumentacijaVer3.2.pdf`); regenerate it with `pdftotext -layout specs/TehnicnaDokumentacijaVer3.2.pdf specs/TehnicnaDokumentacijaVer3.2.txt` when the PDF changes, and verify currency against the official sources.
- Preserve PyJWT 2.x behavior: `jwt.encode()` output is passed directly into JSON as `token`, and server `jwt.decode()` uses `options={"verify_signature": False}`.
- Do not replace `Connector` temp cert/key files with in-memory certs unless the HTTP client changes; current `requests` calls require `(cert_path, key_path)`.
- `software_supplier_tax_number` wins over `foreign_software_supplier_name`; if the tax number is falsey, the generated JSON uses `{'NameForeign': foreign_software_supplier_name}` even when it is `None`.
- FURS message builders use exact FURS key casing (`TaxNumber`, `BusinessPremiseID`, `ProtectedID`, etc.); avoid Pythonic renaming inside request payloads.
- `TaxesPerSeller` and invoice methods currently drop optional numeric fields when they are falsey; changing to `is not None` may alter wire payloads for zero amounts.
- Reference invoices in `get_invoice_eor()` support either parallel lists or scalar values; `get_sales_book_invoice_eor()` only builds a single reference object.
- FURS invoice issue/reference datetimes and request header `DateTime` use `YYYY-MM-DDTHH:MM:SS` without `Z` or offset in the v3.2 examples and field descriptions; keep ZOI input semantically aligned with the invoice issue time sent in the payload.
