# Project Debug Rules (Non-Obvious Only)

- For debugging work involving FURS/eDavki technical specifications, request structures, certificates, signing, communication, or related integrations, first consult the official technical-specifications page at https://edavki.durs.si/edavkiportal/openportal/CommonPages/Opdynp/PageD.aspx?category=dpr_teh_spec and the direct PDF technical documentation at https://www.datoteke.fu.gov.si/dpr/files/TehnicnaDokumentacijaVer3.2.pdf; verify currency and distinguish official-documentation facts from diagnostic conclusions or recommendations.
- Use `specs/TehnicnaDokumentacijaVer3.2.txt` as the local searchable FURS v3.2 spec extract when debugging payload/schema/signing issues; regenerate from `specs/TehnicnaDokumentacijaVer3.2.pdf` with `pdftotext -layout` if needed, then confirm currency against the official sources.
- FURS transport errors are split: non-200 HTTP raises `ConnectionException`, request timeouts raise `ConnectionTimedOutException`, and decoded FURS payload errors raise `FURSException` from the first top-level response object.
- `ConnectionException.code` is accidentally stored as a one-item tuple because of a trailing comma; inspect `exc.code[0]` if existing behavior matters.
- Echo checks (`is_server_accessible()`) still load the client `.p12` and send cert/key paths even though the echo payload is unsigned.
- Response-signature verification is intentionally absent in `_send_request()`; debugging response issues should inspect the decoded JWT payload before assuming signature failures.
- Demos point to `demo_podjetje.p12` with a relative path, so running them from the repository root will not find the certificate unless the path is adjusted.
