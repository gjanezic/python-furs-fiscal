# Project Architecture Rules (Non-Obvious Only)

- For architectural work involving FURS/eDavki technical specifications, request structures, certificates, signing, communication, or related integrations, first consult the official technical-specifications page at https://edavki.durs.si/edavkiportal/openportal/CommonPages/Opdynp/PageD.aspx?category=dpr_teh_spec and the direct PDF technical documentation at https://www.datoteke.fu.gov.si/dpr/files/TehnicnaDokumentacijaVer3.2.pdf; verify currency and clearly distinguish official-documentation facts from architectural inferences or recommendations.
- Use `specs/TehnicnaDokumentacijaVer3.2.txt` for repository-local searches of the FURS v3.2 spec; the source PDF is `specs/TehnicnaDokumentacijaVer3.2.pdf`, and `specs/README.md` documents regeneration with `pdftotext -layout`.
- Public API classes are thin message builders; all certificate handling, JWT signing, endpoint selection, proxying, and HTTP calls are centralized in `Connector`.
- Endpoint selection is only the boolean `production` flag (`9003` production vs `9002` test); there is no injectable base URL without modifying `Connector`.
- The library signs outbound payloads as JWT/JWS for FURS, then uses mutual TLS with temp cert/key files; both layers are required by the current design.
- Server JWT signatures are not verified despite the signed-request architecture; adding verification requires introducing trusted FURS cert handling, not just toggling PyJWT options.
- Business-premise registration and invoice submission share `_send_request()`, but build different root envelope names, so error checking intentionally looks at the first top-level key.
