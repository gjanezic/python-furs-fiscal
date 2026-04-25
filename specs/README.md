# FURS Technical Specification v3.2 Text Extract

Source PDF: [`specs/TehnicnaDokumentacijaVer3.2.pdf`](TehnicnaDokumentacijaVer3.2.pdf)

Official schemas and examples downloaded from the eDavki "Sheme in primeri" section:

- [`specs/schemas/FiscalVerificationSchema.json`](schemas/FiscalVerificationSchema.json) - JSON schema for individual invoice and business-premise messages.
- [`specs/schemas/FiscalVerificationSchemaBatch.json`](schemas/FiscalVerificationSchemaBatch.json) - JSON schema for batch invoice and business-premise messages.
- [`specs/examples/`](examples) - signed JSON token examples published by FURS, including electronic invoices, business premises, batch messages, and vending-machine premises.

Generated with `pdftotext -layout` for repository-local searching and agent review. Regenerate with:

```sh
pdftotext -layout specs/TehnicnaDokumentacijaVer3.2.pdf specs/TehnicnaDokumentacijaVer3.2.txt
```

Schema/example files can be refreshed from the official links listed at:

```text
https://edavki.durs.si/edavkiportal/openportal/CommonPages/Opdynp/PageD.aspx?category=dpr_teh_spec
```
