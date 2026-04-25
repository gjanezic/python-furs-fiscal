# Maintenance Makefile for python-furs-fiscal.
#
# The certs in specs/test_certs/ and specs/prod_certs/ are FURS-published
# *public* material (server TLS certs, response-signing public keys, the
# SIGOV-CA / SI-TRUST chain). FURS rotates the env-specific ones roughly
# yearly. This Makefile keeps the rotation procedure to one command so the
# test suite + demo don't silently rot when FURS issues new certs.
#
# Library *users* are unaffected by rotation — they pass their own paths
# to FURSClient(verify_tls=..., furs_response_public_key=...) and the
# wheel/sdist on PyPI does not bundle these files. This is purely a
# repository-maintenance concern.
#
# Quick usage
# -----------
#   make help                            # list targets
#   make refresh-test-certs              # re-fetch FURS test-env public certs
#   make refresh-prod-certs              # re-fetch with the current PROD_YEAR
#   make refresh-prod-certs PROD_YEAR=2026
#   make refresh-certs                   # both of the above
#   make check-cert-expiry               # run only the expiry-surveillance tests
#
# Year suffix on prod files
# -------------------------
# FURS encodes the rotation year in the production filenames
# (blagajne.fu.gov.si_<YEAR>.cer, DavPotRac_<YEAR>.cer). When the year
# ticks over:
#   1. make refresh-prod-certs PROD_YEAR=<new>
#   2. git rm specs/prod_certs/blagajne.fu.gov.si_<old>.cer \
#             specs/prod_certs/DavPotRac_<old>.cer
#   3. Update PROD_DAVPOTRAC_CER / PROD_BLAGAJNE_CER paths in
#      tests/test_real_cert.py to point at the new filenames.
#   4. Update the CN expectation in
#      test_furs_published_cert_loads_and_has_expected_cn if FURS
#      changed the published CN (e.g. DavPotRac_2025 → DavPotRac_2026
#      may or may not include the year in the CN itself).

PROD_YEAR ?= 2025

DPR_BASE      := https://www.datoteke.fu.gov.si/dpr/files
SI_TRUST_BASE := https://www.si-trust.gov.si/assets/si-trust-root

TEST_CERTS_DIR := specs/test_certs
PROD_CERTS_DIR := specs/prod_certs

.PHONY: help refresh-certs refresh-test-certs refresh-prod-certs check-cert-expiry test

help:  ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Available targets:\n"} \
	     /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2 }' \
	     $(MAKEFILE_LIST)

refresh-certs: refresh-test-certs refresh-prod-certs  ## Refresh both test and prod cert directories.

refresh-test-certs:  ## Re-fetch FURS test-env public certs and rebuild PEM bundle.
	@echo ">>> Refreshing $(TEST_CERTS_DIR)"
	cd $(TEST_CERTS_DIR) && \
	    curl -fsSLO $(DPR_BASE)/blagajne-test.fu.gov.si.cer && \
	    curl -fsSLO $(DPR_BASE)/DavPotRacTEST.cer && \
	    curl -fsSLO $(SI_TRUST_BASE)/povezovalni-podrejeni/sigovca-2/sigov-ca2.xcert.crt && \
	    curl -fsSLO $(SI_TRUST_BASE)/korensko-potrdilo/si-trust-root.crt && \
	    openssl x509 -in sigov-ca2.xcert.crt -inform DER -outform PEM  > sigov-ca-bundle.pem && \
	    openssl x509 -in si-trust-root.crt   -inform DER -outform PEM >> sigov-ca-bundle.pem
	@echo ">>> Done. Review changes with:  git -C $(TEST_CERTS_DIR) status"
	@echo ">>> NB: 10492682-2.p12 is FURS-issued for TESTNO PODJETJE 1211"
	@echo "    and is NOT auto-fetched (no public URL). If FURS reissues it,"
	@echo "    update the file by hand and bump REAL_P12_PASSWORD / the serial"
	@echo "    assertion in tests/test_real_cert.py."

refresh-prod-certs:  ## Re-fetch FURS production public certs (override with PROD_YEAR=YYYY).
	@echo ">>> Refreshing $(PROD_CERTS_DIR) for PROD_YEAR=$(PROD_YEAR)"
	cd $(PROD_CERTS_DIR) && \
	    curl -fsSLO $(DPR_BASE)/blagajne.fu.gov.si_$(PROD_YEAR).cer && \
	    curl -fsSLO $(DPR_BASE)/DavPotRac_$(PROD_YEAR).cer && \
	    curl -fsSLO $(SI_TRUST_BASE)/povezovalni-podrejeni/sigovca-2/sigov-ca2.xcert.crt && \
	    curl -fsSLO $(SI_TRUST_BASE)/korensko-potrdilo/si-trust-root.crt && \
	    openssl x509 -in sigov-ca2.xcert.crt -inform DER -outform PEM  > sigov-ca-bundle.pem && \
	    openssl x509 -in si-trust-root.crt   -inform DER -outform PEM >> sigov-ca-bundle.pem
	@echo ">>> Done. If FURS bumped the year suffix, remember to:"
	@echo "       git rm $(PROD_CERTS_DIR)/blagajne.fu.gov.si_<old>.cer \\"
	@echo "              $(PROD_CERTS_DIR)/DavPotRac_<old>.cer"
	@echo "    and update PROD_DAVPOTRAC_CER / PROD_BLAGAJNE_CER paths in"
	@echo "    tests/test_real_cert.py."

check-cert-expiry:  ## Run only the cert-expiry surveillance tests.
	pytest tests/test_real_cert.py -k cert_expiry -v -W default

test:  ## Run the full pytest suite.
	pytest
