.DEFAULT_GOAL := help

# The three images this project asks anyone to run. Pinned here so `make cve`
# checks exactly what the launcher and the CI use, and nothing else. The
# Chromium one left with the browser it carried: the PDF is typeset in PHP now,
# and a container nobody starts is one less thing to vouch for.
PHP_IMAGE ?= php:8.4-cli-alpine
PHPSTAN_IMAGE ?= ghcr.io/phpstan/phpstan:2-php8.4
TRIVY_IMAGE ?= aquasec/trivy:0.75.0
.PHONY: help test scan judge demo probe phpstan cve advisories declare serve worksheet import examples release

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

test: ## Check that the risk model still discriminates
	@./tests/run.sh

phpstan: ## Static analysis at level max (runs in a container: this project has no vendor)
	@docker run --rm --volume "$(CURDIR)":/app --workdir /app \
		$(PHPSTAN_IMAGE) analyse --no-progress

# Both architectures, because the claim has to hold for the machine the reader
# runs rather than the one we wrote it on: a multi-arch tag is several images,
# rebuilt at different times, and we were a fresh CI runner away from saying
# "clean" about a platform nobody here uses.
PLATFORMS ?= linux/amd64 linux/arm64

# When an upstream image ships a hole we cannot fix, the decision goes in
# .trivyignore.yaml with a statement and an expiry date — the same two things
# `sablier accept` demands of its own users. No file, no exceptions, and the
# flag disappears with it.
IGNORE_FILE := $(wildcard .trivyignore.yaml)

cve: ## Prove the containers we ask you to run carry no known high or critical CVE
	@set -e; for image in $(PHP_IMAGE) $(PHPSTAN_IMAGE) $(TRIVY_IMAGE); do \
		for platform in $(PLATFORMS); do \
			printf '\n  %s (%s)\n' "$$image" "$$platform"; \
			docker run --rm --volume "$(HOME)/.cache/trivy":/root/.cache \
				$(if $(IGNORE_FILE),--volume "$(CURDIR)/.trivyignore.yaml":/.trivyignore.yaml:ro,) \
				$(TRIVY_IMAGE) image --image-src remote --platform "$$platform" \
				--scanners vuln --severity HIGH,CRITICAL \
				$(if $(IGNORE_FILE),--ignorefile /.trivyignore.yaml,) \
				--exit-code 1 --quiet "$$image"; \
			printf '  ✓ no known high or critical vulnerability\n'; \
		done; \
	done

examples: ## Regenerate the documents the README links to, from the one fixture
	@# Linked from the README and read by people who will never run the tool, so
	@# they have to be the current output rather than the output of some past
	@# version. One fixture, one command, no hand editing.
	@./sablier scan tests/fixtures/sample --out=examples/report.html \
		--audit=examples/audit.html --pdf=examples/report.pdf \
		--cbom=examples/cbom.json --calendar=examples/crossings.ics \
		--no-probe --quiet || true
	@# The post-breach document needs a date somebody declared, which the
	@# fixture does not carry: the example supplies one on the command line. The
	@# technical report of that second run is thrown away — only the document
	@# the README links to comes out of it.
	@# Inside the repository rather than in a temporary directory: the document
	@# prints the command that produced it, and an absolute path from this
	@# machine has no business in a file the README links to.
	@mkdir -p examples/.tmp
	@./sablier scan tests/fixtures/sample --breached=2026-07-29 \
		--incident=examples/incident.html --out=examples/.tmp/report.html \
		--pdf=examples/.tmp/report.pdf --no-probe --quiet >/dev/null 2>&1 || true
	@rm -rf examples/.tmp
	@./sablier worksheet tests/fixtures/sample --out=examples/worksheet.html
	@printf '  %s\n' "examples/ regenerated from tests/fixtures/sample"

demo: ## Scan the fixture project and open the report
	@./sablier scan tests/fixtures/sample --out=report.html || true
	@open report.html 2>/dev/null || true

probe: ## What a server actually negotiates: make probe HOST=example.org
	@test -n "$(HOST)" || { echo "make probe HOST=example.org"; exit 1; }
	@./sablier probe "$(HOST)" $(if $(LANG),--lang=$(LANG),)

scan: ## Scan a project: make scan DIR=/path [DECLARE=file.json] [LANG=en] [PDF=1] [CBOM=1] [AUDIT=1] [ICS=1]
	@test -n "$(DIR)" || { echo "make scan DIR=/path"; exit 1; }
	@./sablier scan "$(DIR)" $(if $(DECLARE),--declare=$(DECLARE),) \
		$(if $(LANG),--lang=$(LANG),) $(if $(PDF),--pdf=report.pdf,) \
		$(if $(CBOM),--cbom=cbom.json,) $(if $(AUDIT),--audit=audit.html,) \
		$(if $(ICS),--calendar=crossings.ics,) --out=report.html

declare: ## Fill the lifetimes with the person who knows them: make declare DIR=/path [LANG=en]
	@test -n "$(DIR)" || { echo "make declare DIR=/path"; exit 1; }
	@./sablier declare "$(DIR)" $(if $(LANG),--lang=$(LANG),)

worksheet: ## The interview as one offline file, for a room with no network: make worksheet DIR=/path [LANG=en] [OUT=file.html]
	@test -n "$(DIR)" || { echo "make worksheet DIR=/path"; exit 1; }
	@./sablier worksheet "$(DIR)" $(if $(LANG),--lang=$(LANG),) --out=$(if $(OUT),$(OUT),worksheet.html)

import: ## Take back the answers filled in that file: make import DIR=/path ANSWERS=answers.json
	@test -n "$(DIR)" || { echo "make import DIR=/path ANSWERS=answers.json"; exit 1; }
	@test -n "$(ANSWERS)" || { echo "make import DIR=/path ANSWERS=answers.json"; exit 1; }
	@./sablier declare "$(DIR)" --import="$(ANSWERS)" $(if $(LANG),--lang=$(LANG),)

serve: ## The same interview in a browser, for a session with somebody: make serve DIR=/path [LANG=en]
	@test -n "$(DIR)" || { echo "make serve DIR=/path"; exit 1; }
	@./bin/sablier serve "$(DIR)" $(if $(LANG),--lang=$(LANG),) $(if $(PORT),--port=$(PORT),)

advisories: ## Collect published vulnerabilities: make advisories DIR=/path [OUT=file.json]
	@test -n "$(DIR)" || { echo "make advisories DIR=/path"; exit 1; }
	@./sablier advisories "$(DIR)" $(if $(OUT),--out=$(OUT),)

judge: ## Judge another tool's CBOM: make judge CBOM=cbom.json [DECLARE=file.json] [LANG=en]
	@test -n "$(CBOM)" || { echo "make judge CBOM=cbom.json"; exit 1; }
	@./sablier judge "$(CBOM)" $(if $(DECLARE),--declare=$(DECLARE),) \
		$(if $(LANG),--lang=$(LANG),) --out=report.html

# --- releases anybody can rebuild ----------------------------------------------
# A tag is a promise about bytes, and a promise nobody can check is a decoration.
# This builds the archive from the tag — never from the working tree — and prints
# its digest. Run it on your own machine, against the same tag, and you must get
# the same line; that is the whole claim, and it is one command to refuse it.
#
# `gzip -n` is not a detail: without it gzip stores the current time in the
# header and two archives of the same tree differ. Measured — with it, two runs
# a second apart gave 5fbd3a5c…; without it, ddceae9d… then 465632e8….
#
# GitHub's own "Source code (tar.gz)" is not this file. Its bytes have changed
# before, under everybody, when their compression changed; ours is attached to
# the release and its digest is in the notes.
VERSION := $(shell php -r 'require "src/Version.php"; echo Sablier\Version::NUMBER;')
ARCHIVE := sablier-$(VERSION).tar.gz

release: ## Build the release archive for the current version, reproducibly
	@git rev-parse "v$(VERSION)" >/dev/null 2>&1 \
		|| { echo "✗ no tag v$(VERSION): the archive is built from the tag, not from this tree"; exit 1; }
	@git archive --format=tar --prefix=sablier-$(VERSION)/ "v$(VERSION)" | gzip -n -9 > "$(ARCHIVE)"
	@printf '  %s\n' "$(ARCHIVE)"
	@openssl dgst -sha256 -r "$(ARCHIVE)" | awk '{printf "  sha256  %s\n", $$1}'
