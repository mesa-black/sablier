.DEFAULT_GOAL := help

# The three images this project asks anyone to run. Pinned here so `make cve`
# checks exactly what the launcher and the CI use, and nothing else. The
# Chromium one left with the browser it carried: the PDF is typeset in PHP now,
# and a container nobody starts is one less thing to vouch for.
PHP_IMAGE ?= php:8.4-cli-alpine
PHPSTAN_IMAGE ?= ghcr.io/phpstan/phpstan:2-php8.4
TRIVY_IMAGE ?= aquasec/trivy:0.75.0
.PHONY: help test scan judge demo probe phpstan cve advisories declare serve worksheet import

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
