.DEFAULT_GOAL := help

# The three images this project asks anyone to run. Pinned here so `make cve`
# checks exactly what the launcher and the CI use, and nothing else.
PHP_IMAGE ?= php:8.4-cli-alpine
PHPSTAN_IMAGE ?= ghcr.io/phpstan/phpstan:2-php8.4
TRIVY_IMAGE ?= aquasec/trivy:0.75.0
CHROME_IMAGE ?= zenika/alpine-chrome:124
.PHONY: help test scan judge demo probe phpstan cve

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

test: ## Check that the risk model still discriminates
	@./tests/run.sh

phpstan: ## Static analysis at level max (runs in a container: this project has no vendor)
	@docker run --rm --volume "$(CURDIR)":/app --workdir /app \
		$(PHPSTAN_IMAGE) analyse --no-progress

cve: ## Prove the containers we ask you to run carry no known high or critical CVE
	@set -e; for image in $(PHP_IMAGE) $(PHPSTAN_IMAGE) $(CHROME_IMAGE) $(TRIVY_IMAGE); do \
		printf '\n  %s\n' "$$image"; \
		docker run --rm --volume "$(HOME)/.cache/trivy":/root/.cache $(TRIVY_IMAGE) image \
			--image-src remote --scanners vuln --severity HIGH,CRITICAL \
			--exit-code 1 --quiet "$$image"; \
		printf '  ✓ no known high or critical vulnerability\n'; \
	done

demo: ## Scan the fixture project and open the report
	@./sablier scan tests/fixtures/sample --out=report.html || true
	@open report.html 2>/dev/null || true

probe: ## What a server actually negotiates: make probe HOST=example.org
	@test -n "$(HOST)" || { echo "make probe HOST=example.org"; exit 1; }
	@./sablier probe "$(HOST)" $(if $(LANG),--lang=$(LANG),)

scan: ## Scan a project: make scan DIR=/path [DECLARE=file.json] [LANG=en] [PDF=1] [CBOM=1] [AUDIT=1]
	@test -n "$(DIR)" || { echo "make scan DIR=/path"; exit 1; }
	@./sablier scan "$(DIR)" $(if $(DECLARE),--declare=$(DECLARE),) \
		$(if $(LANG),--lang=$(LANG),) $(if $(PDF),--pdf=report.pdf,) \
		$(if $(CBOM),--cbom=cbom.json,) $(if $(AUDIT),--audit=audit.html,) --out=report.html

judge: ## Judge another tool's CBOM: make judge CBOM=cbom.json [DECLARE=file.json] [LANG=en]
	@test -n "$(CBOM)" || { echo "make judge CBOM=cbom.json"; exit 1; }
	@./sablier judge "$(CBOM)" $(if $(DECLARE),--declare=$(DECLARE),) \
		$(if $(LANG),--lang=$(LANG),) --out=report.html
