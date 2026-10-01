.DEFAULT_GOAL := help
.PHONY: help test scan judge demo probe

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

test: ## Check that the risk model still discriminates
	@./tests/run.sh

demo: ## Scan the fixture project and open the report
	@./bin/sablier scan tests/fixtures/sample --out=report.html || true
	@open report.html 2>/dev/null || true

probe: ## What a server actually negotiates: make probe HOST=example.org
	@test -n "$(HOST)" || { echo "make probe HOST=example.org"; exit 1; }
	@./bin/sablier probe "$(HOST)" $(if $(LANG),--lang=$(LANG),)

scan: ## Scan a project: make scan DIR=/path [DECLARE=file.json] [LANG=en] [PDF=1] [CBOM=1] [AUDIT=1]
	@test -n "$(DIR)" || { echo "make scan DIR=/path"; exit 1; }
	@./bin/sablier scan "$(DIR)" $(if $(DECLARE),--declare=$(DECLARE),) \
		$(if $(LANG),--lang=$(LANG),) $(if $(PDF),--pdf=report.pdf,) \
		$(if $(CBOM),--cbom=cbom.json,) $(if $(AUDIT),--audit=audit.html,) --out=report.html

judge: ## Judge another tool's CBOM: make judge CBOM=cbom.json [DECLARE=file.json] [LANG=en]
	@test -n "$(CBOM)" || { echo "make judge CBOM=cbom.json"; exit 1; }
	@./bin/sablier judge "$(CBOM)" $(if $(DECLARE),--declare=$(DECLARE),) \
		$(if $(LANG),--lang=$(LANG),) --out=report.html
