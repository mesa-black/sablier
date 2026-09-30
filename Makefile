.DEFAULT_GOAL := help
.PHONY: help test scan demo

help: ## Afficher cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

test: ## Vérifier que le modèle de risque discrimine encore
	@./tests/run.sh

demo: ## Scanner le jeu d'essai et ouvrir le rapport
	@./bin/sablier scan tests/fixtures/sample --out=report.html || true
	@open report.html 2>/dev/null || true

scan: ## Scanner un projet : make scan DIR=/chemin [DECLARE=fichier.json]
	@test -n "$(DIR)" || { echo "make scan DIR=/chemin"; exit 1; }
	@./bin/sablier scan "$(DIR)" $(if $(DECLARE),--declare=$(DECLARE),) --out=report.html
