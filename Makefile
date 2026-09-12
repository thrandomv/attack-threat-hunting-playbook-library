# Detection content is code. These are the commands CI runs.
PYTHON ?= python3

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	 awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: check
check: selftest test validate build-check ## Everything CI runs

.PHONY: test
test: ## Run the Sigma unit-test suite
	$(PYTHON) scripts/run_tests.py

.PHONY: test-verbose
test-verbose: ## Run the suite, printing every case
	$(PYTHON) scripts/run_tests.py -v

.PHONY: selftest
selftest: ## Verify the Sigma evaluation engine itself
	$(PYTHON) scripts/run_tests.py --selftest

.PHONY: validate
validate: ## Structural, schema, ATT&CK and Atomic validation
	$(PYTHON) scripts/validate.py

.PHONY: build
build: ## Regenerate every derived artefact from playbook frontmatter
	$(PYTHON) scripts/build.py

.PHONY: build-check
build-check: ## Fail if any generated artefact is stale
	$(PYTHON) scripts/build.py --check

.PHONY: refresh
refresh: ## Re-pin the ATT&CK and Atomic Red Team snapshots from upstream (needs network)
	$(PYTHON) scripts/fetch_attack_reference.py
	$(PYTHON) scripts/fetch_atomic_index.py
	$(PYTHON) scripts/build.py

.PHONY: lint
lint: ## Lint YAML rules and fixtures
	yamllint rules/sigma tests/rules .github

.PHONY: sigma-convert
sigma-convert: ## Smoke-test Sigma conversion with sigma-cli (needs plugins installed)
	sigma check rules/sigma/
	sigma convert -t splunk rules/sigma/TH-001-lsass-memory-access.yml || true

.PHONY: site-src
site-src: build ## Assemble the documentation site source tree
	rm -rf site-src
	mkdir -p site-src
	cp README.md site-src/index.md
	cp CHANGELOG.md CONTRIBUTING.md SECURITY.md DISCLAIMER.md NOTICE.md CODE_OF_CONDUCT.md site-src/
	cp -r docs playbooks mappings validation queries rules tests scripts templates site-src/
	cp LICENSE site-src/LICENSE.md

.PHONY: site
site: site-src ## Serve the documentation site locally
	mkdocs serve

.PHONY: package
package: check ## Build a release ZIP
	$(PYTHON) scripts/package.py

.PHONY: clean
clean: ## Remove build output
	rm -rf site site-src dist __pycache__ scripts/__pycache__
