# Convenience commands. Run `make help` to list them.
PYTHON ?= python3
POLICY_DIR := policy/cis-aws
PLAN_JSON  := terraform/tfplan.json

.DEFAULT_GOAL := help
.PHONY: help test policy-test script-test plan check report dashboard all clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-12s %s\n", $$1, $$2}'

test: policy-test script-test ## Run all tests (no AWS needed)

policy-test: ## Run the Rego unit tests
	conftest verify --policy $(POLICY_DIR)

script-test: ## Run the Python unit tests
	$(PYTHON) -m unittest discover -s tests -v

plan: ## Create terraform/tfplan.json (needs AWS credentials)
	cd terraform && terraform init && terraform plan -out=tfplan.binary && terraform show -json tfplan.binary > tfplan.json

check: ## Evaluate the policies against the plan (raw Conftest output)
	conftest test $(PLAN_JSON) --policy $(POLICY_DIR)

report: ## Generate compliance-report.md (exit 1 = blocking violations)
	$(PYTHON) scripts/generate_report.py

dashboard: ## Generate dashboard.html
	$(PYTHON) scripts/generate_dashboard.py

all: test dashboard report ## Tests, dashboard, then report (report last: it exits 1 on violations)

clean: ## Remove generated report/dashboard (keeps your terraform plan)
	rm -f compliance-report.md dashboard.html
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
