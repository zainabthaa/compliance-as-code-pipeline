# Shortcuts for common tasks. Run "make help" to see them.
# Needs: terraform, conftest, python3 (and AWS login for "make plan").

.PHONY: help plan check report dashboard all clean

help: ## Show this list
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  make %-10s %s\n", $$1, $$2}'

plan: ## Run terraform plan and save it as terraform/tfplan.json (needs AWS login)
	cd terraform && terraform init && terraform plan -out=tfplan.binary && terraform show -json tfplan.binary > tfplan.json

check: ## Check the saved plan against the policies (failures are expected on the demo)
	conftest test terraform/tfplan.json --policy policy/cis-aws

report: ## Write compliance-report.md (exit code 1 if any violation)
	python3 scripts/generate_report.py

dashboard: ## Write dashboard.html
	python3 scripts/generate_dashboard.py

all: ## Report + dashboard (dashboard is built even if the report finds violations)
	-python3 scripts/generate_report.py
	python3 scripts/generate_dashboard.py

clean: ## Delete generated files
	rm -f compliance-report.md dashboard.html terraform/tfplan.binary
	rm -rf scripts/__pycache__
