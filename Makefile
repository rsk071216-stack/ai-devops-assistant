# Common developer commands. Everything runs offline; no API key or cluster needed.
# Requires uv (https://docs.astral.sh/uv/). `make help` lists the targets.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

UV := uv run --frozen

.PHONY: help setup lint fmt typecheck test eval check demo-ci demo-k8s demo-tf image clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

setup: ## Install the locked toolchain (incl. the optional MCP extra)
	uv sync --frozen --all-extras

lint: ## ruff (lint + format check) and yamllint
	$(UV) ruff check .
	$(UV) ruff format --check .
	$(UV) yamllint --strict .

fmt: ## Auto-format Python
	$(UV) ruff format .
	$(UV) ruff check --fix .

typecheck: ## mypy (strict)
	$(UV) mypy

test: ## pytest with the coverage gate
	$(UV) pytest --cov

eval: ## Offline eval gate (rules + mock) against evals/thresholds.json
	$(UV) aida eval --check

check: lint typecheck test eval ## Everything CI runs, locally

demo-ci: ## Triage a saved CI log, rules-only
	$(UV) aida ci-triage --log-file docs/examples/inputs/ci-failure.log --rules-only --explain

demo-k8s: ## Diagnose a saved CrashLoopBackOff/OOMKilled bundle, rules-only
	$(UV) aida k8s-diagnose --fixture docs/examples/inputs/k8s-oomkilled-bundle.json --rules-only --explain

demo-tf: ## Review a saved Terraform plan, rules-only
	$(UV) aida tf-review docs/examples/inputs/tf-plan-ssh-open.json --rules-only

image: ## Build the container image (needs Docker)
	docker build -t ai-devops-assistant:dev .

clean: ## Remove caches
	rm -rf .venv .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
