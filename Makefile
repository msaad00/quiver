## Convenience targets for contributors. CI does not depend on this
## file — every command below has a direct shell-script equivalent
## documented in `CONTRIBUTING.md`.

.PHONY: help docs-regen docs-check validate test ruff

help:
	@echo "Common targets:"
	@echo "  make docs-regen  — regenerate every auto-generated doc (run after editing framework-coverage.json or adding a skill)"
	@echo "  make docs-check  — exit 1 if any auto-generated doc is stale (mirrors the CI gate)"
	@echo "  make validate    — run every shared validator under scripts/"
	@echo "  make test        — pytest repo-wide"
	@echo "  make ruff        — lint everything CI lints"

docs-regen:
	@echo "Regenerating auto-generated docs..."
	python scripts/generate_framework_coverage_doc.py
	python scripts/generate_security_bar_matrix.py
	python scripts/coverage_summary.py --write
	@echo ""
	@echo "Now run \`git status\` and stage any updated files:"
	@echo "  docs/FRAMEWORK_COVERAGE.md"
	@echo "  SECURITY_BAR.md"
	@echo "  docs/COVERAGE_SNAPSHOT.md"

docs-check:
	@set -e; \
	python scripts/generate_framework_coverage_doc.py --check; \
	python scripts/generate_security_bar_matrix.py --check; \
	python scripts/coverage_summary.py --check

validate:
	python scripts/validate_skill_contract.py
	python scripts/validate_skill_integrity.py
	python scripts/validate_skill_runtime.py
	python scripts/validate_skill_structure.py
	python scripts/validate_presets.py
	python scripts/validate_dependency_consistency.py
	python scripts/validate_framework_coverage.py
	python scripts/validate_ocsf_metadata.py
	python scripts/validate_skill_count_consistency.py
	python scripts/validate_deny_list_parity.py
	$(MAKE) docs-check

test:
	python -m pytest -q --no-header --tb=line

ruff:
	ruff check skills/ tests/ mcp-server/ scripts/ --config pyproject.toml
