## Convenience targets for contributors. CI does not depend on this
## file — every command below has a direct shell-script equivalent
## documented in `CONTRIBUTING.md`.

.PHONY: help docs-regen docs-check validate test ruff agent-evals demo

help:
	@echo "Common targets:"
	@echo "  make demo        — run the captured-fixture ingest→detect→view pipeline (no cloud creds)"
	@echo "  make docs-regen  — regenerate every auto-generated doc (run after editing framework-coverage.json or adding a skill)"
	@echo "  make docs-check  — exit 1 if any auto-generated doc is stale (mirrors the CI gate)"
	@echo "  make validate    — run every shared validator under scripts/"
	@echo "  make test        — pytest repo-wide"
	@echo "  make ruff        — lint everything CI lints"
	@echo "  make agent-evals — run agent example tests and LangGraph harness evals"

demo:
	@echo "Running 3-step ingest -> detect -> view pipeline on a captured CloudTrail fixture..."
	@python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py \
	        skills/detection-engineering/golden/cloudtrail_raw_sample.jsonl \
	  | python skills/detection/detect-aws-access-key-creation/src/detect.py \
	  | python skills/view/convert-ocsf-to-sarif/src/convert.py \
	  > /tmp/cloud-security-demo.sarif
	@echo ""
	@echo "Findings written to /tmp/cloud-security-demo.sarif"
	@python -c "import json; d=json.load(open('/tmp/cloud-security-demo.sarif')); rs=d['runs'][0]['results']; print(f'{len(rs)} finding(s) emitted'); [print(f\"  - {r['ruleId']}: {r['message']['text']}\") for r in rs]"

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
	python scripts/validate_doc_counts.py
	python scripts/validate_doc_parity.py
	python scripts/validate_deny_list_parity.py
	python scripts/validate_captured_provenance.py
	python scripts/add_skill_trust_frontmatter.py --check
	python scripts/validate_safe_skill_bar.py
	python scripts/validate_golden_ocsf.py
	python scripts/check_secret_literals.py
	$(MAKE) docs-check

test:
	python -m pytest -q --no-header --tb=line

ruff:
	ruff check skills/ tests/ mcp-server/ scripts/ --config pyproject.toml

agent-evals:
	ruff check examples/agents --config pyproject.toml
	python -m pytest examples/agents/tests -q
	python examples/agents/eval_langgraph_harness.py --check
