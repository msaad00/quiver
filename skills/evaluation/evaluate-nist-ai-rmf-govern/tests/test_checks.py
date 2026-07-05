"""Tests for evaluate-nist-ai-rmf-govern.

Per the #405 evaluation-skill test standard, each check covers at least
five scenarios: empty input, malformed payload, partial-pass, missing
manifest (permission-denied analogue for a read-only skill), and a
multi-resource happy path. Helper-level tests assert the OCSF projection
and benchmark metadata honesty contract.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("nist_ai_rmf_govern_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)

BENCHMARK_NAME = _CHECKS.BENCHMARK_NAME
DOCUMENTED_NOT_IMPLEMENTED = _CHECKS.DOCUMENTED_NOT_IMPLEMENTED
FRAMEWORKS = _CHECKS.FRAMEWORKS
FUNCTION = _CHECKS.FUNCTION
IMPLEMENTED_SUBCATEGORIES = _CHECKS.IMPLEMENTED_SUBCATEGORIES
MANIFEST_ENV = _CHECKS.MANIFEST_ENV
PROVIDER_NAME = _CHECKS.PROVIDER_NAME
SKILL_NAME = _CHECKS.SKILL_NAME
STATUS_ERROR = _CHECKS.STATUS_ERROR
STATUS_FAIL = _CHECKS.STATUS_FAIL
STATUS_NA = _CHECKS.STATUS_NA
STATUS_PARTIAL = _CHECKS.STATUS_PARTIAL
STATUS_PASS = _CHECKS.STATUS_PASS
benchmark_metadata = _CHECKS.benchmark_metadata
findings_to_ocsf = _CHECKS.findings_to_ocsf
load_manifest = _CHECKS.load_manifest
main = _CHECKS.main
run_benchmark = _CHECKS.run_benchmark

NOW = datetime(2026, 5, 10, tzinfo=UTC)


def _full_entry(*, coverage: float = 1.0) -> dict[str, object]:
    return {
        "documented": True,
        "review_cadence_days": 365,
        "last_reviewed": NOW.date().isoformat(),
        "evidence_uri": "s3://ai-rmf/govern.pdf",
        "coverage": coverage,
        "resources": ["policy://ai-risk-mgmt-v3", "wiki://ai-rmf-roles"],
    }


def _all_passing_manifest() -> dict[str, object]:
    return {
        "subcategories": {sub_id: _full_entry() for sub_id, _, _, _ in IMPLEMENTED_SUBCATEGORIES}
    }


class TestEmptyInput:
    def test_empty_manifest_fails_every_subcategory(self):
        findings = run_benchmark({}, now=NOW)
        assert len(findings) == len(IMPLEMENTED_SUBCATEGORIES)
        assert all(f.status == STATUS_FAIL for f in findings)
        assert all("No manifest entry" in f.detail for f in findings)

    def test_empty_subcategories_key_fails(self):
        findings = run_benchmark({"subcategories": {}}, now=NOW)
        assert {f.status for f in findings} == {STATUS_FAIL}

    def test_load_manifest_missing_path_is_empty(self):
        assert load_manifest(None) == {}
        assert load_manifest("") == {}


class TestMalformedPayload:
    def test_entry_must_be_mapping(self):
        manifest = {"subcategories": {"GOVERN-1.1": "not-a-mapping"}}
        findings = run_benchmark(manifest, now=NOW)
        target = next(f for f in findings if f.control_id == "GOVERN-1.1")
        assert target.status == STATUS_ERROR
        assert "must be a mapping" in target.detail

    def test_invalid_date_treated_as_missing_review(self):
        manifest = {
            "subcategories": {
                "GOVERN-1.1": {
                    "documented": True,
                    "review_cadence_days": 365,
                    "last_reviewed": "not-a-date",
                    "evidence_uri": "s3://x",
                    "coverage": 1.0,
                }
            }
        }
        findings = run_benchmark(manifest, now=NOW)
        target = next(f for f in findings if f.control_id == "GOVERN-1.1")
        assert target.status == STATUS_FAIL
        assert "missing last_reviewed" in target.detail

    def test_load_manifest_rejects_non_mapping_root(self, tmp_path: Path):
        path = tmp_path / "m.json"
        path.write_text(json.dumps(["not", "a", "mapping"]))
        with pytest.raises(ValueError):
            load_manifest(path)


class TestPartialPass:
    def test_documented_with_stale_review_is_partial(self):
        manifest = {
            "subcategories": {
                "GOVERN-1.1": {
                    "documented": True,
                    "review_cadence_days": 30,
                    "last_reviewed": "2025-01-01",
                    "evidence_uri": "s3://x",
                    "coverage": 0.9,
                }
            }
        }
        findings = run_benchmark(manifest, now=NOW)
        target = next(f for f in findings if f.control_id == "GOVERN-1.1")
        assert target.status == STATUS_PARTIAL
        assert "stale" in target.detail

    def test_low_coverage_is_fail_not_partial(self):
        manifest = {
            "subcategories": {
                "GOVERN-1.6": {
                    "documented": True,
                    "review_cadence_days": 365,
                    "last_reviewed": NOW.date().isoformat(),
                    "evidence_uri": "s3://x",
                    "coverage": 0.1,
                }
            }
        }
        findings = run_benchmark(manifest, now=NOW)
        target = next(f for f in findings if f.control_id == "GOVERN-1.6")
        # documented=True but coverage<0.5 and last_reviewed fresh -> still FAIL
        # because the partial gate requires coverage>=0.5
        assert target.status == STATUS_FAIL
        assert "coverage" in target.detail


class TestPermissionDeniedAnalogue:
    """A read-only skill has no cloud auth — the analogue is a missing or unreadable manifest."""

    def test_load_manifest_raises_on_missing_file(self, tmp_path: Path):
        missing = tmp_path / "nope.yaml"
        with pytest.raises(FileNotFoundError):
            load_manifest(missing)

    def test_main_returns_exit_code_2_on_missing_file(self, tmp_path: Path, capsys):
        missing = tmp_path / "nope.yaml"
        rc = main([str(missing)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "Manifest not found" in err

    def test_main_uses_env_var_when_arg_missing(self, tmp_path: Path, monkeypatch):
        path = tmp_path / "m.json"
        path.write_text(json.dumps(_all_passing_manifest()))
        monkeypatch.setenv(MANIFEST_ENV, str(path))
        rc = main(["--output", "json"])
        assert rc == 0


class TestMultiResourceHappyPath:
    def test_full_manifest_passes_all_subcategories(self):
        findings = run_benchmark(_all_passing_manifest(), now=NOW)
        assert len(findings) == len(IMPLEMENTED_SUBCATEGORIES)
        statuses = {f.status for f in findings}
        assert statuses == {STATUS_PASS}
        # Each passing finding cites at least one resource
        assert all(len(f.resources) >= 1 for f in findings)
        # Severity stays declared
        severities = {f.severity for f in findings}
        assert severities <= {"HIGH", "MEDIUM"}

    def test_not_applicable_with_reason(self):
        manifest = {
            "subcategories": {
                "GOVERN-3.1": {
                    "not_applicable": True,
                    "not_applicable_reason": "No external impacted communities for internal-only model",
                }
            }
        }
        findings = run_benchmark(manifest, now=NOW)
        target = next(f for f in findings if f.control_id == "GOVERN-3.1")
        assert target.status == STATUS_NA
        assert "internal-only" in target.detail


class TestSubcategoryFilter:
    def test_single_subcategory_returns_one_finding(self):
        findings = run_benchmark(
            _all_passing_manifest(),
            subcategory="GOVERN-1.1",
            now=NOW,
        )
        assert len(findings) == 1
        assert findings[0].control_id == "GOVERN-1.1"

    def test_unknown_subcategory_filter_returns_zero(self):
        findings = run_benchmark(
            _all_passing_manifest(),
            subcategory="GOVERN-99.99",
            now=NOW,
        )
        assert findings == []


class TestOcsfProjection:
    def test_findings_render_as_compliance_findings(self):
        findings = run_benchmark(_all_passing_manifest(), now=NOW)
        rendered = findings_to_ocsf(
            findings,
            skill_name=SKILL_NAME,
            benchmark_name=BENCHMARK_NAME,
            provider=PROVIDER_NAME,
            frameworks=list(FRAMEWORKS),
        )
        assert len(rendered) == len(IMPLEMENTED_SUBCATEGORIES)
        sample = rendered[0]
        assert sample["class_uid"] == 2003
        assert sample["category_uid"] == 2
        assert sample["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        # OCSF requirements must carry the subcategory ID
        assert any(req.startswith("GOVERN:") for req in sample["compliance"]["requirements"])

    def test_failing_finding_has_failure_status_id(self):
        findings = run_benchmark({}, now=NOW)
        rendered = findings_to_ocsf(
            findings,
            skill_name=SKILL_NAME,
            benchmark_name=BENCHMARK_NAME,
            provider=PROVIDER_NAME,
            frameworks=list(FRAMEWORKS),
        )
        # FAIL maps to status_id 2 in the shared OCSF projection.
        assert all(item["status_id"] == 2 for item in rendered)


class TestHonestyContract:
    def test_benchmark_metadata_declares_partial_coverage(self):
        metadata = benchmark_metadata()
        assert metadata["function"] == FUNCTION
        assert metadata["implemented_count"] == 10
        assert metadata["manifest_env"] == MANIFEST_ENV
        assert metadata["documented_not_implemented"]
        # Implemented + documented-not-implemented must not overlap
        overlap = set(metadata["implemented_subcategories"]) & set(
            metadata["documented_not_implemented"]
        )
        assert overlap == set()
        assert "NIST AI RMF 1.0" in metadata["frameworks"]

    def test_documented_not_implemented_constant_present(self):
        assert len(DOCUMENTED_NOT_IMPLEMENTED) > 0

    def test_skill_md_declares_implemented_subcategories(self):
        skill_md = Path(__file__).resolve().parents[1] / "SKILL.md"
        text = skill_md.read_text(encoding="utf-8")
        for sub_id, _, _, _ in IMPLEMENTED_SUBCATEGORIES:
            assert sub_id in text, f"SKILL.md must mention {sub_id}"
        # Honest scope clause
        assert "10 of ~25" in text or "10 of ~" in text
