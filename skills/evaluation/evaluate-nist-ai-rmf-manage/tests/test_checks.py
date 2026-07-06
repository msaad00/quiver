"""Tests for evaluate-nist-ai-rmf-manage."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("nist_ai_rmf_manage_checks", _SRC)
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
        "review_cadence_days": 90,
        "last_reviewed": NOW.date().isoformat(),
        "evidence_uri": "https://wiki/ai-risk-register",
        "coverage": coverage,
        "resources": ["risk-register://airmf-2026"],
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

    def test_empty_subcategories_key_fails(self):
        findings = run_benchmark({"subcategories": {}}, now=NOW)
        assert {f.status for f in findings} == {STATUS_FAIL}

    def test_load_manifest_missing_path_is_empty(self):
        assert load_manifest(None) == {}
        assert load_manifest("") == {}


class TestMalformedPayload:
    def test_entry_must_be_mapping(self):
        manifest = {"subcategories": {"MANAGE-1.1": 123}}
        findings = run_benchmark(manifest, now=NOW)
        target = next(f for f in findings if f.control_id == "MANAGE-1.1")
        assert target.status == STATUS_ERROR

    def test_invalid_date_treated_as_missing_review(self):
        manifest = {
            "subcategories": {
                "MANAGE-1.1": {
                    "documented": True,
                    "review_cadence_days": 90,
                    "last_reviewed": "not-a-date",
                    "evidence_uri": "https://x",
                    "coverage": 1.0,
                }
            }
        }
        findings = run_benchmark(manifest, now=NOW)
        target = next(f for f in findings if f.control_id == "MANAGE-1.1")
        assert target.status == STATUS_FAIL

    def test_load_manifest_rejects_non_mapping_root(self, tmp_path: Path):
        path = tmp_path / "m.json"
        path.write_text(json.dumps("not a mapping"))
        with pytest.raises(ValueError):
            load_manifest(path)


class TestPartialPass:
    def test_documented_with_stale_review_is_partial(self):
        manifest = {
            "subcategories": {
                "MANAGE-1.1": {
                    "documented": True,
                    "review_cadence_days": 7,
                    "last_reviewed": "2025-01-01",
                    "evidence_uri": "https://x",
                    "coverage": 0.9,
                }
            }
        }
        findings = run_benchmark(manifest, now=NOW)
        target = next(f for f in findings if f.control_id == "MANAGE-1.1")
        assert target.status == STATUS_PARTIAL
        assert "stale" in target.detail

    def test_low_coverage_is_fail(self):
        manifest = {
            "subcategories": {
                "MANAGE-2.4": {
                    "documented": True,
                    "review_cadence_days": 365,
                    "last_reviewed": NOW.date().isoformat(),
                    "evidence_uri": "https://x",
                    "coverage": 0.1,
                }
            }
        }
        findings = run_benchmark(manifest, now=NOW)
        target = next(f for f in findings if f.control_id == "MANAGE-2.4")
        assert target.status == STATUS_FAIL


class TestPermissionDeniedAnalogue:
    def test_load_manifest_raises_on_missing_file(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_manifest(tmp_path / "nope.yaml")

    def test_main_returns_exit_code_2_on_missing_file(self, tmp_path: Path, capsys):
        rc = main([str(tmp_path / "nope.yaml")])
        assert rc == 2
        assert "Manifest not found" in capsys.readouterr().err

    def test_main_uses_env_var_when_arg_missing(self, tmp_path: Path, monkeypatch):
        path = tmp_path / "m.json"
        path.write_text(json.dumps(_all_passing_manifest()))
        monkeypatch.setenv(MANIFEST_ENV, str(path))
        assert main(["--output", "json"]) == 0


class TestMultiResourceHappyPath:
    def test_full_manifest_passes_all_subcategories(self):
        findings = run_benchmark(_all_passing_manifest(), now=NOW)
        assert len(findings) == len(IMPLEMENTED_SUBCATEGORIES)
        assert {f.status for f in findings} == {STATUS_PASS}

    def test_not_applicable_with_reason(self):
        manifest = {
            "subcategories": {
                "MANAGE-3.1": {
                    "not_applicable": True,
                    "not_applicable_reason": "No third-party AI components in the perimeter",
                }
            }
        }
        findings = run_benchmark(manifest, now=NOW)
        target = next(f for f in findings if f.control_id == "MANAGE-3.1")
        assert target.status == STATUS_NA


class TestSubcategoryFilter:
    def test_single_subcategory_returns_one_finding(self):
        findings = run_benchmark(
            _all_passing_manifest(),
            subcategory="MANAGE-2.4",
            now=NOW,
        )
        assert len(findings) == 1
        assert findings[0].control_id == "MANAGE-2.4"


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
        assert all(r["class_uid"] == 2003 for r in rendered)
        assert any(req.startswith("MANAGE:") for req in rendered[0]["compliance"]["requirements"])


class TestHonestyContract:
    def test_benchmark_metadata_declares_partial_coverage(self):
        metadata = benchmark_metadata()
        assert metadata["function"] == FUNCTION
        assert metadata["implemented_count"] == 10
        assert metadata["manifest_env"] == MANIFEST_ENV
        overlap = set(metadata["implemented_subcategories"]) & set(
            metadata["documented_not_implemented"]
        )
        assert overlap == set()

    def test_documented_not_implemented_constant_present(self):
        assert len(DOCUMENTED_NOT_IMPLEMENTED) > 0

    def test_skill_md_declares_implemented_subcategories(self):
        skill_md = Path(__file__).resolve().parents[1] / "SKILL.md"
        text = skill_md.read_text(encoding="utf-8")
        for sub_id, _, _, _ in IMPLEMENTED_SUBCATEGORIES:
            assert sub_id in text
        assert "10 of ~14" in text
