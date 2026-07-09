"""Tests for `scripts/coverage_summary.py`.

The script is a deterministic generator: same `framework-coverage.json`
should always produce the same `COVERAGE_SNAPSHOT.md`. The CI gate
(`--check`) refuses any PR where the doc has drifted from the JSON.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "coverage_summary.py"
spec = importlib.util.spec_from_file_location("cloud_security_coverage_summary_test", SCRIPT)
assert spec and spec.loader
COV = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = COV
spec.loader.exec_module(COV)


def test_check_mode_passes_on_real_repo():
    """Regression: the on-disk snapshot must match what the script
    regenerates from `framework-coverage.json`. If this fails, run
    `python scripts/coverage_summary.py --write` and commit."""
    assert COV.main(["--check"]) == 0


def test_render_includes_total_count():
    skills = COV._load()
    rendered = COV.render(skills)
    assert f"**Total shipped skills:** {len(skills)}" in rendered


def test_render_lists_every_provider_in_input():
    skills = COV._load()
    rendered = COV.render(skills)
    providers = set()
    for s in skills:
        providers.update(s.get("providers", []))
    for key in providers:
        label = COV.PROVIDER_LABEL.get(key, key)
        assert label in rendered, f"provider `{key}` ({label}) missing from snapshot"


def test_render_lists_every_framework_in_input():
    skills = COV._load()
    rendered = COV.render(skills)
    frameworks = set()
    for s in skills:
        frameworks.update(s.get("frameworks", []))
    for key in frameworks:
        label = COV.FRAMEWORK_LABEL.get(key, key)
        assert label in rendered, f"framework `{key}` ({label}) missing from snapshot"


def test_render_is_deterministic():
    skills = COV._load()
    a = COV.render(skills)
    b = COV.render(skills)
    assert a == b


def test_check_fails_when_snapshot_is_stale(tmp_path, monkeypatch):
    """Simulate drift by pointing the script at a tmpdir snapshot
    that doesn't match what the script would regenerate."""
    fake_snapshot = tmp_path / "stale.md"
    fake_snapshot.write_text("# Coverage Snapshot\n\nstale content\n", encoding="utf-8")
    monkeypatch.setattr(COV, "SNAPSHOT_MD", fake_snapshot)
    assert COV.main(["--check"]) == 1


def test_check_fails_when_snapshot_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(COV, "SNAPSHOT_MD", tmp_path / "does-not-exist.md")
    assert COV.main(["--check"]) == 1


def test_write_mode_creates_snapshot(tmp_path, monkeypatch):
    target = tmp_path / "out.md"
    monkeypatch.setattr(COV, "SNAPSHOT_MD", target)
    assert COV.main(["--write"]) == 0
    assert target.is_file()
    body = target.read_text(encoding="utf-8")
    assert body.startswith("# Coverage Snapshot")
    # Idempotency: --check on the just-written file must pass.
    assert COV.main(["--check"]) == 0


def test_per_control_coverage_extracts_real_cspm_ids():
    """The CSPM benchmark skills ship a checks.py with explicit
    `control_id` literals. The coverage-summary parser should pull
    them out and bucket them by framework. Lower bounds — counts may
    grow but should never shrink without a deliberate change."""
    aws_controls = COV._controls_in_skill("skills/evaluation/cspm-aws-cis-benchmark")
    gcp_controls = COV._controls_in_skill("skills/evaluation/cspm-gcp-cis-benchmark")
    azure_controls = COV._controls_in_skill("skills/evaluation/cspm-azure-cis-benchmark")
    assert len(aws_controls.get("_cis_numeric", set())) >= 15
    assert len(gcp_controls.get("_cis_numeric", set())) >= 5
    assert len(azure_controls.get("_cis_numeric", set())) >= 5


def test_owasp_and_nist_depth_markers_are_discovered():
    skills = COV._load()
    by_fw = COV._bucket_controls_by_framework(skills)
    assert len(by_fw.get("owasp-llm-top-10", set())) >= 5
    assert len(by_fw.get("owasp-mcp-top-10", set())) >= 3
    assert len(by_fw.get("nist-ai-rmf", set())) >= 40


def test_per_control_coverage_table_appears_for_real_repo():
    skills = COV._load()
    rendered = COV.render(skills)
    assert "## Per-framework control coverage" in rendered
    aws = COV._controls_in_skill("skills/evaluation/cspm-aws-cis-benchmark")
    aws_count = len(aws.get("_cis_numeric", set()))
    assert f"| CIS AWS v3 | {aws_count} | 58 |" in rendered


def test_per_control_coverage_omits_frameworks_not_in_input(tmp_path, monkeypatch):
    """Only render rows for frameworks the input actually claims via
    `frameworks` or via discovered control IDs — synthetic / smaller
    deployments do not see a wall of '0/N' rows for frameworks they
    don't touch."""
    synthetic = tmp_path / "framework-coverage.json"
    synthetic.write_text(
        json.dumps(
            {
                "skills": [
                    {
                        "path": "skills/evaluation/cspm-aws-cis-benchmark",
                        "layer": "evaluation",
                        "providers": ["aws"],
                        "frameworks": ["cis-aws-v3"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(COV, "COVERAGE_JSON", synthetic)
    rendered = COV.render(COV._load())
    assert "CIS AWS v3" in rendered
    assert "CIS Kubernetes" not in rendered


def test_synthetic_skills_render_known_buckets(tmp_path, monkeypatch):
    """Feed a hand-built `framework-coverage.json` so the test does not
    depend on the live repo state. Confirms the bucketing logic."""
    synthetic = tmp_path / "framework-coverage.json"
    synthetic.write_text(
        json.dumps(
            {
                "skills": [
                    {
                        "path": "skills/x/y",
                        "layer": "detection",
                        "providers": ["aws"],
                        "frameworks": ["mitre-attack-v14", "cis-aws-v3"],
                    },
                    {
                        "path": "skills/x/z",
                        "layer": "ingestion",
                        "providers": ["aws", "gcp"],
                        "frameworks": ["ocsf-1.8"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(COV, "COVERAGE_JSON", synthetic)
    skills = COV._load()
    assert len(skills) == 2
    rendered = COV.render(skills)
    assert "AWS | 2 | 100.0%" in rendered  # both skills target AWS
    assert "GCP | 1 | 50.0%" in rendered
    assert "Kubernetes" not in rendered  # not in the input
    assert "**Total shipped skills:** 2" in rendered
