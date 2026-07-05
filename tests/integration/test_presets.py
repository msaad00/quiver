"""Tests for `scripts/validate_presets.py` and the shipped preset files.

The presets are an operator-facing contract: load a preset's
`allowed_skills` into `CLOUD_SECURITY_MCP_ALLOWED_SKILLS` and the agent
loop is scoped to that set. If a preset references a skill that no
longer ships (rename, deletion, layout drift), the agent silently runs
with a no-op allowlist. These tests fail closed on any of those drifts.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PRESETS_ROOT = REPO_ROOT / "presets"
SCRIPT = REPO_ROOT / "scripts" / "validate_presets.py"

spec = importlib.util.spec_from_file_location("cloud_security_validate_presets_test", SCRIPT)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = MODULE
spec.loader.exec_module(MODULE)


def test_at_least_four_shipped_presets():
    """The repo must ship the four canonical presets named in
    docs/SKILL_COMPOSITION.md so each integration doc has a referenceable
    allowlist."""
    names = {p.stem for p in PRESETS_ROOT.glob("*.json")}
    expected = {
        "preset-cspm-readonly",
        "preset-detection-only",
        "preset-incident-response",
        "preset-ai-runtime",
    }
    missing = expected - names
    assert not missing, f"missing canonical presets: {sorted(missing)}"


def test_validate_presets_passes_on_real_repo():
    assert MODULE.main() == 0


def test_each_preset_skill_name_resolves_on_disk():
    shipped = MODULE._shipped_skill_names()
    for path in sorted(PRESETS_ROOT.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for skill in data["allowed_skills"]:
            assert skill in shipped, (
                f"{path.name}: skill {skill!r} not present on disk; "
                f"either fix the preset or remove the skill cleanly."
            )


def test_incident_response_preset_includes_workflow_pointer():
    """A preset that authorizes a write path must reference its workflow
    doc so the operator can read why the write fires."""
    data = json.loads((PRESETS_ROOT / "preset-incident-response.json").read_text())
    assert "workflow" in data
    assert (REPO_ROOT / data["workflow"]).is_file()


def test_validator_catches_unknown_skill(tmp_path, monkeypatch):
    bad = tmp_path / "preset-bad.json"
    bad.write_text(
        json.dumps(
            {
                "name": "bad",
                "description": "references a skill that does not exist",
                "allowed_skills": ["this-skill-does-not-exist"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(MODULE, "PRESETS_ROOT", tmp_path)
    assert MODULE.main() == 1


def test_validator_catches_duplicate_entries(tmp_path, monkeypatch):
    dup = tmp_path / "preset-dup.json"
    # Use a real shipped skill so the only error is the duplicate, not a missing-skill noise hit.
    dup.write_text(
        json.dumps(
            {
                "name": "dup",
                "description": "duplicate entry",
                "allowed_skills": [
                    "convert-ocsf-to-sarif",
                    "convert-ocsf-to-sarif",
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(MODULE, "PRESETS_ROOT", tmp_path)
    assert MODULE.main() == 1
