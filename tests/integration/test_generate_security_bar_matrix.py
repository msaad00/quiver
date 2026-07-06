"""Tests for `scripts/generate_security_bar_matrix.py` (#246).

Verifies:
  - The generated matrix is in sync with main (CI guarantee).
  - `--check` returns exit 1 when the committed file has drifted.
  - The generator handles missing markers cleanly.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "generate_security_bar_matrix.py"
SECURITY_BAR = REPO_ROOT / "SECURITY_BAR.md"


def _run(args: list[str], cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    # Resolve the script path relative to cwd so tests can isolate via tmp_path.
    script_path = cwd / "scripts" / "generate_security_bar_matrix.py"
    return subprocess.run(
        [sys.executable, str(script_path), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


class TestCheckMode:
    def test_check_passes_when_matrix_is_in_sync(self):
        result = _run(["--check"])
        assert result.returncode == 0, f"--check failed: stderr=\n{result.stderr}"
        assert "in sync" in result.stdout

    def test_check_fails_on_drift(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        # Copy the repo structure the script needs into a tmp dir, then mutate
        # SECURITY_BAR.md to create drift, and run `--check` against the clone.
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        (tmp_repo / "scripts").mkdir()
        (tmp_repo / "skills").mkdir()
        # Copy the script + its dependency
        for rel in (
            "scripts/generate_security_bar_matrix.py",
            "scripts/skill_validation_common.py",
        ):
            (tmp_repo / rel).write_text((REPO_ROOT / rel).read_text())
        # Minimal fake skill so discover_skill_contracts has something to enumerate.
        fake_skill_dir = tmp_repo / "skills" / "detection" / "detect-fake"
        fake_skill_dir.mkdir(parents=True)
        (fake_skill_dir / "SKILL.md").write_text(
            "---\n"
            "name: detect-fake\n"
            "description: fake skill for testing\n"
            "license: Apache-2.0\n"
            "approval_model: none\n"
            "execution_modes: jit\n"
            "side_effects: none\n"
            "input_formats: ocsf\n"
            "output_formats: ocsf\n"
            "concurrency_safety: stateless\n"
            "compatibility: test\n"
            "metadata:\n"
            "  author: test\n"
            "  version: 0.1.0\n"
            "  cloud: none\n"
            "  capability: read-only\n"
            "---\n"
            "# detect-fake\n"
        )
        (fake_skill_dir / "src").mkdir()
        (fake_skill_dir / "src" / "detect.py").write_text("# entrypoint\n")
        (fake_skill_dir / "tests").mkdir()
        (fake_skill_dir / "REFERENCES.md").write_text("# Refs\n")

        # Write SECURITY_BAR.md with markers but NO actual matrix content.
        (tmp_repo / "SECURITY_BAR.md").write_text(
            "# Security Bar\n\n"
            "## Per-skill matrix\n\n"
            "<!-- AUTO-GENERATED MATRIX START — do not edit by hand; run scripts/generate_security_bar_matrix.py -->\n"
            "<!-- AUTO-GENERATED MATRIX END -->\n"
        )
        result = _run(["--check"], cwd=tmp_repo)
        assert result.returncode == 1
        assert "out of sync" in result.stderr

    def test_missing_markers_raises(self, tmp_path: Path):
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        (tmp_repo / "scripts").mkdir()
        (tmp_repo / "skills").mkdir()
        for rel in (
            "scripts/generate_security_bar_matrix.py",
            "scripts/skill_validation_common.py",
        ):
            (tmp_repo / rel).write_text((REPO_ROOT / rel).read_text())
        # SECURITY_BAR.md without the markers
        (tmp_repo / "SECURITY_BAR.md").write_text("# Security Bar\n\nno markers here\n")
        result = _run([], cwd=tmp_repo)
        assert result.returncode != 0
        assert "AUTO-GENERATED markers" in result.stderr


class TestGeneratedContent:
    def test_every_skill_present(self):
        """Every SKILL.md on disk must have a row in the generated matrix."""
        content = SECURITY_BAR.read_text()
        on_disk = sorted(p.parent.name for p in REPO_ROOT.glob("skills/*/*/SKILL.md"))
        for name in on_disk:
            assert f"`{name}`" in content, f"{name} missing from SECURITY_BAR.md matrix"

    def test_matrix_row_count_matches_skill_count(self):
        content = SECURITY_BAR.read_text()
        # Count rows between the markers
        start = content.index("AUTO-GENERATED MATRIX START")
        end = content.index("AUTO-GENERATED MATRIX END")
        matrix = content[start:end]
        row_count = sum(1 for line in matrix.splitlines() if line.startswith("| `") and "|" in line)
        on_disk_count = sum(1 for _ in REPO_ROOT.glob("skills/*/*/SKILL.md"))
        assert row_count == on_disk_count, (
            f"matrix has {row_count} rows; {on_disk_count} skills on disk"
        )
