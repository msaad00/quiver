"""Tests for `scripts/validate_skill_structure.py`.

The validator's job is to refuse half-built or stale skill directories
before they ship. We exercise it with a synthetic skills tree under
`tmp_path` so we never depend on the real on-disk layout.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_skill_structure.py"
spec = importlib.util.spec_from_file_location(
    "cloud_security_skill_structure_validator_test",
    SCRIPT_PATH,
)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = MODULE
spec.loader.exec_module(MODULE)


def _build_tree(root: Path, layout: dict[str, dict | str]) -> None:
    for name, value in layout.items():
        target = root / name
        if isinstance(value, dict):
            target.mkdir(parents=True, exist_ok=True)
            _build_tree(target, value)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(value, encoding="utf-8")


def _patch_paths(monkeypatch, fake_repo: Path) -> None:
    monkeypatch.setattr(MODULE, "REPO_ROOT", fake_repo)
    monkeypatch.setattr(MODULE, "SKILLS_ROOT", fake_repo / "skills")


def test_well_formed_repo_passes(tmp_path, monkeypatch):
    _build_tree(
        tmp_path,
        {
            "skills": {
                "detection": {
                    "detect-foo": {"SKILL.md": "frontmatter\n", "src": {"detect.py": ""}},
                },
                "_shared": {"identity.py": ""},
                "detection-engineering": {
                    "golden": {"some_fixture.jsonl": ""},
                    "OCSF_CONTRACT.md": "",
                    "README.md": "",
                },
            }
        },
    )
    _patch_paths(monkeypatch, tmp_path)
    assert MODULE._violations() == []


def test_skill_dir_without_skill_md_fails(tmp_path, monkeypatch):
    _build_tree(
        tmp_path,
        {
            "skills": {
                "detection": {
                    "detect-foo": {"src": {"detect.py": ""}},  # no SKILL.md
                }
            }
        },
    )
    _patch_paths(monkeypatch, tmp_path)
    errs = MODULE._violations()
    assert any("detect-foo: missing SKILL.md" in e for e in errs)


def test_pycache_only_subdir_under_exception_root_fails(tmp_path, monkeypatch):
    _build_tree(
        tmp_path,
        {
            "skills": {
                "detection-engineering": {
                    "golden": {"fixture.jsonl": ""},
                    "ghost": {
                        "src": {"__pycache__": {"x.cpython-313.pyc": "stale"}},
                        "tests": {"__pycache__": {"y.cpython-313.pyc": "stale"}},
                    },
                }
            }
        },
    )
    _patch_paths(monkeypatch, tmp_path)
    errs = MODULE._violations()
    assert any("ghost" in e and "empty subdirectory" in e for e in errs)


def test_doc_only_skill_dir_with_readme_but_no_skill_md_fails(tmp_path, monkeypatch):
    _build_tree(
        tmp_path,
        {
            "skills": {
                "detection": {
                    "halfway-skill": {"README.md": "draft", "src": {}},
                }
            }
        },
    )
    _patch_paths(monkeypatch, tmp_path)
    errs = MODULE._violations()
    assert any("halfway-skill" in e and "doc-only" in e for e in errs)


def test_unknown_skill_root_entry_fails(tmp_path, monkeypatch):
    _build_tree(
        tmp_path,
        {
            "skills": {
                "weird-category": {"detect-foo": {"SKILL.md": ""}},
            }
        },
    )
    _patch_paths(monkeypatch, tmp_path)
    errs = MODULE._violations()
    assert any("weird-category" in e for e in errs)


def test_repo_state_passes_today(monkeypatch):
    """Smoke check: the real on-disk repo (after `git clean -fdX`) passes
    the validator. Run with no monkeypatching so the validator sees the
    real REPO_ROOT.

    If this fails, a contributor likely needs to either run
    `git clean -fdX skills/detection-engineering/` to drop stale local
    pyc-only subtrees, or finish a half-built skill.
    """
    errs = MODULE._violations()
    assert errs == [], "\n".join(errs)
