#!/usr/bin/env python3
"""Fail closed on stale or half-built skill subdirectories.

Every directory under `skills/<category>/<name>/` is expected to be a
shipped skill bundle: it must carry a `SKILL.md`. The 2026-04-28 audit
surfaced a class of bug where a previous repo reorganization left empty
sibling directories under `skills/detection-engineering/` that contained
only `__pycache__/`. Those local-only artefacts confused contributors
and quietly broke the invariant `count(SKILL.md) == count(<skill dir>)`.

This validator walks the disk and refuses any skill-category subdir that
either:

  1. Lacks a `SKILL.md`, OR
  2. Is empty besides cache / dotfiles

…unless the directory matches an explicit allowlist (e.g. shared utils,
fixture roots, doc-only sibling dirs).

Run in CI next to the other `validate_*.py` scripts.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_ROOT = REPO_ROOT / "skills"

# Categories that follow the standard <category>/<skill>/SKILL.md layout.
STANDARD_CATEGORIES = (
    "detection",
    "discovery",
    "evaluation",
    "ingestion",
    "output",
    "remediation",
    "view",
)

# Sibling directories under `skills/` that are NOT skill-category roots.
# These hold shared utilities, golden fixtures, or doc indexes.
SKILL_ROOT_EXCEPTIONS: dict[str, set[str]] = {
    "_shared": set(),  # shared Python utility module — not a category
    "detection-engineering": {
        # Doc-only category alias. Three subdirectories carry real content:
        # `golden/` (synthetic snapshot fixtures), `captured/` (provenance-
        # tracked real-traffic fixtures, sibling honesty contract), and
        # `scoring/` (per-detector precision/recall corpus + scorer for
        # issue #419). Everything else here was retired during the 2026-Q1
        # reorg and the index page now points at the
        # `skills/{ingestion,view}/` siblings.
        "golden",
        "captured",
        "scoring",
    },
}

# Sentinel filenames whose presence demonstrates a directory is "real" even
# if SKILL.md is intentionally absent (e.g. golden fixture roots).
SENTINEL_NON_SKILL_FILES = ("OCSF_CONTRACT.md", "README.md")


def _is_cache_or_dotfile(name: str | Path) -> bool:
    """Match any path *segment* that is a cache or dotfile."""
    n = name.name if isinstance(name, Path) else name
    return n.startswith(".") or n == "__pycache__"


def _has_real_content(path: Path) -> bool:
    """True iff `path` contains any non-cache, non-dot file anywhere in
    its subtree. A directory whose only files are `*.pyc` under
    `__pycache__/` is treated as empty — that is the typical shape of
    a stale subtree left over from a `git mv` that didn't `git clean`."""
    if not path.exists():
        return False
    for child in path.rglob("*"):
        if child.is_dir():
            continue
        if any(_is_cache_or_dotfile(part) for part in child.relative_to(path).parts):
            continue
        return True
    return False


def _violations() -> list[str]:
    errs: list[str] = []
    for entry in sorted(SKILLS_ROOT.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name in SKILL_ROOT_EXCEPTIONS:
            allowed = SKILL_ROOT_EXCEPTIONS[entry.name]
            for child in sorted(entry.iterdir()):
                if not child.is_dir() or _is_cache_or_dotfile(child):
                    continue
                if child.name in allowed:
                    continue
                # Anything not allowlisted under an exception root must
                # either be a real skill (with SKILL.md) or be empty in
                # the working tree.
                if (child / "SKILL.md").is_file():
                    continue
                if not _has_real_content(child):
                    errs.append(
                        f"{child.relative_to(REPO_ROOT)}: empty subdirectory "
                        f"under exception root `skills/{entry.name}/`. Either "
                        f"add a SKILL.md, add it to SKILL_ROOT_EXCEPTIONS, or "
                        f"`git clean -fdX` it locally — it is not a shipped skill."
                    )
                else:
                    errs.append(
                        f"{child.relative_to(REPO_ROOT)}: subdirectory under "
                        f"`skills/{entry.name}/` has content but no SKILL.md."
                    )
            continue
        if entry.name in STANDARD_CATEGORIES:
            for skill_dir in sorted(entry.iterdir()):
                if not skill_dir.is_dir() or _is_cache_or_dotfile(skill_dir):
                    continue
                skill_md = skill_dir / "SKILL.md"
                if not skill_md.is_file():
                    if any(
                        (skill_dir / sentinel).is_file() for sentinel in SENTINEL_NON_SKILL_FILES
                    ):
                        errs.append(
                            f"{skill_dir.relative_to(REPO_ROOT)}: missing SKILL.md "
                            f"but has README/contract — looks like a doc-only "
                            f"sibling. Move it under `docs/` or finish the skill."
                        )
                    else:
                        errs.append(
                            f"{skill_dir.relative_to(REPO_ROOT)}: missing SKILL.md. "
                            f"Every directory under `skills/{entry.name}/` must be "
                            f"a shipped skill bundle."
                        )
            continue
        errs.append(
            f"{entry.relative_to(REPO_ROOT)}: unknown skill-root entry. Add "
            f"`{entry.name}` to STANDARD_CATEGORIES or SKILL_ROOT_EXCEPTIONS."
        )
    return errs


def main() -> int:
    errs = _violations()
    if errs:
        sys.stderr.write("Skill structure validation failed:\n")
        for line in errs:
            sys.stderr.write(f"  - {line}\n")
        return 1
    print("Skill structure validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
