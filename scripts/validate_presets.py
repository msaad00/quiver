#!/usr/bin/env python3
"""Verify every entry in `presets/*.json` is a real shipped skill name.

A preset is a named MCP tool allowlist. If a preset references a skill
name that no SKILL.md declares, the agent loop loads a no-op set —
silently. This validator catches the drift at PR time.

Bar:
  1. Every preset file under `presets/` is valid JSON with `name`,
     `description`, and `allowed_skills` keys.
  2. `allowed_skills` is a non-empty list of strings.
  3. Every name resolves to a `SKILL.md` `name:` field on disk.
  4. No duplicate entries inside a single preset.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PRESETS_ROOT = REPO_ROOT / "presets"
sys.path.insert(0, str(REPO_ROOT / "mcp-server" / "src"))

from tool_registry import discover_skills  # noqa: E402  pylint: disable=wrong-import-position

REQUIRED_KEYS = ("name", "description", "allowed_skills")


def _label(path: Path) -> str:
    """Path label that gracefully handles tmp_path / arbitrary roots in tests."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _shipped_skill_names() -> set[str]:
    return {skill.name for skill in discover_skills(REPO_ROOT)}


def _validate_preset(path: Path, shipped: set[str]) -> list[str]:
    errs: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{_label(path)}: invalid JSON: {exc}"]
    if not isinstance(data, dict):
        return [f"{_label(path)}: top level must be an object"]
    for key in REQUIRED_KEYS:
        if key not in data:
            errs.append(f"{_label(path)}: missing required key `{key}`")
    if errs:
        return errs
    allowed = data["allowed_skills"]
    if not isinstance(allowed, list) or not allowed:
        errs.append(
            f"{_label(path)}: `allowed_skills` must be a non-empty list"
        )
        return errs
    seen: set[str] = set()
    for entry in allowed:
        if not isinstance(entry, str):
            errs.append(
                f"{_label(path)}: `allowed_skills` entry {entry!r} is not a string"
            )
            continue
        if entry in seen:
            errs.append(
                f"{_label(path)}: duplicate entry `{entry}` in `allowed_skills`"
            )
        seen.add(entry)
        if entry not in shipped:
            errs.append(
                f"{_label(path)}: unknown skill `{entry}` — "
                f"no SKILL.md on disk declares this name. Did the skill get renamed?"
            )
    return errs


def main() -> int:
    if not PRESETS_ROOT.is_dir():
        print(f"presets directory missing: {PRESETS_ROOT}", file=sys.stderr)
        return 1
    shipped = _shipped_skill_names()
    paths = sorted(PRESETS_ROOT.glob("*.json"))
    if not paths:
        print(f"no preset JSON files found under {PRESETS_ROOT}", file=sys.stderr)
        return 1
    all_errors: list[str] = []
    for path in paths:
        all_errors.extend(_validate_preset(path, shipped))
    if all_errors:
        sys.stderr.write("Preset validation failed:\n")
        for line in all_errors:
            sys.stderr.write(f"  - {line}\n")
        return 1
    print(f"Preset validation passed: {len(paths)} preset(s), all skill names resolve.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
