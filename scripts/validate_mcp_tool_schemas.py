#!/usr/bin/env python3
"""Validate optional per-skill MCP tool schema overlays.

Every skill that ships ``mcp_tool_schema.json`` must:
  - parse as JSON
  - declare draft 2020-12 in ``$schema``
  - be a top-level object with a ``properties`` mapping
  - avoid reserved wrapper property names
  - attach ``x-cli-flag`` or ``x-cli-style: positional`` to mappable fields

Exit codes: 0 on success, 1 on validation errors.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = REPO_ROOT / "skills"
SCHEMA_FILENAME = "mcp_tool_schema.json"
EXPECTED_SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"

sys.path.insert(0, str(REPO_ROOT / "mcp-server" / "src"))
from tool_registry import (  # noqa: E402
    WRAPPER_SCHEMA_PROPERTY_KEYS,
    discover_skills,
    load_skill_mcp_schema,
    tool_input_schema,
)


def _errors_for_schema_file(skill_dir: Path) -> list[str]:
    path = skill_dir / SCHEMA_FILENAME
    errors: list[str] = []

    try:
        payload = load_skill_mcp_schema(skill_dir)
    except json.JSONDecodeError as exc:
        return [f"{path.relative_to(REPO_ROOT)}: invalid JSON ({exc})"]
    except ValueError as exc:
        return [f"{path.relative_to(REPO_ROOT)}: {exc}"]

    if payload is None:
        return []

    rel = path.relative_to(REPO_ROOT)
    if payload.get("$schema") != EXPECTED_SCHEMA_URI:
        errors.append(f"{rel}: $schema must be {EXPECTED_SCHEMA_URI!r}")
    if payload.get("type") not in {None, "object"}:
        errors.append(f"{rel}: type must be 'object' when present")

    properties = payload.get("properties")
    if not isinstance(properties, dict) or not properties:
        errors.append(f"{rel}: properties must be a non-empty object")
        return errors

    for key in properties:
        if key in WRAPPER_SCHEMA_PROPERTY_KEYS:
            errors.append(f"{rel}: property {key!r} collides with wrapper schema")

    for key, spec in properties.items():
        if not isinstance(spec, dict):
            errors.append(f"{rel}: properties.{key} must be an object")
            continue
        has_flag = bool(spec.get("x-cli-flag"))
        is_positional = spec.get("x-cli-style") == "positional"
        if not has_flag and not is_positional:
            errors.append(f"{rel}: properties.{key} needs x-cli-flag or x-cli-style: positional")

    try:
        skill = next(s for s in discover_skills(REPO_ROOT) if s.skill_dir == skill_dir)
    except StopIteration:
        errors.append(f"{rel}: no SKILL.md registry entry for {skill_dir.name}")
        return errors

    merged = tool_input_schema(skill)
    merged_props = merged.get("properties")
    if not isinstance(merged_props, dict):
        errors.append(f"{rel}: merged schema missing properties")
    else:
        for key in properties:
            if key not in merged_props:
                errors.append(f"{rel}: merged schema dropped property {key!r}")

    return errors


def main() -> int:
    errors: list[str] = []
    for skill_dir in sorted(SKILLS_ROOT.glob("*/*/")):
        if not (skill_dir / SCHEMA_FILENAME).exists():
            continue
        errors.extend(_errors_for_schema_file(skill_dir))

    if errors:
        print("MCP tool schema validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("MCP tool schema validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
