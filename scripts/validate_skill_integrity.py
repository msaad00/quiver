from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Protocol

from skill_validation_common import (
    ROOT,
    discover_skill_contracts,
    extract_reference_urls,
    reference_url_allowed,
)

DANGEROUS_CODE_PATTERNS: dict[str, str] = {
    r"\beval\(": "eval() is not allowed in shipped skill code",
    r"(?<!\.)\bexec\(": "exec() is not allowed in shipped skill code",
    r"\bpickle\.loads\(": "pickle.loads() is not allowed in shipped skill code",
    r"\byaml\.load\(": "yaml.load() is not allowed; use yaml.safe_load() if needed",
    r"\bmarshal\.loads\(": "marshal.loads() is not allowed in shipped skill code",
}


class _ToolRegistryModule(Protocol):
    def discover_skills(self, root: Path) -> list["_RegistrySkill"]: ...


class _RegistrySkill(Protocol):
    name: str
    description: str
    supported: bool


def _load_tool_registry() -> _ToolRegistryModule:
    path = ROOT / "mcp-server" / "src" / "tool_registry.py"
    spec = importlib.util.spec_from_file_location("cloud_security_tool_registry_integrity", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate_unique_names() -> list[str]:
    errors: list[str] = []
    seen: dict[str, Path] = {}
    for skill in discover_skill_contracts():
        if not skill.name:
            continue
        previous = seen.get(skill.name)
        if previous:
            errors.append(
                f"{skill.skill_dir.relative_to(ROOT)}: duplicate skill name `{skill.name}`"
                f" already used by {previous.relative_to(ROOT)}"
            )
        else:
            seen[skill.name] = skill.skill_dir
    return errors


def validate_name_to_path_alignment() -> list[str]:
    errors: list[str] = []
    for skill in discover_skill_contracts():
        rel = skill.skill_dir.relative_to(ROOT)
        if not skill.name:
            continue
        if skill.name != skill.skill_dir.name:
            errors.append(f"{rel}: frontmatter name `{skill.name}` must match directory name")
    return errors


def validate_references() -> list[str]:
    errors: list[str] = []
    for skill in discover_skill_contracts():
        rel = skill.references_path.relative_to(ROOT)
        urls = extract_reference_urls(skill.references_path)
        if not urls:
            errors.append(f"{rel}: REFERENCES.md must include at least one https:// reference")
            continue
        for url in urls:
            if not reference_url_allowed(url):
                errors.append(f"{rel}: unapproved reference source `{url}`")
    return errors


def validate_dangerous_code() -> list[str]:
    errors: list[str] = []
    compiled = [
        (re.compile(pattern), message) for pattern, message in DANGEROUS_CODE_PATTERNS.items()
    ]
    for skill in discover_skill_contracts():
        for path in sorted((skill.skill_dir / "src").rglob("*.py")):
            text = path.read_text()
            for pattern, message in compiled:
                if pattern.search(text):
                    errors.append(f"{path.relative_to(ROOT)}: {message}")
    return errors


def validate_mcp_alignment() -> list[str]:
    errors: list[str] = []
    registry = _load_tool_registry()
    registry_map = {skill.name: skill for skill in registry.discover_skills(ROOT)}
    contracts = {skill.name: skill for skill in discover_skill_contracts()}

    if set(registry_map) != set(contracts):
        missing = sorted(set(contracts) - set(registry_map))
        extra = sorted(set(registry_map) - set(contracts))
        if missing:
            errors.append(
                f"mcp-server: missing skills from registry discovery: {', '.join(missing)}"
            )
        if extra:
            errors.append(
                f"mcp-server: unexpected skills in registry discovery: {', '.join(extra)}"
            )

    for name, contract in contracts.items():
        registry_skill = registry_map.get(name)
        if registry_skill is None:
            continue
        if registry_skill.description != contract.description:
            errors.append(
                f"{contract.skill_dir.relative_to(ROOT)}: MCP description drift for `{name}`"
            )
        expected_support = contract.entrypoint is not None
        if registry_skill.supported != expected_support:
            errors.append(
                f"{contract.skill_dir.relative_to(ROOT)}: MCP supported flag drift for `{name}`"
            )

    return errors


def main() -> int:
    errors: list[str] = []
    errors.extend(validate_unique_names())
    errors.extend(validate_name_to_path_alignment())
    errors.extend(validate_references())
    errors.extend(validate_dangerous_code())
    errors.extend(validate_mcp_alignment())

    if errors:
        print("Skill integrity validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print("Skill integrity validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
