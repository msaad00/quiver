from __future__ import annotations

import json
import sys
from typing import TypedDict

from skill_validation_common import ROOT, discover_skill_contracts

ALLOWED_LAYERS = {
    "ingestion",
    "discovery",
    "detection",
    "evaluation",
    "view",
    "remediation",
    "output",
}
ALLOWED_STATUSES = {"gap", "mapped", "implemented", "tested", "validated"}
ALLOWED_EXECUTION_MODES = {"cli", "ci", "mcp", "persistent"}


class CoverageSkillEntry(TypedDict, total=False):
    path: str
    layer: str
    coverage_status: str
    providers: list[str]
    asset_classes: list[str]
    execution_modes: list[str]
    frameworks: list[str]


class CoverageTargetEntry(TypedDict, total=False):
    framework: str


class CoverageFrameworkEntry(TypedDict, total=False):
    id: str


class CoverageRegistry(TypedDict, total=False):
    frameworks: list[CoverageFrameworkEntry]
    skills: list[CoverageSkillEntry]
    coverage_targets: list[CoverageTargetEntry]


def load_registry() -> CoverageRegistry:
    path = ROOT / "docs" / "framework-coverage.json"
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError("docs/framework-coverage.json must contain a top-level object")
    return raw  # type: ignore[return-value]


def main() -> int:
    registry = load_registry()
    errors: list[str] = []

    frameworks = {item["id"] for item in registry.get("frameworks", [])}
    if not frameworks:
        errors.append("docs/framework-coverage.json: no framework ids declared")

    expected_paths = {
        str(skill.skill_dir.relative_to(ROOT)): skill for skill in discover_skill_contracts()
    }
    registered_paths: dict[str, CoverageSkillEntry] = {}

    for entry in registry.get("skills", []):
        path = entry.get("path", "")
        if not path:
            errors.append("docs/framework-coverage.json: skill entry missing `path`")
            continue
        if path in registered_paths:
            errors.append(f"docs/framework-coverage.json: duplicate skill entry `{path}`")
            continue
        registered_paths[path] = entry

        skill = expected_paths.get(path)
        if skill is None:
            errors.append(f"docs/framework-coverage.json: unknown skill path `{path}`")
            continue

        layer = entry.get("layer")
        if layer not in ALLOWED_LAYERS:
            errors.append(f"{path}: invalid layer `{layer}`")
        elif layer != skill.category:
            errors.append(
                f"{path}: registry layer `{layer}` does not match skill layer `{skill.category}`"
            )

        status = entry.get("coverage_status")
        if status not in ALLOWED_STATUSES:
            errors.append(f"{path}: invalid coverage_status `{status}`")

        providers = entry.get("providers", [])
        if not isinstance(providers, list) or not providers:
            errors.append(f"{path}: providers must be a non-empty list")

        asset_classes = entry.get("asset_classes", [])
        if not isinstance(asset_classes, list) or not asset_classes:
            errors.append(f"{path}: asset_classes must be a non-empty list")

        modes = entry.get("execution_modes", [])
        if not isinstance(modes, list) or not modes:
            errors.append(f"{path}: execution_modes must be a non-empty list")
        else:
            for mode in modes:
                if mode not in ALLOWED_EXECUTION_MODES:
                    errors.append(f"{path}: invalid execution mode `{mode}`")

        entry_frameworks = entry.get("frameworks", [])
        if not isinstance(entry_frameworks, list) or not entry_frameworks:
            errors.append(f"{path}: frameworks must be a non-empty list")
        else:
            for framework_id in entry_frameworks:
                if framework_id not in frameworks:
                    errors.append(f"{path}: unknown framework id `{framework_id}`")

    missing = sorted(set(expected_paths) - set(registered_paths))
    extra = sorted(set(registered_paths) - set(expected_paths))

    for path in missing:
        errors.append(f"docs/framework-coverage.json: missing registry entry for `{path}`")
    for path in extra:
        errors.append(
            f"docs/framework-coverage.json: registry entry without shipped skill `{path}`"
        )

    for target in registry.get("coverage_targets", []):
        framework = target.get("framework")
        if framework not in frameworks:
            errors.append(f"coverage_targets: unknown framework `{framework}`")

    if errors:
        print("Framework coverage validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print(
        f"Framework coverage validation passed for {len(registered_paths)} skills and "
        f"{len(frameworks)} frameworks."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
