"""Generate docs/FRAMEWORK_COVERAGE.md from docs/framework-coverage.json.

Produces a have-vs-coming matrix per framework so readers can see, at a glance,
how many shipped skills map to each framework today. Run manually after the
registry changes; CI enforces the generated doc stays in sync via a diff check.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY = REPO_ROOT / "docs" / "framework-coverage.json"
OUTPUT = REPO_ROOT / "docs" / "FRAMEWORK_COVERAGE.md"


def _load_registry() -> dict[str, Any]:
    decoded = json.loads(REGISTRY.read_text())
    if not isinstance(decoded, dict):
        raise ValueError("framework-coverage registry must be a JSON object")
    return cast(dict[str, Any], decoded)


def _render(data: dict[str, Any]) -> str:
    frameworks: list[dict[str, Any]] = data.get("frameworks", [])
    skills: list[dict[str, Any]] = data.get("skills", [])
    targets: list[dict[str, Any]] = data.get("coverage_targets", [])

    by_framework: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for skill in skills:
        for fw_id in skill.get("frameworks", []):
            by_framework[fw_id].append(skill)

    target_by_framework: dict[str, dict[str, Any]] = {
        t["framework"]: t for t in targets if isinstance(t, dict) and "framework" in t
    }

    repo_version = data.get("repo_version", "?")
    updated = data.get("updated", "?")

    lines: list[str] = []
    lines.append("# Framework Coverage")
    lines.append("")
    lines.append(
        "This file is **generated from [`framework-coverage.json`](framework-coverage.json)** "
        "by `scripts/generate_framework_coverage_doc.py`. Do not edit by hand — update the "
        "registry and regenerate."
    )
    lines.append("")
    lines.append(f"- Registry version: `{repo_version}`")
    lines.append(f"- Registry updated: `{updated}`")
    lines.append(f"- Total shipped skills in registry: **{len(skills)}**")
    lines.append("")
    lines.append("## Roll-up")
    lines.append("")
    lines.append("| Framework | Version | Shipped skills mapped | Coverage target |")
    lines.append("|---|---|---|---|")

    for fw in frameworks:
        fw_id = fw.get("id", "")
        name = fw.get("name", fw_id)
        version = fw.get("version", "")
        mapped = by_framework.get(fw_id, [])
        target = target_by_framework.get(fw_id, {}).get("target", "—")
        lines.append(f"| {name} | {version} | **{len(mapped)}** | {target} |")

    lines.append("")
    lines.append(
        "Shipped skills mapped counts the number of skills in the registry that declare "
        "this framework under `frameworks`. It does not claim per-control depth; see each "
        "skill's `SKILL.md` and `REFERENCES.md` for the concrete controls, techniques, or "
        "benchmarks covered."
    )
    lines.append("")

    lines.append("## Per-framework skill lists")
    lines.append("")
    for fw in frameworks:
        fw_id = fw.get("id", "")
        name = fw.get("name", fw_id)
        version = fw.get("version", "")
        mapped = sorted(
            by_framework.get(fw_id, []),
            key=lambda s: s.get("path", ""),
        )
        target_entry = target_by_framework.get(fw_id, {})
        providers_in_scope = target_entry.get("providers_in_scope", [])
        asset_classes_in_scope = target_entry.get("asset_classes_in_scope", [])

        lines.append(f"### {name} ({version})")
        lines.append("")
        lines.append(f"- Registry id: `{fw_id}`")
        if providers_in_scope:
            lines.append(f"- Providers in scope: {', '.join(providers_in_scope)}")
        if asset_classes_in_scope:
            lines.append(f"- Asset classes in scope: {', '.join(asset_classes_in_scope)}")
        if target_entry.get("target"):
            lines.append(f"- Coverage target: {target_entry['target']}")
        lines.append("")

        if not mapped:
            lines.append(
                "_No shipped skills reference this framework yet. Treat it as documented "
                "scope, not implemented coverage._"
            )
            lines.append("")
            continue

        lines.append(f"Shipped skills mapped: **{len(mapped)}**")
        lines.append("")
        lines.append("| Skill | Layer | Providers | Asset classes |")
        lines.append("|---|---|---|---|")
        for skill in mapped:
            path = skill.get("path", "")
            name_only = path.rsplit("/", 1)[-1] if path else ""
            layer = skill.get("layer", "")
            providers = ", ".join(skill.get("providers", []) or []) or "—"
            asset_classes = ", ".join(skill.get("asset_classes", []) or []) or "—"
            lines.append(
                f"| [`{name_only}`]({_skill_relpath(path)}) | {layer} | {providers} | {asset_classes} |"
            )
        lines.append("")

    lines.append("## Skills with no framework mapping")
    lines.append("")
    unmapped = [s for s in skills if not s.get("frameworks")]
    if unmapped:
        lines.append("| Skill | Layer |")
        lines.append("|---|---|")
        for skill in sorted(unmapped, key=lambda s: s.get("path", "")):
            path = skill.get("path", "")
            layer = skill.get("layer", "")
            name_only = path.rsplit("/", 1)[-1] if path else ""
            lines.append(f"| [`{name_only}`]({_skill_relpath(path)}) | {layer} |")
    else:
        lines.append("_Every shipped skill in the registry references at least one framework._")
    lines.append("")

    lines.append("## How to update")
    lines.append("")
    lines.append(
        "1. Edit [`framework-coverage.json`](framework-coverage.json) with the new "
        "framework, skill, or mapping."
    )
    lines.append(
        "2. Run `python scripts/generate_framework_coverage_doc.py` to regenerate this file."
    )
    lines.append(
        "3. Commit both `framework-coverage.json` and `FRAMEWORK_COVERAGE.md` in the same change."
    )
    lines.append(
        "4. CI runs the script in check mode and fails if the generated doc differs "
        "from the checked-in version."
    )
    lines.append("")

    return "\n".join(lines) + "\n"


def _skill_relpath(path: str) -> str:
    if not path:
        return ""
    return f"../{path}"


def main() -> int:
    data = _load_registry()
    generated = _render(data)
    if len(sys.argv) >= 2 and sys.argv[1] == "--check":
        existing = OUTPUT.read_text() if OUTPUT.exists() else ""
        if existing != generated:
            print(
                f"ERROR: {OUTPUT.relative_to(REPO_ROOT)} is out of sync with "
                f"{REGISTRY.relative_to(REPO_ROOT)}. Run:\n"
                f"  python scripts/generate_framework_coverage_doc.py",
                file=sys.stderr,
            )
            return 1
        return 0
    OUTPUT.write_text(generated)
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)} ({len(generated.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
