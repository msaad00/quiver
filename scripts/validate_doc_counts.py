#!/usr/bin/env python3
"""Fail CI when human-edited docs drift from framework-coverage.json.

Source of truth: docs/framework-coverage.json. This script asserts that every
hard-coded skill or framework count in the README, AGENTS.md, SKILL_INDEX.md,
and FRAMEWORK_MAPPINGS.md matches the registry. Add a new entry to CHECKS
when you add a new hard-coded count.

Exit codes: 0 on match, 1 on drift.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY = REPO_ROOT / "docs" / "framework-coverage.json"


def load_registry() -> dict:
    data: dict = json.loads(REGISTRY.read_text())
    return data


def layer_counts(reg: dict) -> Counter:
    # README + AGENTS split `ingestion/` into "ingest" (ingest-*) vs "sources"
    # (source-*) — both live under layer=ingestion in the registry. Split here
    # so the doc-table check is meaningful.
    c: Counter = Counter()
    for s in reg["skills"]:
        layer = s["layer"]
        if layer == "ingestion":
            name = s["path"].rsplit("/", 1)[-1]
            c["sources" if name.startswith("source-") else "ingestion"] += 1
        else:
            c[layer] += 1
    return c


def framework_counts(reg: dict) -> Counter:
    c: Counter = Counter()
    for s in reg["skills"]:
        for fw in s.get("frameworks", []):
            c[fw] += 1
    return c


def check(path: Path, pattern: str, expected: int, label: str) -> str | None:
    text = path.read_text()
    m = re.search(pattern, text)
    if not m:
        return f"{path.relative_to(REPO_ROOT)}: pattern not found for {label!r} (pattern={pattern!r})"
    got = int(m.group(1))
    if got != expected:
        return (
            f"{path.relative_to(REPO_ROOT)}: {label} drift — doc says {got}, "
            f"registry says {expected}. Update the doc or the registry."
        )
    return None


def main() -> int:
    reg = load_registry()
    total = len(reg["skills"])
    layers = layer_counts(reg)
    fws = framework_counts(reg)

    readme = REPO_ROOT / "README.md"
    skill_index = REPO_ROOT / "docs" / "SKILL_INDEX.md"
    agents = REPO_ROOT / "AGENTS.md"
    mappings = REPO_ROOT / "docs" / "FRAMEWORK_MAPPINGS.md"
    architecture = REPO_ROOT / "ARCHITECTURE.md"

    candidates: list[str | None] = [
        check(readme, r"(\d+)\s+shipped skill bundles", total, "README total"),
        check(readme, r"Total:\s+(\d+)\s+shipped skills", total, "README total (table footer)"),
        check(readme, r"\*\*Ingest\*\*\s+\|\s+(\d+)", layers["ingestion"], "README ingest"),
        check(readme, r"\*\*Discover\*\*\s+\|\s+(\d+)", layers["discovery"], "README discover"),
        check(readme, r"\*\*Detect\*\*\s+\|\s+(\d+)", layers["detection"], "README detect"),
        check(readme, r"\*\*Evaluate\*\*\s+\|\s+(\d+)", layers["evaluation"], "README evaluate"),
        check(readme, r"\*\*Remediate\*\*\s+\|\s+(\d+)", layers["remediation"], "README remediate"),
        check(readme, r"\*\*View\*\*\s+\|\s+(\d+)", layers["view"], "README view"),
        check(readme, r"\*\*Output\*\*\s+\|\s+(\d+)", layers["output"], "README output"),
        check(readme, r"\*\*Sources\*\*\s+\|\s+(\d+)", layers["sources"], "README sources"),
        check(skill_index, r"The same (\d+) skill bundles", total, "SKILL_INDEX total"),
        check(agents, r"`ingestion/`\*\*:\s+(\d+)\s+ingest skills", layers["ingestion"], "AGENTS ingestion"),
        check(agents, r"ingest skills plus (\d+)\s+source adapters", layers["sources"], "AGENTS sources"),
        check(agents, r"`discovery/`\*\*:\s+(\d+)\s+read-only", layers["discovery"], "AGENTS discovery"),
        check(agents, r"`detection/`\*\*:\s+(\d+)\s+deterministic", layers["detection"], "AGENTS detection"),
        check(agents, r"`evaluation/`\*\*:\s+(\d+)\s+posture", layers["evaluation"], "AGENTS evaluation"),
        check(agents, r"`remediation/`\*\*:\s+(\d+)\s+HITL", layers["remediation"], "AGENTS remediation"),
        check(agents, r"`output/`\*\*:\s+(\d+)\s+append-only", layers["output"], "AGENTS output"),
        check(
            mappings,
            r"MITRE ATT&CK v14\*\*\s+\|\s+[^|]+\|\s+(\d+)\s+mapped skills",
            fws.get("mitre-attack-v14", 0),
            "FRAMEWORK_MAPPINGS ATT&CK",
        ),
        check(architecture, r"repo ships \*\*(\d+) skills\*\*", total, "ARCHITECTURE total"),
        check(architecture, r"(\d+) ingest skills plus", layers["ingestion"], "ARCHITECTURE ingest"),
        check(architecture, r"plus (\d+) `source-\*` adapters", layers["sources"], "ARCHITECTURE sources"),
        check(architecture, r"(\d+) discover", layers["discovery"], "ARCHITECTURE discover"),
        check(architecture, r"(\d+) detect", layers["detection"], "ARCHITECTURE detect"),
        check(architecture, r"(\d+) evaluate", layers["evaluation"], "ARCHITECTURE evaluate"),
        check(architecture, r"(\d+) remediate", layers["remediation"], "ARCHITECTURE remediate"),
        check(architecture, r"(\d+) view", layers["view"], "ARCHITECTURE view"),
        check(architecture, r"(\d+) output sinks", layers["output"], "ARCHITECTURE output"),
    ]
    errors: list[str] = [e for e in candidates if e is not None]
    if errors:
        print("Doc-count drift detected (source of truth: docs/framework-coverage.json):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "\nFix: update the offending line in the doc, or update the registry "
            "and run scripts/generate_framework_coverage_doc.py.",
            file=sys.stderr,
        )
        return 1

    print(
        f"Doc counts in sync with registry "
        f"({total} skills, {sum(layers.values())} layered, "
        f"{len(fws)} frameworks)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
