#!/usr/bin/env python3
"""Validate that every count-bearing repo-truth claim matches the on-disk count.

Prevents the class of drift where a PR adds a skill but forgets to bump
counts in README.md / ARCHITECTURE.md / runtime/architecture SVGs /
FRAMEWORK_COVERAGE.md / CHANGELOG.md. Run in CI next to the other
`validate_*.py` scripts.

Passes silently; fails with a diff-style report pointing to each claim that
does not equal the true count from `find skills -name SKILL.md`.

The check is **anchored to explicit patterns** (e.g. `N shipped skill bundles`,
`Total: N shipped skills`, `N shipped detectors`). A bare number like `82`
elsewhere in docs is ignored — we only assert the patterns we own.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ----- Claims we own. Each entry: (file, regex, what the int should equal) -----
#
# The regex MUST have exactly one capture group `(\d+)` that is the claimed
# count. `expected` names the metric the capture should equal.

Claim = tuple[Path, str, str]

CLAIMS: list[Claim] = [
    # README.md claims
    (REPO_ROOT / "README.md", r"(\d+) shipped skill bundles", "total"),
    (REPO_ROOT / "README.md", r"\*\*Total: (\d+) shipped skills", "total"),
    (REPO_ROOT / "README.md", r"\| \*\*Ingest\*\* \| (\d+) \|", "ingest_only"),
    (REPO_ROOT / "README.md", r"\| \*\*Discover\*\* \| (\d+) \|", "discovery"),
    (REPO_ROOT / "README.md", r"\| \*\*Detect\*\* \| (\d+) \|", "detection"),
    (REPO_ROOT / "README.md", r"\| \*\*Evaluate\*\* \| (\d+) \|", "evaluation"),
    (REPO_ROOT / "README.md", r"\| \*\*Remediate\*\* \| (\d+) \|", "remediation"),
    (REPO_ROOT / "README.md", r"\| \*\*View\*\* \| (\d+) \|", "view"),
    (REPO_ROOT / "README.md", r"\| \*\*Output\*\* \| (\d+) \|", "output"),
    (REPO_ROOT / "README.md", r"\| \*\*Sources\*\* \| (\d+) \|", "sources"),
    # The legacy '| **Detect** | N detectors' row was a second copy of
    # the layer-table count; dropped during the README polish (PR-A
    # README polish), so the layer-table claim above is now the single
    # source of truth in README.
    (
        REPO_ROOT / "README.md",
        r"Closed-loop coverage matrix — \d+ of (\d+) shipped detections",
        "detection",
    ),
    # The L3 Detect mermaid claim was removed when both README mermaids were
    # replaced by docs/images/*.svg in #248 phase 1. Count-bearing SVG text and
    # descriptions are now checked directly because these visuals are source SVG.
    # docs/ARCHITECTURE.md claims
    (REPO_ROOT / "docs" / "ARCHITECTURE.md", r"(\d+) shipped detectors", "detection"),
    (REPO_ROOT / "docs" / "AGENT_QUICKSTART.md", r"Give any agent these (\d+) skills", "total"),
    (
        REPO_ROOT / "docs" / "QUICKSTART.md",
        r"repo is structured as (\d+)[\s>]+independent\s+skill bundles",
        "total",
    ),
    (
        REPO_ROOT / "docs" / "CLICKHOUSE_DATA_LAKE.md",
        r"ingest-\*\s+\((\d+) skills\)",
        "ingest_only",
    ),
    (
        REPO_ROOT / "docs" / "CLICKHOUSE_DATA_LAKE.md",
        r"detect-\*\s+\((\d+) skills\)",
        "detection",
    ),
    (
        REPO_ROOT / "docs" / "SNOWFLAKE_DATA_LAKE.md",
        r"ingest-\*\s+\((\d+) skills\)",
        "ingest_only",
    ),
    # Core SVG / alt-text surfaces that drifted during the ATT&CK + CIS expansion.
    (
        REPO_ROOT / "docs" / "images" / "runtime-surfaces.svg",
        r"Counts: (\d+) shipped skills",
        "total",
    ),
    (
        REPO_ROOT / "docs" / "images" / "runtime-surfaces.svg",
        r"\d+ ingest · (\d+) detect · \d+ discover · \d+ eval",
        "detection",
    ),
    (
        REPO_ROOT / "docs" / "images" / "runtime-surfaces.svg",
        r"(\d+) ingest, \d+ detect, \d+ discover, \d+ eval",
        "ingest_only",
    ),
    (
        REPO_ROOT / "docs" / "images" / "runtime-surfaces.svg",
        r"\d+ ingest, (\d+) detect, \d+ discover, \d+ eval",
        "detection",
    ),
    (
        REPO_ROOT / "docs" / "images" / "runtime-surfaces.svg",
        r"\d+ ingest, \d+ detect, (\d+) discover, \d+ eval",
        "discovery",
    ),
    (
        REPO_ROOT / "docs" / "images" / "runtime-surfaces.svg",
        r"\d+ ingest, \d+ detect, \d+ discover, (\d+) eval",
        "evaluation",
    ),
    (
        REPO_ROOT / "docs" / "images" / "runtime-surfaces.svg",
        r"(\d+) remediate, \d+ view, \d+ sink, \d+ source",
        "remediation",
    ),
    (
        REPO_ROOT / "docs" / "images" / "runtime-surfaces.svg",
        r"\d+ remediate, (\d+) view, \d+ sink, \d+ source",
        "view",
    ),
    (
        REPO_ROOT / "docs" / "images" / "runtime-surfaces.svg",
        r"\d+ remediate, \d+ view, (\d+) sink, \d+ source",
        "output",
    ),
    (
        REPO_ROOT / "docs" / "images" / "runtime-surfaces.svg",
        r"\d+ remediate, \d+ view, \d+ sink, (\d+) source",
        "sources",
    ),
    (
        REPO_ROOT / "docs" / "images" / "architecture-layers.svg",
        r"L1 Ingest with (\d+) ingesters",
        "ingest_only",
    ),
    (
        REPO_ROOT / "docs" / "images" / "architecture-layers.svg",
        r"plus (\d+) source adapters",
        "sources",
    ),
    (
        REPO_ROOT / "docs" / "images" / "architecture-layers.svg",
        r"L2 Discover with (\d+) inventory",
        "discovery",
    ),
    (
        REPO_ROOT / "docs" / "images" / "architecture-layers.svg",
        r"L3 Detect with (\d+) deterministic",
        "detection",
    ),
    (
        REPO_ROOT / "docs" / "images" / "architecture-layers.svg",
        r"L4 Evaluate with (\d+) benchmark",
        "evaluation",
    ),
    (
        REPO_ROOT / "docs" / "images" / "architecture-layers.svg",
        r"L5 Remediate with (\d+) HITL",
        "remediation",
    ),
    (
        REPO_ROOT / "docs" / "images" / "architecture-layers.svg",
        r"L6 View with (\d+) OCSF-to-render",
        "view",
    ),
    (
        REPO_ROOT / "docs" / "images" / "hero-banner.svg",
        r"(\d+) shipped skill bundles",
        "total",
    ),
    (
        REPO_ROOT / "docs" / "images" / "hero-banner.svg",
        r"current shipped layer counts: (\d+) ingest",
        "ingest_only",
    ),
    (
        REPO_ROOT / "docs" / "images" / "hero-banner.svg",
        r"\d+ ingest, (\d+) discover",
        "discovery",
    ),
    (
        REPO_ROOT / "docs" / "images" / "hero-banner.svg",
        r"\d+ discover, (\d+) detect",
        "detection",
    ),
    (
        REPO_ROOT / "docs" / "images" / "hero-banner.svg",
        r"\d+ detect, (\d+) evaluate",
        "evaluation",
    ),
    (
        REPO_ROOT / "docs" / "images" / "hero-banner.svg",
        r"\d+ evaluate, (\d+) remediate",
        "remediation",
    ),
    (
        REPO_ROOT / "docs" / "images" / "hero-banner.svg",
        r"\d+ remediate, (\d+) view",
        "view",
    ),
    (
        REPO_ROOT / "docs" / "images" / "hero-banner.svg",
        r"\d+ view, (\d+) output",
        "output",
    ),
    (
        REPO_ROOT / "docs" / "images" / "hero-banner.svg",
        r"\d+ output, and (\d+) source adapters",
        "sources",
    ),
    (
        REPO_ROOT / "docs" / "images" / "coverage-matrix.svg",
        r"Rows list every shipped detection \((\d+)\)",
        "detection",
    ),
    (
        REPO_ROOT / "docs" / "images" / "coverage-matrix.svg",
        r"DETECTION \((\d+)\)",
        "detection",
    ),
    (
        REPO_ROOT / "docs" / "images" / "coverage-matrix.svg",
        r"Closed-loop ratio: <tspan[^>]*>\d+ / (\d+)</tspan>",
        "detection",
    ),
]

# Catch-all scan: any mermaid label of the form `<br/>N skills` or `<br/>N shipped`
# inside a `*.md` file MUST equal an on-disk count for the layer it names. This
# is what catches drift like the issue #302 case where README mermaid said
# "46 shipped" while the actual total was 48 — a stale label that escaped CLAIMS.
#
# The scan parses the layer name from the same mermaid node text. Recognized
# layer hints map to the truth dict keys; unknown hints fall back to the
# repo-wide total. Lines inside ALLOWED_DRIFT_LINES are skipped (e.g. example
# snippets in skill-authoring docs).

# Ordered: more specific terms first. The README/diagrams treat "L1 Ingest" as
# the count of `ingest-*` skills only, with `source-*` adapters listed
# separately in the layer table. Hence the `ingest_only` (= 15 today) vs
# `ingestion` (= 18 today, includes source-*) split.
LAYER_HINT_TO_METRIC = (
    ("source", "sources"),
    ("ingestion", "ingestion"),
    ("ingest", "ingest_only"),
    ("discover", "discovery"),
    ("detect", "detection"),
    ("evaluate", "evaluation"),
    ("evaluation", "evaluation"),
    ("remediate", "remediation"),
    ("remediation", "remediation"),
    ("view", "view"),
    ("output", "output"),
    ("sink", "output"),
    ("shipped", "total"),
    ("bundle", "total"),
)

# Substrings (matched on the line) that mark a count-claim as intentionally
# decorative or example-only and exclude it from the scan. Add sparingly.
ALLOWED_DRIFT_LINES: tuple[str, ...] = ("<!-- skill-count-scan: ignore -->",)

# Pattern: `<br/>N <something> skills|shipped|sinks` inside a mermaid node.
# The `<br/>` prefix anchors us to flowchart node labels (single-line text in
# rect labels) and avoids matching every `\d+` in prose.
SCAN_PATTERN = re.compile(
    r"<br/>(\d+)\s+(?:[A-Za-z·\-/+]+\s+)?(skills?|shipped|sinks?)\b",
    re.IGNORECASE,
)


def _count_skills(layer: str | None = None) -> int:
    """Count SKILL.md files under skills/<layer>/*/ (or all layers when None)."""
    if layer is None:
        return sum(1 for _ in (REPO_ROOT / "skills").glob("*/*/SKILL.md"))
    return sum(1 for _ in (REPO_ROOT / "skills" / layer).glob("*/SKILL.md"))


def _count_ingest_only() -> int:
    """Count `ingest-*` skills under ingestion/, excluding `source-*` adapters.
    Mirrors the layer-table convention used in README and the architecture
    diagram (Ingest = 15 + Sources = 3 listed separately)."""
    return sum(1 for _ in (REPO_ROOT / "skills" / "ingestion").glob("ingest-*/SKILL.md"))


def _count_sources() -> int:
    """Count `source-*` warehouse query adapters under ingestion/."""
    return sum(1 for _ in (REPO_ROOT / "skills" / "ingestion").glob("source-*/SKILL.md"))


def _resolve_metric_for_line(line: str) -> str:
    """Inspect the mermaid node text and pick the truth-dict key it should equal.

    Heuristic: if the line names a specific layer (e.g. `L1 Ingest`, `Remediate`),
    use that layer's count; otherwise default to total. Keeps the scan honest
    about what each label is claiming. Order in LAYER_HINT_TO_METRIC matters:
    the first matching hint wins, so more specific terms (e.g. `source`,
    `ingestion`) come before broader ones (`ingest`, `shipped`).
    """
    lowered = line.lower()
    for hint, metric in LAYER_HINT_TO_METRIC:
        if hint in lowered:
            return metric
    return "total"


def _scan_drift(truth: dict[str, int]) -> list[str]:
    """Walk every tracked `*.md` file and flag any `<br/>N (skills|shipped|sinks)`
    label whose number does not equal the on-disk count for the layer it names.

    Catches the failure mode from issue #302: a stale mermaid count in README
    or any other doc that wasn't on the explicit CLAIMS allow-list.
    """
    errors: list[str] = []
    md_paths = sorted(
        p
        for p in REPO_ROOT.rglob("*.md")
        if ".venv" not in p.parts and "node_modules" not in p.parts and ".claude" not in p.parts
    )
    for path in md_paths:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in SCAN_PATTERN.finditer(text):
            claimed = int(match.group(1))
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            line = text[line_start : line_end if line_end != -1 else None]
            if any(skip in line for skip in ALLOWED_DRIFT_LINES):
                continue
            metric = _resolve_metric_for_line(line)
            expected = truth.get(metric)
            if expected is None or claimed == expected:
                continue
            line_no = text[: match.start()].count("\n") + 1
            errors.append(
                f"{path.relative_to(REPO_ROOT)}:{line_no}: mermaid label claims "
                f"{claimed} for `{metric}`, on-disk count is {expected} — "
                f"line: `{line.strip()}`"
            )
    return errors


def _check_coverage_matrix_rows(truth: dict[str, int]) -> list[str]:
    """Validate that the coverage matrix draws one visible row per detector.

    The explicit CLAIMS above catch stale numeric text. This catches a subtler
    visual drift: updating the count to N while forgetting to add the Nth
    detector row to the SVG.
    """
    path = REPO_ROOT / "docs" / "images" / "coverage-matrix.svg"
    if not path.exists():
        return [f"{path.relative_to(REPO_ROOT)}: file not found (row check skipped)"]

    text = path.read_text(encoding="utf-8")
    row_matches = re.findall(r'<text x="48"\s+y="\d+"\s+[^>]*>detect-[^<]+</text>', text)
    expected = truth["detection"]
    if len(row_matches) == expected:
        return []
    return [
        f"{path.relative_to(REPO_ROOT)}: draws {len(row_matches)} visible detection rows, "
        f"but on-disk detection count is {expected}"
    ]


def main() -> int:
    truth: dict[str, int] = {
        "total": _count_skills(),
        "ingestion": _count_skills("ingestion"),
        "ingest_only": _count_ingest_only(),
        "sources": _count_sources(),
        "discovery": _count_skills("discovery"),
        "detection": _count_skills("detection"),
        "evaluation": _count_skills("evaluation"),
        "remediation": _count_skills("remediation"),
        "view": _count_skills("view"),
        "output": _count_skills("output"),
    }

    errors: list[str] = []
    for path, pattern, metric in CLAIMS:
        if not path.exists():
            errors.append(f"{path.relative_to(REPO_ROOT)}: file not found (claim check skipped)")
            continue
        text = path.read_text(encoding="utf-8")
        matches = list(re.finditer(pattern, text))
        if not matches:
            errors.append(
                f"{path.relative_to(REPO_ROOT)}: pattern `{pattern}` did not match — "
                "claim was removed or reworded; update scripts/validate_skill_count_consistency.py"
            )
            continue
        expected = truth[metric]
        for match in matches:
            claimed = int(match.group(1))
            if claimed != expected:
                line_no = text[: match.start()].count("\n") + 1
                errors.append(
                    f"{path.relative_to(REPO_ROOT)}:{line_no}: claims {claimed} for `{metric}`, "
                    f"but on-disk count is {expected} (pattern `{pattern}`)"
                )

    # Catch-all scan for any unauthorized mermaid count drift (issue #302 class)
    errors.extend(_scan_drift(truth))
    errors.extend(_check_coverage_matrix_rows(truth))

    if errors:
        print("Skill-count consistency check FAILED:\n")
        for err in errors:
            print(f"  - {err}")
        print("\nOn-disk counts: " + ", ".join(f"{k}={v}" for k, v in truth.items()))
        print(
            "\nFix: update the file(s) above OR, if the claim was intentionally reworded, "
            "update CLAIMS in scripts/validate_skill_count_consistency.py."
        )
        return 1

    print(
        f"Skill-count consistency check passed "
        f"(total={truth['total']}, detection={truth['detection']}, "
        f"remediation={truth['remediation']}, evaluation={truth['evaluation']})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
