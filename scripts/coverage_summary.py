#!/usr/bin/env python3
"""Generate the repo's coverage snapshot from `docs/framework-coverage.json`.

Three tables: by cloud / vendor (provider), by framework, by layer.
Plus the layered-target progress against each open roadmap issue.

The snapshot is checked in at `docs/COVERAGE_SNAPSHOT.md` and the
README "Progress snapshot" section pulls from the same numbers via
the `--readme` mode. A CI gate (`--check`) refuses any PR where the
on-disk snapshot has drifted from `framework-coverage.json`.

Usage:
  python scripts/coverage_summary.py            # print to stdout
  python scripts/coverage_summary.py --write    # write docs/COVERAGE_SNAPSHOT.md
  python scripts/coverage_summary.py --check    # exit 1 if disk != regenerated
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COVERAGE_JSON = REPO_ROOT / "docs" / "framework-coverage.json"
SNAPSHOT_MD = REPO_ROOT / "docs" / "COVERAGE_SNAPSHOT.md"

# Total control count per published framework — the denominator for the
# 'X of Y controls covered' computation. Numbers come from each
# framework's official enumeration as of the version we tag.
#
# When a framework grows or its version bumps, update this table and
# regenerate. Frameworks not in this map fall back to skill-tag count
# (the looser proxy).
FRAMEWORK_TOTAL_CONTROLS: dict[str, int] = {
    "cis-aws-v3": 58,           # CIS AWS Foundations v3 — numbered controls
    "cis-gcp-v3": 60,
    "cis-azure-v2.1": 60,
    "cis-k8s": 30,              # CIS K8s Benchmark v1.8 — agent-bom-relevant slice
    "cis-docker": 17,           # CIS Docker Benchmark v1.7 — runtime-relevant slice
    "cis-controls-v8": 18,      # 18 controls in CIS Controls v8
    "owasp-top-10": 10,
    "owasp-llm-top-10": 10,
    "owasp-mcp-top-10": 10,
    "nist-ai-rmf": 24,          # AI RMF 1.0 categories (the level outcomes roll up to)
    # mitre-attack-v14, mitre-atlas, ocsf-1.8, nist-csf-2.0, soc2-tsc,
    # iso-27001-2022, pci-dss-4.0, cyclonedx-ml-bom intentionally not
    # enumerated yet — either too coarse-grained or the repo doesn't
    # claim per-control mapping. Skill-tag count is the proxy.
}

# Control-ID extractor for evaluation skills that ship a `checks.py`
# carrying `control_id="x.y"` literals. Returns deduplicated control
# IDs grouped by framework, derived from the skill's framework tags.
_CONTROL_ID_PATTERN = re.compile(r'control_id\s*=\s*"([^"]+)"')


def _controls_in_skill(skill_path: str) -> set[str]:
    """Parse `control_id="..."` literals from a skill's `src/checks.py`."""
    checks = REPO_ROOT / skill_path / "src" / "checks.py"
    if not checks.is_file():
        return set()
    try:
        text = checks.read_text(encoding="utf-8")
    except OSError:
        return set()
    return set(_CONTROL_ID_PATTERN.findall(text))


def _bucket_controls_by_framework(
    skills: list[dict],
) -> dict[str, set[str]]:
    """For each framework that has a known total, bucket the controls
    each shipped skill claims to cover. The control IDs themselves come
    from the skill's checks.py (CSPM-shape skills); the framework
    binding comes from the skill's `frameworks` tag list.

    Same control ID covered by two skills counts once (the metric is
    'is the control covered', not 'how many skills cover it')."""
    by_fw: dict[str, set[str]] = defaultdict(set)
    for skill in skills:
        controls = _controls_in_skill(skill["path"])
        if not controls:
            continue
        for fw in skill.get("frameworks", []):
            if fw in FRAMEWORK_TOTAL_CONTROLS:
                by_fw[fw].update(controls)
    return dict(by_fw)


def _label_path(path: Path) -> str:
    """Pretty-print a path relative to the repo root when possible.
    Falls back to the absolute string for tmp_path / monkey-patched
    locations used in tests."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)

# Friendly labels for the framework / provider / layer keys we ship.
PROVIDER_LABEL = {
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "multi": "Multi-cloud (vendor-neutral)",
    "kubernetes": "Kubernetes",
    "mcp": "MCP / AI runtime",
    "okta": "Okta",
    "entra": "Microsoft Entra",
    "snowflake": "Snowflake",
    "databricks": "Databricks",
    "clickhouse": "ClickHouse",
    "google-workspace": "Google Workspace",
    "microsoft-graph": "Microsoft Graph",
    "containers": "Containers (runtime)",
    "workday": "Workday",
}

FRAMEWORK_LABEL = {
    "ocsf-1.8": "OCSF 1.8",
    "mitre-attack-v14": "MITRE ATT&CK v14",
    "mitre-atlas": "MITRE ATLAS",
    "nist-csf-2.0": "NIST CSF 2.0",
    "nist-ai-rmf": "NIST AI RMF",
    "soc2-tsc": "SOC 2 TSC",
    "pci-dss-4.0": "PCI DSS 4.0",
    "iso-27001-2022": "ISO 27001:2022",
    "owasp-llm-top-10": "OWASP LLM Top 10",
    "owasp-mcp-top-10": "OWASP MCP Top 10",
    "owasp-top-10": "OWASP Top 10",
    "cyclonedx-ml-bom": "CycloneDX ML-BOM",
    "cis-aws-v3": "CIS AWS v3",
    "cis-gcp-v3": "CIS GCP v3",
    "cis-azure-v2.1": "CIS Azure v2.1",
    "cis-k8s": "CIS Kubernetes",
    "cis-controls-v8": "CIS Controls v8",
    "cis-docker": "CIS Docker",
}

# Roadmap targets — bound to the open umbrella issues. Update these
# alongside the issue text when targets shift.
ROADMAP_TARGETS = [
    ("MITRE ATT&CK breadth", "#253", "mitre-attack-v14", 50),
    ("MITRE ATLAS", "#255", "mitre-atlas", 40),
    ("OWASP LLM Top 10", "#255", "owasp-llm-top-10", 40),
    ("OWASP MCP Top 10", "#255", "owasp-mcp-top-10", 50),
    ("OWASP Top 10 (web)", "TBD", "owasp-top-10", 30),
    ("NIST AI RMF", "TBD", "nist-ai-rmf", 30),
]


def _load() -> list[dict]:
    raw = json.loads(COVERAGE_JSON.read_text(encoding="utf-8"))
    skills = raw.get("skills", [])
    if not isinstance(skills, list):
        raise ValueError(
            f"{COVERAGE_JSON.name}: top-level `skills` must be a list, got {type(skills).__name__}"
        )
    out: list[dict] = []
    for entry in skills:
        if not isinstance(entry, dict):
            raise ValueError(f"{COVERAGE_JSON.name}: every `skills` entry must be an object")
        out.append(entry)
    return out


def _bucket_by(skills: list[dict], key: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for s in skills:
        for v in s.get(key, []):
            out[v].add(s["path"])
    return dict(out)


def _bucket_by_layer(skills: list[dict]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for s in skills:
        out[s["layer"]].add(s["path"])
    return dict(out)


def _row(label: str, count: int, total: int) -> str:
    pct = 100 * count / total if total else 0
    return f"| {label} | {count} | {pct:.1f}% |"


def _label(key: str, table: dict[str, str]) -> str:
    return table.get(key, key)


def render(skills: list[dict]) -> str:
    total = len(skills)
    providers = _bucket_by(skills, "providers")
    frameworks = _bucket_by(skills, "frameworks")
    layers = _bucket_by_layer(skills)

    lines: list[str] = []
    lines.append("# Coverage Snapshot")
    lines.append("")
    lines.append(
        "Auto-generated from [`framework-coverage.json`](framework-coverage.json) by "
        "[`scripts/coverage_summary.py`](../scripts/coverage_summary.py). Do not edit "
        "by hand — the CI gate `--check` will refuse the PR. Regenerate with:"
    )
    lines.append("")
    lines.append("```bash")
    lines.append("python scripts/coverage_summary.py --write")
    lines.append("```")
    lines.append("")
    lines.append(f"**Total shipped skills:** {total}")
    lines.append("")
    lines.append("## By cloud / vendor")
    lines.append("")
    lines.append("Skills overlap when a skill targets multiple providers (the `multi` row), so the column may sum to more than the total.")
    lines.append("")
    lines.append("| Cloud / vendor | Skills | % of repo |")
    lines.append("|---|---:|---:|")
    for key in sorted(providers, key=lambda k: -len(providers[k])):
        lines.append(_row(_label(key, PROVIDER_LABEL), len(providers[key]), total))
    lines.append("")
    lines.append("## By framework")
    lines.append("")
    lines.append("Skills can carry multiple framework tags (e.g. a CIS check tagged with NIST CSF mapping); the column does not sum to 100%.")
    lines.append("")
    lines.append("| Framework | Skills | % of repo |")
    lines.append("|---|---:|---:|")
    for key in sorted(frameworks, key=lambda k: -len(frameworks[k])):
        lines.append(_row(_label(key, FRAMEWORK_LABEL), len(frameworks[key]), total))
    lines.append("")
    lines.append("## By layer")
    lines.append("")
    lines.append("| Layer | Skills | % of repo |")
    lines.append("|---|---:|---:|")
    for key in sorted(layers, key=lambda k: -len(layers[k])):
        lines.append(_row(key, len(layers[key]), total))
    lines.append("")
    lines.append("## Per-framework control coverage")
    lines.append("")
    lines.append(
        "**Depth, not breadth.** When a skill ships a `checks.py` with "
        "explicit `control_id` literals (the CSPM benchmarks today), this "
        "table counts the unique controls covered against the framework's "
        "published total. Same control covered by two skills counts once."
    )
    lines.append("")
    controls_by_fw = _bucket_controls_by_framework(skills)
    # Only render frameworks the input is actually claiming — either via
    # a skill tag or via a discovered control. Synthetic inputs (and
    # smaller deployments) shouldn't see a wall of '0 / N' rows for
    # frameworks they don't touch.
    relevant = {k for k in FRAMEWORK_TOTAL_CONTROLS if k in frameworks or controls_by_fw.get(k)}
    if relevant:
        lines.append("| Framework | Controls covered | Total | Coverage % |")
        lines.append("|---|---:|---:|---:|")
        for fw_key in sorted(relevant, key=lambda k: (-len(controls_by_fw.get(k, set())), k)):
            covered = len(controls_by_fw.get(fw_key, set()))
            fw_total = FRAMEWORK_TOTAL_CONTROLS[fw_key]
            pct = 100 * covered / fw_total if fw_total else 0
            lines.append(
                f"| {_label(fw_key, FRAMEWORK_LABEL)} | {covered} | {fw_total} | {pct:.0f}% |"
            )
    else:
        lines.append("_No frameworks in this input have per-control totals defined._")
    lines.append("")
    lines.append("## Roadmap progress")
    lines.append("")
    lines.append(
        "Per-track breadth toward the published target. The 'Today' column "
        "uses **per-control coverage** when the framework has known totals "
        "(see table above), else falls back to skill-tag breadth."
    )
    lines.append("")
    lines.append("| Track | Tag | Issue | Target | Today |")
    lines.append("|---|---|---|---:|---:|")
    for label, issue, key, target in ROADMAP_TARGETS:
        # Prefer control-coverage % when known; fall back to skill-tag % otherwise.
        if key in FRAMEWORK_TOTAL_CONTROLS:
            covered = len(controls_by_fw.get(key, set()))
            fw_total = FRAMEWORK_TOTAL_CONTROLS[key]
            pct_today = 100 * covered / fw_total if fw_total else 0
        else:
            skill_count = len(frameworks.get(key, set()))
            pct_today = 100 * skill_count / total if total else 0
        lines.append(
            f"| {label} | `{key}` | {issue} | {target}% | {pct_today:.0f}% |"
        )
    lines.append("")
    lines.append("## Where the gaps are")
    lines.append("")
    lines.append(
        "- **CIS depth** — only 4–6 controls per cloud × 3 clouds today. "
        "Roadmap [#254](https://github.com/msaad00/cloud-ai-security-skills/issues/254) "
        "calls for 50% per platform; ~35–40 more controls to ship."
    )
    lines.append(
        "- **OWASP Top 10 (web)** — zero detectors today. The hero banner "
        "advertises the framework — coverage owed."
    )
    lines.append(
        "- **NIST AI RMF + CycloneDX ML-BOM** — only 4 + 2 skills. AI "
        "inventory and posture is a credible next theme."
    )
    lines.append(
        "- **Per-vendor depth** — Snowflake / Databricks / ClickHouse are "
        "3–4 skills each. Detect-side coverage on those is thin."
    )
    lines.append(
        "- **PCI / ISO** — 3–4 skills each, mostly evidence-side. "
        "Detect / remediate slices could be added cheaply."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--write", action="store_true", help="overwrite docs/COVERAGE_SNAPSHOT.md")
    g.add_argument("--check", action="store_true", help="exit 1 if disk drifts from regenerated")
    args = parser.parse_args(argv)

    skills = _load()
    rendered = render(skills)

    if args.write:
        SNAPSHOT_MD.write_text(rendered, encoding="utf-8")
        print(f"wrote {_label_path(SNAPSHOT_MD)} ({len(rendered)} bytes)")
        return 0
    if args.check:
        if not SNAPSHOT_MD.is_file():
            print(
                f"error: {_label_path(SNAPSHOT_MD)} is missing. "
                f"Run `python scripts/coverage_summary.py --write`.",
                file=sys.stderr,
            )
            return 1
        on_disk = SNAPSHOT_MD.read_text(encoding="utf-8")
        if on_disk != rendered:
            print(
                f"error: {_label_path(SNAPSHOT_MD)} is stale. "
                f"Run `python scripts/coverage_summary.py --write` and commit.",
                file=sys.stderr,
            )
            return 1
        print(f"{_label_path(SNAPSHOT_MD)} is in sync.")
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
