#!/usr/bin/env python3
"""Fail CI when secondary docs drift from code-backed facts.

Complements ``validate_doc_counts.py`` (registry count parity) with semantic
checks: ingest totals in long-form architecture docs, MCP exposure claims,
security-bar headings, and catalog routing.

Exit codes: 0 on match, 1 on drift.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY = REPO_ROOT / "docs" / "framework-coverage.json"


def _ingest_count() -> int:
    reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
    count = 0
    for skill in reg["skills"]:
        if skill.get("layer") != "ingestion":
            continue
        name = skill["path"].rsplit("/", 1)[-1]
        if name.startswith("ingest-"):
            count += 1
    return count


def _check_ingest_count_in_docs_architecture(expected: int) -> str | None:
    path = REPO_ROOT / "docs" / "ARCHITECTURE.md"
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r"L1 ingest \| shipping \| (\d+) source-specific ingesters",
        text,
    )
    if not match:
        return f"{path.relative_to(REPO_ROOT)}: L1 ingest row pattern missing"
    got = int(match.group(1))
    if got != expected:
        return (
            f"{path.relative_to(REPO_ROOT)}: ingest count drift — doc says {got}, "
            f"registry says {expected}"
        )
    return None


def _check_agents_sse_wording() -> str | None:
    path = REPO_ROOT / "AGENTS.md"
    text = path.read_text(encoding="utf-8")
    if "remote HTTP/SSE MCP deployments" not in text:
        return f"{path.relative_to(REPO_ROOT)}: must document remote-hosted SSE gap"
    if "Opt-in local SSE" not in text and "mcp-server/src/transports/sse.py" not in text:
        return (
            f"{path.relative_to(REPO_ROOT)}: must document opt-in local SSE "
            "(see docs/MCP_TRANSPORT.md) alongside remote-hosted gap"
        )
    return None


def _check_security_bar_heading() -> str | None:
    path = REPO_ROOT / "SECURITY_BAR.md"
    text = path.read_text(encoding="utf-8")
    if "## The eleven principles" not in text:
        return (
            f"{path.relative_to(REPO_ROOT)}: heading must be "
            "'## The eleven principles' (table has 11 rows)"
        )
    if "## The ten principles" in text:
        return f"{path.relative_to(REPO_ROOT)}: stale 'ten principles' heading remains"
    return None


def _check_mcp_server_iam_departures_claim() -> str | None:
    path = REPO_ROOT / "mcp-server" / "README.md"
    text = path.read_text(encoding="utf-8")
    if "iam-departures-" not in text and "handler shim" not in text:
        return (
            f"{path.relative_to(REPO_ROOT)}: must document iam-departures-* MCP "
            "exposure via top-level handler shims (#411)"
        )
    if re.search(
        r"iam-departures-\*.*not exposed as one MCP tool",
        text,
        flags=re.IGNORECASE,
    ):
        return (
            f"{path.relative_to(REPO_ROOT)}: stale claim that iam-departures-* "
            "are not MCP-exposed; they ship handler shims"
        )
    return None


def _check_skills_readme_routes_to_skill_index() -> str | None:
    path = REPO_ROOT / "skills" / "README.md"
    text = path.read_text(encoding="utf-8")
    if "docs/SKILL_INDEX.md" not in text:
        return f"{path.relative_to(REPO_ROOT)}: must link to docs/SKILL_INDEX.md"
    if "authoritative" not in text.lower() and "complete catalog" not in text.lower():
        return (
            f"{path.relative_to(REPO_ROOT)}: must state SKILL_INDEX is the "
            "complete / authoritative catalog"
        )
    return None


def _check_skill_index_validator_reference() -> str | None:
    path = REPO_ROOT / "docs" / "SKILL_INDEX.md"
    text = path.read_text(encoding="utf-8")
    if "validate_doc_counts.py" not in text:
        return (
            f"{path.relative_to(REPO_ROOT)}: must reference "
            "scripts/validate_doc_counts.py (not validate_count_drift.sh)"
        )
    if "validate_count_drift.sh" in text:
        return f"{path.relative_to(REPO_ROOT)}: stale validate_count_drift.sh reference"
    return None


def main() -> int:
    ingest_count = _ingest_count()
    checks = [
        _check_ingest_count_in_docs_architecture(ingest_count),
        _check_agents_sse_wording(),
        _check_security_bar_heading(),
        _check_mcp_server_iam_departures_claim(),
        _check_skills_readme_routes_to_skill_index(),
        _check_skill_index_validator_reference(),
    ]
    errors = [error for error in checks if error is not None]
    if errors:
        print("Doc parity drift detected:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"Doc parity checks passed ({ingest_count} ingest-* skills).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
