#!/usr/bin/env python3
"""Fail closed on hardcoded secret literals in enforced repo paths.

Scans skill sources, MCP server, scripts, agent harness entrypoints, shipped
presets, and harness profiles. Test trees and golden fixtures are excluded —
they intentionally carry synthetic token shapes for detector regression tests.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

SECRET_PATTERNS = [
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"ghp_[a-zA-Z0-9]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(
        r"(?i)\b(?:openai_api_key|anthropic_api_key|github_token|"
        r"aws_secret_access_key|snowflake_password|secret_access_key)\b"
        r"\s*[:=]\s*[\"'][^\"']{4,}[\"']"
    ),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
]

SKIP_LINE_MARKERS = (
    "re.compile(",
    "SECRET_PATTERNS",
    "SECRET_VALUE_RE",
    "SECRET_FIELD_RE",
    "synthetic_pat",
    "redacted-test-value",
    "must not contain password",
    "no PAT/API-key/password literals",
)

PYTHON_GLOBS = [
    "skills/*/src/*.py",
    "skills/*/*/src/*.py",
    "mcp-server/src/*.py",
    "mcp-server/src/**/*.py",
    "scripts/*.py",
    "examples/agents/*.py",
]

TEXT_GLOBS = [
    "examples/agents/harness_profiles/*.json",
    "presets/*.json",
    "docs/AGENT_QUICKSTART.md",
]


def _iter_paths() -> list[Path]:
    seen: set[Path] = set()
    paths: list[Path] = []
    for pattern in [*PYTHON_GLOBS, *TEXT_GLOBS]:
        for path in REPO_ROOT.glob(pattern):
            resolved = path.resolve()
            if resolved in seen or not path.is_file():
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            if "/tests/" in rel or rel.startswith("tests/"):
                continue
            if "/golden/" in rel or "/tests/golden/" in rel:
                continue
            seen.add(resolved)
            paths.append(path)
    return sorted(paths)


def _scan_file(path: Path) -> list[str]:
    findings: list[str] = []
    text = path.read_text(encoding="utf-8")
    for line_no, line in enumerate(text.splitlines(), start=1):
        if any(marker in line for marker in SKIP_LINE_MARKERS):
            continue
        for pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if match is None:
                continue
            snippet = match.group(0)
            if len(snippet) > 40:
                snippet = snippet[:37] + "..."
            try:
                display = path.relative_to(REPO_ROOT)
            except ValueError:
                display = path
            findings.append(f"{display}:{line_no}: {snippet}")
    return findings


def main() -> int:
    all_findings: list[str] = []
    for path in _iter_paths():
        all_findings.extend(_scan_file(path))
    if all_findings:
        print("Hardcoded secret literals found:", file=sys.stderr)
        for finding in all_findings:
            print(finding, file=sys.stderr)
        return 1
    print(f"Secret literal check passed: {len(_iter_paths())} enforced path(s), no literals.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
