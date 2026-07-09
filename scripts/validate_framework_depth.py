#!/usr/bin/env python3
"""Gate per-framework control depth reported in COVERAGE_SNAPSHOT.

Complements ``validate_framework_coverage.py`` (skill-tag breadth) by
refusing regressions in explicit per-control depth for frameworks that
ship typed ``control_id`` markers.

Exit codes: 0 on pass, 1 on regression.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COVERAGE_SUMMARY = REPO_ROOT / "scripts" / "coverage_summary.py"

# Minimum unique controls that must remain covered. Raise these when depth
# expands deliberately — never lower without an issue + snapshot regen.
MIN_DEPTH: dict[str, int] = {
    "owasp-llm-top-10": 5,
    "owasp-mcp-top-10": 3,
    "nist-ai-rmf": 40,
}


def _load_coverage_summary() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("coverage_summary_depth", COVERAGE_SUMMARY)
    if not spec or not spec.loader:
        raise RuntimeError(f"unable to import {COVERAGE_SUMMARY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    mod = _load_coverage_summary()
    skills = mod._load()
    by_fw = mod._bucket_controls_by_framework(skills)
    errors: list[str] = []

    for framework, minimum in sorted(MIN_DEPTH.items()):
        covered = len(by_fw.get(framework, set()))
        if covered < minimum:
            label = mod.FRAMEWORK_LABEL.get(framework, framework)
            errors.append(
                f"{label}: depth regression — {covered} controls covered, minimum {minimum}"
            )

    if errors:
        print("Framework depth validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Framework depth validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
