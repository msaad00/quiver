#!/usr/bin/env python3
"""Validate ingest→detect golden pipe fixtures referenced by integration tests.

Reads ``tests/integration/golden_pipes.json`` and verifies raw + expected
fixtures exist. Count gate prevents accidental pipe registry shrinkage.

Exit codes: 0 on pass, 1 on failure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY = REPO_ROOT / "tests" / "integration" / "golden_pipes.json"
GOLDEN_DIR = REPO_ROOT / "skills" / "detection-engineering" / "golden"
MIN_PIPES = 18


def main() -> int:
    payload = json.loads(REGISTRY.read_text(encoding="utf-8"))
    pipes = payload.get("pipes", [])
    errors: list[str] = []

    if len(pipes) < MIN_PIPES:
        errors.append(f"registry has {len(pipes)} pipes, minimum {MIN_PIPES}")

    for pipe in pipes:
        name = pipe.get("name", "<unnamed>")
        for key in ("raw_fixture", "expected_fixture"):
            rel = pipe.get(key)
            if not rel:
                errors.append(f"{name}: missing {key}")
                continue
            path = GOLDEN_DIR / rel
            if not path.is_file():
                errors.append(f"{name}: missing golden file {path.relative_to(REPO_ROOT)}")

    if errors:
        print("Golden pipe validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"Golden pipe validation passed ({len(pipes)} pipes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
