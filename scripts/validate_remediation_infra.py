#!/usr/bin/env python3
"""Validate remediation skills ship reference infrastructure stubs.

Every ``remediate-*`` bundle must include:
  - ``infra/README.md`` — deploy topology + audit wiring
  - ``infra/terraform/main.tf`` — skeleton IaC entrypoint
  - ``infra/iam_policies/worker_execution_role.json`` — least-privilege reference

``iam-departures-*`` skills already ship full stacks; this gate only
refuses missing paths.

Exit codes: 0 on pass, 1 on failure.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REMEDIATION_ROOT = REPO_ROOT / "skills" / "remediation"

REQUIRED_PATHS = (
    "infra/README.md",
    "infra/terraform/main.tf",
    "infra/iam_policies/worker_execution_role.json",
)


def main() -> int:
    errors: list[str] = []
    skill_dirs = sorted(
        path for path in REMEDIATION_ROOT.glob("remediate-*") if (path / "SKILL.md").is_file()
    )
    if not skill_dirs:
        print("error: no remediate-* skills found", file=sys.stderr)
        return 1

    for skill_dir in skill_dirs:
        for rel in REQUIRED_PATHS:
            path = skill_dir / rel
            if not path.is_file():
                errors.append(f"{skill_dir.relative_to(REPO_ROOT)}: missing {rel}")

    if errors:
        print("Remediation infra validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"Remediation infra validation passed ({len(skill_dirs)} skills).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
