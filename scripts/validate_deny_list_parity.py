#!/usr/bin/env python3
"""Assert the IaC deny list and the Python code-side deny list agree.

The load-bearing guard for `iam-departures-aws` is an IAM `Deny` statement in
`infra/iam_policies/cross_account_remediation_role.json` that refuses
`iam:*` against `root`, `break-glass-*`, `emergency-*`, and `role/*`.

A defense-in-depth Python mirror lives at
`skills/remediation/iam-departures-aws/src/lambda_worker/protected_principals.py`
so the worker refuses locally even if the IaC policy is ever missing.

If the two lists drift, CI should fail. This script parses both and asserts
that every ARN pattern in the `DenyProtectedUsers` IaC statement is covered
by the Python list (and vice versa).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
IAC_POLICY = (
    REPO_ROOT
    / "skills"
    / "remediation"
    / "iam-departures-aws"
    / "infra"
    / "iam_policies"
    / "cross_account_remediation_role.json"
)
PYTHON_MIRROR = (
    REPO_ROOT
    / "skills"
    / "remediation"
    / "iam-departures-aws"
    / "src"
    / "lambda_worker"
    / "protected_principals.py"
)

# ARN template suffix patterns we treat as "user-scoped" deny entries. The
# IaC uses `${TARGET_ACCOUNT_ID}` as a CloudFormation placeholder.
_USER_ARN_RE = re.compile(r"^arn:aws:iam::\${TARGET_ACCOUNT_ID}:user/(?P<pattern>.+)$")
_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::\${TARGET_ACCOUNT_ID}:role/(?P<pattern>.+)$")


def _iac_user_patterns() -> set[str]:
    data = json.loads(IAC_POLICY.read_text(encoding="utf-8"))
    for stmt in data.get("PermissionPolicy", {}).get("Statement", []):
        if stmt.get("Sid") != "DenyProtectedUsers":
            continue
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        users: set[str] = set()
        for resource in resources:
            m = _USER_ARN_RE.match(resource)
            if m:
                users.add(m.group("pattern"))
        return users
    return set()


def _iac_role_patterns() -> set[str]:
    data = json.loads(IAC_POLICY.read_text(encoding="utf-8"))
    for stmt in data.get("PermissionPolicy", {}).get("Statement", []):
        if stmt.get("Sid") != "DenyProtectedUsers":
            continue
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        roles: set[str] = set()
        for resource in resources:
            m = _ROLE_ARN_RE.match(resource)
            if m:
                roles.add(m.group("pattern"))
        return roles
    return set()


def _python_tuple(source: str, var_name: str) -> set[str]:
    """Extract a tuple-of-str literal assignment by name from Python source."""
    # Match: `PROTECTED_USER_PATTERNS: tuple[str, ...] = (...)`.
    pattern = re.compile(
        rf"{re.escape(var_name)}\s*:\s*tuple\[str,\s*\.\.\.\]\s*=\s*\((?P<body>[^)]*)\)",
        re.DOTALL,
    )
    match = pattern.search(source)
    if not match:
        return set()
    body = match.group("body")
    return {m.group(1) for m in re.finditer(r'"([^"]+)"', body)}


def main() -> int:
    if not IAC_POLICY.exists():
        print(f"error: IaC policy not found: {IAC_POLICY}", file=sys.stderr)
        return 2
    if not PYTHON_MIRROR.exists():
        print(f"error: Python mirror not found: {PYTHON_MIRROR}", file=sys.stderr)
        return 2

    iac_users = _iac_user_patterns()
    iac_roles = _iac_role_patterns()

    py_source = PYTHON_MIRROR.read_text(encoding="utf-8")
    py_users = _python_tuple(py_source, "PROTECTED_USER_PATTERNS")
    py_roles = _python_tuple(py_source, "PROTECTED_ROLE_PATTERNS")

    errors: list[str] = []

    users_only_in_iac = iac_users - py_users
    users_only_in_py = py_users - iac_users
    if users_only_in_iac:
        errors.append(
            f"IaC denies user patterns {sorted(users_only_in_iac)} but they are "
            f"missing from `PROTECTED_USER_PATTERNS` in {PYTHON_MIRROR.relative_to(REPO_ROOT)}"
        )
    if users_only_in_py:
        errors.append(
            f"Python `PROTECTED_USER_PATTERNS` lists {sorted(users_only_in_py)} but "
            f"they are missing from the IaC `DenyProtectedUsers` statement in "
            f"{IAC_POLICY.relative_to(REPO_ROOT)}"
        )

    roles_only_in_iac = iac_roles - py_roles
    roles_only_in_py = py_roles - iac_roles
    if roles_only_in_iac:
        errors.append(
            f"IaC denies role patterns {sorted(roles_only_in_iac)} but they are "
            f"missing from `PROTECTED_ROLE_PATTERNS` in {PYTHON_MIRROR.relative_to(REPO_ROOT)}"
        )
    if roles_only_in_py:
        errors.append(
            f"Python `PROTECTED_ROLE_PATTERNS` lists {sorted(roles_only_in_py)} but "
            f"they are missing from the IaC `DenyProtectedUsers` statement in "
            f"{IAC_POLICY.relative_to(REPO_ROOT)}"
        )

    if errors:
        print("Deny-list parity check FAILED:\n", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        print(
            "\nFix: update whichever file is behind. Both locations must list the same patterns.",
            file=sys.stderr,
        )
        return 1

    print(f"Deny-list parity check passed (users={sorted(iac_users)}, roles={sorted(iac_roles)}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
