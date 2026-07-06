"""Protected IAM principals — defense-in-depth deny list, mirrored from IaC.

The authoritative deny list is the `DenyProtectedUsers` statement in
`infra/iam_policies/cross_account_remediation_role.json`. That IAM policy is
the load-bearing guard: AWS refuses `iam:*` against these ARNs at the API
boundary, so even a compromised worker Lambda cannot delete them.

This Python module is a **second-layer guard**. Before the worker calls any
IAM API, it checks whether the target `iam_username` matches any of these
patterns and refuses the call locally. The point is twofold:

1. Defense-in-depth: if the IaC deny policy is ever missing from a deployment
   (e.g. a region where CloudFormation StackSet has not landed yet, or a
   hand-rolled role), the Python guard still refuses protected principals.
2. Code visibility: operators reading `handler.py` can see the list without
   chasing JSON policies in `infra/`.

`scripts/validate_deny_list_parity.py` asserts that every pattern in the IaC
`DenyProtectedUsers` statement has an equivalent entry here (and vice versa).
If the lists drift, CI fails.

Pattern syntax matches `fnmatch`: `*` is a wildcard, case-insensitive match.
"""

from __future__ import annotations

import fnmatch

# Keep in sync with `infra/iam_policies/cross_account_remediation_role.json`
# `DenyProtectedUsers` statement. The IaC stores fully-qualified ARNs
# (`arn:aws:iam::...:user/<pattern>`); we store just the `<pattern>` half
# because the handler works in terms of `iam_username`, not ARN.
#
# The IaC list also denies `role/*` — that's enforced at the IAM layer
# because this worker only ever receives `iam_username` inputs, never role
# ARNs. Still listed here to make the full protected surface visible.
PROTECTED_USER_PATTERNS: tuple[str, ...] = (
    "root",
    "break-glass-*",
    "emergency-*",
)

# Role patterns — present for documentation + parity check with IaC. The
# handler only deletes users, so these are never reached as deletion targets.
# The IaC `Resource` deny still covers them at the API boundary.
PROTECTED_ROLE_PATTERNS: tuple[str, ...] = ("*",)


class ProtectedPrincipalError(ValueError):
    """Raised when a remediation target matches the protected-principal deny list."""


def is_protected_user(username: str) -> bool:
    """True if `username` matches any protected-user pattern (case-insensitive)."""
    lowered = username.lower()
    return any(fnmatch.fnmatchcase(lowered, pattern.lower()) for pattern in PROTECTED_USER_PATTERNS)


def assert_not_protected(username: str) -> None:
    """Raise `ProtectedPrincipalError` if `username` is on the deny list.

    Call this before any IAM API invocation in the worker. The IAM deny
    policy is the load-bearing guard; this is defense-in-depth so the worker
    refuses locally even if the deny policy is ever missing.
    """
    if is_protected_user(username):
        raise ProtectedPrincipalError(
            f"refusing to remediate protected principal `{username}` — matches one of "
            f"{PROTECTED_USER_PATTERNS}. This list is mirrored from the IaC deny "
            "policy in infra/iam_policies/cross_account_remediation_role.json."
        )
