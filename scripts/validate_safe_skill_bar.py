from __future__ import annotations

import re
import sys
from typing import Any

from skill_validation_common import ROOT, SKILLS_ROOT, discover_skill_contracts

SUBPROCESS_PATTERNS = (
    "import subprocess",
    "from subprocess import",
    "os.system(",
    "Popen(",
    "check_output(",
)

WILDCARD_PATTERNS = (
    re.compile(r'"Action"\s*:\s*"\*"'),
    re.compile(r'"Resource"\s*:\s*"\*"'),
    re.compile(r"\bAction\s*=\s*\"\*\""),
    re.compile(r"\bResource\s*=\s*\"\*\""),
)

POLICY_SUFFIXES = (".json", ".tf", ".yaml", ".yml")

# Policy floors from docs/HITL_POLICY.md that are stricter than the generic
# "write-capable skills need human approval" bar. Keep the set explicit so CI
# fails when a shipped skill drifts from the published policy matrix.
POLICY_MIN_APPROVERS: dict[str, int] = {
    "remediate-mcp-tool-quarantine": 2,
}


def validate_read_only_no_subprocess(skill: object) -> list[str]:
    errors: list[str] = []
    skill_dir = getattr(skill, "skill_dir")
    is_write_capable = bool(getattr(skill, "is_write_capable"))
    approval_model = getattr(skill, "approval_model")
    side_effects = getattr(skill, "side_effects")
    if is_write_capable:
        return errors

    for path in sorted((skill_dir / "src").rglob("*.py")):
        text = path.read_text()
        for pattern in SUBPROCESS_PATTERNS:
            if pattern in text:
                rel = path.relative_to(ROOT)
                errors.append(
                    f"{rel}: read-only skill must not use subprocess/shell pattern `{pattern}`"
                )
    if approval_model != "none":
        errors.append(
            f"{skill_dir.relative_to(ROOT)}: read-only skill must keep approval_model `none`"
        )
    if side_effects != ("none",):
        errors.append(
            f"{skill_dir.relative_to(ROOT)}: read-only skill must keep side_effects `none`"
        )
    return errors


def validate_write_skill_dry_run(skill: object) -> list[str]:
    errors: list[str] = []
    skill_dir = getattr(skill, "skill_dir")
    is_write_capable = bool(getattr(skill, "is_write_capable"))
    approval_model = getattr(skill, "approval_model")
    if not is_write_capable:
        return errors

    skill_md = (skill_dir / "SKILL.md").read_text().lower()
    if "dry-run" not in skill_md and "dry_run" not in skill_md:
        errors.append(
            f"{skill_dir.relative_to(ROOT)}: write-capable skill must document dry-run in SKILL.md"
        )

    tests_dir = skill_dir / "tests"
    test_text = "\n".join(path.read_text() for path in sorted(tests_dir.rglob("*.py")))
    if "dry_run" not in test_text and "--dry-run" not in test_text and "dry-run" not in test_text:
        errors.append(
            f"{skill_dir.relative_to(ROOT)}: write-capable skill must exercise dry-run in tests"
        )
    if approval_model != "human_required":
        errors.append(
            f"{skill_dir.relative_to(ROOT)}: write-capable skill must require human approval"
        )

    return errors


# -- Runtime contract: frontmatter declarations must match src/ behaviour ----
#
# The existing validate_write_skill_dry_run check verifies SKILL.md documents
# dry-run and tests exercise it. These sibling checks verify the src/ CODE
# actually implements what frontmatter declares. Without them, a skill could
# declare approval_model: human_required + side_effects: writes-identity in
# frontmatter while shipping a src/ that skips dry-run or skips the audit
# write — a silent HITL bypass.
#
# Heuristic (grep-based), not AST. Cheap to run, catches the bug class that
# matters: "the skill's own code stopped implementing what its own frontmatter
# promises."

_DRY_RUN_MARKERS_IN_SRC = (
    "dry_run",
    "--dry-run",
    "--apply",
    "DryRun",
)

_AUDIT_WRITE_MARKERS_IN_SRC = (
    "put_item",  # DynamoDB
    "put_object",  # S3
    "dynamodb",
    "audit",
    "AuditWriter",
    "write_audit",
    "record_audit",
)

# boto3 / google-cloud / msgraph method prefixes that mutate state. A read-only
# skill should never invoke any of these. Subset matches the most common write
# surfaces; extend when new ones land.
_CLOUD_WRITE_METHOD_PREFIXES = (
    ".delete_",  # delete_user / delete_access_key / delete_role etc.
    ".create_",  # create_user / create_access_key / create_role etc.
    ".update_",  # update_access_key / update_role etc.
    ".put_",  # put_role_policy / put_bucket_policy etc.
    ".attach_",  # attach_role_policy etc.
    ".detach_",  # detach_user_policy etc.
    ".remove_",  # remove_user_from_group etc.
    ".deactivate_",  # deactivate_mfa_device
    ".revoke_",  # revoke_security_group_ingress
    ".terminate_",  # terminate_instances
)


def _src_python_files(skill_dir: Any) -> list[Any]:
    src_dir = skill_dir / "src"
    if not src_dir.exists():
        return []
    return sorted(src_dir.rglob("*.py"))


def _blank_quoted(line: str, quote: str) -> str:
    result: list[str] = []
    inside = False
    for char in line:
        if char == quote:
            inside = not inside
            result.append(char)
            continue
        result.append(" " if inside else char)
    return "".join(result)


def _strip_strings_and_comments(text: str) -> str:
    """Blank out #-comments and body of '...' / "..." strings so grep doesn't
    false-positive on method names that appear in docstrings, log messages, or
    example prose. Crude but sufficient for the patterns we detect."""
    out: list[str] = []
    for line in text.splitlines():
        if "#" in line:
            line = line[: line.index("#")]
        line = _blank_quoted(line, '"')
        line = _blank_quoted(line, "'")
        out.append(line)
    return "\n".join(out)


def validate_write_skill_source_guards(skill: object) -> list[str]:
    """Writable skill's src/ must actually implement the dry-run + audit
    guardrails its frontmatter promises.

    Scope: **remediation skills only**. Output-sinks (`capability: write-sink`)
    are writable by design but are themselves the audit artifact that
    remediation skills feed into — they do not "audit their own writes."
    """
    errors: list[str] = []
    skill_dir = getattr(skill, "skill_dir")
    is_write_capable = bool(getattr(skill, "is_write_capable"))
    if not is_write_capable:
        return errors

    # Exempt sinks: they are the audit destination, not an audit emitter.
    capability = getattr(skill, "frontmatter", {}).get("capability", "")
    category = getattr(skill, "category", "")
    if capability == "write-sink" or category == "output":
        return errors

    src_files = _src_python_files(skill_dir)
    if not src_files:
        errors.append(f"{skill_dir.relative_to(ROOT)}: writable skill has no src/**/*.py files")
        return errors

    src_text = "\n".join(path.read_text() for path in src_files)

    if not any(marker in src_text for marker in _DRY_RUN_MARKERS_IN_SRC):
        errors.append(
            f"{skill_dir.relative_to(ROOT)}: writable skill src/ must implement a "
            "dry-run switch (dry_run parameter or --dry-run / --apply flag). "
            "Frontmatter says writable but code shows no dry-run surface."
        )

    if not any(marker in src_text for marker in _AUDIT_WRITE_MARKERS_IN_SRC):
        errors.append(
            f"{skill_dir.relative_to(ROOT)}: writable skill src/ must implement an "
            "audit write path (put_item / put_object / audit.record / similar). "
            "Frontmatter says writable but code shows no audit marker."
        )

    return errors


def validate_read_only_no_cloud_writes(skill: object) -> list[str]:
    """Read-only skill's src/ must not invoke any cloud-SDK write method.

    Catches the regression where a detection / evaluation / discovery skill
    starts calling a write method when a read method would do.
    """
    errors: list[str] = []
    skill_dir = getattr(skill, "skill_dir")
    is_write_capable = bool(getattr(skill, "is_write_capable"))
    if is_write_capable:
        return errors

    src_files = _src_python_files(skill_dir)
    if not src_files:
        return errors

    for path in src_files:
        text = path.read_text()
        stripped = _strip_strings_and_comments(text)
        for idx, line in enumerate(stripped.splitlines(), start=1):
            for marker in _CLOUD_WRITE_METHOD_PREFIXES:
                if marker in line:
                    rel = path.relative_to(ROOT)
                    errors.append(
                        f"{rel}:{idx}: read-only skill appears to call a "
                        f"cloud-write method (`{marker.strip('.')}...`). "
                        "Frontmatter declares read-only; either remove the call "
                        "or move the skill to remediation/ and update frontmatter."
                    )
                    break  # one error per line is enough

    return errors


def _has_wildcard_marker(lines: list[str], line_index: int) -> bool:
    # JSON IAM statements and Terraform policy blocks can span many lines before
    # the wildcard resource/action appears. Keep the marker local to the block,
    # but don't make the validator brittle on line wrapping.
    start = max(0, line_index - 32)
    window = "\n".join(lines[start : line_index + 1])
    return "WILDCARD_OK" in window


def validate_wildcards() -> list[str]:
    errors: list[str] = []
    for path in sorted(SKILLS_ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in POLICY_SUFFIXES:
            continue
        text = path.read_text()
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            if any(pattern.search(line) for pattern in WILDCARD_PATTERNS):
                if not _has_wildcard_marker(lines, idx):
                    rel = path.relative_to(ROOT)
                    errors.append(
                        f"{rel}:{idx + 1}: wildcard Action/Resource requires explicit WILDCARD_OK justification"
                    )
    return errors


# -- Guardrail: every Allow of sts:AssumeRole must carry a boundary condition --
#
# Zero-trust guardrail. A remediation Lambda that can AssumeRole anywhere is an
# instant privilege-escalation surface. Any Allow of `sts:AssumeRole` MUST carry
# at least one boundary condition:
#   - aws:PrincipalOrgID (org boundary — recommended default)
#   - aws:PrincipalTag / aws:SourceAccount / aws:SourceOrgID (adjacent boundary
#     conditions that are still acceptable)
#
# The alternative — "just trust the IAM policy on the target role" — is not
# sufficient: a misconfigured target role becomes an escape hatch, and the
# target role is often in a separate account with a different review culture.
#
# To opt out for a genuinely unusual case, add ASSUME_ROLE_CONDITION_OK near
# the statement with a written justification. Symmetrical to WILDCARD_OK.

ASSUME_ROLE_ACTION_PATTERNS = (
    re.compile(r'"Action"\s*:\s*"sts:AssumeRole"', re.IGNORECASE),
    re.compile(r'\bAction\s*=\s*"sts:AssumeRole"', re.IGNORECASE),
    re.compile(r"^\s*Action\s*:\s*sts:AssumeRole\s*$", re.IGNORECASE | re.MULTILINE),
)

_BOUNDARY_CONDITION_MARKERS = (
    "aws:PrincipalOrgID",
    "aws:PrincipalOrgPaths",
    "aws:PrincipalTag",
    "aws:SourceAccount",
    "aws:SourceOrgID",
    "aws:SourceOrgPaths",
    "aws:ResourceOrgID",
    "ASSUME_ROLE_CONDITION_OK",
)

# Trust-policy statements (the AssumeRolePolicyDocument that lets a service
# principal assume this role) are NOT the concern here. Those are bounded by
# `Principal: { Service: "lambda.amazonaws.com" }` or similar, not by a
# PrincipalOrgID condition. Skip any AssumeRole line whose 32-line window
# contains a Service or Federated principal marker.
_TRUST_POLICY_MARKERS = (
    '"Service"',
    "Service =",
    "Service:",
    '"Federated"',
    "Federated =",
    "Federated:",
)


def _is_trust_policy_statement(lines: list[str], line_index: int) -> bool:
    start = max(0, line_index - 32)
    end = min(len(lines), line_index + 32)
    window = "\n".join(lines[start:end])
    return any(marker in window for marker in _TRUST_POLICY_MARKERS)


def _has_boundary_condition(lines: list[str], line_index: int) -> bool:
    # Look ~32 lines in either direction for a boundary condition on the same
    # statement. Policy statements in CFN/TF/JSON commonly put the Condition
    # block after the Action line, so forward-scan generously.
    start = max(0, line_index - 8)
    end = min(len(lines), line_index + 32)
    window = "\n".join(lines[start:end])
    return any(marker in window for marker in _BOUNDARY_CONDITION_MARKERS)


def validate_assume_role_boundaries() -> list[str]:
    errors: list[str] = []
    for path in sorted(SKILLS_ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in POLICY_SUFFIXES:
            continue
        text = path.read_text()
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            if not any(pattern.search(line) for pattern in ASSUME_ROLE_ACTION_PATTERNS):
                continue
            if _is_trust_policy_statement(lines, idx):
                continue
            if not _has_boundary_condition(lines, idx):
                rel = path.relative_to(ROOT)
                errors.append(
                    f"{rel}:{idx + 1}: sts:AssumeRole Allow must carry an org/account/tag "
                    "boundary condition (aws:PrincipalOrgID, aws:SourceAccount, "
                    "aws:PrincipalTag, aws:SourceOrgID) or an explicit "
                    "ASSUME_ROLE_CONDITION_OK justification"
                )
    return errors


# -- Guardrail: every remediation skill's --apply path must require HITL ------
#
# A remediation skill's frontmatter declares `approval_model: human_required`.
# The src/ must back that up by gating its destructive (--apply) path on TWO
# env vars: an incident identifier (pinning the action to a declared incident)
# AND an approver identifier (pinning who authorized it). Both end up in the
# dual-audit row.
#
# Without this check, a skill could declare `human_required` in frontmatter
# while shipping a src/ that runs --apply on a bare CLI invocation — a silent
# HITL bypass that would only be caught by manual review.
#
# Heuristic (case-insensitive substring): any of {INCIDENT, TICKET, CASE_ID}
# for the incident var, AND any of {APPROVER, APPROVED_BY, AUTHORIZED_BY,
# AUTHORIZER} for the approver var. The remediation suite uses the per-skill
# prefix pattern (e.g. AWS_SG_REVOKE_INCIDENT_ID + AWS_SG_REVOKE_APPROVER), so
# substring matching is robust to renames.
#
# Exempt: `iam-departures-aws` predates this convention and uses a richer
# Step-Functions-driven approval model (grace-period + EventBridge gate +
# multi-layer deny lists). It is grandfathered via HITL_ENV_OK at the file
# level. New remediation skills must use the env-var pattern or add the same
# grandfather marker with a documented justification.

_INCIDENT_ENV_TOKENS = ("INCIDENT", "TICKET", "CASE_ID")
_APPROVER_ENV_TOKENS = ("APPROVER", "APPROVED_BY", "AUTHORIZED_BY", "AUTHORIZER")


def validate_remediation_hitl_env_vars(skill: object) -> list[str]:
    """Remediation skill src/ must gate --apply on incident + approver env vars."""
    errors: list[str] = []
    skill_dir = getattr(skill, "skill_dir")
    is_write_capable = bool(getattr(skill, "is_write_capable"))
    category = getattr(skill, "category", "")
    capability = getattr(skill, "frontmatter", {}).get("capability", "")

    if not is_write_capable or category != "remediation":
        return errors
    if capability == "write-sink":
        return errors

    src_files = _src_python_files(skill_dir)
    if not src_files:
        return errors

    src_text = "\n".join(path.read_text() for path in src_files)
    if "HITL_ENV_OK" in src_text:
        return errors

    has_incident = any(token in src_text for token in _INCIDENT_ENV_TOKENS)
    has_approver = any(token in src_text for token in _APPROVER_ENV_TOKENS)
    rel = skill_dir.relative_to(ROOT)

    if not has_incident:
        errors.append(
            f"{rel}: remediation skill src/ must gate --apply on an incident env var "
            f"(name containing one of {_INCIDENT_ENV_TOKENS}). Frontmatter declares "
            "approval_model: human_required; the src/ must enforce it. "
            "Use HITL_ENV_OK with a justification to grandfather a non-conforming gate."
        )
    if not has_approver:
        errors.append(
            f"{rel}: remediation skill src/ must gate --apply on an approver env var "
            f"(name containing one of {_APPROVER_ENV_TOKENS}). Frontmatter declares "
            "approval_model: human_required; the src/ must enforce it. "
            "Use HITL_ENV_OK with a justification to grandfather a non-conforming gate."
        )
    return errors


def validate_policy_min_approvers(skill: object) -> list[str]:
    errors: list[str] = []
    skill_name = getattr(skill, "name", "")
    required = POLICY_MIN_APPROVERS.get(skill_name)
    if required is None:
        return errors

    frontmatter = getattr(skill, "frontmatter", {})
    raw_value = str(frontmatter.get("min_approvers", "")).strip()
    rel = getattr(skill, "skill_dir").relative_to(ROOT)
    if not raw_value:
        errors.append(
            f"{rel}: min_approvers must be set to {required} to match docs/HITL_POLICY.md"
        )
        return errors
    try:
        actual = int(raw_value)
    except ValueError:
        errors.append(f"{rel}: min_approvers must be an integer to match docs/HITL_POLICY.md")
        return errors
    if actual < required:
        errors.append(
            f"{rel}: min_approvers={actual} is below the policy floor {required} from docs/HITL_POLICY.md"
        )
    return errors


def main() -> int:
    errors: list[str] = []
    for skill in discover_skill_contracts():
        errors.extend(validate_read_only_no_subprocess(skill))
        errors.extend(validate_read_only_no_cloud_writes(skill))
        errors.extend(validate_write_skill_dry_run(skill))
        errors.extend(validate_write_skill_source_guards(skill))
        errors.extend(validate_remediation_hitl_env_vars(skill))
        errors.extend(validate_policy_min_approvers(skill))
    errors.extend(validate_wildcards())
    errors.extend(validate_assume_role_boundaries())

    if errors:
        print("Safe-skill validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print("Safe-skill validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
