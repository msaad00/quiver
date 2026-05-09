"""Lambda 1: Parser — validate and filter the S3 remediation manifest.

Triggered by Step Function after EventBridge detects a new S3 object
in the departures/ prefix. Reads the manifest, validates each entry,
filters out rehires and already-deleted IAMs, and passes actionable
entries to the worker Lambda.

MITRE ATT&CK coverage:
    T1078.004  Valid Accounts: Cloud Accounts — validates departed-employee IAM persistence
    T1087.004  Account Discovery: Cloud Account — enumerates IAM users per account

NIST CSF:
    PR.AC-1   Identities and credentials are issued, managed, verified, revoked
    DE.CM-3   Personnel activity is monitored to detect potential cybersecurity events

CIS Controls v8:
    5.3   Disable Dormant Accounts
    6.1   Establish an Access Granting Process
    6.2   Establish an Access Revoking Process
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configuration from environment
GRACE_PERIOD_DAYS = int(os.environ.get("IAM_GRACE_PERIOD_DAYS", "7"))
CROSS_ACCOUNT_ROLE = os.environ.get("IAM_CROSS_ACCOUNT_ROLE", "iam-remediation-role")
ACCOUNT_ID_RE = re.compile(r"^\d{12}$")


def handler(event: dict, context: Any) -> dict:
    """Step Function task: parse manifest and validate IAM users.

    Input (from Step Function):
        {
            "bucket": "my-bucket",
            "key": "departures/2026-03-01.json"
        }

    Output (to worker Lambda via Step Function Map state):
        {
            "validated_entries": [...],
            "validation_summary": {...}
        }
    """
    bucket = event.get("bucket")
    key = event.get("key")

    if not isinstance(bucket, str) or not bucket or not isinstance(key, str) or not key:
        logger.error("Invalid parser event payload: missing bucket/key")
        return {
            "validated_entries": [],
            "validation_summary": {
                "manifest_key": key if isinstance(key, str) else "",
                "total_entries": 0,
                "validated_count": 0,
                "skipped_count": 0,
                "error_count": 1,
                "skipped": [],
                "errors": [{"error": "Invalid event payload: bucket and key are required"}],
                "validated_at": datetime.now(timezone.utc).isoformat(),
            },
            "source_bucket": bucket if isinstance(bucket, str) else "",
            "source_key": key if isinstance(key, str) else "",
        }

    logger.info("Parsing manifest: s3://%s/%s", bucket, key)

    # 1. Read manifest from S3
    s3 = boto3.client("s3")
    response = s3.get_object(Bucket=bucket, Key=key)
    manifest = json.loads(response["Body"].read().decode("utf-8"))

    entries = manifest.get("entries", [])
    logger.info("Manifest contains %d entries", len(entries))

    # 2. Validate each entry
    validated = []
    skipped = []
    errors = []

    for entry in entries:
        try:
            result = _validate_entry(entry)
            if result["action"] == "remediate":
                validated.append(result["entry"])
            else:
                skipped.append(
                    {
                        "email": entry.get("email", ""),
                        "iam_username": entry.get("iam_username", ""),
                        "reason": result["reason"],
                    }
                )
        except Exception as exc:
            errors.append(
                {
                    "email": entry.get("email", ""),
                    "iam_username": entry.get("iam_username", ""),
                    "error": str(exc),
                }
            )
            logger.exception("Validation error for %s", entry.get("email", ""))

    summary = {
        "manifest_key": key,
        "total_entries": len(entries),
        "validated_count": len(validated),
        "skipped_count": len(skipped),
        "error_count": len(errors),
        "skipped": skipped,
        "errors": errors,
        "validated_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "Validation complete: %d actionable, %d skipped, %d errors",
        len(validated),
        len(skipped),
        len(errors),
    )

    return {
        "validated_entries": validated,
        "validation_summary": summary,
        "source_bucket": bucket,
        "source_key": key,
    }


def _validate_entry(entry: dict) -> dict:
    """Validate a single departure record.

    Checks:
        1. Required fields present
        2. Grace period not expired
        3. Rehire status (same IAM vs different IAM)
        4. IAM user exists in target account
        5. IAM not already deleted

    Returns:
        {"action": "remediate"|"skip", "entry": {...}, "reason": "..."}
    """
    # Required field validation
    required = ["email", "recipient_account_id", "iam_username", "terminated_at"]
    for field in required:
        if not entry.get(field):
            return {"action": "skip", "reason": f"Missing required field: {field}", "entry": entry}

    if not ACCOUNT_ID_RE.fullmatch(str(entry["recipient_account_id"])):
        return {"action": "skip", "reason": "Invalid recipient_account_id format", "entry": entry}

    # Already deleted — skip
    if entry.get("iam_deleted"):
        return {"action": "skip", "reason": "IAM user already deleted", "entry": entry}

    # Already remediated — skip
    if entry.get("remediation_status") == "remediated":
        return {"action": "skip", "reason": "Already remediated", "entry": entry}

    # Grace period check — don't act on very recent terminations
    terminated_at = _parse_iso(entry["terminated_at"])
    if terminated_at:
        grace_deadline = datetime.now(timezone.utc) - timedelta(days=GRACE_PERIOD_DAYS)
        if terminated_at > grace_deadline:
            days_since = (datetime.now(timezone.utc) - terminated_at).days
            return {
                "action": "skip",
                "reason": f"Within grace period ({days_since}d < {GRACE_PERIOD_DAYS}d)",
                "entry": entry,
            }

    # Rehire check — the critical caveats
    if entry.get("is_rehire") and entry.get("rehire_date"):
        rehire_date = _parse_iso(entry["rehire_date"])
        iam_last_used = _parse_iso(entry.get("iam_last_used_at"))
        iam_created = _parse_iso(entry.get("iam_created_at"))

        # Rehired + same IAM still in use → SKIP
        if iam_last_used and rehire_date and iam_last_used > rehire_date:
            return {
                "action": "skip",
                "reason": "Rehired employee — IAM used after rehire date (same IAM in use)",
                "entry": entry,
            }

        # Rehired + IAM created after rehire → this is their new IAM → SKIP
        if iam_created and rehire_date and iam_created > rehire_date:
            return {
                "action": "skip",
                "reason": "IAM created after rehire — this is the employee's current IAM",
                "entry": entry,
            }

        # Rehired but old IAM NOT used after rehire → employee got new IAM
        # This old IAM is orphaned → REMEDIATE
        logger.info(
            "Rehired employee %s has orphaned IAM %s (not used after rehire)",
            entry["email"],
            entry["iam_username"],
        )

    # Confirm IAM user actually exists in the target account.
    # Skipped on the MCP / CLI plan path — that surface lacks per-account
    # assumed-role credentials. The deployed runner always runs the check.
    if os.environ.get("IAM_DEPARTURES_AWS_SKIP_EXISTENCE_CHECK", "").strip() not in {"1", "true", "yes", "on"}:
        account_id = entry["recipient_account_id"]
        iam_username = entry["iam_username"]

        try:
            iam_client = _get_iam_client(account_id)
            iam_client.get_user(UserName=iam_username)
        except iam_client.exceptions.NoSuchEntityException:
            return {
                "action": "skip",
                "reason": f"IAM user {iam_username} not found in account {account_id}",
                "entry": entry,
            }
        except Exception as exc:
            # If we can't verify, don't remediate — fail safe
            return {
                "action": "skip",
                "reason": f"Cannot verify IAM user: {exc}",
                "entry": entry,
            }

    # All checks passed — remediate
    entry["validation_timestamp"] = datetime.now(timezone.utc).isoformat()
    return {"action": "remediate", "entry": entry, "reason": ""}


def _get_iam_client(account_id: str) -> Any:
    """Assume role into target account for IAM operations.

    Uses STS AssumeRole with the cross-account remediation role.
    The role must exist in every target account and trust the
    Security OU management account.
    """
    if not ACCOUNT_ID_RE.fullmatch(account_id):
        raise ValueError("Invalid AWS account ID")

    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}"

    credentials = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="iam-departures-parser",
        DurationSeconds=900,  # 15 min max for validation
    )["Credentials"]

    return boto3.client(
        "iam",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def _parse_iso(value: str | None) -> datetime | None:
    """Parse ISO 8601 datetime string."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


# ── CLI entrypoint ──────────────────────────────────────────────────


_SAFE_ENTRY_KEYS = (
    "email",
    "recipient_account_id",
    "iam_username",
    "terminated_at",
    "iam_deleted",
    "remediation_status",
    "is_rehire",
    "rehire_date",
    "iam_last_used_at",
    "iam_created_at",
    "validation_timestamp",
)


def _redact_entry(entry: dict) -> dict:
    return {k: v for k, v in entry.items() if k in _SAFE_ENTRY_KEYS}


def main(argv: list[str] | None = None) -> int:
    """CLI / MCP entrypoint: dry-run the parser against a manifest.

    Mirrors the runner's pure pre-flight checks (required fields, account
    ID format, grace period, rehire decision tree). The IAM-existence call
    is bypassed via `IAM_DEPARTURES_AWS_SKIP_EXISTENCE_CHECK` because this
    surface lacks per-account assumed-role credentials. The Step Function
    pipeline (deployed under runners/) is the only path that actually
    deletes IAM users.
    """
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "iam-departures-aws parser — dry-run a JSONL manifest of "
            "departed-employee entries against the runner's pre-flight "
            "policy checks. Read-only at this layer; --apply has no "
            "effect because deletion happens only in the deployed runner."
        )
    )
    parser.add_argument(
        "--manifest",
        type=str,
        help="Path to a JSONL manifest. Default: read JSONL entries from stdin.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Refused on this surface — the runner pipeline owns the "
            "destructive path. Use the deployed Step Function to act."
        ),
    )
    args = parser.parse_args(argv)

    if args.apply:
        sys.stderr.write(
            json.dumps(
                {
                    "event": "apply_refused",
                    "reason": (
                        "iam-departures-aws --apply runs only in the deployed Step Function. "
                        "The MCP/CLI surface stays plan-only; deploy the runner under "
                        "runners/aws-s3-sqs-detect/ siblings to act."
                    ),
                }
            )
            + "\n"
        )
        return 2

    os.environ.setdefault("IAM_DEPARTURES_AWS_SKIP_EXISTENCE_CHECK", "1")

    if args.manifest:
        with open(args.manifest, "r", encoding="utf-8") as fh:
            entries_iter = list(fh)
    else:
        entries_iter = list(sys.stdin)

    actions = 0
    skips = 0
    for line in entries_iter:
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        result = _validate_entry(entry)
        out = {
            "action": result["action"],
            "reason": result.get("reason", ""),
            "entry": _redact_entry(result["entry"]),
        }
        sys.stdout.write(json.dumps(out, sort_keys=True) + "\n")
        if result["action"] == "remediate":
            actions += 1
        else:
            skips += 1

    sys.stderr.write(
        json.dumps(
            {
                "event": "plan_summary",
                "actions": actions,
                "skips": skips,
                "dry_run": True,
            }
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
