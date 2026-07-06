"""Cloud Function 1: Parser — validate and filter the GCS departures manifest.

Triggered by Cloud Workflow after Eventarc detects a new object in the
`departures/` prefix of the manifest GCS bucket. Reads the manifest,
validates each entry, applies the grace-period and rehire filters, and
emits validated entries for the Worker Cloud Function to fan out across
in the next Workflow step.

Mirrors `iam-departures-aws/src/lambda_parser/handler.py` step for step;
the only differences are the GCS read, the GCP-specific principal types,
and the lazy `googleapiclient` import for the existence check.

MITRE ATT&CK coverage:
    T1078.004  Valid Accounts: Cloud Accounts — validates departed-employee Workspace / SA persistence
    T1087.004  Account Discovery: Cloud Account — enumerates IAM principals per project

NIST CSF:
    PR.AC-1   Identities and credentials are issued, managed, verified, revoked
    DE.CM-3   Personnel activity is monitored to detect potential cybersecurity events

CIS Controls v8:
    5.3   Disable Dormant Accounts
    6.2   Establish an Access Revoking Process

The handler runs three ways:
    1. As a deployed Cloud Function Gen 2 invoked by Cloud Workflow.
    2. As a CLI tool (`python handler.py --dry-run path/to/manifest.json`).
    3. Via the test suite (mocked GCS + mocked Admin SDK / IAM clients).

Dry-run does not import googleapiclient; the IAM existence check is skipped.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configuration from environment
GRACE_PERIOD_DAYS = int(os.environ.get("IAM_DEPARTURES_GCP_GRACE_DAYS", "7"))
PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
ORG_ID_RE = re.compile(r"^\d{6,16}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SUPPORTED_PRINCIPAL_TYPES = frozenset({"workspace_user", "service_account"})


def handler(event: dict, context: Any | None = None) -> dict:
    """Cloud Workflow task: parse manifest and validate principals.

    Input (from Cloud Workflow, originally from the Eventarc payload):
        {
            "bucket": "my-bucket",
            "name": "departures/2026-04-20.json"
        }

    Output (to worker Cloud Function via Workflow fan-out):
        {
            "validated_entries": [...],
            "validation_summary": {...},
            "source_bucket": "...",
            "source_object": "..."
        }
    """
    bucket = event.get("bucket")
    obj_name = event.get("name") or event.get("object_name") or event.get("key")

    if not isinstance(bucket, str) or not bucket or not isinstance(obj_name, str) or not obj_name:
        logger.error("Invalid parser event payload: missing bucket/name")
        return _error_payload(
            bucket, obj_name, "Invalid event payload: bucket and name are required"
        )

    logger.info("Parsing manifest: gs://%s/%s", bucket, obj_name)
    try:
        manifest = _read_gcs_object(bucket, obj_name)
    except Exception as exc:  # pragma: no cover — defensive
        logger.exception("Failed to read manifest gs://%s/%s", bucket, obj_name)
        return _error_payload(bucket, obj_name, f"Failed to read manifest: {exc}")

    return _validate_manifest(manifest, bucket, obj_name)


def parse_local_manifest(path: str | Path) -> dict:
    """Local path entrypoint used by `--dry-run` and tests."""
    text = Path(path).read_text(encoding="utf-8")
    manifest = json.loads(text)
    return _validate_manifest(manifest, source_bucket="local", source_object=str(path))


def _validate_manifest(manifest: dict, source_bucket: str, source_object: str) -> dict:
    entries = manifest.get("entries", [])
    if not isinstance(entries, list):
        return _error_payload(source_bucket, source_object, "Manifest `entries` must be a list")

    logger.info("Manifest contains %d entries", len(entries))

    validated: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []

    for entry in entries:
        if not isinstance(entry, dict):
            errors.append({"email": "", "principal_id": "", "error": "entry must be an object"})
            continue
        try:
            result = _validate_entry(entry)
            if result["action"] == "remediate":
                validated.append(result["entry"])
            else:
                skipped.append(
                    {
                        "email": entry.get("email", ""),
                        "principal_id": entry.get("principal_id", ""),
                        "reason": result["reason"],
                    }
                )
        except Exception as exc:
            errors.append(
                {
                    "email": entry.get("email", ""),
                    "principal_id": entry.get("principal_id", ""),
                    "error": str(exc),
                }
            )
            logger.exception("Validation error for %s", entry.get("email", ""))

    summary = {
        "manifest_object": source_object,
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
        "source_bucket": source_bucket,
        "source_object": source_object,
    }


def _validate_entry(entry: dict) -> dict:
    """Validate a single departure record.

    Returns:
        {"action": "remediate"|"skip", "entry": {...}, "reason": "..."}
    """
    required = ("email", "principal_type", "principal_id", "gcp_org_id", "terminated_at")
    for field in required:
        if not entry.get(field):
            return {"action": "skip", "reason": f"Missing required field: {field}", "entry": entry}

    if entry["principal_type"] not in SUPPORTED_PRINCIPAL_TYPES:
        return {
            "action": "skip",
            "reason": (
                f"Unsupported principal_type `{entry['principal_type']}`; "
                f"expected one of {sorted(SUPPORTED_PRINCIPAL_TYPES)}"
            ),
            "entry": entry,
        }

    if not EMAIL_RE.fullmatch(str(entry["email"])):
        return {"action": "skip", "reason": "Invalid email format", "entry": entry}

    if not ORG_ID_RE.fullmatch(str(entry["gcp_org_id"])):
        return {"action": "skip", "reason": "Invalid gcp_org_id format", "entry": entry}

    project_ids = entry.get("project_ids", []) or []
    if not isinstance(project_ids, list):
        return {"action": "skip", "reason": "project_ids must be a list", "entry": entry}
    for project_id in project_ids:
        if not isinstance(project_id, str) or not PROJECT_ID_RE.fullmatch(project_id):
            return {
                "action": "skip",
                "reason": f"Invalid project id `{project_id}`",
                "entry": entry,
            }

    # Already deleted — skip
    if entry.get("principal_deleted"):
        return {"action": "skip", "reason": "Principal already deleted", "entry": entry}

    if entry.get("remediation_status") == "remediated":
        return {"action": "skip", "reason": "Already remediated", "entry": entry}

    # Grace period check — never act inside the HR correction window
    terminated_at = _parse_iso(entry["terminated_at"])
    if terminated_at:
        grace_days = max(GRACE_PERIOD_DAYS, 1)  # never zero — fail safe
        grace_deadline = datetime.now(timezone.utc) - timedelta(days=grace_days)
        if terminated_at > grace_deadline:
            days_since = (datetime.now(timezone.utc) - terminated_at).days
            return {
                "action": "skip",
                "reason": f"Within grace period ({days_since}d < {grace_days}d)",
                "entry": entry,
            }

    # Rehire filter — same logic as iam-departures-aws
    if entry.get("is_rehire") and entry.get("rehire_date"):
        rehire_date = _parse_iso(entry["rehire_date"])
        last_used = _parse_iso(entry.get("principal_last_used_at"))
        created = _parse_iso(entry.get("principal_created_at"))

        # Rehired + same principal still in use → SKIP
        if last_used and rehire_date and last_used > rehire_date:
            return {
                "action": "skip",
                "reason": "Rehired employee — principal used after rehire date (same identity in use)",
                "entry": entry,
            }
        # Rehired + principal created after rehire → this is the new identity → SKIP
        if created and rehire_date and created > rehire_date:
            return {
                "action": "skip",
                "reason": "Principal created after rehire — this is the employee's current identity",
                "entry": entry,
            }
        logger.info(
            "Rehired employee %s has orphaned principal %s (not used after rehire)",
            entry["email"],
            entry["principal_id"],
        )

    # Confirm the principal actually exists. Skip the API check when running
    # the parser in dry-run / CLI mode (the `--dry-run` flag sets the
    # IAM_DEPARTURES_GCP_SKIP_EXISTENCE_CHECK env var).
    if not os.environ.get("IAM_DEPARTURES_GCP_SKIP_EXISTENCE_CHECK"):
        try:
            exists = _principal_exists(
                principal_type=entry["principal_type"],
                principal_id=entry["principal_id"],
                project_ids=project_ids,
            )
        except Exception as exc:
            return {
                "action": "skip",
                "reason": f"Cannot verify principal: {exc}",
                "entry": entry,
            }
        if not exists:
            return {
                "action": "skip",
                "reason": f"Principal {entry['principal_id']} not found",
                "entry": entry,
            }

    entry["validation_timestamp"] = datetime.now(timezone.utc).isoformat()
    return {"action": "remediate", "entry": entry, "reason": ""}


# ── GCP integration helpers (lazy-imported) ─────────────────────────


def _read_gcs_object(bucket: str, name: str) -> dict:
    """Read manifest JSON from GCS via the JSON HTTP API.

    Lazy-imports `googleapiclient.discovery.build` so the parser stays
    importable in tests without google-cloud-storage installed.
    """
    from googleapiclient.discovery import build  # noqa: PLC0415  — lazy import

    service = build("storage", "v1", cache_discovery=False)
    response = service.objects().get_media(bucket=bucket, object=name).execute()
    if isinstance(response, bytes):
        response = response.decode("utf-8")
    return json.loads(response)


def _principal_exists(*, principal_type: str, principal_id: str, project_ids: list[str]) -> bool:
    """Confirm the Workspace user / service account still exists.

    The handler refuses to remediate principals that have already been
    deleted out of band — a no-op should be a no-op, not a failed
    Workflow execution.
    """
    from googleapiclient.discovery import build  # noqa: PLC0415  — lazy import

    if principal_type == "workspace_user":
        service = build("admin", "directory_v1", cache_discovery=False)
        try:
            service.users().get(userKey=principal_id).execute()
            return True
        except Exception as exc:  # noqa: BLE001 — vendor SDK throws HttpError
            if "404" in str(exc) or "notFound" in str(exc):
                return False
            raise
    # service_account — check first project where it should exist
    service = build("iam", "v1", cache_discovery=False)
    project_id = project_ids[0] if project_ids else principal_id.split("@", 1)[-1].split(".", 1)[0]
    name = f"projects/{project_id}/serviceAccounts/{principal_id}"
    try:
        service.projects().serviceAccounts().get(name=name).execute()
        return True
    except Exception as exc:  # noqa: BLE001
        if "404" in str(exc) or "notFound" in str(exc):
            return False
        raise


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _error_payload(bucket: Any, name: Any, error: str) -> dict:
    return {
        "validated_entries": [],
        "validation_summary": {
            "manifest_object": name if isinstance(name, str) else "",
            "total_entries": 0,
            "validated_count": 0,
            "skipped_count": 0,
            "error_count": 1,
            "skipped": [],
            "errors": [{"error": error}],
            "validated_at": datetime.now(timezone.utc).isoformat(),
        },
        "source_bucket": bucket if isinstance(bucket, str) else "",
        "source_object": name if isinstance(name, str) else "",
    }


# ── CLI entrypoint ──────────────────────────────────────────────────


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "iam-departures-gcp parser — validate a GCS departures manifest. "
            "Use --dry-run to filter without firing the worker; --apply is "
            "intentionally absent here (the worker function is the destructive "
            "surface). Both incident + approver env vars are still required to "
            "exercise the worker."
        )
    )
    parser.add_argument("manifest", help="Path to local manifest JSON or `gs://bucket/object` URI")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip the GCP existence check; print validation decisions only",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)
    if args.dry_run:
        os.environ.setdefault("IAM_DEPARTURES_GCP_SKIP_EXISTENCE_CHECK", "1")

    if args.manifest.startswith("gs://"):
        rest = args.manifest[len("gs://") :]
        bucket, _, obj = rest.partition("/")
        result = handler({"bucket": bucket, "name": obj}, context=None)
    else:
        result = parse_local_manifest(args.manifest)

    json.dump(result, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0 if result["validation_summary"]["error_count"] == 0 else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
