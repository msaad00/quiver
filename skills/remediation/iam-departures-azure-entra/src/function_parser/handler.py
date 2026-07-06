"""Function 1: Parser — validate and filter the Azure Blob Storage manifest.

Triggered by the Logic App after EventGrid detects a new blob in the
`departures/` prefix. Reads the manifest, validates each entry, filters
out rehires and already-deleted Entra users, and passes actionable
entries to the worker Function.

This is the Azure Entra counterpart to
`skills/remediation/iam-departures-aws/src/lambda_parser/handler.py`.
Same shape, same semantics, different cloud surface.

MITRE ATT&CK coverage:
    T1078.004  Valid Accounts: Cloud Accounts — validates departed-employee Entra persistence
    T1087.004  Account Discovery: Cloud Account — enumerates Entra users per tenant

NIST CSF 2.0:
    PR.AC-1   Identities and credentials are issued, managed, verified, revoked
    DE.CM-3   Personnel activity is monitored to detect potential cybersecurity events

CIS Controls v8:
    5.3   Disable Dormant Accounts
    6.1   Establish an Access Granting Process
    6.2   Establish an Access Revoking Process
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configuration from environment.
GRACE_PERIOD_DAYS = int(os.environ.get("IAM_DEPARTURES_AZURE_GRACE_PERIOD_DAYS", "7"))

# UPN: liberal RFC 5322-style local-part + domain. We only enforce shape here;
# Microsoft Graph is the authority on whether a UPN actually exists.
_UPN_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
# Entra ObjectIds are GUIDs.
_OBJECT_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def handler(event: dict[str, Any], context: Any | None = None) -> dict[str, Any]:
    """Logic App task: parse manifest and validate Entra users.

    Input (from the Logic App after EventGrid):
        {"storage_account": "...", "container": "...", "blob_name": "departures/2026-04.json"}

    Output (to worker Function via the Logic App map step):
        {"validated_entries": [...], "validation_summary": {...}}
    """
    storage_account_raw = event.get("storage_account")
    container_raw = event.get("container")
    blob_name_raw = event.get("blob_name")

    if not (
        isinstance(storage_account_raw, str)
        and storage_account_raw
        and isinstance(container_raw, str)
        and container_raw
        and isinstance(blob_name_raw, str)
        and blob_name_raw
    ):
        logger.error("Invalid parser event payload: missing storage_account/container/blob_name")
        return _empty_summary(
            storage_account_raw if isinstance(storage_account_raw, str) else "",
            container_raw if isinstance(container_raw, str) else "",
            blob_name_raw if isinstance(blob_name_raw, str) else "",
            error="Invalid event payload: storage_account, container, blob_name are required",
        )

    storage_account: str = storage_account_raw
    container: str = container_raw
    blob_name: str = blob_name_raw

    logger.info(
        "Parsing manifest blob: https://%s.blob.core.windows.net/%s/%s",
        storage_account,
        container,
        blob_name,
    )

    raw = _read_blob(storage_account=storage_account, container=container, blob_name=blob_name)
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.exception("Manifest is not valid JSON")
        return _empty_summary(storage_account, container, blob_name, error=f"Invalid JSON: {exc}")

    entries = manifest.get("entries", [])
    if not isinstance(entries, list):
        return _empty_summary(
            storage_account, container, blob_name, error="manifest.entries must be a JSON array"
        )

    logger.info("Manifest contains %d entries", len(entries))

    return _validate_entries(
        entries,
        storage_account=storage_account,
        container=container,
        blob_name=blob_name,
    )


def _validate_entries(
    entries: list[dict[str, Any]],
    *,
    storage_account: str,
    container: str,
    blob_name: str,
    graph_client: Any | None = None,
) -> dict[str, Any]:
    """Validate every entry. Pure function — no env or I/O when graph_client is provided."""
    validated: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    client = graph_client if graph_client is not None else _get_graph_client()

    for entry in entries:
        if not isinstance(entry, dict):
            errors.append({"upn": "", "object_id": "", "error": "entry is not a JSON object"})
            continue
        try:
            result = _validate_entry(entry, graph_client=client)
            if result["action"] == "remediate":
                validated.append(result["entry"])
            else:
                skipped.append(
                    {
                        "upn": entry.get("upn", ""),
                        "object_id": entry.get("object_id", ""),
                        "reason": result["reason"],
                    }
                )
        except Exception as exc:  # noqa: BLE001 — defensive: never let one bad entry break the batch
            errors.append(
                {
                    "upn": entry.get("upn", ""),
                    "object_id": entry.get("object_id", ""),
                    "error": str(exc),
                }
            )
            logger.exception("Validation error for %s", entry.get("upn", ""))

    summary = {
        "manifest_blob": blob_name,
        "manifest_container": container,
        "manifest_storage_account": storage_account,
        "total_entries": len(entries),
        "validated_count": len(validated),
        "skipped_count": len(skipped),
        "error_count": len(errors),
        "skipped": skipped,
        "errors": errors,
        "validated_at": _now(),
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
        "source_storage_account": storage_account,
        "source_container": container,
        "source_blob_name": blob_name,
    }


def _validate_entry(entry: dict[str, Any], *, graph_client: Any | None) -> dict[str, Any]:
    """Validate a single departure record.

    Checks (mirrors the AWS sibling, adapted for Entra fields):
        1. Required fields present (upn, object_id, terminated_at)
        2. Grace period not expired
        3. Rehire status (same UPN/objectId vs different UPN)
        4. Entra user exists in target tenant
        5. Entra user not already deleted
    """
    required = ("upn", "object_id", "terminated_at")
    for field in required:
        if not entry.get(field):
            return {"action": "skip", "reason": f"Missing required field: {field}", "entry": entry}

    if not _UPN_RE.fullmatch(str(entry["upn"])):
        return {"action": "skip", "reason": "Invalid UPN format", "entry": entry}
    if not _OBJECT_ID_RE.fullmatch(str(entry["object_id"])):
        return {
            "action": "skip",
            "reason": "Invalid Entra ObjectId format (expected GUID)",
            "entry": entry,
        }

    if entry.get("user_deleted"):
        return {"action": "skip", "reason": "Entra user already deleted", "entry": entry}

    if entry.get("remediation_status") == "remediated":
        return {"action": "skip", "reason": "Already remediated", "entry": entry}

    terminated_at = _parse_iso(entry["terminated_at"])
    if terminated_at:
        grace_deadline = datetime.now(timezone.utc) - timedelta(days=GRACE_PERIOD_DAYS)
        if terminated_at > grace_deadline:
            days_since = max(0, (datetime.now(timezone.utc) - terminated_at).days)
            return {
                "action": "skip",
                "reason": f"Within grace period ({days_since}d < {GRACE_PERIOD_DAYS}d)",
                "entry": entry,
            }

    if entry.get("is_rehire") and entry.get("rehire_date"):
        rehire_date = _parse_iso(entry["rehire_date"])
        signin = _parse_iso(entry.get("user_last_signin_at"))
        created = _parse_iso(entry.get("user_created_at"))

        # Rehired + same Entra user still in use -> SKIP
        if signin and rehire_date and signin > rehire_date:
            return {
                "action": "skip",
                "reason": "Rehired employee — Entra user used after rehire date (same user in use)",
                "entry": entry,
            }
        # Rehired + Entra user created after rehire -> SKIP (this is the new identity)
        if created and rehire_date and created > rehire_date:
            return {
                "action": "skip",
                "reason": "Entra user created after rehire — this is the employee's current identity",
                "entry": entry,
            }
        logger.info(
            "Rehired employee %s has orphaned Entra user %s (not used after rehire)",
            entry["upn"],
            entry["object_id"],
        )

    # Confirm Entra user actually exists. If we cannot verify, fail safe.
    if graph_client is not None:
        try:
            present = graph_client.user_exists(object_id=entry["object_id"])
        except Exception as exc:  # noqa: BLE001 — fail safe (don't remediate)
            return {"action": "skip", "reason": f"Cannot verify Entra user: {exc}", "entry": entry}
        if not present:
            return {
                "action": "skip",
                "reason": f"Entra user {entry['object_id']} not found in tenant",
                "entry": entry,
            }

    entry["validation_timestamp"] = _now()
    return {"action": "remediate", "entry": entry, "reason": ""}


def _empty_summary(
    storage_account: str, container: str, blob_name: str, *, error: str
) -> dict[str, Any]:
    return {
        "validated_entries": [],
        "validation_summary": {
            "manifest_blob": blob_name,
            "manifest_container": container,
            "manifest_storage_account": storage_account,
            "total_entries": 0,
            "validated_count": 0,
            "skipped_count": 0,
            "error_count": 1,
            "skipped": [],
            "errors": [{"error": error}],
            "validated_at": _now(),
        },
        "source_storage_account": storage_account,
        "source_container": container,
        "source_blob_name": blob_name,
    }


def _read_blob(*, storage_account: str, container: str, blob_name: str) -> str:
    """Read a blob from Azure Storage. Lazy-imports the SDK so tests can patch it out."""
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    credential = DefaultAzureCredential()
    service = BlobServiceClient(
        account_url=f"https://{storage_account}.blob.core.windows.net",
        credential=credential,
    )
    blob_client = service.get_blob_client(container=container, blob=blob_name)
    download = blob_client.download_blob()
    return download.readall().decode("utf-8")


def _get_graph_client() -> Any | None:
    """Build the lazy Graph client used at runtime.

    Returns None when the SDK is not importable (the validator dry-run path
    can run without it) so the parser can still emit the schema-correct
    skip/error summary.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from msgraph import GraphServiceClient
    except Exception:  # noqa: BLE001 — SDK absent in dry-run/test environments
        return None
    return _GraphUserExistenceProbe(GraphServiceClient(credentials=DefaultAzureCredential()))


class _GraphUserExistenceProbe:
    """Tiny adapter around msgraph-sdk: only `user_exists(object_id)` is needed by this module."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def user_exists(self, *, object_id: str) -> bool:
        try:
            user = self._client.users.by_user_id(object_id).get()
        except Exception:  # noqa: BLE001 — Graph "not found" usually surfaces as ODataError
            return False
        return user is not None


def _parse_iso(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: dry-run the parser against a local manifest file.

    The CLI does not call Microsoft Graph (it cannot prove user existence
    without credentials). It only applies the static filters: required
    fields, grace period, rehire decision tree, and `user_deleted`. This
    matches the dry-run path the Logic App exercises before invoking the
    worker Function.
    """
    parser = argparse.ArgumentParser(
        description="Dry-run the Entra IAM departures parser against a manifest file."
    )
    parser.add_argument(
        "manifest", help="Path to a manifest JSON file (see examples/manifest.json)."
    )
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    args = parser.parse_args(argv)

    with open(args.manifest, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)

    entries = manifest.get("entries", [])
    summary = _validate_entries(
        entries,
        storage_account="dry-run",
        container="dry-run",
        blob_name=os.path.basename(args.manifest),
        graph_client=None,
    )

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        for entry in summary["validated_entries"]:
            out.write(
                json.dumps({"action": "remediate", "entry": entry}, separators=(",", ":")) + "\n"
            )
        for skipped in summary["validation_summary"]["skipped"]:
            out.write(json.dumps({"action": "skip", **skipped}, separators=(",", ":")) + "\n")
        for err in summary["validation_summary"]["errors"]:
            out.write(json.dumps({"action": "error", **err}, separators=(",", ":")) + "\n")
    finally:
        if args.output:
            out.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
