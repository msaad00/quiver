"""Cloud Function 2: Worker — execute the GCP IAM teardown for one principal.

Receives a single validated entry from the parser via Cloud Workflow's
fan-out. For each entry the worker runs the 11 step functions in
`steps.py` in strict order, writes a per-step Firestore checkpoint, and
emits a dual audit (Firestore audit row + GCS evidence object) when the
sequence completes.

The handler runs three ways:

    1. Cloud Function Gen 2 invoked by Cloud Workflow (event payload is a
       single validated entry).
    2. Local CLI (`python handler.py --apply manifest.json`) — fans out
       across the manifest's entries serially.
    3. Test suite (mocked Firestore + GCS + steps).

Destructive paths require BOTH:
    IAM_DEPARTURES_GCP_INCIDENT_ID   — declared incident id (e.g. INC-...)
    IAM_DEPARTURES_GCP_APPROVER      — approver identity (e.g. alice@security)
The worker fails closed when either env var is missing under --apply.

MITRE ATT&CK coverage:
    T1531     Account Access Removal — revoking departed-employee access
    T1098.001 Account Manipulation: Additional Cloud Credentials — removing orphaned SA keys
    T1078.004 Valid Accounts: Cloud Accounts — eliminating persistence vector

NIST CSF: PR.AC-1, PR.AC-4, RS.MI-2
CIS Controls v8: 5.3, 6.2
SOC 2 (TSC): CC6.1, CC6.2, CC6.3
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[5]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Allow `from cloud_function_worker import steps` whether imported as a package
# (Cloud Functions deployment), as a sibling module (CLI execution), or via
# the test harness's `sys.path.insert(skill/src)` shim.
try:
    from cloud_function_worker import steps as steps_module
except ImportError:  # pragma: no cover  — direct script execution fallback
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import steps as steps_module  # type: ignore[no-redef]

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

SKILL_NAME = "iam-departures-gcp"
CANONICAL_VERSION = "2026-04"

INCIDENT_ENV_VAR = "IAM_DEPARTURES_GCP_INCIDENT_ID"
APPROVER_ENV_VAR = "IAM_DEPARTURES_GCP_APPROVER"
AUDIT_FIRESTORE_ENV_VAR = "IAM_DEPARTURES_GCP_AUDIT_FIRESTORE_COLLECTION"
AUDIT_BUCKET_ENV_VAR = "IAM_DEPARTURES_GCP_AUDIT_BUCKET"
AUDIT_KMS_ENV_VAR = "IAM_DEPARTURES_GCP_KMS_KEY"

ORG_ID_RE = re.compile(r"^\d{6,16}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

CHECKPOINT_DOC_ID = "CURRENT"

STATUS_NEW = "new"
STATUS_IN_PROGRESS = "in_progress"
STATUS_REMEDIATED = "remediated"
STATUS_ERROR = "error"
STATUS_REFUSED = "refused"
STATUS_DRY_RUN = "dry_run"


class RemediationStatus(str, enum.Enum):
    SUCCESS = "remediated"
    ERROR = "error"
    REFUSED = "refused"
    DRY_RUN = "dry_run"


@dataclasses.dataclass
class WorkerResult:
    email: str
    principal_id: str
    principal_type: str
    gcp_org_id: str
    status: str
    actions_taken: list[dict[str, Any]]
    error: str | None = None
    remediated_at: str | None = None
    checkpoint_reused: bool = False


# ── Public Cloud Function entrypoint ────────────────────────────────


def handler(event: dict, context: Any | None = None) -> dict:
    """Cloud Workflow fan-out task: remediate a single validated entry.

    Input (from Cloud Workflow Map step):
        {
            "entry": {
                "email": "jane@acme.example",
                "principal_type": "workspace_user",
                "principal_id": "jane@acme.example",
                "gcp_org_id": "111122223333",
                "project_ids": ["acme-prod"],
                "folder_ids": [],
                "terminated_at": "2026-04-01T17:00:00Z",
                ...
            },
            "source_bucket": "...",
            "source_object": "...",
            "dry_run": false
        }
    """
    entry = event.get("entry", event)
    if not isinstance(entry, dict):
        entry = {}

    dry_run = bool(event.get("dry_run", False))
    return _process_entry(entry, dry_run=dry_run, context=context).__dict__


def _process_entry(entry: dict, *, dry_run: bool, context: Any | None = None) -> WorkerResult:
    try:
        email = _require_str(entry, "email")
        principal_id = _require_str(entry, "principal_id")
        principal_type = _require_str(entry, "principal_type")
        gcp_org_id = _require_str(entry, "gcp_org_id")
        if not EMAIL_RE.fullmatch(email):
            raise ValueError("email format invalid")
        if not ORG_ID_RE.fullmatch(gcp_org_id):
            raise ValueError("gcp_org_id must match ^\\d{6,16}$")
        if principal_type not in {"workspace_user", "service_account"}:
            raise ValueError(f"principal_type `{principal_type}` not supported")
        steps_module.assert_not_protected(principal_type, principal_id)
    except steps_module.ProtectedPrincipalError as exc:
        logger.error("Refusing protected principal: %s", exc)
        result = WorkerResult(
            email=entry.get("email", ""),
            principal_id=entry.get("principal_id", ""),
            principal_type=entry.get("principal_type", ""),
            gcp_org_id=entry.get("gcp_org_id", ""),
            status=STATUS_REFUSED,
            actions_taken=[],
            error=str(exc),
        )
        _write_audit(
            _build_audit_record(entry, [], STATUS_REFUSED, error=str(exc), context=context)
        )
        return result
    except ValueError as exc:
        logger.warning("Invalid worker payload: %s", exc)
        result = WorkerResult(
            email=entry.get("email", ""),
            principal_id=entry.get("principal_id", ""),
            principal_type=entry.get("principal_type", ""),
            gcp_org_id=entry.get("gcp_org_id", ""),
            status=STATUS_ERROR,
            actions_taken=[],
            error=f"Invalid worker payload: {exc}",
        )
        _write_audit(_build_audit_record(entry, [], STATUS_ERROR, error=str(exc), context=context))
        return result

    # HITL gate: --apply path must have both env vars; --dry-run is exempt.
    if not dry_run:
        gate_error = _validate_hitl_env()
        if gate_error:
            result = WorkerResult(
                email=email,
                principal_id=principal_id,
                principal_type=principal_type,
                gcp_org_id=gcp_org_id,
                status=STATUS_ERROR,
                actions_taken=[],
                error=gate_error,
            )
            _write_audit(
                _build_audit_record(entry, [], STATUS_ERROR, error=gate_error, context=context)
            )
            return result

    if dry_run:
        plan = [
            {"step": name, "status": RemediationStatus.DRY_RUN.value}
            for name, _ in steps_module.remediation_steps()
        ]
        return WorkerResult(
            email=email,
            principal_id=principal_id,
            principal_type=principal_type,
            gcp_org_id=gcp_org_id,
            status=STATUS_DRY_RUN,
            actions_taken=plan,
            remediated_at=None,
        )

    logger.info(
        "Remediating %s principal %s (org=%s, employee=%s)",
        principal_type,
        principal_id,
        gcp_org_id,
        email,
    )

    checkpoint = _load_checkpoint(entry)
    actions_taken: list[dict[str, Any]] = list(checkpoint["actions_taken"])
    completed_steps: list[str] = list(checkpoint["completed_steps"])
    completed_set = set(completed_steps)

    if checkpoint["status"] == STATUS_REMEDIATED:
        logger.info("Replay-safe short-circuit: %s already remediated", principal_id)
        return WorkerResult(
            email=email,
            principal_id=principal_id,
            principal_type=principal_type,
            gcp_org_id=gcp_org_id,
            status=STATUS_REMEDIATED,
            actions_taken=actions_taken,
            remediated_at=checkpoint["updated_at"],
            checkpoint_reused=True,
        )

    try:
        clients = steps_module.GcpClients()
        for step_name, step_fn in steps_module.remediation_steps():
            if step_name in completed_set:
                continue
            step_fn(clients, entry, actions_taken)
            completed_steps.append(step_name)
            completed_set.add(step_name)
            _save_checkpoint(entry, actions_taken, completed_steps, status=STATUS_IN_PROGRESS)

        audit_record = _build_audit_record(entry, actions_taken, STATUS_REMEDIATED, context=context)
        _write_audit(audit_record)
        _save_checkpoint(
            entry,
            actions_taken,
            completed_steps,
            status=STATUS_REMEDIATED,
            audit_timestamp=audit_record["audit_timestamp"],
        )
        return WorkerResult(
            email=email,
            principal_id=principal_id,
            principal_type=principal_type,
            gcp_org_id=gcp_org_id,
            status=STATUS_REMEDIATED,
            actions_taken=actions_taken,
            remediated_at=_now(),
        )
    except Exception as exc:  # noqa: BLE001 — top-level capture for audit
        logger.exception("Remediation failed for %s", principal_id)
        _save_checkpoint(entry, actions_taken, completed_steps, status=STATUS_ERROR, error=str(exc))
        _write_audit(
            _build_audit_record(entry, actions_taken, STATUS_ERROR, error=str(exc), context=context)
        )
        return WorkerResult(
            email=email,
            principal_id=principal_id,
            principal_type=principal_type,
            gcp_org_id=gcp_org_id,
            status=STATUS_ERROR,
            actions_taken=actions_taken,
            error=str(exc),
        )


# ── HITL env-var gate ───────────────────────────────────────────────


def _validate_hitl_env() -> str | None:
    """Return None if both incident + approver env vars are populated."""
    incident_id = os.environ.get(INCIDENT_ENV_VAR, "").strip()
    approver = os.environ.get(APPROVER_ENV_VAR, "").strip()
    if not incident_id:
        return f"missing-hitl-env-vars: {INCIDENT_ENV_VAR} not set"
    if not approver:
        return f"missing-hitl-env-vars: {APPROVER_ENV_VAR} not set"
    return None


# ── Audit dual-write ────────────────────────────────────────────────


def _build_audit_record(
    entry: dict,
    actions: list[dict],
    status: str,
    error: str = "",
    context: Any | None = None,
) -> dict:
    audit_timestamp = _now()
    row_uid = _deterministic_uid(
        entry.get("principal_id", ""),
        entry.get("gcp_org_id", ""),
        audit_timestamp,
    )
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "remediation_audit",
        "source_skill": SKILL_NAME,
        "row_uid": row_uid,
        "audit_timestamp": audit_timestamp,
        "email": entry.get("email", ""),
        "principal_id": entry.get("principal_id", ""),
        "principal_type": entry.get("principal_type", ""),
        "gcp_org_id": entry.get("gcp_org_id", ""),
        "project_ids": list(entry.get("project_ids", []) or []),
        "folder_ids": list(entry.get("folder_ids", []) or []),
        "terminated_at": entry.get("terminated_at", ""),
        "termination_source": entry.get("termination_source", ""),
        "is_rehire": bool(entry.get("is_rehire", False)),
        "rehire_date": entry.get("rehire_date"),
        "status": status,
        "error": error,
        "actions_taken": actions,
        "actions_count": len(actions),
        "function_name": os.environ.get("K_SERVICE", "iam-departures-gcp-worker"),
        "workflow_execution_id": getattr(context, "execution_id", "") if context else "",
        "invoked_by": os.environ.get("SKILL_CALLER_ID", ""),
        "invoked_by_email": os.environ.get("SKILL_CALLER_EMAIL", ""),
        "agent_session_id": os.environ.get("SKILL_SESSION_ID", ""),
        "caller_roles": os.environ.get("SKILL_CALLER_ROLES", ""),
        "approved_by": os.environ.get(APPROVER_ENV_VAR, ""),
        "approved_by_email": os.environ.get("SKILL_APPROVER_EMAIL", ""),
        "approval_ticket": os.environ.get(INCIDENT_ENV_VAR, ""),
        "approval_timestamp": os.environ.get("SKILL_APPROVAL_TIMESTAMP", ""),
    }


def _write_audit(record: dict) -> None:
    """Dual-write the audit record to Firestore + GCS evidence object.

    Both writes are best-effort: a failure to land the audit MUST not
    abort the remediation (the action already happened); the failure
    is logged so the operator can replay. The next reconciler run will
    flag a missing audit row as drift via the shared verifier contract.
    """
    collection = os.environ.get(AUDIT_FIRESTORE_ENV_VAR, "")
    if collection:
        try:
            _write_firestore_audit(collection, record)
        except Exception:  # pragma: no cover — defensive
            logger.exception("Failed to write Firestore audit row")

    bucket = os.environ.get(AUDIT_BUCKET_ENV_VAR, "")
    if bucket:
        try:
            _write_gcs_audit(bucket, record)
        except Exception:  # pragma: no cover — defensive
            logger.exception("Failed to write GCS audit object")


def _write_firestore_audit(collection: str, record: dict) -> None:
    from googleapiclient.discovery import build  # noqa: PLC0415

    project_id = (record.get("project_ids") or ["unknown"])[0]
    service = build("firestore", "v1", cache_discovery=False)
    document_id = record["row_uid"]
    parent = f"projects/{project_id}/databases/(default)/documents/{collection}"
    body = {"fields": _to_firestore_fields(record)}
    service.projects().databases().documents().createDocument(
        parent=parent, documentId=document_id, body=body
    ).execute()


def _write_gcs_audit(bucket: str, record: dict) -> None:
    from googleapiclient.discovery import build  # noqa: PLC0415
    from googleapiclient.http import MediaInMemoryUpload  # noqa: PLC0415

    service = build("storage", "v1", cache_discovery=False)
    date_str = record["audit_timestamp"][:10]
    safe_principal = record["principal_id"].replace("/", "_")
    object_name = f"departures/audit/{date_str}/{safe_principal}.json"
    body_bytes = json.dumps(record, indent=2, default=str).encode("utf-8")
    media = MediaInMemoryUpload(body_bytes, mimetype="application/json")
    body = {"name": object_name}
    kms_key = os.environ.get(AUDIT_KMS_ENV_VAR)
    insert_kwargs: dict[str, Any] = {"bucket": bucket, "body": body, "media_body": media}
    if kms_key:
        insert_kwargs["kmsKeyName"] = kms_key
    service.objects().insert(**insert_kwargs).execute()


def _to_firestore_fields(record: dict) -> dict:
    out: dict[str, dict[str, Any]] = {}
    for key, value in record.items():
        if isinstance(value, bool):
            out[key] = {"booleanValue": value}
        elif isinstance(value, int):
            out[key] = {"integerValue": str(value)}
        elif isinstance(value, list):
            out[key] = {"stringValue": json.dumps(value, default=str)}
        elif isinstance(value, dict):
            out[key] = {"stringValue": json.dumps(value, default=str)}
        else:
            out[key] = {"stringValue": str(value or "")}
    return out


# ── Checkpointing (Firestore) ───────────────────────────────────────


def _load_checkpoint(entry: dict) -> dict[str, Any]:
    checkpoint: dict[str, Any] = {
        "status": STATUS_NEW,
        "actions_taken": [],
        "completed_steps": [],
        "updated_at": "",
    }
    collection = os.environ.get(AUDIT_FIRESTORE_ENV_VAR, "")
    if not collection:
        return checkpoint
    try:
        from googleapiclient.discovery import build  # noqa: PLC0415

        project_id = (entry.get("project_ids") or ["unknown"])[0]
        service = build("firestore", "v1", cache_discovery=False)
        name = (
            f"projects/{project_id}/databases/(default)/documents/"
            f"{collection}/{_checkpoint_doc_name(entry)}"
        )
        doc = service.projects().databases().documents().get(name=name).execute() or {}
        fields = doc.get("fields", {}) or {}
    except Exception:  # pragma: no cover — defensive
        logger.exception("Failed to load Firestore checkpoint")
        return checkpoint

    raw_actions = fields.get("actions_taken", {}).get("stringValue", "")
    parsed_actions: list[dict[str, Any]] = []
    if raw_actions:
        try:
            decoded = json.loads(raw_actions)
            if isinstance(decoded, list):
                parsed_actions = [a for a in decoded if isinstance(a, dict)]
        except json.JSONDecodeError:
            parsed_actions = []
    raw_steps = fields.get("completed_steps", {}).get("stringValue", "")
    completed_steps: list[str] = []
    if raw_steps:
        try:
            decoded_steps = json.loads(raw_steps)
            if isinstance(decoded_steps, list):
                completed_steps = [s for s in decoded_steps if isinstance(s, str)]
        except json.JSONDecodeError:
            completed_steps = []

    checkpoint["status"] = fields.get("status", {}).get("stringValue", STATUS_NEW) or STATUS_NEW
    checkpoint["actions_taken"] = parsed_actions
    checkpoint["completed_steps"] = completed_steps
    checkpoint["updated_at"] = fields.get("updated_at", {}).get("stringValue", "") or ""
    return checkpoint


def _save_checkpoint(
    entry: dict,
    actions_taken: list[dict[str, Any]],
    completed_steps: list[str],
    *,
    status: str,
    error: str = "",
    audit_timestamp: str = "",
) -> None:
    collection = os.environ.get(AUDIT_FIRESTORE_ENV_VAR, "")
    if not collection:
        return
    try:
        from googleapiclient.discovery import build  # noqa: PLC0415

        project_id = (entry.get("project_ids") or ["unknown"])[0]
        service = build("firestore", "v1", cache_discovery=False)
        document_id = _checkpoint_doc_name(entry)
        parent = f"projects/{project_id}/databases/(default)/documents/{collection}"
        body = {
            "fields": _to_firestore_fields(
                {
                    "record_type": "remediation_checkpoint",
                    "status": status,
                    "email": entry.get("email", ""),
                    "principal_id": entry.get("principal_id", ""),
                    "principal_type": entry.get("principal_type", ""),
                    "gcp_org_id": entry.get("gcp_org_id", ""),
                    "completed_steps": completed_steps,
                    "actions_taken": actions_taken,
                    "updated_at": _now(),
                    "error": error,
                    "audit_timestamp": audit_timestamp,
                }
            )
        }
        service.projects().databases().documents().createDocument(
            parent=parent, documentId=document_id, body=body
        ).execute()
    except Exception:  # pragma: no cover — defensive
        logger.exception("Failed to write Firestore checkpoint")


def _checkpoint_doc_name(entry: dict) -> str:
    principal = entry.get("principal_id", "")
    org = entry.get("gcp_org_id", "")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"CHECKPOINT_{org}_{principal}")
    return safe[:1500] or CHECKPOINT_DOC_ID


# ── Helpers ─────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_str(entry: dict, field: str) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing required field: {field}")
    return value.strip()


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"iam-gcp-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


# ── CLI entrypoint ──────────────────────────────────────────────────


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "iam-departures-gcp worker — execute the 11-step GCP IAM teardown. "
            "--dry-run prints the plan; --apply executes and dual-audits; --reverify "
            "checks post-action drift. --apply requires "
            f"{INCIDENT_ENV_VAR} + {APPROVER_ENV_VAR}."
        )
    )
    parser.add_argument("manifest", help="Path to local manifest JSON or `gs://bucket/object` URI")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Plan-only, no GCP calls")
    mode.add_argument(
        "--apply", action="store_true", help="Execute the teardown (HITL env vars required)"
    )
    mode.add_argument(
        "--reverify", action="store_true", help="Re-read and emit verification records"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)

    manifest = _load_manifest_for_cli(args.manifest)
    entries = manifest.get("entries", []) or []

    if args.reverify:
        return _cli_reverify(entries)

    results: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        result = _process_entry(entry, dry_run=args.dry_run)
        results.append(result.__dict__)

    json.dump({"results": results}, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    if any(r["status"] == STATUS_ERROR for r in results):
        return 1
    return 0


def _load_manifest_for_cli(source: str) -> dict:
    if source.startswith("gs://"):
        rest = source[len("gs://") :]
        bucket, _, obj = rest.partition("/")
        from googleapiclient.discovery import build  # noqa: PLC0415

        service = build("storage", "v1", cache_discovery=False)
        body = service.objects().get_media(bucket=bucket, object=obj).execute()
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        return json.loads(body)
    return json.loads(Path(source).read_text(encoding="utf-8"))


def _cli_reverify(entries: list) -> int:
    """Emit one verification record per entry against the shared contract."""
    from skills._shared.remediation_verifier import (  # noqa: PLC0415
        DEFAULT_VERIFICATION_SLA_MS,
        RemediationReference,
        VerificationResult,
        VerificationStatus,
        build_drift_finding,
        build_verification_record,
        sla_deadline,
    )

    out: list[dict] = []
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ref = RemediationReference(
            remediation_skill=SKILL_NAME,
            remediation_action_uid=_deterministic_uid(
                entry.get("principal_id", ""), entry.get("gcp_org_id", "")
            ),
            target_provider="GCP",
            target_identifier=entry.get("principal_id", ""),
            original_finding_uid=entry.get("origin_finding_uid", ""),
            remediated_at_ms=now_ms - 60_000,
        )
        # Deterministic placeholder result; an integration verifier replaces this
        # with real target-state reads. We still emit the envelope so the caller
        # can wire the verifier downstream without changing the schema.
        result = VerificationResult(
            status=VerificationStatus.UNREACHABLE,
            checked_at_ms=now_ms,
            sla_deadline_ms=sla_deadline(now_ms - 60_000, DEFAULT_VERIFICATION_SLA_MS),
            expected_state="principal disabled and removed from all IAM bindings",
            actual_state="reverify-handler is a stub; integration verifier required",
            detail="See SKILL.md § Re-verify — operator wires real reads.",
        )
        record = build_verification_record(reference=ref, result=result, verifier_skill=SKILL_NAME)
        out.append(record)
        if result.status == VerificationStatus.DRIFT:
            out.append(build_drift_finding(reference=ref, result=result, verifier_skill=SKILL_NAME))

    json.dump({"verification": out}, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
