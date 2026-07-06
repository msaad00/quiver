"""Detect Google Workspace Super Admin role grants outside an allowlist."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-admin-role-grant-workspace"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-06"
REPO_NAME = "cloud-ai-security-skills"

_log = get_logger(__name__, skill=SKILL_NAME, layer="detection")

OUTPUT_FORMATS = ("ocsf", "native")

ACCOUNT_CHANGE_CLASS_UID = 3001
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

WORKSPACE_INGEST_SKILL = "ingest-workspace-admin-ocsf"
AUTHORIZED_GRANTERS_ENV = "WORKSPACE_AUTHORIZED_ADMIN_ROLE_GRANTERS"
PROTECTED_ROLES_ENV = "WORKSPACE_PROTECTED_ADMIN_ROLES"
DEFAULT_PROTECTED_ROLES = frozenset({"SUPER_ADMIN", "SUPER ADMIN", "SUPERADMIN"})

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0003"
MITRE_TACTIC_NAME = "Persistence"
MITRE_TECHNIQUE_UID = "T1098.003"
MITRE_TECHNIQUE_NAME = "Additional Cloud Roles"

OWASP_FINDING_TYPE = "OWASP-Top-10-A01"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _event_time(event: dict[str, Any]) -> int:
    try:
        return int(event.get("time_ms") or event.get("time") or 0)
    except (TypeError, ValueError):
        return 0


def _metadata_uid(event: dict[str, Any]) -> str:
    return str(event.get("event_uid") or (event.get("metadata") or {}).get("uid") or "")


def _producer(event: dict[str, Any]) -> str:
    if event.get("source_skill"):
        return str(event["source_skill"])
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _workspace_block(event: dict[str, Any]) -> dict[str, Any]:
    if event.get("schema_mode") in {"canonical", "native"}:
        return {
            "application_name": event.get("application_name"),
            "event_name": event.get("event_name"),
            "parameters": event.get("parameters") or {},
        }
    block = ((event.get("unmapped") or {}).get("google_workspace_admin")) or {}
    return block if isinstance(block, dict) else {}


def _params(event: dict[str, Any]) -> dict[str, Any]:
    params = _workspace_block(event).get("parameters") or {}
    return params if isinstance(params, dict) else {}


def _event_name(event: dict[str, Any]) -> str:
    return str(_workspace_block(event).get("event_name") or "").strip()


def _application(event: dict[str, Any]) -> str:
    return str(_workspace_block(event).get("application_name") or "").strip()


def _actor(event: dict[str, Any]) -> tuple[str, str]:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    uid = str(user.get("uid") or user.get("email_addr") or user.get("name") or "").strip()
    name = str(user.get("email_addr") or user.get("name") or user.get("uid") or "").strip()
    return uid, name


def _grantee(event: dict[str, Any]) -> tuple[str, str]:
    params = _params(event)
    user = event.get("user") or {}
    uid = str(
        params.get("assigned_to")
        or params.get("target_user")
        or user.get("uid")
        or user.get("name")
        or ""
    ).strip()
    name = str(
        params.get("assigned_to")
        or params.get("target_user")
        or params.get("email")
        or user.get("email_addr")
        or user.get("name")
        or uid
    ).strip()
    return uid, name


def _role(event: dict[str, Any]) -> str:
    params = _params(event)
    return str(params.get("role_name") or params.get("role") or params.get("role_id") or "").strip()


def _normalize_role(value: str) -> str:
    return value.strip().replace("-", "_").replace(" ", "_").upper()


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _authorized_granters() -> frozenset[str]:
    return _parse_env_set(AUTHORIZED_GRANTERS_ENV)


def _protected_roles() -> frozenset[str]:
    configured = _parse_env_set(PROTECTED_ROLES_ENV)
    if not configured:
        return DEFAULT_PROTECTED_ROLES
    return frozenset(_normalize_role(role) for role in configured)


def _is_role_grant(event: dict[str, Any]) -> bool:
    name = _event_name(event).upper()
    params = _params(event)
    if name in {
        "ASSIGN_ROLE",
        "ASSIGN_ROLE_TO_USER",
        "CREATE_ROLE_ASSIGNMENT",
        "GRANT_ADMIN_PRIVILEGE",
        "ROLE_ASSIGNED",
        "USER_GRANTED_ADMIN_PRIVILEGE",
    }:
        return True
    if "ROLE" in name and any(term in name for term in ("ASSIGN", "GRANT", "ADD", "CREATE")):
        return True
    return bool(params.get("role_name") or params.get("role_id")) and bool(
        params.get("assigned_to") or params.get("target_user")
    )


def _is_relevant(
    event: dict[str, Any],
    authorized: frozenset[str],
    protected_roles: frozenset[str],
) -> tuple[bool, str]:
    if (
        event.get("class_uid") != ACCOUNT_CHANGE_CLASS_UID
        and event.get("record_type") != "account_change"
    ):
        return False, ""
    if _producer(event) != WORKSPACE_INGEST_SKILL:
        return False, ""
    if _application(event) != "admin" or not _is_role_grant(event):
        return False, ""
    role = _role(event)
    if _normalize_role(role) not in protected_roles:
        return False, ""
    granter_uid, granter_name = _actor(event)
    if not granter_uid:
        return False, ""
    identities = {granter_uid, granter_name}
    if authorized and identities & authorized:
        return False, ""
    if not authorized:
        return True, f"{AUTHORIZED_GRANTERS_ENV} is empty; firing in fail-open mode"
    return True, f"granter is not in {AUTHORIZED_GRANTERS_ENV}"


def _finding_uid(granter: str, grantee: str, role: str, time_ms: int) -> str:
    material = f"{granter}|{grantee}|{role}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-workspace-admin-role-grant-{digest}"


def _build_native_finding(event: dict[str, Any], reason: str) -> dict[str, Any]:
    granter_uid, granter_name = _actor(event)
    grantee_uid, grantee_name = _grantee(event)
    role = _role(event)
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(granter_uid, grantee_uid, role, time_ms)

    description = (
        f"Google Workspace principal '{granter_name or granter_uid}' granted protected "
        f"admin role '{role}' to '{grantee_name or grantee_uid}'. {reason}. "
        "Super Admin grants should be limited to a documented break-glass path."
    )

    observables = [
        {"name": "actor.user.uid", "type": "User Name", "value": granter_uid},
        {"name": "user.uid", "type": "User Name", "value": grantee_uid},
        {"name": "workspace.admin.role", "type": "Role", "value": role},
    ]

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Google Workspace",
        "time_ms": time_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": f"Google Workspace protected admin role '{role}' granted outside break-glass allowlist",
        "description": description,
        "finding_types": ["workspace-admin-role-grant", OWASP_FINDING_TYPE],
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": MITRE_TACTIC_UID,
                "tactic_name": MITRE_TACTIC_NAME,
                "technique_uid": MITRE_TECHNIQUE_UID,
                "technique_name": MITRE_TECHNIQUE_NAME,
            }
        ],
        "observables": observables,
        "evidence": {
            "granter": granter_uid,
            "grantee": grantee_uid,
            "role": role,
            "event_name": _event_name(event),
            "policy_reason": reason,
            "raw_event_uids": [event_uid] if event_uid else [],
        },
    }


def _render_ocsf_finding(native_finding: dict[str, Any]) -> dict[str, Any]:
    attack = native_finding["mitre_attacks"][0]
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": native_finding["severity_id"],
        "status_id": native_finding["status_id"],
        "time": native_finding["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native_finding["event_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["identity", "google-workspace", "admin-role", "detection"],
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "attacks": [
                {
                    "version": attack["version"],
                    "tactic": {"uid": attack["tactic_uid"], "name": attack["tactic_name"]},
                    "technique": {"uid": attack["technique_uid"], "name": attack["technique_name"]},
                }
            ],
        },
        "evidence": native_finding["evidence"],
        "observables": native_finding["observables"],
    }


def iter_records(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, raw in enumerate(stream, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=str(exc),
                line=lineno,
            )
            continue
        if isinstance(obj, dict):
            yield obj


def detect(stream: Iterable[str], output_format: str = "ocsf") -> list[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(f"unsupported output_format `{output_format}`")
    authorized = _authorized_granters()
    protected_roles = _protected_roles()
    findings: list[dict[str, Any]] = []
    for event in iter_records(stream):
        relevant, reason = _is_relevant(event, authorized, protected_roles)
        if not relevant:
            continue
        native = _build_native_finding(event, reason)
        findings.append(native if output_format == "native" else _render_ocsf_finding(native))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect Google Workspace protected admin role grants."
    )
    parser.add_argument("input", nargs="?", help="Input OCSF/native JSONL. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default="ocsf")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")
    try:
        for finding in detect(in_stream, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    except SkillError as exc:
        emit_error(SKILL_NAME, exc)
        return 2
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
