"""Detect Google Workspace OAuth grants with high-risk scopes."""

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

SKILL_NAME = "detect-suspicious-oauth-grant-workspace"
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
PREAPPROVED_CLIENTS_ENV = "WORKSPACE_PREAPPROVED_OAUTH_CLIENT_IDS"

HIGH_RISK_SCOPE_MARKERS = (
    "https://mail.google.com/",
    "gmail.",
    "gmail/",
    "drive",
    "admin.directory",
    "admin.reports.audit",
    "cloud-platform",
    "contacts",
    "groups",
    "calendar",
)

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0003"
MITRE_TACTIC_NAME = "Persistence"
MITRE_TECHNIQUE_UID = "T1550.001"
MITRE_TECHNIQUE_NAME = "Use Alternate Authentication Material: Application Access Token"

OWASP_FINDING_TYPE = "OWASP-Top-10-A05"


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


def _client_id(event: dict[str, Any]) -> str:
    params = _params(event)
    return str(params.get("client_id") or params.get("clientId") or "").strip()


def _app_name(event: dict[str, Any]) -> str:
    params = _params(event)
    return str(params.get("app_name") or params.get("appName") or _client_id(event)).strip()


def _scope_values(raw: Any) -> list[str]:
    if isinstance(raw, list):
        values: list[str] = []
        for item in raw:
            values.extend(_scope_values(item))
        return values
    if isinstance(raw, dict):
        for key in ("scope", "name", "value"):
            if raw.get(key):
                return _scope_values(raw[key])
        return []
    if not raw:
        return []
    text = str(raw)
    normalized = text.replace(",", " ").replace("\n", " ")
    return [part.strip() for part in normalized.split() if part.strip()]


def _scopes(event: dict[str, Any]) -> list[str]:
    params = _params(event)
    values: list[str] = []
    values.extend(_scope_values(params.get("scope")))
    values.extend(_scope_values(params.get("scope_data") or params.get("scope_ data")))
    deduped: dict[str, None] = {}
    for value in values:
        deduped.setdefault(value, None)
    return list(deduped)


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _preapproved_clients() -> frozenset[str]:
    return _parse_env_set(PREAPPROVED_CLIENTS_ENV)


def _scope_reason(scopes: list[str]) -> str:
    lowered = [scope.lower() for scope in scopes]
    for marker in HIGH_RISK_SCOPE_MARKERS:
        for scope in lowered:
            if marker in scope:
                return f"high-risk scope marker: {marker}"
    return ""


def _is_relevant(event: dict[str, Any], allowlist: frozenset[str]) -> tuple[bool, str]:
    if (
        event.get("class_uid") != ACCOUNT_CHANGE_CLASS_UID
        and event.get("record_type") != "account_change"
    ):
        return False, ""
    if _producer(event) != WORKSPACE_INGEST_SKILL:
        return False, ""
    if _application(event) != "token" or _event_name(event) != "authorize":
        return False, ""
    client_id = _client_id(event)
    if not client_id or client_id in allowlist:
        return False, ""
    scopes = _scopes(event)
    if not scopes:
        return False, ""
    reason = _scope_reason(scopes)
    if not reason:
        return False, ""
    return True, reason


def _finding_uid(client_id: str, actor: str, time_ms: int) -> str:
    material = f"{client_id}|{actor}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-workspace-oauth-grant-{digest}"


def _build_native_finding(event: dict[str, Any], reason: str) -> dict[str, Any]:
    actor_uid, actor_name = _actor(event)
    client_id = _client_id(event)
    app_name = _app_name(event)
    scopes = sorted(_scopes(event))
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(client_id, actor_uid, time_ms)

    description = (
        f"Google Workspace user '{actor_name or actor_uid}' authorized OAuth client "
        f"'{app_name or client_id}' with high-risk scopes ({reason}). The client id "
        f"is not in {PREAPPROVED_CLIENTS_ENV}, so this grant can provide persistent "
        f"application-token access to mail, files, directory, or tenant audit data. "
        f"Granted scopes: {scopes}."
    )

    observables: list[dict[str, Any]] = [
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
        {"name": "workspace.oauth.client_id", "type": "Resource UID", "value": client_id},
    ]
    if app_name:
        observables.append(
            {"name": "workspace.oauth.app_name", "type": "Resource Name", "value": app_name}
        )
    for scope in scopes:
        observables.append({"name": "workspace.oauth.scope", "type": "Other", "value": scope})

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
        "title": f"Google Workspace OAuth client '{app_name or client_id}' granted high-risk scopes",
        "description": description,
        "finding_types": ["workspace-suspicious-oauth-grant", OWASP_FINDING_TYPE],
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
            "actor": actor_uid,
            "client_id": client_id,
            "app_name": app_name,
            "scopes": scopes,
            "high_risk_reason": reason,
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
            "labels": ["identity", "google-workspace", "oauth", "detection"],
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
    allowlist = _preapproved_clients()
    findings: list[dict[str, Any]] = []
    for event in iter_records(stream):
        relevant, reason = _is_relevant(event, allowlist)
        if not relevant:
            continue
        native = _build_native_finding(event, reason)
        findings.append(native if output_format == "native" else _render_ocsf_finding(native))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect Google Workspace OAuth grants with high-risk scopes."
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
