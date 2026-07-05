"""Detect large Salesforce data exports followed by session close."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict
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

SKILL_NAME = "detect-bulk-export-salesforce"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-06"
REPO_NAME = "cloud-ai-security-skills"

_log = get_logger(__name__, skill=SKILL_NAME, layer="detection")

OUTPUT_FORMATS = ("ocsf", "native")
APP_ACTIVITY_CLASS_UID = 6002
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

SALESFORCE_INGEST_SKILL = "ingest-salesforce-event-mon-ocsf"
MIN_ROWS_ENV = "SALESFORCE_BULK_EXPORT_MIN_ROWS"
MIN_BYTES_ENV = "SALESFORCE_BULK_EXPORT_MIN_BYTES"
WINDOW_MINUTES_ENV = "SALESFORCE_EXPORT_LOGOUT_WINDOW_MINUTES"
APPROVED_USERS_ENV = "SALESFORCE_APPROVED_EXPORT_USERS"
DEFAULT_MIN_ROWS = 10_000
DEFAULT_MIN_BYTES = 50 * 1024 * 1024
DEFAULT_WINDOW_MINUTES = 30

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0010"
MITRE_TACTIC_NAME = "Exfiltration"
MITRE_TECHNIQUE_UID = "T1567"
MITRE_TECHNIQUE_NAME = "Exfiltration Over Web Service"
OWASP_FINDING_TYPE = "OWASP-Top-10-A01"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _parse_positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="invalid_env_int",
            message=f"{name} must be an integer",
            env_var=name,
        )
        return default
    return value if value > 0 else default


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


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


def _salesforce_block(event: dict[str, Any]) -> dict[str, Any]:
    if event.get("schema_mode") in {"canonical", "native"}:
        block = event.get("salesforce")
        return block if isinstance(block, dict) else {}
    block = ((event.get("unmapped") or {}).get("salesforce")) or {}
    return block if isinstance(block, dict) else {}


def _family(event: dict[str, Any]) -> str:
    block = _salesforce_block(event)
    return str(block.get("event_family") or "").strip().lower()


def _actor_id(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("email_addr") or user.get("name") or "").strip()


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("email_addr") or user.get("name") or user.get("uid") or "").strip()


def _session_key(event: dict[str, Any]) -> str:
    block = _salesforce_block(event)
    session = event.get("session") or {}
    return str(block.get("session_key") or session.get("uid") or "").strip()


def _rows(event: dict[str, Any]) -> int:
    value = _salesforce_block(event).get("rows_processed") or 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _bytes(event: dict[str, Any]) -> int:
    value = _salesforce_block(event).get("bytes") or 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _client_name(event: dict[str, Any]) -> str:
    return str(_salesforce_block(event).get("client_name") or "").strip()


def _src_ip(event: dict[str, Any]) -> str:
    endpoint = event.get("src_endpoint") or {}
    return str(endpoint.get("ip") or "").strip()


def _is_salesforce_event(event: dict[str, Any]) -> bool:
    if (
        event.get("class_uid") != APP_ACTIVITY_CLASS_UID
        and event.get("record_type") != "application_activity"
    ):
        return False
    return _producer(event) == SALESFORCE_INGEST_SKILL


def _is_large_export(event: dict[str, Any], min_rows: int, min_bytes: int) -> bool:
    return (
        _is_salesforce_event(event)
        and _family(event) == "export"
        and (_rows(event) >= min_rows or _bytes(event) >= min_bytes)
    )


def _is_logout(event: dict[str, Any]) -> bool:
    return _is_salesforce_event(event) and _family(event) == "logout"


def _correlation_key(event: dict[str, Any]) -> str:
    session = _session_key(event)
    return f"session:{session}" if session else f"actor:{_actor_id(event)}"


def _finding_uid(export_event: dict[str, Any], logout_event: dict[str, Any]) -> str:
    material = (
        f"{_metadata_uid(export_event)}|{_metadata_uid(logout_event)}|{_actor_id(export_event)}"
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-salesforce-bulk-export-{digest}"


def _build_native_finding(
    export_event: dict[str, Any],
    logout_event: dict[str, Any],
    window_minutes: int,
    min_rows: int,
    min_bytes: int,
) -> dict[str, Any]:
    time_ms = _event_time(logout_event) or _event_time(export_event) or _now_ms()
    finding_uid = _finding_uid(export_event, logout_event)
    actor_uid = _actor_id(export_event)
    actor_name = _actor_name(export_event)
    rows = _rows(export_event)
    byte_count = _bytes(export_event)
    client_name = _client_name(export_event)
    src_ip = _src_ip(export_event)
    raw_uids = [uid for uid in (_metadata_uid(export_event), _metadata_uid(logout_event)) if uid]

    description = (
        f"Salesforce principal '{actor_name or actor_uid}' exported {rows} rows / {byte_count} bytes "
        f"and closed the same session within {window_minutes} minutes. Thresholds: rows>={min_rows} "
        f"or bytes>={min_bytes}. Review report/Bulk API scope, client, and downstream data handling."
    )
    observables = [
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
        {"name": "salesforce.rows_processed", "type": "Counter", "value": str(rows)},
        {"name": "salesforce.bytes", "type": "Counter", "value": str(byte_count)},
    ]
    if client_name:
        observables.append(
            {"name": "salesforce.client_name", "type": "Process Name", "value": client_name}
        )
    if src_ip:
        observables.append({"name": "src.ip", "type": "IP Address", "value": src_ip})

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Salesforce",
        "time_ms": time_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": "Salesforce bulk export followed by session close",
        "description": description,
        "finding_types": ["salesforce-bulk-export", OWASP_FINDING_TYPE],
        "first_seen_time_ms": _event_time(export_event) or time_ms,
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
            "client_name": client_name,
            "src_ip": src_ip,
            "rows_processed": rows,
            "bytes": byte_count,
            "window_minutes": window_minutes,
            "min_rows": min_rows,
            "min_bytes": min_bytes,
            "session_key": _session_key(export_event),
            "raw_event_uids": raw_uids,
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
            "labels": ["salesforce", "bulk-export", "detection"],
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
    min_rows = _parse_positive_int_env(MIN_ROWS_ENV, DEFAULT_MIN_ROWS)
    min_bytes = _parse_positive_int_env(MIN_BYTES_ENV, DEFAULT_MIN_BYTES)
    window_minutes = _parse_positive_int_env(WINDOW_MINUTES_ENV, DEFAULT_WINDOW_MINUTES)
    approved_users = _parse_env_set(APPROVED_USERS_ENV)
    exports_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    findings: list[dict[str, Any]] = []
    window_ms = window_minutes * 60 * 1000

    for event in iter_records(stream):
        actor = _actor_id(event)
        if actor and actor in approved_users:
            continue
        if _is_large_export(event, min_rows, min_bytes):
            exports_by_key[_correlation_key(event)].append(event)
            continue
        if not _is_logout(event):
            continue
        logout_time = _event_time(event) or _now_ms()
        key = _correlation_key(event)
        for export_event in exports_by_key.get(key, []):
            export_time = _event_time(export_event) or logout_time
            if 0 <= logout_time - export_time <= window_ms:
                native = _build_native_finding(
                    export_event, event, window_minutes, min_rows, min_bytes
                )
                findings.append(
                    native if output_format == "native" else _render_ocsf_finding(native)
                )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect Salesforce bulk export followed by session close."
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
