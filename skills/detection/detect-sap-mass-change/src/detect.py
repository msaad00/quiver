"""Detect mass changes to sensitive SAP transactions from normalized SAL events."""

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

SKILL_NAME = "detect-sap-mass-change"
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

SAP_INGEST_SKILL = "ingest-sap-audit-log-ocsf"
WINDOW_MINUTES_ENV = "SAP_MASS_CHANGE_WINDOW_MINUTES"
CHANGE_THRESHOLD_ENV = "SAP_MASS_CHANGE_EVENT_THRESHOLD"
SENSITIVE_TX_ENV = "SAP_SENSITIVE_TRANSACTIONS"
APPROVED_USERS_ENV = "SAP_APPROVED_MASS_CHANGE_USERS"
DEFAULT_WINDOW_MINUTES = 15
DEFAULT_CHANGE_THRESHOLD = 25
DEFAULT_SENSITIVE_TX = (
    "PFCG",
    "RZ10",
    "RZ11",
    "SCC4",
    "SE11",
    "SE16",
    "SE16N",
    "SE38",
    "SE80",
    "SM30",
    "SM59",
    "STMS",
    "SU01",
    "SU10",
)

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0040"
MITRE_TACTIC_NAME = "Impact"
MITRE_TECHNIQUE_UID = "T1565"
MITRE_TECHNIQUE_NAME = "Data Manipulation"
OWASP_FINDING_TYPE = "OWASP-Top-10-A04"


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


def _parse_env_set(name: str, default: Iterable[str] = ()) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset(item.upper() for item in default)
    return frozenset(part.strip().upper() for part in raw.split(",") if part.strip())


def _event_time(event: dict[str, Any]) -> int:
    try:
        return int(event.get("time_ms") or event.get("time") or 0)
    except (TypeError, ValueError):
        return 0


def _window_start(time_ms: int, window_minutes: int) -> int:
    window_ms = window_minutes * 60 * 1000
    return (time_ms // window_ms) * window_ms


def _metadata_uid(event: dict[str, Any]) -> str:
    return str(event.get("event_uid") or (event.get("metadata") or {}).get("uid") or "")


def _producer(event: dict[str, Any]) -> str:
    if event.get("source_skill"):
        return str(event["source_skill"])
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _sap_block(event: dict[str, Any]) -> dict[str, Any]:
    if event.get("schema_mode") in {"canonical", "native"}:
        block = event.get("sap")
        return block if isinstance(block, dict) else {}
    block = ((event.get("unmapped") or {}).get("sap")) or {}
    return block if isinstance(block, dict) else {}


def _family(event: dict[str, Any]) -> str:
    return str(_sap_block(event).get("event_family") or "").strip().lower()


def _actor_id(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("name") or "").strip()


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "").strip()


def _client(event: dict[str, Any]) -> str:
    return str(_sap_block(event).get("client") or "").strip()


def _transaction(event: dict[str, Any]) -> str:
    return str(_sap_block(event).get("transaction_code") or "").strip().upper()


def _change_count(event: dict[str, Any]) -> int:
    raw = _sap_block(event).get("change_count") or 0
    try:
        count = int(raw)
    except (TypeError, ValueError):
        count = 0
    return count if count > 0 else 1


def _is_relevant(event: dict[str, Any], sensitive_tx: frozenset[str]) -> bool:
    if (
        event.get("class_uid") != APP_ACTIVITY_CLASS_UID
        and event.get("record_type") != "application_activity"
    ):
        return False
    if _producer(event) != SAP_INGEST_SKILL:
        return False
    if not _actor_id(event):
        return False
    tx_code = _transaction(event)
    if tx_code not in sensitive_tx:
        return False
    return _family(event) in {"change", "privileged_access", "transaction"}


def _finding_uid(
    actor: str, client: str, tx_code: str, window_start: int, event_uids: list[str]
) -> str:
    material = f"{actor}|{client}|{tx_code}|{window_start}|{'|'.join(sorted(event_uids))}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-sap-mass-change-{digest}"


def _build_native_finding(
    actor: str,
    actor_name: str,
    client: str,
    tx_code: str,
    window_start: int,
    window_minutes: int,
    threshold: int,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    event_uids = [_metadata_uid(event) for event in events if _metadata_uid(event)]
    change_total = sum(_change_count(event) for event in events)
    first_seen = min(
        (_event_time(event) for event in events if _event_time(event)), default=window_start
    )
    last_seen = max(
        (_event_time(event) for event in events if _event_time(event)), default=window_start
    )
    finding_uid = _finding_uid(actor, client, tx_code, window_start, event_uids)
    description = (
        f"SAP principal '{actor_name or actor}' performed {change_total} sensitive changes through "
        f"transaction '{tx_code}' in client '{client or 'unknown'}' within {window_minutes} minutes. "
        f"Threshold is {threshold}; review transport, role, table, and user-maintenance evidence."
    )
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "SAP",
        "time_ms": last_seen or _now_ms(),
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": "SAP mass change through sensitive transaction",
        "description": description,
        "finding_types": ["sap-mass-change", OWASP_FINDING_TYPE],
        "first_seen_time_ms": first_seen,
        "last_seen_time_ms": last_seen,
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": MITRE_TACTIC_UID,
                "tactic_name": MITRE_TACTIC_NAME,
                "technique_uid": MITRE_TECHNIQUE_UID,
                "technique_name": MITRE_TECHNIQUE_NAME,
            }
        ],
        "observables": [
            {"name": "actor.user.uid", "type": "User Name", "value": actor},
            {"name": "sap.client", "type": "Resource Name", "value": client},
            {"name": "sap.transaction_code", "type": "Process Name", "value": tx_code},
            {"name": "sap.change_count", "type": "Counter", "value": str(change_total)},
        ],
        "evidence": {
            "actor": actor,
            "client": client,
            "transaction_code": tx_code,
            "change_count": change_total,
            "event_count": len(events),
            "threshold": threshold,
            "window_minutes": window_minutes,
            "raw_event_uids": event_uids,
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
            "labels": ["sap", "mass-change", "detection"],
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
    window_minutes = _parse_positive_int_env(WINDOW_MINUTES_ENV, DEFAULT_WINDOW_MINUTES)
    threshold = _parse_positive_int_env(CHANGE_THRESHOLD_ENV, DEFAULT_CHANGE_THRESHOLD)
    sensitive_tx = _parse_env_set(SENSITIVE_TX_ENV, DEFAULT_SENSITIVE_TX)
    approved_users = _parse_env_set(APPROVED_USERS_ENV)
    buckets: dict[tuple[str, str, str, int], list[dict[str, Any]]] = defaultdict(list)
    actor_names: dict[tuple[str, str, str, int], str] = {}

    for event in iter_records(stream):
        actor = _actor_id(event)
        if actor.upper() in approved_users:
            continue
        if not _is_relevant(event, sensitive_tx):
            continue
        time_ms = _event_time(event) or _now_ms()
        key = (actor, _client(event), _transaction(event), _window_start(time_ms, window_minutes))
        buckets[key].append(event)
        actor_names[key] = _actor_name(event)

    findings: list[dict[str, Any]] = []
    for (actor, client, tx_code, window_start), events in buckets.items():
        change_total = sum(_change_count(event) for event in events)
        if change_total < threshold:
            continue
        native = _build_native_finding(
            actor,
            actor_names.get((actor, client, tx_code, window_start), ""),
            client,
            tx_code,
            window_start,
            window_minutes,
            threshold,
            events,
        )
        findings.append(native if output_format == "native" else _render_ocsf_finding(native))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect SAP mass change through sensitive transactions."
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
