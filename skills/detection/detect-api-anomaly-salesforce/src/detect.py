"""Detect Salesforce API usage outside an operator baseline."""

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

SKILL_NAME = "detect-api-anomaly-salesforce"
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
BASELINE_ENV = "SALESFORCE_API_BASELINE_JSON"
WINDOW_MINUTES_ENV = "SALESFORCE_API_ANOMALY_WINDOW_MINUTES"
EVENT_THRESHOLD_ENV = "SALESFORCE_API_ANOMALY_EVENT_THRESHOLD"
ALLOWED_CLIENTS_ENV = "SALESFORCE_API_ALLOWED_CLIENTS"
DEFAULT_WINDOW_MINUTES = 60
DEFAULT_EVENT_THRESHOLD = 25

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0003"
MITRE_TACTIC_NAME = "Persistence"
MITRE_TECHNIQUE_UID = "T1078.004"
MITRE_TECHNIQUE_NAME = "Valid Accounts: Cloud Accounts"
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
        emit_stderr_event(SKILL_NAME, level="warning", event="invalid_env_int", message=f"{name} must be an integer", env_var=name)
        return default
    return value if value > 0 else default


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _load_baseline() -> dict[str, dict[str, Any]]:
    raw = os.environ.get(BASELINE_ENV, "")
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        emit_stderr_event(SKILL_NAME, level="warning", event="invalid_baseline_json", message=str(exc), env_var=BASELINE_ENV)
        return {}
    if not isinstance(parsed, dict):
        return {}
    baseline: dict[str, dict[str, Any]] = {}
    for key, value in parsed.items():
        if isinstance(value, dict):
            baseline[str(key)] = value
    return baseline


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


def _salesforce_block(event: dict[str, Any]) -> dict[str, Any]:
    if event.get("schema_mode") in {"canonical", "native"}:
        block = event.get("salesforce")
        return block if isinstance(block, dict) else {}
    block = ((event.get("unmapped") or {}).get("salesforce")) or {}
    return block if isinstance(block, dict) else {}


def _family(event: dict[str, Any]) -> str:
    return str(_salesforce_block(event).get("event_family") or "").strip().lower()


def _actor_id(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("email_addr") or user.get("name") or "").strip()


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("email_addr") or user.get("name") or user.get("uid") or "").strip()


def _client_name(event: dict[str, Any]) -> str:
    return str(_salesforce_block(event).get("client_name") or "").strip()


def _src_ip(event: dict[str, Any]) -> str:
    endpoint = event.get("src_endpoint") or {}
    return str(endpoint.get("ip") or "").strip()


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or _salesforce_block(event).get("operation") or "").strip()


def _is_relevant(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != APP_ACTIVITY_CLASS_UID and event.get("record_type") != "application_activity":
        return False
    if _producer(event) != SALESFORCE_INGEST_SKILL:
        return False
    return _family(event) == "api" and bool(_actor_id(event))


def _baseline_for_actor(actor: str, baseline: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return baseline.get(actor) or baseline.get("*") or {}


def _as_set(value: Any) -> frozenset[str]:
    if isinstance(value, list):
        return frozenset(str(item) for item in value if item not in (None, ""))
    if isinstance(value, str) and value:
        return frozenset(part.strip() for part in value.split(",") if part.strip())
    return frozenset()


def _max_events(config: dict[str, Any], default: int) -> int:
    try:
        value = int(config.get("max_events") or default)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _finding_uid(actor: str, window_start_ms: int, reason: str, event_uids: list[str]) -> str:
    material = f"{actor}|{window_start_ms}|{reason}|{'|'.join(sorted(event_uids))}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-salesforce-api-anomaly-{digest}"


def _reason_for_bucket(
    events: list[dict[str, Any]],
    actor: str,
    baseline: dict[str, dict[str, Any]],
    allowed_clients: frozenset[str],
    default_threshold: int,
) -> str:
    config = _baseline_for_actor(actor, baseline)
    baseline_clients = _as_set(config.get("client_names") or config.get("clients")) | allowed_clients
    baseline_ips = _as_set(config.get("ips") or config.get("ip_addrs"))
    max_events = _max_events(config, default_threshold)
    clients = {_client_name(event) for event in events if _client_name(event)}
    ips = {_src_ip(event) for event in events if _src_ip(event)}
    unknown_clients = sorted(clients - baseline_clients) if baseline_clients else []
    unknown_ips = sorted(ips - baseline_ips) if baseline_ips else []
    if unknown_clients:
        return f"client outside baseline: {unknown_clients[0]}"
    if unknown_ips:
        return f"source IP outside baseline: {unknown_ips[0]}"
    if len(events) >= max_events:
        if not config and not baseline_clients:
            return f"no actor baseline and event count {len(events)} >= {max_events}"
        return f"event count {len(events)} exceeds baseline max_events {max_events}"
    return ""


def _build_native_finding(events: list[dict[str, Any]], actor: str, window_start_ms: int, window_minutes: int, reason: str) -> dict[str, Any]:
    actor_name = _actor_name(events[0])
    event_uids = [_metadata_uid(event) for event in events if _metadata_uid(event)]
    finding_uid = _finding_uid(actor, window_start_ms, reason, event_uids)
    window_end_ms = window_start_ms + window_minutes * 60 * 1000
    clients = sorted({_client_name(event) for event in events if _client_name(event)})
    ips = sorted({_src_ip(event) for event in events if _src_ip(event)})
    operations = sorted({_api_operation(event) for event in events if _api_operation(event)})

    description = (
        f"Salesforce principal '{actor_name or actor}' produced API activity outside baseline: {reason}. "
        f"Observed {len(events)} API events across clients={clients or ['unknown']} and source IPs={ips or ['unknown']}."
    )
    observables = [
        {"name": "actor.user.uid", "type": "User Name", "value": actor},
        {"name": "salesforce.api.event_count", "type": "Counter", "value": str(len(events))},
    ]
    for client in clients[:10]:
        observables.append({"name": "salesforce.client_name", "type": "Process Name", "value": client})
    for ip in ips[:10]:
        observables.append({"name": "src.ip", "type": "IP Address", "value": ip})

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Salesforce",
        "time_ms": window_end_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": "Salesforce API usage outside baseline",
        "description": description,
        "finding_types": ["salesforce-api-anomaly", OWASP_FINDING_TYPE],
        "first_seen_time_ms": min((_event_time(event) for event in events), default=window_start_ms),
        "last_seen_time_ms": max((_event_time(event) for event in events), default=window_end_ms),
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
            "actor": actor,
            "reason": reason,
            "event_count": len(events),
            "window_minutes": window_minutes,
            "window_start_time_ms": window_start_ms,
            "window_end_time_ms": window_end_ms,
            "client_names": clients,
            "src_ips": ips,
            "operations": operations[:25],
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
            "labels": ["salesforce", "api-anomaly", "detection"],
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
            emit_stderr_event(SKILL_NAME, level="warning", event="json_parse_failed", message=str(exc), line=lineno)
            continue
        if isinstance(obj, dict):
            yield obj


def detect(stream: Iterable[str], output_format: str = "ocsf") -> list[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(f"unsupported output_format `{output_format}`")
    baseline = _load_baseline()
    allowed_clients = _parse_env_set(ALLOWED_CLIENTS_ENV)
    window_minutes = _parse_positive_int_env(WINDOW_MINUTES_ENV, DEFAULT_WINDOW_MINUTES)
    threshold = _parse_positive_int_env(EVENT_THRESHOLD_ENV, DEFAULT_EVENT_THRESHOLD)
    buckets: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for event in iter_records(stream):
        if not _is_relevant(event):
            continue
        actor = _actor_id(event)
        event_time = _event_time(event) or _now_ms()
        buckets[(actor, _window_start(event_time, window_minutes))].append(event)

    findings: list[dict[str, Any]] = []
    for (actor, window_start_ms), events in sorted(buckets.items(), key=lambda item: (item[0][1], item[0][0])):
        reason = _reason_for_bucket(events, actor, baseline, allowed_clients, threshold)
        if not reason:
            continue
        native = _build_native_finding(events, actor, window_start_ms, window_minutes, reason)
        findings.append(native if output_format == "native" else _render_ocsf_finding(native))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect Salesforce API usage outside baseline.")
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
