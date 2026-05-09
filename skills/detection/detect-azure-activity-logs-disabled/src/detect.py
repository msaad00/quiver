"""Detect Azure diagnostic settings being explicitly deleted.

Reads OCSF 1.8 API Activity (class 6003) records emitted by
`ingest-azure-activity-ocsf` from stdin or a file. Fires on successful
`Microsoft.Insights/diagnosticSettings/delete` operations and emits an OCSF
1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1562.001
(Disable or Modify Tools).

This first slice is intentionally narrow and high-confidence:
1. event.api.operation case-insensitively equals
   `Microsoft.Insights/diagnosticSettings/delete`
2. event.status_id == 1 (success)
3. the target diagnostic setting resource id resolves from `resources[]`
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-azure-activity-logs-disabled"
CANONICAL_VERSION = "2026-04"
OCSF_VERSION = "1.8.0"
REPO_NAME = "cloud-ai-security-skills"
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402

FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

MITRE_VERSION = "v14"
TACTIC_UID = "TA0005"
TACTIC_NAME = "Defense Evasion"
TECHNIQUE_UID = "T1562.001"
TECHNIQUE_NAME = "Disable or Modify Tools"

ACCEPTED_PRODUCERS = frozenset({"ingest-azure-activity-ocsf"})
DIAGNOSTIC_DELETE_OPERATION = "microsoft.insights/diagnosticsettings/delete"
OUTPUT_FORMATS = frozenset({"ocsf", "native"})


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "")


def _normalized_operation(event: dict[str, Any]) -> str:
    return _api_operation(event).strip().lower()


def _is_success(event: dict[str, Any]) -> bool:
    return event.get("status_id") == STATUS_SUCCESS


def _actor(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _account(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    account = cloud.get("account") or {}
    return str(account.get("uid") or "")


def _region(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    return str(cloud.get("region") or "")


def _src_ip(event: dict[str, Any]) -> str:
    endpoint = event.get("src_endpoint") or {}
    return str(endpoint.get("ip") or "")


def _resource_id(event: dict[str, Any]) -> str:
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        name = str(resource.get("name") or resource.get("uid") or "")
        if name:
            return name
    return ""


def _setting_name(resource_id: str) -> str:
    if not resource_id:
        return ""
    return resource_id.rstrip("/").split("/")[-1]


def _finding_uid(event_uid: str, resource_id: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{resource_id}|{time_ms}"
    return f"aad-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(*, event: dict[str, Any], resource_id: str, setting_name: str) -> dict[str, Any]:
    time_ms = int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)
    event_uid = str((event.get("metadata") or {}).get("uid") or "")
    finding_uid = _finding_uid(event_uid, resource_id, time_ms)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": "azure-activity-logs-disabled",
        "api_operation": _api_operation(event),
        "resource_id": resource_id,
        "setting_name": setting_name,
        "actor_name": _actor(event),
        "account_uid": _account(event),
        "region": _region(event),
        "src_ip": _src_ip(event),
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    description = (
        f"Actor `{native['actor_name'] or 'unknown'}` successfully called "
        f"`{native['api_operation']}` against Azure diagnostic setting "
        f"`{native['setting_name'] or '<unknown>'}` in subscription "
        f"`{native['account_uid']}`. Source IP: {native['src_ip'] or '<unknown>'}."
    )
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "Azure"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "api.operation", "type": "Other", "value": native["api_operation"]},
        {"name": "rule", "type": "Other", "value": native["rule"]},
        {"name": "target.type", "type": "Other", "value": "diagnostic_setting"},
        {"name": "target.uid", "type": "Other", "value": native["resource_id"]},
        {"name": "target.name", "type": "Other", "value": native["setting_name"]},
        {"name": "account.uid", "type": "Other", "value": native["account_uid"]},
    ]
    if native["region"]:
        observables.append({"name": "region", "type": "Other", "value": native["region"]})
    if native["src_ip"]:
        observables.append({"name": "src.ip", "type": "IP Address", "value": native["src_ip"]})
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_HIGH,
        "status_id": STATUS_SUCCESS,
        "time": native["first_seen_time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native["finding_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["azure", "diagnostic-settings", "defense-evasion"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": "Azure diagnostic setting deleted",
            "desc": description,
            "types": ["azure-activity-logs-disabled"],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic_uid": TACTIC_UID,
                    "tactic_name": TACTIC_NAME,
                    "technique_uid": TECHNIQUE_UID,
                    "technique_name": TECHNIQUE_NAME,
                }
            ],
        },
        "observables": observables,
        "evidence": {
            "events_observed": 1,
            "api_operation": native["api_operation"],
            "resource_id": native["resource_id"],
            "setting_name": native["setting_name"],
        },
    }


def detect(events: Iterable[dict[str, Any]], *, output_format: str = "ocsf") -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    for event in events:
        producer = _producer(event)
        if producer not in ACCEPTED_PRODUCERS:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="wrong_source",
                message=f"skipping event from non-azure-activity producer `{producer}`",
            )
            continue
        if _normalized_operation(event) != DIAGNOSTIC_DELETE_OPERATION:
            continue
        if not _is_success(event):
            continue
        resource_id = _resource_id(event)
        if not resource_id:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_target",
                message="diagnostic settings delete event missing resource id; skipping",
            )
            continue
        setting_name = _setting_name(resource_id)
        native = _build_native_finding(event=event, resource_id=resource_id, setting_name=setting_name)
        yield native if output_format == "native" else _to_ocsf(native)


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=f"skipping line {lineno}: json parse failed: {exc}",
                line=lineno,
            )
            continue
        if isinstance(obj, dict):
            yield obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect successful Azure diagnostic settings delete operations."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="Emit OCSF Detection Finding (default) or native projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")
    try:
        for finding in detect(load_jsonl(in_stream), output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
