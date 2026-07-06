"""Detect sudden spikes in Workday termination Account Change events."""

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

SKILL_NAME = "detect-mass-termination-anomaly"
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

WORKDAY_INGEST_SKILL = "ingest-workday-audit-ocsf"
WINDOW_MINUTES_ENV = "WORKDAY_TERMINATION_WINDOW_MINUTES"
COUNT_THRESHOLD_ENV = "WORKDAY_TERMINATION_COUNT_THRESHOLD"
APPROVED_BATCH_IDS_ENV = "WORKDAY_APPROVED_TERMINATION_BATCH_IDS"
DEFAULT_WINDOW_MINUTES = 60
DEFAULT_COUNT_THRESHOLD = 10

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0003"
MITRE_TACTIC_NAME = "Persistence"
MITRE_TECHNIQUE_UID = "T1098"
MITRE_TECHNIQUE_NAME = "Account Manipulation"

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
    raw = event.get("time_ms") or event.get("time") or 0
    try:
        return int(raw)
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


def _workday_block(event: dict[str, Any]) -> dict[str, Any]:
    if event.get("schema_mode") in {"canonical", "native"}:
        native_block = event.get("workday")
        return native_block if isinstance(native_block, dict) else {}
    block = ((event.get("unmapped") or {}).get("workday")) or {}
    return block if isinstance(block, dict) else {}


def _event_family(event: dict[str, Any]) -> str:
    block = _workday_block(event)
    return str(block.get("event_family") or event.get("event_family") or "").strip().lower()


def _batch_id(event: dict[str, Any]) -> str:
    block = _workday_block(event)
    raw_value = block.get("raw")
    raw: dict[str, Any] = raw_value if isinstance(raw_value, dict) else {}
    for key in (
        "batch_id",
        "batchId",
        "campaign_id",
        "campaignId",
        "transaction_id",
        "transactionId",
    ):
        value = block.get(key) or raw.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _worker_id(event: dict[str, Any]) -> str:
    user = event.get("user") or {}
    block = _workday_block(event)
    return str(
        user.get("uid")
        or user.get("email_addr")
        or user.get("name")
        or block.get("worker_id")
        or block.get("worker_email")
        or ""
    ).strip()


def _worker_label(event: dict[str, Any]) -> str:
    user = event.get("user") or {}
    return str(
        user.get("email_addr") or user.get("name") or user.get("uid") or _worker_id(event)
    ).strip()


def _org(event: dict[str, Any]) -> str:
    block = _workday_block(event)
    raw_value = block.get("raw")
    raw: dict[str, Any] = raw_value if isinstance(raw_value, dict) else {}
    return str(
        block.get("supervisory_org")
        or raw.get("supervisory_org")
        or raw.get("supervisoryOrg")
        or raw.get("organization")
        or ""
    ).strip()


def _is_relevant(event: dict[str, Any]) -> bool:
    if (
        event.get("class_uid") != ACCOUNT_CHANGE_CLASS_UID
        and event.get("record_type") != "account_change"
    ):
        return False
    if _producer(event) != WORKDAY_INGEST_SKILL:
        return False
    if _event_family(event) != "termination":
        return False
    return bool(_worker_id(event))


def _window_start(time_ms: int, window_minutes: int) -> int:
    bucket_ms = window_minutes * 60 * 1000
    return (time_ms // bucket_ms) * bucket_ms


def _finding_uid(window_start_ms: int, count: int, raw_event_uids: list[str]) -> str:
    material = f"{window_start_ms}|{count}|{'|'.join(sorted(raw_event_uids))}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-workday-mass-termination-{digest}"


def _build_native_finding(
    events: list[dict[str, Any]], window_start_ms: int, window_minutes: int, threshold: int
) -> dict[str, Any]:
    workers = sorted({_worker_label(event) for event in events if _worker_label(event)})
    orgs = sorted({_org(event) for event in events if _org(event)})
    batch_ids = sorted({_batch_id(event) for event in events if _batch_id(event)})
    raw_event_uids = [_metadata_uid(event) for event in events if _metadata_uid(event)]
    finding_uid = _finding_uid(window_start_ms, len(events), raw_event_uids)
    window_end_ms = window_start_ms + window_minutes * 60 * 1000

    description = (
        f"Workday produced {len(events)} termination events in {window_minutes} minutes, "
        f"meeting threshold {threshold}. Review HR batch approval, initiators, and downstream IAM deprovisioning before automated remediation."
    )

    observables: list[dict[str, Any]] = [
        {"name": "workday.termination.count", "type": "Counter", "value": str(len(events))},
    ]
    for worker in workers[:20]:
        observables.append({"name": "user.uid", "type": "User Name", "value": worker})
    for org in orgs[:10]:
        observables.append({"name": "workday.supervisory_org", "type": "Resource", "value": org})

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Workday",
        "time_ms": window_end_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": f"Workday mass termination anomaly: {len(events)} events in {window_minutes} minutes",
        "description": description,
        "finding_types": ["workday-mass-termination-anomaly", OWASP_FINDING_TYPE],
        "first_seen_time_ms": min(
            (_event_time(event) for event in events), default=window_start_ms
        ),
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
            "termination_count": len(events),
            "threshold": threshold,
            "window_minutes": window_minutes,
            "window_start_time_ms": window_start_ms,
            "window_end_time_ms": window_end_ms,
            "workers": workers[:50],
            "supervisory_orgs": orgs,
            "batch_ids": batch_ids,
            "raw_event_uids": raw_event_uids,
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
            "labels": ["identity", "workday", "termination", "detection"],
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
    threshold = _parse_positive_int_env(COUNT_THRESHOLD_ENV, DEFAULT_COUNT_THRESHOLD)
    approved_batch_ids = _parse_env_set(APPROVED_BATCH_IDS_ENV)
    buckets: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for event in iter_records(stream):
        if not _is_relevant(event):
            continue
        batch_id = _batch_id(event)
        if batch_id and batch_id in approved_batch_ids:
            continue
        event_time = _event_time(event) or _now_ms()
        buckets[_window_start(event_time, window_minutes)].append(event)

    findings: list[dict[str, Any]] = []
    for window_start_ms, events in sorted(buckets.items()):
        distinct_workers = {_worker_id(event) for event in events if _worker_id(event)}
        if len(distinct_workers) < threshold:
            continue
        native = _build_native_finding(events, window_start_ms, window_minutes, threshold)
        findings.append(native if output_format == "native" else _render_ocsf_finding(native))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect Workday mass termination anomalies.")
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
