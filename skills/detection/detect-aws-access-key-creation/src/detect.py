"""Detect AWS IAM user access-key creation via CloudTrail.

Reads OCSF 1.8 API Activity (class 6003) records emitted by
`ingest-cloudtrail-ocsf` from stdin or a file. Fires on successful
`CreateAccessKey` calls against IAM users and emits an OCSF 1.8 Detection
Finding (class 2004) tagged with MITRE ATT&CK T1098.001
(Additional Cloud Credentials).
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

SKILL_NAME = "detect-aws-access-key-creation"
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
TACTIC_UID = "TA0003"
TACTIC_NAME = "Persistence"
TECHNIQUE_UID = "T1098"
TECHNIQUE_NAME = "Account Manipulation"
SUBTECHNIQUE_UID = "T1098.001"
SUBTECHNIQUE_NAME = "Additional Cloud Credentials"

ACCEPTED_PRODUCERS = frozenset({"ingest-cloudtrail-ocsf"})
ACCESS_KEY_CREATE_OPERATION = "CreateAccessKey"
OUTPUT_FORMATS = frozenset({"ocsf", "native"})


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "")


def _is_success(event: dict[str, Any]) -> bool:
    return event.get("status_id") == STATUS_SUCCESS


def _target_user(event: dict[str, Any]) -> str:
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        resource_type = str(resource.get("type") or "")
        resource_name = str(resource.get("name") or "")
        if resource_type.lower() in {"username", "user", "iamusername"} and resource_name:
            return resource_name
    return ""


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


def _finding_uid(event_uid: str, target_user: str, actor_name: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{target_user}|{actor_name}|{time_ms}"
    return f"aakc-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(*, event: dict[str, Any], target_user: str) -> dict[str, Any]:
    time_ms = int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)
    event_uid = str((event.get("metadata") or {}).get("uid") or "")
    actor_name = _actor(event)
    finding_uid = _finding_uid(event_uid, target_user, actor_name, time_ms)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": "aws-access-key-creation",
        "api_operation": ACCESS_KEY_CREATE_OPERATION,
        "target_user_name": target_user,
        "actor_name": actor_name,
        "account_uid": _account(event),
        "region": _region(event),
        "src_ip": _src_ip(event),
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    description = (
        f"Actor `{native['actor_name'] or 'unknown'}` successfully called "
        f"`{native['api_operation']}` for IAM user `{native['target_user_name']}` in account "
        f"`{native['account_uid']}` ({native['region']}). Source IP: "
        f"{native['src_ip'] or '<unknown>'}. This creates additional AWS credential "
        "material for a valid cloud account."
    )
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "AWS"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "api.operation", "type": "Other", "value": native["api_operation"]},
        {"name": "rule", "type": "Other", "value": native["rule"]},
        {"name": "target.type", "type": "Other", "value": "IAMUser"},
        {"name": "target.name", "type": "Other", "value": native["target_user_name"]},
        {"name": "account.uid", "type": "Other", "value": native["account_uid"]},
        {"name": "region", "type": "Other", "value": native["region"]},
    ]
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
            "labels": ["aws", "iam", "credentials", "persistence"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": "AWS IAM access key created",
            "desc": description,
            "types": ["aws-access-key-creation"],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic_uid": TACTIC_UID,
                    "tactic_name": TACTIC_NAME,
                    "technique_uid": TECHNIQUE_UID,
                    "technique_name": TECHNIQUE_NAME,
                    "sub_technique_uid": SUBTECHNIQUE_UID,
                    "sub_technique_name": SUBTECHNIQUE_NAME,
                }
            ],
        },
        "observables": observables,
        "evidence": {
            "events_observed": 1,
            "api_operation": native["api_operation"],
            "target_user_name": native["target_user_name"],
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    for event in events:
        producer = _producer(event)
        if producer not in ACCEPTED_PRODUCERS:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="wrong_source",
                message=f"skipping event from non-cloudtrail producer `{producer}`",
            )
            continue
        if _api_operation(event) != ACCESS_KEY_CREATE_OPERATION:
            continue
        if not _is_success(event):
            continue
        target_user = _target_user(event)
        if not target_user:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_target_user",
                message="skipping CreateAccessKey event with no target IAM username",
            )
            continue
        native = _build_native_finding(event=event, target_user=target_user)
        yield native if output_format == "native" else _to_ocsf(native)


def _iter_jsonl(path: str | None) -> Iterator[dict[str, Any]]:
    handle = open(path, "r", encoding="utf-8") if path else sys.stdin
    with handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="invalid_json",
                    message=f"skipping line {line_number}: invalid JSON ({exc.msg})",
                )
                continue
            if isinstance(obj, dict):
                yield obj
            else:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="wrong_shape",
                    message=f"skipping line {line_number}: expected JSON object",
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="JSONL file path (default: stdin)")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="Emit repo-native or OCSF findings (default: ocsf)",
    )
    args = parser.parse_args(argv)

    for finding in detect(_iter_jsonl(args.input), output_format=args.output_format):
        print(json.dumps(finding, separators=(",", ":"), sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
