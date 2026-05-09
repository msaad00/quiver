"""Detect AWS S3 cross-account object copies via CloudTrail."""

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

SKILL_NAME = "detect-s3-cross-account-copy"
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
TACTIC_UID = "TA0010"
TACTIC_NAME = "Exfiltration"
TECHNIQUE_UID = "T1537"
TECHNIQUE_NAME = "Transfer Data to Cloud Account"

ACCEPTED_PRODUCERS = frozenset({"ingest-cloudtrail-ocsf"})
S3_SERVICE = "s3.amazonaws.com"
COPY_OBJECT_OPERATION = "CopyObject"
OUTPUT_FORMATS = frozenset({"ocsf", "native"})


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "")


def _api_service(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    service = api.get("service") or {}
    return str(service.get("name") or "")


def _is_success(event: dict[str, Any]) -> bool:
    return event.get("status_id") == STATUS_SUCCESS


def _resource_value(event: dict[str, Any], *resource_types: str) -> str:
    allowed = {item.lower() for item in resource_types}
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        resource_type = str(resource.get("type") or "").lower()
        resource_name = str(resource.get("name") or "")
        if resource_type in allowed and resource_name:
            return resource_name
    return ""


def _target_bucket(event: dict[str, Any]) -> str:
    return _resource_value(event, "bucketname")


def _target_key(event: dict[str, Any]) -> str:
    return _resource_value(event, "key")


def _copy_source(event: dict[str, Any]) -> str:
    return _resource_value(event, "x-amz-copy-source", "xamzcopysource")


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _actor_account(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    account = user.get("account") or {}
    return str(account.get("uid") or "")


def _target_account(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    account = cloud.get("account") or {}
    return str(account.get("uid") or "")


def _region(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    return str(cloud.get("region") or "")


def _src_ip(event: dict[str, Any]) -> str:
    endpoint = event.get("src_endpoint") or {}
    return str(endpoint.get("ip") or "")


def _time_ms(event: dict[str, Any]) -> int:
    return int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)


def _event_uid(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    return str(metadata.get("uid") or "")


def _parse_copy_source(copy_source: str) -> tuple[str, str]:
    cleaned = copy_source.lstrip("/")
    if "/" not in cleaned:
        return cleaned, ""
    bucket, key = cleaned.split("/", 1)
    return bucket, key


def _finding_uid(
    *,
    event_uid: str,
    actor_account_uid: str,
    target_account_uid: str,
    destination_bucket: str,
    destination_key: str,
    time_ms: int,
) -> str:
    material = "|".join(
        [
            SKILL_NAME,
            event_uid,
            actor_account_uid,
            target_account_uid,
            destination_bucket,
            destination_key,
            str(time_ms),
        ]
    )
    return f"s3x-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(
    *,
    event: dict[str, Any],
    destination_bucket: str,
    destination_key: str,
    copy_source: str,
) -> dict[str, Any]:
    time_ms = _time_ms(event)
    source_bucket, source_key = _parse_copy_source(copy_source)
    actor_account_uid = _actor_account(event)
    target_account_uid = _target_account(event)
    finding_uid = _finding_uid(
        event_uid=_event_uid(event),
        actor_account_uid=actor_account_uid,
        target_account_uid=target_account_uid,
        destination_bucket=destination_bucket,
        destination_key=destination_key,
        time_ms=time_ms,
    )
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": "s3-cross-account-copy",
        "api_operation": COPY_OBJECT_OPERATION,
        "actor_name": _actor_name(event),
        "actor_account_uid": actor_account_uid,
        "target_account_uid": target_account_uid,
        "region": _region(event),
        "src_ip": _src_ip(event),
        "source_bucket": source_bucket,
        "source_key": source_key,
        "destination_bucket": destination_bucket,
        "destination_key": destination_key,
        "copy_source": copy_source,
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    description = (
        f"Principal `{native['actor_name'] or 'unknown'}` from AWS account "
        f"`{native['actor_account_uid']}` successfully called `CopyObject` into "
        f"`{native['destination_bucket']}/{native['destination_key']}` owned by account "
        f"`{native['target_account_uid']}`. Source object: "
        f"`{native['source_bucket']}/{native['source_key'] or ''}`. Source IP: "
        f"{native['src_ip'] or '<unknown>'}."
    )
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "AWS"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "rule", "type": "Other", "value": native["rule"]},
        {"name": "actor.account.uid", "type": "Other", "value": native["actor_account_uid"]},
        {"name": "target.account.uid", "type": "Other", "value": native["target_account_uid"]},
        {"name": "destination.bucket", "type": "Other", "value": native["destination_bucket"]},
        {"name": "destination.key", "type": "Other", "value": native["destination_key"]},
        {"name": "source.copy_path", "type": "Other", "value": native["copy_source"]},
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
            "labels": ["aws", "s3", "exfiltration", "cross-account"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": "S3 cross-account copy detected",
            "desc": description,
            "types": ["s3-cross-account-copy"],
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
            "copy_source": native["copy_source"],
            "destination_bucket": native["destination_bucket"],
            "destination_key": native["destination_key"],
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
        if _api_service(event) != S3_SERVICE or _api_operation(event) != COPY_OBJECT_OPERATION:
            continue
        if not _is_success(event):
            continue

        actor_account_uid = _actor_account(event)
        target_account_uid = _target_account(event)
        if not actor_account_uid or not target_account_uid:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_account_context",
                message="skipping CopyObject event with missing actor or target account context",
            )
            continue
        if actor_account_uid == target_account_uid:
            continue

        destination_bucket = _target_bucket(event)
        destination_key = _target_key(event)
        copy_source = _copy_source(event)
        if not destination_bucket or not destination_key or not copy_source:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_copy_context",
                message="skipping CopyObject event missing bucket, key, or x-amz-copy-source",
            )
            continue

        native = _build_native_finding(
            event=event,
            destination_bucket=destination_bucket,
            destination_key=destination_key,
            copy_source=copy_source,
        )
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


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", help="optional JSONL input path; defaults to stdin")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="emit OCSF Detection Finding 2004 (default) or native findings",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    for finding in detect(_iter_jsonl(args.path), output_format=args.output_format):
        json.dump(finding, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
