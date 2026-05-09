"""Detect suspicious AWS S3 model-artifact downloads via CloudTrail."""

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

SKILL_NAME = "detect-aws-model-artifact-download"
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
ATTACK_TACTIC_UID = "TA0009"
ATTACK_TACTIC_NAME = "Collection"
ATTACK_TECHNIQUE_UID = "T1530"
ATTACK_TECHNIQUE_NAME = "Data from Cloud Storage"

ATLAS_VERSION = "current"
ATLAS_TACTIC_UID = "AML.TA0009"
ATLAS_TACTIC_NAME = "Collection"
ATLAS_TECHNIQUE_UID = "AML.T0035"
ATLAS_TECHNIQUE_NAME = "ML Artifact Collection"

ACCEPTED_PRODUCERS = frozenset({"ingest-cloudtrail-ocsf"})
S3_SERVICE = "s3.amazonaws.com"
GET_OBJECT_OPERATION = "GetObject"
OUTPUT_FORMATS = frozenset({"ocsf", "native"})

STRICT_SUFFIXES = (
    ".safetensors",
    ".pt",
    ".pth",
    ".ckpt",
    ".onnx",
    ".gguf",
    ".tflite",
    ".keras",
    ".h5",
)
EXACT_FILENAMES = frozenset(
    {
        "pytorch_model.bin",
        "adapter_model.bin",
        "consolidated.safetensors",
        "model.safetensors",
        "model.ckpt",
        "saved_model.pb",
    }
)
MODEL_HINTS = (
    "model",
    "models",
    "artifact",
    "artifacts",
    "checkpoint",
    "checkpoints",
    "weights",
    "huggingface",
    "finetune",
    "fine-tune",
    "lora",
    "adapter",
    "sagemaker",
    "bedrock",
)


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


def _bucket_name(event: dict[str, Any]) -> str:
    return _resource_value(event, "bucketname")


def _object_key(event: dict[str, Any]) -> str:
    return _resource_value(event, "key")


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _actor_type(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("type") or "")


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


def _artifact_match(key: str) -> tuple[bool, str]:
    lowered = key.strip().lower()
    if not lowered:
        return False, ""
    filename = lowered.rsplit("/", 1)[-1]
    if filename in EXACT_FILENAMES:
        return True, filename
    for suffix in STRICT_SUFFIXES:
        if lowered.endswith(suffix):
            return True, suffix
    if lowered.endswith(".bin") and any(token in lowered for token in MODEL_HINTS):
        return True, ".bin+model-hint"
    return False, ""


def _finding_uid(
    *,
    event_uid: str,
    actor_account_uid: str,
    bucket_name: str,
    object_key: str,
    time_ms: int,
) -> str:
    material = "|".join([SKILL_NAME, event_uid, actor_account_uid, bucket_name, object_key, str(time_ms)])
    return f"amad-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(
    *,
    event: dict[str, Any],
    bucket_name: str,
    object_key: str,
    artifact_match: str,
) -> dict[str, Any]:
    time_ms = _time_ms(event)
    finding_uid = _finding_uid(
        event_uid=_event_uid(event),
        actor_account_uid=_actor_account(event),
        bucket_name=bucket_name,
        object_key=object_key,
        time_ms=time_ms,
    )
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": "aws-model-artifact-download",
        "api_operation": GET_OBJECT_OPERATION,
        "bucket_name": bucket_name,
        "object_key": object_key,
        "artifact_match": artifact_match,
        "actor_name": _actor_name(event),
        "actor_type": _actor_type(event),
        "actor_account_uid": _actor_account(event),
        "target_account_uid": _target_account(event),
        "region": _region(event),
        "src_ip": _src_ip(event),
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": ATTACK_TACTIC_UID,
                "tactic_name": ATTACK_TACTIC_NAME,
                "technique_uid": ATTACK_TECHNIQUE_UID,
                "technique_name": ATTACK_TECHNIQUE_NAME,
            },
            {
                "version": ATLAS_VERSION,
                "tactic_uid": ATLAS_TACTIC_UID,
                "tactic_name": ATLAS_TACTIC_NAME,
                "technique_uid": ATLAS_TECHNIQUE_UID,
                "technique_name": ATLAS_TECHNIQUE_NAME,
            },
        ],
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    description = (
        f"Principal `{native['actor_name'] or 'unknown'}` successfully downloaded "
        f"`s3://{native['bucket_name']}/{native['object_key']}` via `GetObject`. "
        f"The object name matched model-artifact heuristics (`{native['artifact_match']}`) "
        f"in account `{native['target_account_uid']}` ({native['region']}). Source IP: "
        f"{native['src_ip'] or '<unknown>'}. This is an AWS-first detector for suspicious "
        "AI model-weight or checkpoint collection from S3-backed storage."
    )
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "AWS"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "actor.type", "type": "Other", "value": native["actor_type"] or "unknown"},
        {"name": "actor.account.uid", "type": "Other", "value": native["actor_account_uid"]},
        {"name": "target.account.uid", "type": "Other", "value": native["target_account_uid"]},
        {"name": "bucket.name", "type": "Other", "value": native["bucket_name"]},
        {"name": "object.key", "type": "Other", "value": native["object_key"]},
        {"name": "artifact.match", "type": "Other", "value": native["artifact_match"]},
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
            "labels": ["aws", "s3", "ai", "model-artifacts", "collection"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": "AWS model artifact downloaded from S3",
            "desc": description,
            "types": ["aws-model-artifact-download"],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": native["mitre_attacks"],
        },
        "observables": observables,
        "evidence": {
            "events_observed": 1,
            "api_operation": native["api_operation"],
            "bucket_name": native["bucket_name"],
            "object_key": native["object_key"],
            "artifact_match": native["artifact_match"],
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
        if _api_service(event) != S3_SERVICE or _api_operation(event) != GET_OBJECT_OPERATION:
            continue
        if not _is_success(event):
            continue
        if _actor_type(event).lower() == "awsservice":
            continue
        bucket_name = _bucket_name(event)
        object_key = _object_key(event)
        if not bucket_name or not object_key:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_s3_context",
                message="skipping GetObject event missing bucket or key context",
            )
            continue
        is_artifact, artifact_match = _artifact_match(object_key)
        if not is_artifact:
            continue
        native = _build_native_finding(
            event=event,
            bucket_name=bucket_name,
            object_key=object_key,
            artifact_match=artifact_match,
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="optional path to JSONL input (default: stdin)")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="emit OCSF findings (default) or native findings",
    )
    args = parser.parse_args(argv)

    for finding in detect(_iter_jsonl(args.input), output_format=args.output_format):
        print(json.dumps(finding, separators=(",", ":"), sort_keys=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
