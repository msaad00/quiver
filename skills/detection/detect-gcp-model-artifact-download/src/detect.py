"""Detect suspicious GCS model-artifact downloads via GCP Audit Logs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-gcp-model-artifact-download"
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

ACCEPTED_PRODUCERS = frozenset({"ingest-gcp-audit-ocsf"})
GCS_SERVICE = "storage.googleapis.com"
GET_OBJECT_OPERATION = "storage.objects.get"
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
    "vertex",
    "aiplatform",
    "ml",
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


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _actor_type(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("type") or "")


def _target_project(event: dict[str, Any]) -> str:
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


def _resource_name(event: dict[str, Any]) -> str:
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        name = str(resource.get("name") or "")
        if name:
            return name
    return ""


def _bucket_and_object(resource_name: str) -> tuple[str, str]:
    cleaned = unquote(resource_name.strip())
    marker = "/buckets/"
    objects_marker = "/objects/"
    if marker not in cleaned or objects_marker not in cleaned:
        return "", ""
    after_bucket = cleaned.split(marker, 1)[1]
    bucket_name, sep, object_part = after_bucket.partition(objects_marker)
    if not sep:
        return "", ""
    return bucket_name.strip("/"), object_part.lstrip("/")


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
    actor_name: str,
    bucket_name: str,
    object_key: str,
    time_ms: int,
) -> str:
    material = "|".join([SKILL_NAME, event_uid, actor_name, bucket_name, object_key, str(time_ms)])
    return f"gmad-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


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
        actor_name=_actor_name(event),
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
        "rule": "gcp-model-artifact-download",
        "api_operation": GET_OBJECT_OPERATION,
        "bucket_name": bucket_name,
        "object_key": object_key,
        "artifact_match": artifact_match,
        "actor_name": _actor_name(event),
        "actor_type": _actor_type(event),
        "target_project_uid": _target_project(event),
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
        f"`gs://{native['bucket_name']}/{native['object_key']}` via `storage.objects.get`. "
        "The accessed object path matched model-weight or checkpoint artifact heuristics, "
        "which can indicate model theft, staging, or unauthorized artifact collection."
    )
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
            "labels": ["detection-engineering", "gcp", "gcs", "model-artifact-download", "ai"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": "GCP model artifact downloaded from Cloud Storage",
            "desc": description,
            "types": ["gcp-model-artifact-download", "ml-artifact-collection"],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic": {"uid": ATTACK_TACTIC_UID, "name": ATTACK_TACTIC_NAME},
                    "technique": {"uid": ATTACK_TECHNIQUE_UID, "name": ATTACK_TECHNIQUE_NAME},
                },
                {
                    "version": ATLAS_VERSION,
                    "tactic": {"uid": ATLAS_TACTIC_UID, "name": ATLAS_TACTIC_NAME},
                    "technique": {"uid": ATLAS_TECHNIQUE_UID, "name": ATLAS_TECHNIQUE_NAME},
                },
            ],
        },
        "cloud": {
            "provider": "GCP",
            "account": {"uid": native["target_project_uid"]},
            "region": native["region"],
        },
        "src_endpoint": {"ip": native["src_ip"]},
        "observables": [
            {"name": "bucket.name", "type": "Other", "value": native["bucket_name"]},
            {"name": "object.key", "type": "Other", "value": native["object_key"]},
            {"name": "artifact.match", "type": "Other", "value": native["artifact_match"]},
        ],
    }


def detect(events: Iterable[dict[str, Any]], *, output_format: str = "ocsf") -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    for event in events:
        if _producer(event) not in ACCEPTED_PRODUCERS:
            continue
        if not _is_success(event):
            continue
        if _api_service(event) != GCS_SERVICE or _api_operation(event) != GET_OBJECT_OPERATION:
            continue

        resource_name = _resource_name(event)
        bucket_name, object_key = _bucket_and_object(resource_name)
        if not bucket_name or not object_key:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_object_context",
                message="skipping event with missing bucket or object context in GCS resourceName",
                resource_name=resource_name,
            )
            continue

        matched, artifact_match = _artifact_match(object_key)
        if not matched:
            continue

        native = _build_native_finding(
            event=event,
            bucket_name=bucket_name,
            object_key=object_key,
            artifact_match=artifact_match,
        )
        yield native if output_format == "native" else _to_ocsf(native)


def _load_jsonl(stream: Iterable[str]) -> Iterator[dict[str, Any]]:
    for line in stream:
        line = line.strip()
        if not line:
            continue
        payload = json.loads(line)
        if isinstance(payload, dict):
            yield payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect GCP model artifact downloads from GCS audit logs.")
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument("--output-format", choices=sorted(OUTPUT_FORMATS), default="ocsf")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")
    try:
        for finding in detect(_load_jsonl(in_stream), output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
