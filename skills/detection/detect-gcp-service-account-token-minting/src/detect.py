"""Detect GCP service-account token minting via Cloud Audit Logs."""

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

SKILL_NAME = "detect-gcp-service-account-token-minting"
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

ACCEPTED_PRODUCERS = frozenset({"ingest-gcp-audit-ocsf"})
IAM_CREDENTIALS_SERVICE = "iamcredentials.googleapis.com"
TOKEN_MINT_OPERATIONS = frozenset(
    {
        "google.iam.credentials.v1.GenerateAccessToken",
        "google.iam.credentials.v1.GenerateIdToken",
    }
)
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


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _account_uid(event: dict[str, Any]) -> str:
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


def _target_service_account(event: dict[str, Any]) -> str:
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        name = str(resource.get("name") or "")
        if not name:
            continue
        marker = "serviceAccounts/"
        if marker in name:
            return name.split(marker, 1)[1].strip("/")
        if name.endswith(".iam.gserviceaccount.com"):
            return name
    return ""


def _token_type(operation: str) -> str:
    if operation.endswith("GenerateAccessToken"):
        return "access_token"
    if operation.endswith("GenerateIdToken"):
        return "id_token"
    return "unknown"


def _finding_uid(event_uid: str, target_sa: str, actor_name: str, operation: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{target_sa}|{actor_name}|{operation}|{time_ms}"
    return f"gsatm-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(*, event: dict[str, Any], target_service_account: str) -> dict[str, Any]:
    time_ms = _time_ms(event)
    operation = _api_operation(event)
    actor_name = _actor_name(event)
    finding_uid = _finding_uid(_event_uid(event), target_service_account, actor_name, operation, time_ms)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": "gcp-service-account-token-minting",
        "api_operation": operation,
        "token_type": _token_type(operation),
        "target_service_account": target_service_account,
        "actor_name": actor_name,
        "project_uid": _account_uid(event),
        "region": _region(event),
        "src_ip": _src_ip(event),
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    description = (
        f"Actor `{native['actor_name'] or 'unknown'}` successfully called "
        f"`{native['api_operation']}` for service account "
        f"`{native['target_service_account']}` in project `{native['project_uid']}`. "
        f"Token type: {native['token_type']}. Source IP: {native['src_ip'] or '<unknown>'}. "
        "This can create short-lived credential material for service-account impersonation."
    )
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "GCP"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "api.operation", "type": "Other", "value": native["api_operation"]},
        {"name": "token.type", "type": "Other", "value": native["token_type"]},
        {"name": "rule", "type": "Other", "value": native["rule"]},
        {"name": "target.type", "type": "Other", "value": "ServiceAccount"},
        {"name": "target.name", "type": "Other", "value": native["target_service_account"]},
        {"name": "project.uid", "type": "Other", "value": native["project_uid"]},
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
            "labels": ["gcp", "iam", "service-account", "iam-credentials", "persistence"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": "GCP service account token minted",
            "desc": description,
            "types": ["gcp-service-account-token-minting"],
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
            "token_type": native["token_type"],
            "target_service_account": native["target_service_account"],
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
                message=f"skipping event from non-gcp-audit producer `{producer}`",
            )
            continue
        operation = _api_operation(event)
        if _api_service(event) != IAM_CREDENTIALS_SERVICE or operation not in TOKEN_MINT_OPERATIONS:
            continue
        if not _is_success(event):
            continue
        target_service_account = _target_service_account(event)
        if not target_service_account:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_target_service_account",
                message="skipping IAM Credentials event with no target service account",
            )
            continue
        native = _build_native_finding(event=event, target_service_account=target_service_account)
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
    parser = argparse.ArgumentParser(description="Detect GCP service-account token minting from audit logs.")
    parser.add_argument("input", nargs="?", help="Optional JSONL input file. Defaults to stdin.")
    parser.add_argument(
        "--output-format",
        default="ocsf",
        choices=sorted(OUTPUT_FORMATS),
        help="Emit OCSF detection findings or the native repo shape.",
    )
    args = parser.parse_args(argv)

    for finding in detect(_iter_jsonl(args.input), output_format=args.output_format):
        sys.stdout.write(json.dumps(finding, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

