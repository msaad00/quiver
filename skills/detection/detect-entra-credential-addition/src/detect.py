"""Detect Entra application and service-principal credential additions.

Reads OCSF 1.8 API Activity (class 6003) events or the native API activity
projection produced by ingest-entra-directory-audit-ocsf and emits OCSF 1.8
Detection Findings (class 2004) by default when a successful Entra credential
addition or federated identity credential creation is observed.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "detect-entra-credential-addition"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402

OUTPUT_FORMATS = ("ocsf", "native")

INGEST_SKILL = "ingest-entra-directory-audit-ocsf"
API_ACTIVITY_CLASS_UID = 6003

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

CREDENTIAL_ADD_OPERATIONS = {
    "ADD SERVICE PRINCIPAL CREDENTIALS",
    "UPDATE APPLICATION - CERTIFICATES AND SECRETS MANAGEMENT",
}
FEDERATED_CREDENTIAL_OPERATIONS = {
    "CREATE FEDERATED IDENTITY CREDENTIAL",
    "ADD FEDERATED IDENTITY CREDENTIAL",
}


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_token(value: str) -> str:
    return " ".join((value or "").upper().replace("_", " ").split())


def _event_uid(event: dict[str, Any]) -> str:
    return str(event.get("event_uid") or (event.get("metadata") or {}).get("uid") or "").strip()


def _event_time(event: dict[str, Any]) -> int:
    return _safe_int(event.get("time_ms") or event.get("time"))


def _source_skill(event: dict[str, Any]) -> str:
    if event.get("source_skill"):
        return str(event["source_skill"])
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _resource_list(event: dict[str, Any]) -> list[dict[str, Any]]:
    resources = event.get("resources") or []
    return [item for item in resources if isinstance(item, dict)]


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
            return None
        return {
            "source_format": "ocsf",
            "source_skill": _source_skill(event),
            "event_uid": _event_uid(event),
            "time_ms": _event_time(event),
            "provider": str(((event.get("cloud") or {}).get("provider")) or ""),
            "status_id": _safe_int(event.get("status_id")),
            "operation": str(((event.get("api") or {}).get("operation")) or ""),
            "service_name": str((((event.get("api") or {}).get("service")) or {}).get("name") or ""),
            "correlation_uid": str((((event.get("api") or {}).get("request")) or {}).get("uid") or ""),
            "actor": ((event.get("actor") or {}).get("user")) or {},
            "src_endpoint": event.get("src_endpoint") or {},
            "resources": _resource_list(event),
            "unmapped": ((event.get("unmapped") or {}).get("entra")) or {},
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"canonical", "native"}:
        return None
    record_type = str(event.get("record_type") or "").strip().lower()
    if record_type and record_type != "api_activity":
        return None
    return {
        "source_format": schema_mode or "native",
        "source_skill": str(event.get("source_skill") or ""),
        "event_uid": _event_uid(event),
        "time_ms": _event_time(event),
        "provider": str(event.get("provider") or event.get("cloud_provider") or ""),
        "status_id": _safe_int(event.get("status_id")),
        "operation": str(event.get("operation") or event.get("api_operation") or ""),
        "service_name": str(event.get("service_name") or event.get("api_service") or ""),
        "correlation_uid": str(event.get("correlation_uid") or ""),
        "actor": ((event.get("actor") or {}).get("user")) or {},
        "src_endpoint": event.get("src_endpoint") or {},
        "resources": _resource_list(event),
        "unmapped": ((event.get("unmapped") or {}).get("entra")) or {},
    }


def _classify_event(event: dict[str, Any]) -> str | None:
    normalized = _normalize_event(event)
    if normalized is None:
        return None
    if normalized["source_skill"] != INGEST_SKILL:
        return None
    if normalized["status_id"] != STATUS_SUCCESS:
        return None
    operation = _normalize_token(normalized["operation"])
    if operation in CREDENTIAL_ADD_OPERATIONS:
        return "credential"
    if operation in FEDERATED_CREDENTIAL_OPERATIONS:
        return "federated"
    return None


def _actor_name(normalized: dict[str, Any]) -> str:
    actor = normalized.get("actor") or {}
    return str(actor.get("name") or actor.get("email_addr") or actor.get("uid") or "").strip()


def _target(normalized: dict[str, Any]) -> dict[str, str]:
    for resource in normalized.get("resources") or []:
        uid = str(resource.get("uid") or "").strip()
        name = str(resource.get("name") or uid or "").strip()
        resource_type = str(resource.get("type") or "resource").strip()
        if name:
            return {"uid": uid, "name": name, "type": resource_type}
    return {"uid": "", "name": "", "type": ""}


def _finding_uid(kind: str, event_uid: str, target_uid: str) -> str:
    material = f"{kind}|{event_uid}|{target_uid}"
    return f"det-entra-cred-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(normalized: dict[str, Any], kind: str) -> dict[str, Any]:
    target = _target(normalized)
    actor_name = _actor_name(normalized)
    event_uid = normalized["event_uid"]
    finding_uid = _finding_uid(kind, event_uid, target["uid"] or target["name"])
    operation = normalized["operation"]
    if kind == "federated":
        title = "Microsoft Entra created a federated identity credential"
        description = (
            f"Principal '{actor_name or 'unknown'}' successfully executed '{operation}'"
            f" against {target['type'] or 'resource'} '{target['name'] or target['uid'] or 'unknown'}'. "
            "This creates an external workload-identity trust path and maps to MITRE T1098.001 "
            "Additional Cloud Credentials."
        )
        finding_type = "entra-federated-credential-addition"
    else:
        title = "Microsoft Entra added credentials to an application or service principal"
        description = (
            f"Principal '{actor_name or 'unknown'}' successfully executed '{operation}'"
            f" against {target['type'] or 'resource'} '{target['name'] or target['uid'] or 'unknown'}'. "
            "This creates or rotates application or service-principal credential material and maps to "
            "MITRE T1098.001 Additional Cloud Credentials."
        )
        finding_type = "entra-credential-addition"

    observables = [
        {"name": "cloud.provider", "type": "Other", "value": normalized["provider"] or "Azure"},
        {"name": "actor.name", "type": "Other", "value": actor_name or "unknown"},
        {"name": "api.operation", "type": "Other", "value": operation},
        {"name": "rule", "type": "Other", "value": finding_type},
    ]
    if normalized.get("correlation_uid"):
        observables.append(
            {"name": "api.request.uid", "type": "Other", "value": normalized["correlation_uid"]}
        )
    if target["name"]:
        observables.append({"name": "target.name", "type": "Other", "value": target["name"]})
    if target["uid"]:
        observables.append({"name": "target.uid", "type": "Other", "value": target["uid"]})
    if target["type"]:
        observables.append({"name": "target.type", "type": "Other", "value": target["type"]})
    src_ip = str((normalized.get("src_endpoint") or {}).get("ip") or "")
    if src_ip:
        observables.append({"name": "src.ip", "type": "IP Address", "value": src_ip})

    attack = {
        "version": MITRE_VERSION,
        "tactic_uid": TACTIC_UID,
        "tactic_name": TACTIC_NAME,
        "technique_uid": TECHNIQUE_UID,
        "technique_name": TECHNIQUE_NAME,
        "sub_technique_uid": SUBTECHNIQUE_UID,
        "sub_technique_name": SUBTECHNIQUE_NAME,
    }

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": normalized["provider"] or "Azure",
        "time_ms": normalized["time_ms"] or _now_ms(),
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": title,
        "description": description,
        "finding_types": [finding_type],
        "first_seen_time_ms": normalized["time_ms"],
        "last_seen_time_ms": normalized["time_ms"],
        "mitre_attacks": [attack],
        "actor_name": actor_name,
        "target_name": target["name"],
        "target_uid": target["uid"],
        "observables": observables,
        "evidence": {
            "raw_event_uids": [event_uid],
            "correlation_uid": normalized["correlation_uid"],
            "source_service": normalized["service_name"],
            "additional_details": normalized.get("unmapped", {}).get("additional_details", []),
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
            "labels": ["identity", "entra", "credentials", "detection"],
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "first_seen_time": native_finding["first_seen_time_ms"],
            "last_seen_time": native_finding["last_seen_time_ms"],
            "attacks": [
                {
                    "version": attack["version"],
                    "tactic": {"name": attack["tactic_name"], "uid": attack["tactic_uid"]},
                    "technique": {"name": attack["technique_name"], "uid": attack["technique_uid"]},
                    "sub_technique": {
                        "name": attack["sub_technique_name"],
                        "uid": attack["sub_technique_uid"],
                    },
                }
            ],
        },
        "observables": native_finding["observables"],
        "evidence": native_finding["evidence"],
    }


def coverage_metadata() -> dict[str, Any]:
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14"),
        "providers": ("azure", "entra", "microsoft-graph"),
        "asset_classes": ("identities", "applications", "service-principals", "federated-credentials"),
        "attack_coverage": {
            "azure": {
                "principal_types": ["applications", "service-principals"],
                "anchor_operations": sorted(CREDENTIAL_ADD_OPERATIONS | FEDERATED_CREDENTIAL_OPERATIONS),
                "techniques": [SUBTECHNIQUE_UID],
            }
        },
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format: {output_format}")

    seen: set[str] = set()
    normalized_events: list[dict[str, Any]] = []
    for event in events:
        kind = _classify_event(event)
        if kind is None:
            continue
        normalized = _normalize_event(event)
        if normalized is None:
            continue
        uid = normalized["event_uid"]
        if uid and uid in seen:
            continue
        if uid:
            seen.add(uid)
        normalized["kind"] = kind
        normalized_events.append(normalized)

    normalized_events.sort(key=lambda item: (item["time_ms"], item["event_uid"]))
    for normalized in normalized_events:
        native_finding = _build_native_finding(normalized, normalized["kind"])
        if output_format == "native":
            yield native_finding
        else:
            yield _render_ocsf_finding(native_finding)


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {exc}", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect Entra application and service-principal credential additions.")
    parser.add_argument("input", nargs="?", help="Input JSONL. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Detection Finding JSONL output. Defaults to stdout.")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default="ocsf", help="Output format.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        events = list(load_jsonl(in_stream))
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
