"""Convert AWS Config notifications to OCSF 1.8 events."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "ingest-aws-config-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-06"
OUTPUT_FORMATS = ("ocsf", "native")

API_CLASS_UID = 6003
API_CLASS_NAME = "API Activity"
API_CATEGORY_UID = 6
API_CATEGORY_NAME = "Application Activity"
COMPLIANCE_CLASS_UID = 2003
COMPLIANCE_CLASS_NAME = "Compliance Finding"
COMPLIANCE_CATEGORY_UID = 2
COMPLIANCE_CATEGORY_NAME = "Findings"

ACTIVITY_CREATE = 1
ACTIVITY_READ = 2
ACTIVITY_UPDATE = 3
ACTIVITY_DELETE = 4
STATUS_SUCCESS = 1
STATUS_FAILURE = 2
SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_HIGH = 4

_CONFIG_MESSAGE_TYPES = {
    "ConfigurationItemChangeNotification",
    "ConfigurationSnapshotDeliveryCompleted",
    "ConfigurationHistoryDeliveryCompleted",
}


def parse_ts_ms(ts: str | int | float | None) -> int:
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        return int(ts if ts > 1_000_000_000_000 else ts * 1000)
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _short(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _maybe_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text[0] not in "[{":
        return value
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return value


def _state_id(item: dict[str, Any]) -> str:
    return str(item.get("configurationStateId") or item.get("configurationStateID") or "")


def _resource_arn(item: dict[str, Any]) -> str:
    return str(item.get("arn") or item.get("ARN") or "")


def _configuration(item: dict[str, Any]) -> dict[str, Any]:
    config = _maybe_json(item.get("configuration") or {})
    return config if isinstance(config, dict) else {}


def _tags(raw_tags: Any) -> dict[str, str]:
    raw_tags = _maybe_json(raw_tags)
    if isinstance(raw_tags, dict):
        return {str(k): str(v) for k, v in raw_tags.items()}
    if isinstance(raw_tags, list):
        out: dict[str, str] = {}
        for tag in raw_tags:
            if isinstance(tag, dict):
                key = tag.get("key", tag.get("Key"))
                value = tag.get("value", tag.get("Value"))
                if key is not None and value is not None:
                    out[str(key)] = str(value)
        return out
    return {}


def _relationships(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for rel in raw:
        if not isinstance(rel, dict):
            continue
        projected = {
            "resource_id": str(rel.get("resourceId") or ""),
            "resource_name": str(rel.get("resourceName") or ""),
            "resource_type": str(rel.get("resourceType") or ""),
            "name": str(rel.get("name") or ""),
        }
        out.append({k: v for k, v in projected.items() if v})
    return out


def _activity_id(message: dict[str, Any], item: dict[str, Any]) -> int:
    diff = message.get("configurationItemDiff")
    if isinstance(diff, dict):
        change_type = str(diff.get("changeType") or "").upper()
        if change_type == "CREATE":
            return ACTIVITY_CREATE
        if change_type == "UPDATE":
            return ACTIVITY_UPDATE
        if change_type == "DELETE":
            return ACTIVITY_DELETE
    status = str(item.get("configurationItemStatus") or "").upper()
    if status in {"RESOURCEDELETED", "RESOURCE_DELETED"}:
        return ACTIVITY_DELETE
    if status in {"RESOURCEDISCOVERED", "RESOURCE_DISCOVERED"}:
        return ACTIVITY_CREATE
    return ACTIVITY_READ


def _activity_name(activity_id: int) -> str:
    return {
        ACTIVITY_CREATE: "Create",
        ACTIVITY_READ: "Read",
        ACTIVITY_UPDATE: "Update",
        ACTIVITY_DELETE: "Delete",
    }.get(activity_id, "Other")


def _metadata(event_uid: str, labels: list[str]) -> dict[str, Any]:
    return {
        "version": OCSF_VERSION,
        "uid": event_uid,
        "product": {
            "name": "cloud-ai-security-skills",
            "vendor_name": VENDOR_NAME,
            "feature": {"name": SKILL_NAME},
        },
        "labels": labels,
    }


def _resource(item: dict[str, Any]) -> dict[str, str]:
    resource = {
        "uid": str(item.get("resourceId") or ""),
        "name": str(item.get("resourceName") or item.get("resourceId") or ""),
        "type": str(item.get("resourceType") or ""),
        "region": str(item.get("awsRegion") or ""),
    }
    arn = _resource_arn(item)
    if arn:
        resource["uid_alt"] = arn
    return {k: v for k, v in resource.items() if v}


def _canonical_config_item(message: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    account_id = str(item.get("awsAccountId") or message.get("awsAccountId") or "")
    region = str(item.get("awsRegion") or message.get("awsRegion") or "")
    resource_type = str(item.get("resourceType") or "")
    resource_id = str(item.get("resourceId") or "")
    capture_time = str(
        item.get("configurationItemCaptureTime")
        or item.get("configurationItemDeliveryTime")
        or message.get("notificationCreationTime")
        or message.get("NotificationCreateTime")
        or ""
    )
    message_type = str(message.get("messageType") or "ConfigurationItem")
    activity_id = _activity_id(message, item)
    diff = message.get("configurationItemDiff")
    config = _configuration(item)
    event_uid = "aws-config-ci-" + _short(
        account_id, region, resource_type, resource_id, _state_id(item), capture_time, message_type
    )
    return {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "aws_config_configuration_item",
        "event_uid": event_uid,
        "message_type": message_type,
        "activity_id": activity_id,
        "activity_name": _activity_name(activity_id),
        "time_ms": parse_ts_ms(capture_time),
        "account_uid": account_id,
        "region": region,
        "resource": _resource(item),
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_status": str(item.get("configurationItemStatus") or ""),
        "configuration_state_id": _state_id(item),
        "configuration": config,
        "tags": _tags(item.get("tags") or config.get("tags")),
        "relationships": _relationships(item.get("relationships")),
        "change_type": str(diff.get("changeType") or "") if isinstance(diff, dict) else "",
        "changed_properties": diff.get("changedProperties", {}) if isinstance(diff, dict) else {},
        "cloud": {"provider": "AWS", "account": {"uid": account_id}, "region": region},
        "raw": {"message": message, "configuration_item": item},
    }


def _qualifier(message: dict[str, Any]) -> dict[str, str]:
    result = message.get("newEvaluationResult") or message.get("evaluationResult") or {}
    result = result if isinstance(result, dict) else {}
    identifier = result.get("evaluationResultIdentifier") or {}
    identifier = identifier if isinstance(identifier, dict) else {}
    qualifier = identifier.get("evaluationResultQualifier") or {}
    qualifier = qualifier if isinstance(qualifier, dict) else {}
    return {
        "configRuleName": str(
            message.get("configRuleName") or qualifier.get("configRuleName") or ""
        ),
        "resourceType": str(message.get("resourceType") or qualifier.get("resourceType") or ""),
        "resourceId": str(message.get("resourceId") or qualifier.get("resourceId") or ""),
        "orderingTimestamp": str(
            identifier.get("orderingTimestamp") or result.get("orderingTimestamp") or ""
        ),
    }


def _compliance_status(raw_status: str) -> tuple[str, int]:
    status = raw_status.upper()
    if status == "COMPLIANT":
        return "PASS", STATUS_SUCCESS
    if status == "NON_COMPLIANT":
        return "FAIL", STATUS_FAILURE
    if status == "NOT_APPLICABLE":
        return "NOT_APPLICABLE", STATUS_SUCCESS
    return status or "UNKNOWN", STATUS_FAILURE


def _canonical_compliance(message: dict[str, Any]) -> dict[str, Any]:
    result = message.get("newEvaluationResult") or message.get("evaluationResult") or {}
    result = result if isinstance(result, dict) else {}
    qualifier = _qualifier(message)
    status, status_id = _compliance_status(
        str(message.get("newComplianceType") or result.get("complianceType") or "")
    )
    recorded_time = str(
        result.get("resultRecordedTime")
        or message.get("notificationCreationTime")
        or qualifier.get("orderingTimestamp")
        or ""
    )
    account_id = str(message.get("awsAccountId") or "")
    region = str(message.get("awsRegion") or "")
    rule_name = qualifier["configRuleName"]
    resource_type = qualifier["resourceType"]
    resource_id = qualifier["resourceId"]
    event_uid = "aws-config-compliance-" + _short(
        account_id, region, rule_name, resource_type, resource_id, status, recorded_time
    )
    return {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "aws_config_compliance_finding",
        "event_uid": event_uid,
        "finding_uid": event_uid,
        "message_type": str(message.get("messageType") or "ComplianceChangeNotification"),
        "time_ms": parse_ts_ms(recorded_time),
        "severity_id": SEVERITY_HIGH
        if status == "FAIL"
        else (SEVERITY_LOW if status == "NOT_APPLICABLE" else SEVERITY_INFORMATIONAL),
        "status": status,
        "status_id": status_id,
        "account_uid": account_id,
        "region": region,
        "rule_name": rule_name,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "title": f"AWS Config rule {rule_name} {status}".strip(),
        "description": str(
            result.get("annotation")
            or f"{resource_type} {resource_id} evaluated as {status} by AWS Config."
        ),
        "result_recorded_time": recorded_time,
        "ordering_time": qualifier["orderingTimestamp"],
        "cloud": {"provider": "AWS", "account": {"uid": account_id}, "region": region},
        "resource": {
            "uid": resource_id,
            "name": resource_id,
            "type": resource_type,
            "region": region,
        },
        "raw": {"message": message},
    }


def _render_config_ocsf(canonical: dict[str, Any]) -> dict[str, Any]:
    activity_id = int(canonical["activity_id"])
    return {
        "activity_id": activity_id,
        "activity_name": canonical["activity_name"],
        "category_uid": API_CATEGORY_UID,
        "category_name": API_CATEGORY_NAME,
        "class_uid": API_CLASS_UID,
        "class_name": API_CLASS_NAME,
        "type_uid": API_CLASS_UID * 100 + activity_id,
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": STATUS_SUCCESS,
        "time": canonical["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["ingestion", "aws", "config", "configuration-item", "api-activity"],
        },
        "api": {
            "operation": canonical["message_type"],
            "service": {"name": "config.amazonaws.com"},
            "request": {"uid": canonical["configuration_state_id"]},
        },
        "cloud": canonical["cloud"],
        "resources": [canonical["resource"]] if canonical["resource"] else [],
        "observables": [
            {"name": "aws.account", "type": "Other", "value": canonical["account_uid"]},
            {"name": "aws.region", "type": "Other", "value": canonical["region"]},
            {
                "name": "aws.config.resource_type",
                "type": "Other",
                "value": canonical["resource_type"],
            },
            {"name": "aws.config.resource_id", "type": "Other", "value": canonical["resource_id"]},
            {"name": "aws.config.change_type", "type": "Other", "value": canonical["change_type"]},
        ],
        "message": f"AWS Config recorded {canonical['resource_type']} {canonical['resource_id']}",
        "unmapped": {
            "aws_config": {
                "message_type": canonical["message_type"],
                "configuration_item_status": canonical["resource_status"],
                "configuration_state_id": canonical["configuration_state_id"],
                "configuration": canonical["configuration"],
                "tags": canonical["tags"],
                "relationships": canonical["relationships"],
                "changed_properties": canonical["changed_properties"],
            }
        },
    }


def _render_compliance_ocsf(canonical: dict[str, Any]) -> dict[str, Any]:
    return {
        "activity_id": ACTIVITY_CREATE,
        "activity_name": "Create",
        "category_uid": COMPLIANCE_CATEGORY_UID,
        "category_name": COMPLIANCE_CATEGORY_NAME,
        "class_uid": COMPLIANCE_CLASS_UID,
        "class_name": COMPLIANCE_CLASS_NAME,
        "type_uid": COMPLIANCE_CLASS_UID * 100 + ACTIVITY_CREATE,
        "severity_id": canonical["severity_id"],
        "status_id": canonical["status_id"],
        "time": canonical["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["ingestion", "aws", "config", "compliance", "compliance-finding"],
        },
        "finding_info": {
            "uid": canonical["finding_uid"],
            "title": canonical["title"],
            "desc": canonical["description"],
            "types": [canonical["rule_name"]],
            "first_seen_time": canonical["time_ms"],
            "last_seen_time": canonical["time_ms"],
        },
        "compliance": {
            "status": canonical["status"],
            "control": canonical["rule_name"],
            "frameworks": ["AWS Config"],
            "requirements": [canonical["rule_name"]],
        },
        "cloud": canonical["cloud"],
        "resources": [canonical["resource"]] if canonical["resource"]["uid"] else [],
        "observables": [
            {"name": "aws.account", "type": "Other", "value": canonical["account_uid"]},
            {"name": "aws.region", "type": "Other", "value": canonical["region"]},
            {"name": "aws.config.rule_name", "type": "Other", "value": canonical["rule_name"]},
            {
                "name": "aws.config.resource_type",
                "type": "Other",
                "value": canonical["resource_type"],
            },
            {"name": "aws.config.resource_id", "type": "Other", "value": canonical["resource_id"]},
            {"name": "aws.config.compliance_status", "type": "Other", "value": canonical["status"]},
        ],
        "evidence": {
            "provider": "AWS",
            "source": "AWS Config",
            "rule_name": canonical["rule_name"],
            "result_recorded_time": canonical["result_recorded_time"],
            "ordering_time": canonical["ordering_time"],
        },
        "unmapped": {
            "aws_config": {
                "message_type": canonical["message_type"],
                "raw_message": canonical["raw"]["message"],
            }
        },
    }


def _native(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["source_skill"] = SKILL_NAME
    native["output_format"] = "native"
    return native


def convert_message(message: dict[str, Any], output_format: str = "ocsf") -> list[dict[str, Any]]:
    message_type = str(message.get("messageType") or "")
    if (
        message_type in _CONFIG_MESSAGE_TYPES
        or "configurationItem" in message
        or "configurationItems" in message
    ):
        items = message.get("configurationItems", message.get("configurationItem"))
        if isinstance(items, dict):
            items = [items]
        if isinstance(items, list):
            converted: list[dict[str, Any]] = []
            for item in items:
                if isinstance(item, dict):
                    canonical = _canonical_config_item(message, item)
                    converted.append(
                        _native(canonical)
                        if output_format == "native"
                        else _render_config_ocsf(canonical)
                    )
            return converted
    if message_type == "ComplianceChangeNotification" or "newEvaluationResult" in message:
        canonical = _canonical_compliance(message)
        return [
            _native(canonical) if output_format == "native" else _render_compliance_ocsf(canonical)
        ]
    if {"resourceType", "resourceId", "configurationItemCaptureTime"} <= set(message):
        canonical = _canonical_config_item({"messageType": "ConfigurationItem"}, message)
        return [_native(canonical) if output_format == "native" else _render_config_ocsf(canonical)]
    return []


def _unwrap(obj: Any) -> Iterable[dict[str, Any]]:
    obj = _maybe_json(obj)
    if isinstance(obj, list):
        for item in obj:
            yield from _unwrap(item)
        return
    if not isinstance(obj, dict):
        return
    if "Message" in obj and ("TopicArn" in obj or obj.get("Type") == "Notification"):
        yield from _unwrap(obj["Message"])
        return
    detail = obj.get("detail")
    if isinstance(detail, dict) and (
        "configurationItem" in detail or "newEvaluationResult" in detail
    ):
        yield detail
        return
    if "Records" in obj and isinstance(obj["Records"], list):
        for record in obj["Records"]:
            yield from _unwrap(record)
        return
    yield obj


def iter_raw_messages(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    lines = list(stream)
    if not lines:
        return
    full = "\n".join(line.rstrip("\n") for line in lines).strip()
    if not full:
        return
    try:
        whole = json.loads(full)
    except json.JSONDecodeError:
        whole = None
    if whole is not None:
        yield from _unwrap(whole)
        return
    for lineno, raw_line in enumerate(lines, start=1):
        try:
            yield from _unwrap(json.loads(raw_line))
        except json.JSONDecodeError as exc:
            print(
                f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {exc}", file=sys.stderr
            )


def ingest(stream: Iterable[str], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format: {output_format}")
    for message in iter_raw_messages(stream):
        try:
            yield from convert_message(message, output_format=output_format)
        except Exception as exc:
            marker = message.get("messageType") or message.get("resourceId") or "?"
            print(
                f"[{SKILL_NAME}] skipping message {marker}: convert error: {exc}", file=sys.stderr
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert AWS Config notifications to OCSF 1.8 JSONL."
    )
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default="ocsf")
    args = parser.parse_args(argv)
    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")
    try:
        for event in ingest(in_stream, output_format=args.output_format):
            out_stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
