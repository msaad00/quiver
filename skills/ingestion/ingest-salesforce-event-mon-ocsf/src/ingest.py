"""Convert Salesforce Event Monitoring exports into OCSF Application Activity.

Input: Salesforce Event Monitoring JSON/JSONL or Event Log File CSV exports.
Output: JSONL of OCSF 1.8 Application Activity (6002) records, or native JSONL.
"""

from __future__ import annotations

import argparse
import csv
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
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "ingest-salesforce-event-mon-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-06"
OUTPUT_FORMATS = ("ocsf", "native")

CLASS_UID = 6002
CLASS_NAME = "Application Activity"
CATEGORY_UID = 6
CATEGORY_NAME = "Application Activity"
ACTIVITY_CREATE = 1
ACTIVITY_READ = 2
ACTIVITY_UPDATE = 3
ACTIVITY_DELETE = 4
ACTIVITY_OTHER = 99

STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3

WRAPPER_KEYS = ("records", "events", "items", "data", "EventLogFile", "eventLogFiles")


def _norm_key(key: str) -> str:
    return key.strip().lower().replace("-", "_").replace(" ", "_")


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    return {_norm_key(str(key)): value for key, value in record.items()}


def _first(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(_norm_key(key))
        if value not in (None, ""):
            return value
    return None


def parse_ts_ms(value: Any) -> int:
    if value in (None, ""):
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    if isinstance(value, (int, float)):
        raw = int(value)
        return raw if raw > 10_000_000_000 else raw * 1000
    text = str(value).strip()
    if text.isdigit():
        raw = int(text)
        return raw if raw > 10_000_000_000 else raw * 1000
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            cleaned = text.replace("Z", "+0000")
            dt = datetime.strptime(cleaned, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            pass
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _event_type(record: dict[str, Any]) -> str:
    return str(_first(record, "event_type", "eventtype", "type", "log_type", "event_name") or "").strip()


def _event_family(record: dict[str, Any]) -> str:
    event_type = _event_type(record).lower().replace("_", "").replace("-", "")
    operation = str(_first(record, "operation", "method", "action", "uri") or "").lower()
    joined = f"{event_type} {operation}"
    if any(term in joined for term in ("logout", "logoff", "sessionend")):
        return "logout"
    if "login" in joined and "logout" not in joined:
        return "login"
    if any(term in joined for term in ("reportexport", "report_export", "export", "bulkapi", "bulkapi2", "dataloader")):
        return "export"
    if any(term in joined for term in ("api", "rest", "soap", "query", "apex")):
        return "api"
    if any(term in joined for term in ("reportrun", "report", "listview")):
        return "report"
    return "application"


def _activity_id(family: str, record: dict[str, Any]) -> int:
    operation = str(_first(record, "operation", "method", "action") or "").lower()
    if family in {"login", "api", "report", "export"}:
        return ACTIVITY_READ
    if family == "logout":
        return ACTIVITY_OTHER
    if any(term in operation for term in ("delete", "remove")):
        return ACTIVITY_DELETE
    if any(term in operation for term in ("insert", "create")):
        return ACTIVITY_CREATE
    if any(term in operation for term in ("update", "patch", "upsert")):
        return ACTIVITY_UPDATE
    return ACTIVITY_OTHER


def _status_id(record: dict[str, Any]) -> int:
    text = str(_first(record, "status", "login_status", "result", "outcome") or "").lower()
    if not text:
        return STATUS_SUCCESS
    if any(term in text for term in ("fail", "error", "denied", "invalid")):
        return STATUS_FAILURE
    if any(term in text for term in ("success", "succeeded", "ok")):
        return STATUS_SUCCESS
    return STATUS_UNKNOWN


def _severity_id(family: str, status_id: int) -> int:
    if status_id == STATUS_FAILURE:
        return SEVERITY_LOW
    if family == "export":
        return SEVERITY_MEDIUM
    return SEVERITY_INFORMATIONAL


def _status_name(status_id: int) -> str:
    return {STATUS_SUCCESS: "success", STATUS_FAILURE: "failure", STATUS_UNKNOWN: "unknown"}.get(status_id, "unknown")


def _severity_name(severity_id: int) -> str:
    return {
        SEVERITY_INFORMATIONAL: "informational",
        SEVERITY_LOW: "low",
        SEVERITY_MEDIUM: "medium",
    }.get(severity_id, "unknown")


def _int_value(record: dict[str, Any], *keys: str) -> int:
    raw = _first(record, *keys)
    try:
        return int(float(str(raw).replace(",", "")))
    except (TypeError, ValueError):
        return 0


def _actor(record: dict[str, Any]) -> dict[str, Any]:
    uid = str(_first(record, "user_id", "userid", "user", "username") or "").strip()
    name = str(_first(record, "user_name", "username", "user_email", "user") or uid).strip()
    user: dict[str, Any] = {}
    if uid:
        user["uid"] = uid
    if name:
        user["name"] = name
        if "@" in name:
            user["email_addr"] = name
    return {"user": user} if user else {}


def _src_endpoint(record: dict[str, Any]) -> dict[str, Any]:
    endpoint: dict[str, Any] = {}
    ip = str(_first(record, "client_ip", "source_ip", "ip_address", "ip") or "").strip()
    if ip:
        endpoint["ip"] = ip
    user_agent = str(_first(record, "user_agent", "browser", "client_version") or "").strip()
    if user_agent:
        endpoint["svc_name"] = user_agent
    return endpoint


def _session(record: dict[str, Any]) -> dict[str, Any]:
    uid = str(_first(record, "session_key", "session_id", "session", "login_key") or "").strip()
    return {"uid": uid} if uid else {}


def _resources(record: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for keys, resource_type in (
        (("report_id", "reportid"), "salesforce_report"),
        (("report_name", "reportname"), "salesforce_report"),
        (("entity_name", "entity", "object", "object_name"), "salesforce_object"),
        (("job_id", "jobid", "request_id", "requestid"), "salesforce_request"),
    ):
        value = str(_first(record, *keys) or "").strip()
        if value:
            resource: dict[str, Any] = {"type": resource_type, "name": value}
            if value.startswith(("00O", "750", "751", "500")):
                resource["uid"] = value
            resources.append(resource)
    return resources


def _api(record: dict[str, Any]) -> dict[str, Any]:
    operation = str(_first(record, "operation", "method", "action", "event_type") or _event_type(record) or "unknown").strip()
    return {"operation": operation, "service": {"name": "salesforce.event_monitoring"}}


def _http_request(record: dict[str, Any]) -> dict[str, Any]:
    request: dict[str, Any] = {}
    uri = str(_first(record, "uri", "request_uri", "url") or "").strip()
    if uri:
        request["url"] = {"url_string": uri}
    method = str(_first(record, "method", "http_method") or "").strip()
    if method:
        request["http_method"] = method
    user_agent = str(_first(record, "user_agent", "browser") or "").strip()
    if user_agent:
        request["user_agent"] = user_agent
    return request


def _salesforce_block(record: dict[str, Any], family: str) -> dict[str, Any]:
    return {
        "event_type": _event_type(record),
        "event_family": family,
        "org_id": str(_first(record, "organization_id", "org_id") or "").strip(),
        "client_name": str(_first(record, "client_name", "client", "connected_app_name", "application") or "").strip(),
        "api_type": str(_first(record, "api_type", "api_version", "api") or "").strip(),
        "operation": str(_first(record, "operation", "method", "action") or "").strip(),
        "rows_processed": _int_value(record, "rows_processed", "rows_returned", "records_processed", "records_returned", "record_count"),
        "bytes": _int_value(record, "bytes", "response_size", "request_size", "db_total_time"),
        "session_key": str(_first(record, "session_key", "session_id", "session") or "").strip(),
        "request_id": str(_first(record, "request_id", "requestid", "event_identifier", "event_id") or "").strip(),
        "raw": record,
    }


def _event_uid(record: dict[str, Any], family: str) -> str:
    material = {
        "event_type": _event_type(record),
        "family": family,
        "time": str(_first(record, "timestamp", "time", "date", "event_date", "login_time", "logout_time") or ""),
        "user": str(_first(record, "user_id", "username", "user_name") or ""),
        "request": str(_first(record, "request_id", "requestid", "event_identifier", "event_id") or ""),
        "session": str(_first(record, "session_key", "session_id", "session") or ""),
    }
    if not any(material.values()):
        material["raw"] = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def validate_record(record: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(record, dict):
        return False, "not a dict"
    normalized = _normalize_record(record)
    if not (_event_type(normalized) or _first(normalized, "user_id", "username", "operation", "request_id")):
        return False, "missing event type and user/request identifiers"
    return True, ""


def _build_canonical_event(raw: dict[str, Any]) -> dict[str, Any]:
    record = _normalize_record(raw)
    family = _event_family(record)
    status_id = _status_id(record)
    severity_id = _severity_id(family, status_id)
    time_ms = parse_ts_ms(_first(record, "timestamp", "time", "date", "event_date", "login_time", "logout_time"))
    activity_id = _activity_id(family, record)
    event_uid = _event_uid(record, family)
    out: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "application_activity",
        "source_skill": SKILL_NAME,
        "event_uid": event_uid,
        "provider": "Salesforce",
        "time_ms": time_ms,
        "activity_id": activity_id,
        "activity_name": family,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "severity_id": severity_id,
        "severity": _severity_name(severity_id),
        "status_id": status_id,
        "status": _status_name(status_id),
        "api": _api(record),
        "salesforce": _salesforce_block(record, family),
        "message": f"Salesforce {family} event: {_event_type(record) or 'unknown'}",
    }
    for key, value in (
        ("actor", _actor(record)),
        ("src_endpoint", _src_endpoint(record)),
        ("session", _session(record)),
        ("resources", _resources(record)),
        ("http_request", _http_request(record)),
    ):
        if value:
            out[key] = value
    return out


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "activity_id": canonical["activity_id"],
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + int(canonical["activity_id"]),
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
            "labels": ["salesforce", "event-monitoring", "ingest"],
        },
        "api": canonical["api"],
        "unmapped": {"salesforce": canonical["salesforce"]},
    }
    for field in ("actor", "src_endpoint", "session", "resources", "http_request", "message"):
        if canonical.get(field):
            out[field] = canonical[field]
    return out


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["output_format"] = "native"
    return native


def convert_record(record: dict[str, Any], output_format: str = "ocsf") -> dict[str, Any]:
    canonical = _build_canonical_event(record)
    return _render_native_event(canonical) if output_format == "native" else _render_ocsf_event(canonical)


def _yield_wrapped(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, list):
        for item in value:
            yield from _yield_wrapped(item)
        return
    if not isinstance(value, dict):
        return
    for key in WRAPPER_KEYS:
        wrapped = value.get(key)
        if isinstance(wrapped, (list, dict)):
            yield from _yield_wrapped(wrapped)
            return
    yield value


def iter_raw_records(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    buf = list(stream)
    if not buf:
        return
    full = "\n".join(line.rstrip("\n") for line in buf).strip()
    if not full:
        return
    try:
        whole = json.loads(full)
    except json.JSONDecodeError:
        whole = None
    if whole is not None:
        yield from _yield_wrapped(whole)
        return

    nonempty = [line for line in buf if line.strip()]
    if nonempty and "," in nonempty[0]:
        try:
            reader = csv.DictReader(nonempty)
            if reader.fieldnames:
                for row in reader:
                    yield {key: value for key, value in row.items() if key}
                return
        except csv.Error as exc:
            emit_stderr_event(SKILL_NAME, level="warning", event="csv_parse_failed", message=str(exc))

    for lineno, raw_line in enumerate(buf, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            emit_stderr_event(SKILL_NAME, level="warning", event="json_parse_failed", message=str(exc), line=lineno)
            continue
        yield from _yield_wrapped(obj)


def ingest(stream: Iterable[str], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    for record in iter_raw_records(stream):
        ok, reason = validate_record(record)
        if not ok:
            emit_stderr_event(SKILL_NAME, level="warning", event="invalid_record", message=f"skipping record: {reason}", reason=reason)
            continue
        try:
            yield convert_record(record, output_format=output_format)
        except Exception as exc:
            emit_stderr_event(SKILL_NAME, level="warning", event="convert_error", message=f"skipping record: {exc}", error=str(exc))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert Salesforce Event Monitoring exports to OCSF Application Activity.")
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL/CSV file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default="ocsf")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")
    try:
        for event in ingest(in_stream, output_format=args.output_format):
            out_stream.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
