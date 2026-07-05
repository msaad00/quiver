"""Convert SAP Security Audit Log exports into OCSF Application Activity.

Input: SAP Security Audit Log (SAL) JSON/JSONL/CSV or delimited text exports.
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

SKILL_NAME = "ingest-sap-audit-log-ocsf"
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

WRAPPER_KEYS = ("records", "events", "items", "data", "audit_log", "auditLogs", "SecurityAuditLog")
SENSITIVE_TX_CODES = {
    "PFCG",
    "RZ10",
    "RZ11",
    "SCC4",
    "SE11",
    "SE16",
    "SE16N",
    "SE38",
    "SE80",
    "SM19",
    "SM20",
    "SM30",
    "SM59",
    "STMS",
    "SU01",
    "SU10",
}
PRIVILEGED_PROFILES = {"SAP_ALL", "SAP_NEW"}


def _norm_key(key: str) -> str:
    return key.strip().lower().replace("-", "_").replace(" ", "_").replace("/", "_")


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    return {_norm_key(str(key)): value for key, value in record.items()}


def _first(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(_norm_key(key))
        if value not in (None, ""):
            return value
    return None


def _text(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return str(value).strip()


def _tokens(value: Any) -> list[str]:
    text = _text(value).replace(";", ",")
    return [item.strip().upper() for item in text.split(",") if item.strip()]


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
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y%m%d %H%M%S",
        "%Y%m%d%H%M%S",
        "%d.%m.%Y %H:%M:%S",
    ):
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


def _timestamp_value(record: dict[str, Any]) -> Any:
    direct = _first(record, "timestamp", "time", "event_time", "date_time", "datetime")
    if direct:
        return direct
    date = _first(record, "date", "datum")
    time = _first(record, "time_of_day", "uzeit", "time")
    return f"{date} {time}" if date and time else date or time


def _message(record: dict[str, Any]) -> str:
    return _text(
        _first(
            record,
            "message",
            "message_text",
            "text",
            "audit_message",
            "event_text",
            "long_text",
            "description",
        )
    )


def _event_code(record: dict[str, Any]) -> str:
    return _text(
        _first(record, "message_id", "msgid", "event_id", "event_code", "audit_event", "event")
    ).upper()


def _transaction_code(record: dict[str, Any]) -> str:
    value = _first(record, "transaction", "transaction_code", "tcode", "tcod", "sap_transaction")
    if value:
        return _text(value).upper()
    message = _message(record).upper()
    for token in SENSITIVE_TX_CODES:
        if token in message:
            return token
    return ""


def _event_family(record: dict[str, Any]) -> str:
    code = _event_code(record).lower()
    message = _message(record).lower()
    tx_code = _transaction_code(record)
    joined = f"{code} {message}"
    if any(term in joined for term in ("logoff", "logout", "session ended")):
        return "logout"
    if any(term in joined for term in ("logon", "login", "user authenticated", "authentication")):
        return "login"
    if tx_code:
        if any(
            term in joined
            for term in ("change", "changed", "update", "delete", "maintain", "import", "transport")
        ):
            return "change"
        return "transaction"
    if any(
        term in joined
        for term in ("sap_all", "sap_new", "profile assigned", "authorization assigned")
    ):
        return "privileged_access"
    if any(
        term in joined
        for term in ("change", "changed", "update", "delete", "maintain", "debug", "table")
    ):
        return "change"
    if any(term in joined for term in ("rfc", "function module", "remote function")):
        return "rfc"
    return "application"


def _activity_id(family: str, record: dict[str, Any]) -> int:
    message = _message(record).lower()
    if family in {"login", "transaction", "rfc"}:
        return ACTIVITY_READ
    if family == "logout":
        return ACTIVITY_OTHER
    if "delete" in message:
        return ACTIVITY_DELETE
    if any(term in message for term in ("create", "insert", "add")):
        return ACTIVITY_CREATE
    if family in {"change", "privileged_access"} or any(
        term in message for term in ("change", "update", "maintain")
    ):
        return ACTIVITY_UPDATE
    return ACTIVITY_OTHER


def _status_id(record: dict[str, Any]) -> int:
    text = f"{_text(_first(record, 'status', 'result', 'outcome', 'severity'))} {_message(record)}".lower()
    if any(
        term in text for term in ("fail", "error", "denied", "invalid", "unsuccessful", "rejected")
    ):
        return STATUS_FAILURE
    if any(term in text for term in ("success", "successful", "succeeded", "ok")):
        return STATUS_SUCCESS
    return STATUS_SUCCESS


def _severity_id(family: str, status_id: int) -> int:
    if status_id == STATUS_FAILURE:
        return SEVERITY_LOW
    if family in {"privileged_access", "change"}:
        return SEVERITY_MEDIUM
    return SEVERITY_INFORMATIONAL


def _status_name(status_id: int) -> str:
    return {STATUS_SUCCESS: "success", STATUS_FAILURE: "failure", STATUS_UNKNOWN: "unknown"}.get(
        status_id, "unknown"
    )


def _severity_name(severity_id: int) -> str:
    return {
        SEVERITY_INFORMATIONAL: "informational",
        SEVERITY_LOW: "low",
        SEVERITY_MEDIUM: "medium",
    }.get(severity_id, "unknown")


def _actor(record: dict[str, Any]) -> dict[str, Any]:
    uid = _text(_first(record, "user", "username", "user_name", "uname", "sap_user", "account"))
    client = _text(_first(record, "client", "mandt"))
    user: dict[str, Any] = {}
    if uid:
        user["uid"] = f"{client}:{uid}" if client else uid
        user["name"] = uid
    if client:
        user["account"] = {"uid": client, "name": f"SAP client {client}"}
    return {"user": user} if user else {}


def _src_endpoint(record: dict[str, Any]) -> dict[str, Any]:
    endpoint: dict[str, Any] = {}
    ip = _text(_first(record, "source_ip", "client_ip", "terminal_ip", "ip_address", "ip"))
    if ip:
        endpoint["ip"] = ip
    terminal = _text(_first(record, "terminal", "terminal_id", "workstation", "host"))
    if terminal:
        endpoint["name"] = terminal
    instance = _text(_first(record, "instance", "application_server", "server", "host_name"))
    if instance:
        endpoint["svc_name"] = instance
    return endpoint


def _resources(record: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    tx_code = _transaction_code(record)
    if tx_code:
        resources.append({"type": "sap_transaction", "name": tx_code, "uid": tx_code})
    for keys, resource_type in (
        (("program", "report", "abap_program"), "sap_program"),
        (("table", "table_name", "object", "object_name"), "sap_object"),
        (("role", "role_name"), "sap_role"),
        (("profile", "profile_name"), "sap_profile"),
    ):
        value = _text(_first(record, *keys))
        if value:
            resources.append({"type": resource_type, "name": value, "uid": value})
    return resources


def _privilege_names(record: dict[str, Any]) -> list[str]:
    names = set(
        _tokens(_first(record, "privilege", "privileges", "profile", "profiles", "role", "roles"))
    )
    message = _message(record).upper()
    for profile in PRIVILEGED_PROFILES:
        if profile in message:
            names.add(profile)
    return sorted(names)


def _int_value(record: dict[str, Any], *keys: str) -> int:
    raw = _first(record, *keys)
    try:
        return int(float(str(raw).replace(",", "")))
    except (TypeError, ValueError):
        return 0


def _sap_block(record: dict[str, Any], family: str) -> dict[str, Any]:
    tx_code = _transaction_code(record)
    privilege_names = _privilege_names(record)
    return {
        "event_code": _event_code(record),
        "event_family": family,
        "client": _text(_first(record, "client", "mandt")),
        "transaction_code": tx_code,
        "program": _text(_first(record, "program", "report", "abap_program")),
        "table": _text(_first(record, "table", "table_name", "object", "object_name")),
        "privilege_names": privilege_names,
        "privileged": bool(PRIVILEGED_PROFILES.intersection(privilege_names)),
        "change_count": _int_value(
            record, "change_count", "changed_records", "records_changed", "row_count", "count"
        ),
        "terminal": _text(_first(record, "terminal", "terminal_id", "workstation")),
        "instance": _text(_first(record, "instance", "application_server", "server", "host_name")),
        "raw": record,
    }


def _api(record: dict[str, Any], family: str) -> dict[str, Any]:
    operation = _transaction_code(record) or _event_code(record) or family
    return {"operation": operation, "service": {"name": "sap.security_audit_log"}}


def _event_uid(record: dict[str, Any], family: str) -> str:
    material = {
        "event_code": _event_code(record),
        "family": family,
        "time": str(_timestamp_value(record) or ""),
        "client": _text(_first(record, "client", "mandt")),
        "user": _text(_first(record, "user", "username", "user_name", "uname", "sap_user")),
        "transaction": _transaction_code(record),
        "message": _message(record),
    }
    if not any(material.values()):
        material["raw"] = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def validate_record(record: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(record, dict):
        return False, "not a dict"
    normalized = _normalize_record(record)
    if not (_message(normalized) or _event_code(normalized) or _transaction_code(normalized)):
        return False, "missing SAP audit message, event code, or transaction"
    return True, ""


def _build_canonical_event(raw: dict[str, Any]) -> dict[str, Any]:
    record = _normalize_record(raw)
    family = _event_family(record)
    status_id = _status_id(record)
    severity_id = _severity_id(family, status_id)
    activity_id = _activity_id(family, record)
    event_uid = _event_uid(record, family)
    out: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "application_activity",
        "source_skill": SKILL_NAME,
        "event_uid": event_uid,
        "provider": "SAP",
        "time_ms": parse_ts_ms(_timestamp_value(record)),
        "activity_id": activity_id,
        "activity_name": family,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "severity_id": severity_id,
        "severity": _severity_name(severity_id),
        "status_id": status_id,
        "status": _status_name(status_id),
        "api": _api(record, family),
        "sap": _sap_block(record, family),
        "message": _message(record) or f"SAP {family} event",
    }
    for key, value in (
        ("actor", _actor(record)),
        ("src_endpoint", _src_endpoint(record)),
        ("resources", _resources(record)),
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
            "labels": ["sap", "security-audit-log", "ingest"],
        },
        "api": canonical["api"],
        "unmapped": {"sap": canonical["sap"]},
    }
    for field in ("actor", "src_endpoint", "resources", "message"):
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
    return (
        _render_native_event(canonical)
        if output_format == "native"
        else _render_ocsf_event(canonical)
    )


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


def _parse_delimited_text(lines: list[str]) -> Iterable[dict[str, Any]]:
    nonempty = [line for line in lines if line.strip()]
    if not nonempty:
        return
    sample = "\n".join(nonempty[:5])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
    except csv.Error:
        dialect = csv.excel
    if len(nonempty) > 1 and any(char in nonempty[0] for char in (",", ";", "|", "\t")):
        try:
            reader = csv.DictReader(nonempty, dialect=dialect)
            if reader.fieldnames and any(
                field and not field.isdigit() for field in reader.fieldnames
            ):
                for row in reader:
                    yield {key: value for key, value in row.items() if key}
                return
        except csv.Error as exc:
            emit_stderr_event(
                SKILL_NAME, level="warning", event="csv_parse_failed", message=str(exc)
            )
    for line in nonempty:
        parts = [part.strip() for part in line.replace("|", ";").split(";")]
        if len(parts) >= 6:
            yield {
                "date_time": f"{parts[0]} {parts[1]}",
                "client": parts[2],
                "user": parts[3],
                "terminal": parts[4],
                "transaction": parts[5],
                "message_text": "; ".join(parts[6:]) if len(parts) > 6 else parts[5],
            }


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

    parsed_any = False
    for lineno, raw_line in enumerate(buf, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed_any = True
        yield from _yield_wrapped(obj)
    if parsed_any:
        return

    yield from _parse_delimited_text(buf)


def ingest(stream: Iterable[str], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    for record in iter_raw_records(stream):
        ok, reason = validate_record(record)
        if not ok:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_record",
                message=f"skipping record: {reason}",
                reason=reason,
            )
            continue
        try:
            yield convert_record(record, output_format=output_format)
        except Exception as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="convert_error",
                message=f"skipping record: {exc}",
                error=str(exc),
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert SAP Security Audit Log exports to OCSF Application Activity."
    )
    parser.add_argument(
        "input", nargs="?", help="Input JSON/JSONL/CSV/text file. Defaults to stdin."
    )
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
