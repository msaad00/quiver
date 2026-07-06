"""Convert Workday audit/report exports into OCSF Account Change events.

Input: Workday REST/RaaS JSON exported upstream. Supports objects, arrays,
       JSONL, and common wrappers such as Report_Entry, data, events, or items.
Output: JSONL of OCSF 1.8 Account Change (3001) records, or the repo-owned
        native projection.
"""

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
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "ingest-workday-audit-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-06"
OUTPUT_FORMATS = ("ocsf", "native")

CATEGORY_UID = 3
CATEGORY_NAME = "Identity & Access Management"
ACCOUNT_CHANGE_CLASS_UID = 3001
ACCOUNT_CHANGE_CLASS_NAME = "Account Change"
ACCOUNT_CHANGE_CREATE = 1
ACCOUNT_CHANGE_UPDATE = 3
ACCOUNT_CHANGE_DELETE = 4
ACCOUNT_CHANGE_OTHER = 99

STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3

WRAPPER_KEYS = (
    "Report_Entry",
    "report_entries",
    "reports",
    "data",
    "events",
    "items",
    "value",
)

EVENT_NAME_KEYS = (
    "event_name",
    "eventName",
    "activity",
    "action",
    "business_process",
    "businessProcess",
    "business_process_type",
    "businessProcessType",
    "transaction_type",
    "transactionType",
    "type",
)

ACTOR_KEYS = (
    "initiated_by",
    "initiatedBy",
    "actor",
    "performed_by",
    "performedBy",
    "created_by",
    "createdBy",
    "user",
)

WORKER_ID_KEYS = ("worker_id", "workerId", "employee_id", "employeeId", "worker")
WORKER_EMAIL_KEYS = (
    "worker_email",
    "workerEmail",
    "email",
    "email_address",
    "emailAddress",
    "primary_email",
    "primaryEmail",
)
EFFECTIVE_TIME_KEYS = (
    "effective_at",
    "effectiveAt",
    "effective_date",
    "effectiveDate",
    "event_time",
    "eventTime",
    "timestamp",
    "time",
)
TERMINATION_TIME_KEYS = ("termination_date", "terminationDate", "terminated_at", "terminatedAt")
REHIRE_TIME_KEYS = ("rehire_date", "rehireDate", "rehired_at", "rehiredAt")


def parse_ts_ms(value: Any) -> int:
    if value in (None, ""):
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    if isinstance(value, (int, float)):
        raw = int(value)
        return raw if raw > 10_000_000_000 else raw * 1000
    text = str(value).strip()
    if not text:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    if text.isdigit():
        raw = int(text)
        return raw if raw > 10_000_000_000 else raw * 1000
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _first(record: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _flatten_label(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("descriptor", "name", "displayName", "id", "uid", "value"):
            item = value.get(key)
            if item not in (None, ""):
                return str(item)
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    if isinstance(value, list):
        return ",".join(_flatten_label(item) for item in value if item not in (None, ""))
    return "" if value in (None, "") else str(value)


def _event_name(record: dict[str, Any]) -> str:
    return _flatten_label(_first(record, EVENT_NAME_KEYS)).strip()


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    lowered = text.lower().replace("_", " ").replace("-", " ")
    return any(term in lowered for term in terms)


def _event_family(record: dict[str, Any]) -> str:
    name = _event_name(record)
    status_text = _flatten_label(
        _first(record, ("employment_status", "employmentStatus", "status"))
    ).lower()
    reason = _flatten_label(
        _first(record, ("reason", "termination_reason", "terminationReason"))
    ).lower()
    joined = " ".join(part for part in (name, status_text, reason) if part)
    if _contains_any(
        joined,
        (
            "termination",
            "terminate employee",
            "end employment",
            "employee terminated",
            "worker terminated",
        ),
    ):
        return "termination"
    if _contains_any(joined, ("rehire", "re hire", "return from termination")):
        return "rehire"
    if _contains_any(joined, ("hire", "new worker", "employee hire", "worker hire")):
        return "hire"
    if _contains_any(
        joined, ("worker change", "job change", "position change", "employment change")
    ):
        return "worker_change"
    return "account_change"


def _activity_id(family: str) -> int:
    if family == "hire":
        return ACCOUNT_CHANGE_CREATE
    if family == "termination":
        return ACCOUNT_CHANGE_DELETE
    if family in {"rehire", "worker_change", "account_change"}:
        return ACCOUNT_CHANGE_UPDATE
    return ACCOUNT_CHANGE_OTHER


def _status_id(record: dict[str, Any]) -> int:
    text = _flatten_label(
        _first(record, ("status", "result", "outcome", "event_status", "eventStatus"))
    ).lower()
    if not text:
        return STATUS_SUCCESS
    if any(term in text for term in ("fail", "error", "denied", "cancel", "rescinded")):
        return STATUS_FAILURE
    if any(term in text for term in ("success", "complete", "completed", "approved", "done")):
        return STATUS_SUCCESS
    return STATUS_UNKNOWN


def _status_name(status_id: int) -> str:
    return {STATUS_SUCCESS: "success", STATUS_FAILURE: "failure", STATUS_UNKNOWN: "unknown"}.get(
        status_id, "unknown"
    )


def _severity_id(family: str, status_id: int) -> int:
    if status_id == STATUS_FAILURE:
        return SEVERITY_LOW
    if family == "termination":
        return SEVERITY_MEDIUM
    return SEVERITY_INFORMATIONAL


def _severity_name(severity_id: int) -> str:
    return {
        SEVERITY_INFORMATIONAL: "informational",
        SEVERITY_LOW: "low",
        SEVERITY_MEDIUM: "medium",
    }.get(severity_id, "unknown")


def _actor(record: dict[str, Any]) -> dict[str, Any]:
    raw = _first(record, ACTOR_KEYS)
    raw_dict = _as_dict(raw)
    name = _flatten_label(raw)
    uid = _flatten_label(
        _first(raw_dict, ("id", "uid", "worker_id", "workerId", "user_id", "userId"))
    )
    email = _flatten_label(_first(raw_dict, WORKER_EMAIL_KEYS))
    if not email and "@" in name:
        email = name
    user: dict[str, Any] = {}
    if uid:
        user["uid"] = uid
    if email:
        user["email_addr"] = email
        user["name"] = email
    elif name:
        user["name"] = name
    return {"user": user} if user else {}


def _worker_user(record: dict[str, Any]) -> dict[str, Any]:
    worker = _as_dict(record.get("worker")) or _as_dict(record.get("employee"))
    uid = _flatten_label(
        _first(record, WORKER_ID_KEYS) or _first(worker, WORKER_ID_KEYS + ("id", "uid"))
    )
    email = _flatten_label(_first(record, WORKER_EMAIL_KEYS) or _first(worker, WORKER_EMAIL_KEYS))
    name = _flatten_label(
        _first(record, ("worker_name", "workerName", "employee_name", "employeeName", "name"))
        or _first(worker, ("name", "displayName", "descriptor"))
    )
    user: dict[str, Any] = {}
    if uid:
        user["uid"] = uid
    if email:
        user["email_addr"] = email
        user["name"] = email
    elif name:
        user["name"] = name
    if user:
        user.setdefault("type", "User")
    return user


def _resources(record: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for key, resource_type in (
        ("business_process", "workday_business_process"),
        ("businessProcess", "workday_business_process"),
        ("supervisory_org", "workday_supervisory_org"),
        ("supervisoryOrg", "workday_supervisory_org"),
        ("organization", "workday_organization"),
    ):
        value = _flatten_label(record.get(key))
        if value:
            resources.append({"type": resource_type, "name": value})
    return resources


def _stable_uid(record: dict[str, Any], family: str) -> str:
    material = {
        "event_name": _event_name(record),
        "family": family,
        "worker": _flatten_label(
            _first(record, WORKER_ID_KEYS) or _first(record, WORKER_EMAIL_KEYS)
        ),
        "effective": _flatten_label(
            _first(record, EFFECTIVE_TIME_KEYS) or _first(record, TERMINATION_TIME_KEYS)
        ),
        "source_id": _flatten_label(
            _first(record, ("id", "uid", "event_id", "eventId", "transaction_id", "transactionId"))
        ),
    }
    if not any(material.values()):
        material["raw"] = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _workday_unmapped(record: dict[str, Any], family: str) -> dict[str, Any]:
    return {
        "event_family": family,
        "event_name": _event_name(record),
        "worker_id": _flatten_label(_first(record, WORKER_ID_KEYS)),
        "worker_email": _flatten_label(_first(record, WORKER_EMAIL_KEYS)),
        "effective_at": _flatten_label(_first(record, EFFECTIVE_TIME_KEYS)),
        "termination_date": _flatten_label(_first(record, TERMINATION_TIME_KEYS)),
        "rehire_date": _flatten_label(_first(record, REHIRE_TIME_KEYS)),
        "business_process": _flatten_label(
            _first(
                record,
                (
                    "business_process",
                    "businessProcess",
                    "business_process_type",
                    "businessProcessType",
                ),
            )
        ),
        "supervisory_org": _flatten_label(
            _first(record, ("supervisory_org", "supervisoryOrg", "organization"))
        ),
        "reason": _flatten_label(
            _first(record, ("reason", "termination_reason", "terminationReason"))
        ),
        "raw": record,
    }


def validate_record(record: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(record, dict):
        return False, "not a dict"
    if not (
        _event_name(record) or _first(record, WORKER_ID_KEYS) or _first(record, WORKER_EMAIL_KEYS)
    ):
        return False, "missing event name and worker identifiers"
    return True, ""


def _build_canonical_event(record: dict[str, Any]) -> dict[str, Any]:
    family = _event_family(record)
    status_id = _status_id(record)
    severity_id = _severity_id(family, status_id)
    time_source = (
        _first(record, EFFECTIVE_TIME_KEYS)
        or _first(record, TERMINATION_TIME_KEYS)
        or _first(record, REHIRE_TIME_KEYS)
    )
    event_uid = _stable_uid(record, family)
    event_name = _event_name(record) or family

    out: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "account_change",
        "source_skill": SKILL_NAME,
        "event_uid": event_uid,
        "provider": "Workday",
        "activity_id": _activity_id(family),
        "activity_name": family,
        "class_uid": ACCOUNT_CHANGE_CLASS_UID,
        "class_name": ACCOUNT_CHANGE_CLASS_NAME,
        "severity_id": severity_id,
        "severity": _severity_name(severity_id),
        "status_id": status_id,
        "status": _status_name(status_id),
        "time_ms": parse_ts_ms(time_source),
        "event_name": event_name,
        "event_family": family,
        "workday": _workday_unmapped(record, family),
    }
    for key, value in (
        ("actor", _actor(record)),
        ("user", _worker_user(record)),
        ("resources", _resources(record)),
    ):
        if value:
            out[key] = value
    user = out.get("user") or {}
    out["message"] = (
        f"Workday {family.replace('_', ' ')} event for {user.get('email_addr') or user.get('uid') or 'worker'}"
    )
    return out


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "activity_id": canonical["activity_id"],
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": ACCOUNT_CHANGE_CLASS_UID,
        "class_name": ACCOUNT_CHANGE_CLASS_NAME,
        "type_uid": ACCOUNT_CHANGE_CLASS_UID * 100 + int(canonical["activity_id"]),
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
            "labels": ["identity", "workday", "audit", "ingest"],
        },
        "unmapped": {"workday": canonical["workday"]},
    }
    for field in ("actor", "user", "resources", "message"):
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
    if output_format == "native":
        return _render_native_event(canonical)
    return _render_ocsf_event(canonical)


def _yield_wrapped(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, list):
        for item in value:
            yield from _yield_wrapped(item)
        return
    if not isinstance(value, dict):
        return
    for key in WRAPPER_KEYS:
        wrapped = value.get(key)
        if isinstance(wrapped, list):
            for item in wrapped:
                yield from _yield_wrapped(item)
            return
        if isinstance(wrapped, dict):
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

    for lineno, raw_line in enumerate(buf, start=1):
        line = raw_line.strip()
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
        yield from _yield_wrapped(obj)


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
        description="Convert Workday audit/report exports to OCSF Account Change events."
    )
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
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
