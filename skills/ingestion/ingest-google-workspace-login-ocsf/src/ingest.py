"""Convert Google Workspace login audit activities to native or OCSF IAM events.

Input:  Admin SDK Reports API activities.list JSON objects for applicationName=login.
        Supports top-level {"items": [...]}, arrays, single activities, or JSONL.
Output: JSONL of OCSF 1.8 IAM events across:
        - Authentication (3002)
        - Account Change (3001)

Contract: see ../OCSF_CONTRACT.md
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

SKILL_NAME = "ingest-google-workspace-login-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
OUTPUT_FORMATS = ("ocsf", "native")

CATEGORY_UID = 3
CATEGORY_NAME = "Identity & Access Management"

AUTH_CLASS_UID = 3002
AUTH_CLASS_NAME = "Authentication"
AUTH_ACTIVITY_LOGON = 1
AUTH_ACTIVITY_LOGOFF = 2

ACCOUNT_CHANGE_CLASS_UID = 3001
ACCOUNT_CHANGE_CLASS_NAME = "Account Change"
ACCOUNT_CHANGE_MFA_ENABLE = 10
ACCOUNT_CHANGE_MFA_DISABLE = 11

STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

SEVERITY_UNKNOWN = 0
SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2

SUPPORTED_EVENT_NAMES = {
    "login_success",
    "login_failure",
    "logout",
    "2sv_enroll",
    "2sv_disable",
}


def parse_ts_ms(ts: str | None) -> int:
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        if ts.isdigit():
            value = int(ts)
            return value if value > 10_000_000_000 else value * 1000
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _param_value(param: dict[str, Any]) -> Any:
    for key in ("value", "intValue", "boolValue"):
        value = param.get(key)
        if value not in (None, ""):
            return value
    if isinstance(param.get("multiValue"), list):
        return param["multiValue"]
    return None


def _parameter_map(event: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for param in event.get("parameters") or []:
        if not isinstance(param, dict):
            continue
        name = param.get("name")
        if not isinstance(name, str) or not name:
            continue
        value = _param_value(param)
        if value is not None:
            out[name] = value
    return out


def _classify(event_name: str) -> tuple[int, str, int]:
    if event_name == "login_success":
        return AUTH_CLASS_UID, AUTH_CLASS_NAME, AUTH_ACTIVITY_LOGON
    if event_name == "login_failure":
        return AUTH_CLASS_UID, AUTH_CLASS_NAME, AUTH_ACTIVITY_LOGON
    if event_name == "logout":
        return AUTH_CLASS_UID, AUTH_CLASS_NAME, AUTH_ACTIVITY_LOGOFF
    if event_name == "2sv_enroll":
        return ACCOUNT_CHANGE_CLASS_UID, ACCOUNT_CHANGE_CLASS_NAME, ACCOUNT_CHANGE_MFA_ENABLE
    if event_name == "2sv_disable":
        return ACCOUNT_CHANGE_CLASS_UID, ACCOUNT_CHANGE_CLASS_NAME, ACCOUNT_CHANGE_MFA_DISABLE
    raise ValueError(f"unsupported event name: {event_name}")


def _status_and_severity(event_name: str) -> tuple[int, int]:
    if event_name == "login_failure":
        return STATUS_FAILURE, SEVERITY_LOW
    if event_name in {"login_success", "logout", "2sv_enroll", "2sv_disable"}:
        return STATUS_SUCCESS, SEVERITY_INFORMATIONAL
    return STATUS_UNKNOWN, SEVERITY_UNKNOWN


def _actor(activity: dict[str, Any]) -> dict[str, Any]:
    actor = activity.get("actor") or {}
    if not isinstance(actor, dict):
        return {}
    user: dict[str, Any] = {}
    if actor.get("profileId"):
        user["uid"] = str(actor["profileId"])
    if actor.get("email"):
        user["name"] = str(actor["email"])
        user["email_addr"] = str(actor["email"])
    elif actor.get("key"):
        user["name"] = str(actor["key"])
    if actor.get("callerType"):
        user["type"] = str(actor["callerType"])
    return {"user": user} if user else {}


def _subject_user(activity: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    user: dict[str, Any] = {}
    email = params.get("affected_email_address")
    actor = activity.get("actor") or {}
    if not email and isinstance(actor, dict):
        email = actor.get("email")
    if email:
        user["name"] = str(email)
        if "@" in str(email):
            user["email_addr"] = str(email)
    if isinstance(actor, dict) and actor.get("profileId"):
        user["uid"] = str(actor["profileId"])
    if user:
        user.setdefault("type", "User")
    return user


def _src_endpoint(activity: dict[str, Any]) -> dict[str, Any]:
    endpoint: dict[str, Any] = {}
    if activity.get("ipAddress"):
        endpoint["ip"] = str(activity["ipAddress"])
    return endpoint


def _session(activity: dict[str, Any]) -> dict[str, Any]:
    identity = activity.get("id") or {}
    if not isinstance(identity, dict):
        return {}
    session: dict[str, Any] = {}
    if identity.get("uniqueQualifier"):
        session["uid"] = str(identity["uniqueQualifier"])
    return session


def _message(activity: dict[str, Any], event_name: str) -> str | None:
    actor = (activity.get("actor") or {}).get("email") or "user"
    messages = {
        "login_success": f"{actor} logged in",
        "login_failure": f"{actor} failed to login",
        "logout": f"{actor} logged out",
        "2sv_enroll": f"{actor} enrolled in 2-step verification",
        "2sv_disable": f"{actor} disabled 2-step verification",
    }
    return messages.get(event_name)


def _metadata_uid(activity: dict[str, Any], event_name: str) -> str:
    identity = activity.get("id") or {}
    if not isinstance(identity, dict):
        identity = {}
    stable = {
        "applicationName": identity.get("applicationName"),
        "time": identity.get("time"),
        "uniqueQualifier": identity.get("uniqueQualifier"),
        "event": event_name,
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _status_name(status_id: int) -> str:
    return {
        STATUS_SUCCESS: "success",
        STATUS_FAILURE: "failure",
        STATUS_UNKNOWN: "unknown",
    }.get(status_id, "unknown")


def _record_type(class_uid: int) -> str:
    return {
        AUTH_CLASS_UID: "authentication",
        ACCOUNT_CHANGE_CLASS_UID: "account_change",
    }.get(class_uid, "iam_activity")


def validate_activity(activity: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(activity, dict):
        return False, "not a dict"
    identity = activity.get("id") or {}
    if not isinstance(identity, dict):
        return False, "missing required field: id"
    if not identity.get("time"):
        return False, "missing required field: id.time"
    if identity.get("applicationName") not in {None, "", "login"}:
        return False, f"unsupported applicationName: {identity.get('applicationName')}"
    if not isinstance(activity.get("events"), list) or not activity["events"]:
        return False, "missing required field: events"
    return True, ""


def _supported_events(activity: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for event in activity.get("events") or []:
        if not isinstance(event, dict):
            continue
        name = str(event.get("name") or "")
        if name not in SUPPORTED_EVENT_NAMES:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="unsupported_event_name",
                message=f"skipping event: unsupported event name: {name}",
                event_name=name,
            )
            continue
        yield event


def _build_canonical_event(activity: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    event_name = str(event.get("name") or "")
    class_uid, class_name, activity_id = _classify(event_name)
    status_id, severity_id = _status_and_severity(event_name)
    params = _parameter_map(event)
    actor = _actor(activity)
    subject_user = _subject_user(activity, params)
    src_endpoint = _src_endpoint(activity)
    session = _session(activity)
    message = _message(activity, event_name)

    out: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": _record_type(class_uid),
        "source_skill": SKILL_NAME,
        "event_uid": _metadata_uid(activity, event_name),
        "provider": "Google Workspace",
        "activity_id": activity_id,
        "activity_name": event_name,
        "severity_id": severity_id,
        "severity": "low" if severity_id == SEVERITY_LOW else "informational" if severity_id == SEVERITY_INFORMATIONAL else "unknown",
        "status_id": status_id,
        "status": _status_name(status_id),
        "time_ms": parse_ts_ms((activity.get("id") or {}).get("time")),
        "application_name": ((activity.get("id") or {}).get("applicationName") or "login"),
        "customer_id": (activity.get("id") or {}).get("customerId"),
        "event_type": event.get("type"),
        "event_name": event_name,
        "owner_domain": activity.get("ownerDomain"),
        "parameters": params,
    }
    if actor:
        out["actor"] = actor
    if subject_user:
        out["user"] = subject_user
    if src_endpoint:
        out["src_endpoint"] = src_endpoint
    if session:
        out["session"] = session
    if message:
        out["message"] = message
    if status_id == STATUS_FAILURE:
        failure = params.get("login_failure_type")
        if failure:
            out["status_detail"] = str(failure)
    return out


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "activity_id": canonical["activity_id"],
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": AUTH_CLASS_UID if canonical["record_type"] == "authentication" else ACCOUNT_CHANGE_CLASS_UID,
        "class_name": "Authentication" if canonical["record_type"] == "authentication" else "Account Change",
        "type_uid": (AUTH_CLASS_UID if canonical["record_type"] == "authentication" else ACCOUNT_CHANGE_CLASS_UID) * 100 + canonical["activity_id"],
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
            "labels": ["identity", "google-workspace", "login-audit", "ingest"],
        },
        "unmapped": {
            "google_workspace_login": {
                "application_name": canonical["application_name"],
                "customer_id": canonical.get("customer_id"),
                "event_type": canonical.get("event_type"),
                "event_name": canonical["event_name"],
                "owner_domain": canonical.get("owner_domain"),
                "parameters": canonical.get("parameters") or {},
            }
        },
    }
    for field in ("actor", "user", "src_endpoint", "session", "message", "status_detail"):
        if canonical.get(field):
            out[field] = canonical[field]
    return out


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["output_format"] = "native"
    return native


def convert_activity_event(activity: dict[str, Any], event: dict[str, Any], output_format: str = "ocsf") -> dict[str, Any]:
    canonical = _build_canonical_event(activity, event)
    if output_format == "native":
        return _render_native_event(canonical)
    return _render_ocsf_event(canonical)


def iter_raw_activities(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
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

    if isinstance(whole, dict):
        if isinstance(whole.get("items"), list):
            for item in whole["items"]:
                if isinstance(item, dict):
                    yield item
            return
        yield whole
        return

    if isinstance(whole, list):
        for item in whole:
            if isinstance(item, dict):
                yield item
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
                message=f"skipping line {lineno}: json parse failed: {exc}",
                line=lineno,
                error=str(exc),
            )
            continue
        if isinstance(obj, dict) and isinstance(obj.get("items"), list):
            for item in obj["items"]:
                if isinstance(item, dict):
                    yield item
        elif isinstance(obj, dict):
            yield obj
        else:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_json_shape",
                message=f"skipping line {lineno}: not a JSON object",
                line=lineno,
            )


def ingest(stream: Iterable[str], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    for activity in iter_raw_activities(stream):
        ok, reason = validate_activity(activity)
        if not ok:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_activity",
                message=f"skipping activity: {reason}",
                reason=reason,
                unique_qualifier=str(((activity.get("id") or {}).get("uniqueQualifier")) or ""),
            )
            continue
        for event in _supported_events(activity):
            try:
                yield convert_activity_event(activity, event, output_format=output_format)
            except Exception as exc:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="convert_error",
                    message=f"skipping event: convert error: {exc}",
                    error=str(exc),
                    event_name=str(event.get("name") or ""),
                    unique_qualifier=str(((activity.get("id") or {}).get("uniqueQualifier")) or ""),
                )
                continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert raw Google Workspace login audit JSON to OCSF or native IAM JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF IAM events (default) or the native canonical projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        for record in ingest(in_stream, output_format=args.output_format):
            out_stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
