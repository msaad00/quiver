"""Convert Google Workspace Admin SDK Reports activities to OCSF IAM events.

Input: Admin SDK Reports API activities.list JSON for applicationName values
       login, admin, and token. Supports {"items": [...]}, arrays, single
       activities, or JSONL.
Output: JSONL of OCSF 1.8 Authentication (3002) and Account Change (3001)
        records, or the repo-owned native projection.
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

SKILL_NAME = "ingest-workspace-admin-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-06"
OUTPUT_FORMATS = ("ocsf", "native")

CATEGORY_UID = 3
CATEGORY_NAME = "Identity & Access Management"

AUTH_CLASS_UID = 3002
AUTH_CLASS_NAME = "Authentication"
AUTH_ACTIVITY_LOGON = 1
AUTH_ACTIVITY_LOGOFF = 2

ACCOUNT_CHANGE_CLASS_UID = 3001
ACCOUNT_CHANGE_CLASS_NAME = "Account Change"
ACCOUNT_CHANGE_CREATE = 1
ACCOUNT_CHANGE_UPDATE = 3
ACCOUNT_CHANGE_DELETE = 4
ACCOUNT_CHANGE_MFA_ENABLE = 10
ACCOUNT_CHANGE_MFA_DISABLE = 11
ACCOUNT_CHANGE_OTHER = 99

STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

SEVERITY_UNKNOWN = 0
SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2

SUPPORTED_APPLICATIONS = {"login", "admin", "token"}

LOGIN_EVENTS = {
    "login_success": (
        AUTH_CLASS_UID,
        AUTH_CLASS_NAME,
        AUTH_ACTIVITY_LOGON,
        STATUS_SUCCESS,
        SEVERITY_INFORMATIONAL,
    ),
    "login_failure": (
        AUTH_CLASS_UID,
        AUTH_CLASS_NAME,
        AUTH_ACTIVITY_LOGON,
        STATUS_FAILURE,
        SEVERITY_LOW,
    ),
    "logout": (
        AUTH_CLASS_UID,
        AUTH_CLASS_NAME,
        AUTH_ACTIVITY_LOGOFF,
        STATUS_SUCCESS,
        SEVERITY_INFORMATIONAL,
    ),
    "2sv_enroll": (
        ACCOUNT_CHANGE_CLASS_UID,
        ACCOUNT_CHANGE_CLASS_NAME,
        ACCOUNT_CHANGE_MFA_ENABLE,
        STATUS_SUCCESS,
        SEVERITY_INFORMATIONAL,
    ),
    "2sv_disable": (
        ACCOUNT_CHANGE_CLASS_UID,
        ACCOUNT_CHANGE_CLASS_NAME,
        ACCOUNT_CHANGE_MFA_DISABLE,
        STATUS_SUCCESS,
        SEVERITY_LOW,
    ),
}

TOKEN_EVENTS = {
    "authorize": (ACCOUNT_CHANGE_CREATE, STATUS_SUCCESS, SEVERITY_LOW),
    "request": (ACCOUNT_CHANGE_CREATE, STATUS_UNKNOWN, SEVERITY_INFORMATIONAL),
    "deny": (ACCOUNT_CHANGE_OTHER, STATUS_FAILURE, SEVERITY_LOW),
    "revoke": (ACCOUNT_CHANGE_DELETE, STATUS_SUCCESS, SEVERITY_INFORMATIONAL),
}

ADMIN_ROLE_GRANT_EVENTS = {
    "ASSIGN_ROLE",
    "ASSIGN_ROLE_TO_USER",
    "CREATE_ROLE_ASSIGNMENT",
    "GRANT_ADMIN_PRIVILEGE",
    "ROLE_ASSIGNED",
    "USER_GRANTED_ADMIN_PRIVILEGE",
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
    if isinstance(param.get("messageValue"), dict):
        return param["messageValue"]
    if isinstance(param.get("multiMessageValue"), list):
        return param["multiMessageValue"]
    return None


def _as_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


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


def _application(activity: dict[str, Any]) -> str:
    identity = _as_dict(activity.get("id"))
    return str(identity.get("applicationName") or activity.get("applicationName") or "").strip()


def _event_name(event: dict[str, Any]) -> str:
    return str(event.get("name") or "").strip()


def _classify(
    application: str, event_name: str, params: dict[str, Any]
) -> tuple[int, str, int, int, int] | None:
    if application == "login" and event_name in LOGIN_EVENTS:
        return LOGIN_EVENTS[event_name]
    if application == "token" and event_name in TOKEN_EVENTS:
        activity_id, status_id, severity_id = TOKEN_EVENTS[event_name]
        return (
            ACCOUNT_CHANGE_CLASS_UID,
            ACCOUNT_CHANGE_CLASS_NAME,
            activity_id,
            status_id,
            severity_id,
        )
    if application == "admin" and _is_admin_role_grant_event(event_name, params):
        return (
            ACCOUNT_CHANGE_CLASS_UID,
            ACCOUNT_CHANGE_CLASS_NAME,
            ACCOUNT_CHANGE_CREATE,
            STATUS_SUCCESS,
            SEVERITY_LOW,
        )
    return None


def _is_admin_role_grant_event(event_name: str, params: dict[str, Any]) -> bool:
    if event_name in ADMIN_ROLE_GRANT_EVENTS:
        return True
    upper_name = event_name.upper()
    if "ROLE" in upper_name and any(
        term in upper_name for term in ("ASSIGN", "GRANT", "ADD", "CREATE")
    ):
        return True
    keys = {key.lower() for key in params}
    return bool({"role_name", "role_id", "role_assignment_id", "assigned_to"} & keys) and bool(
        {"assignee", "assigned_to", "target_user", "email", "user_email"} & keys
    )


def _status_name(status_id: int) -> str:
    return {STATUS_SUCCESS: "success", STATUS_FAILURE: "failure", STATUS_UNKNOWN: "unknown"}.get(
        status_id, "unknown"
    )


def _severity_name(severity_id: int) -> str:
    return {
        SEVERITY_INFORMATIONAL: "informational",
        SEVERITY_LOW: "low",
        SEVERITY_UNKNOWN: "unknown",
    }.get(severity_id, "unknown")


def _record_type(class_uid: int) -> str:
    return "authentication" if class_uid == AUTH_CLASS_UID else "account_change"


def _actor(activity: dict[str, Any]) -> dict[str, Any]:
    raw = _as_dict(activity.get("actor"))
    user: dict[str, Any] = {}
    if raw.get("profileId"):
        user["uid"] = str(raw["profileId"])
    if raw.get("email"):
        user["name"] = str(raw["email"])
        user["email_addr"] = str(raw["email"])
    elif raw.get("key"):
        user["name"] = str(raw["key"])
    if raw.get("callerType"):
        user["type"] = str(raw["callerType"])
    return {"user": user} if user else {}


def _subject_user(activity: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    raw_actor = _as_dict(activity.get("actor"))
    email = (
        params.get("affected_email_address")
        or params.get("email")
        or params.get("user_email")
        or params.get("target_user")
        or params.get("assigned_to")
        or raw_actor.get("email")
    )
    user: dict[str, Any] = {}
    if email:
        user["name"] = str(email)
        if "@" in str(email):
            user["email_addr"] = str(email)
    if raw_actor.get("profileId") and not params.get("target_user"):
        user["uid"] = str(raw_actor["profileId"])
    if user:
        user.setdefault("type", "User")
    return user


def _src_endpoint(activity: dict[str, Any]) -> dict[str, Any]:
    if activity.get("ipAddress"):
        return {"ip": str(activity["ipAddress"])}
    return {}


def _session(activity: dict[str, Any]) -> dict[str, Any]:
    identity = _as_dict(activity.get("id"))
    if identity.get("uniqueQualifier"):
        return {"uid": str(identity["uniqueQualifier"])}
    return {}


def _resources(application: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    if application == "token":
        client_id = params.get("client_id") or params.get("clientId")
        app_name = params.get("app_name") or params.get("appName")
        if client_id or app_name:
            resource: dict[str, Any] = {"type": "oauth_client", "name": str(app_name or client_id)}
            if client_id:
                resource["uid"] = str(client_id)
            return [resource]
    if application == "admin":
        role = params.get("role_name") or params.get("role") or params.get("role_id")
        if role:
            return [{"type": "admin_role", "name": str(role)}]
    return []


def _message(
    application: str, event_name: str, params: dict[str, Any], activity: dict[str, Any]
) -> str:
    actor = _as_dict(activity.get("actor")).get("email") or "user"
    if application == "token":
        app_name = params.get("app_name") or params.get("client_id") or "OAuth client"
        verbs = {
            "authorize": "authorized",
            "request": "requested",
            "deny": "was denied",
            "revoke": "revoked",
        }
        verb = verbs.get(event_name, event_name)
        return f"{actor} {verb} access to {app_name}"
    if application == "admin":
        role = (
            params.get("role_name") or params.get("role") or params.get("role_id") or "admin role"
        )
        assignee = (
            params.get("assigned_to")
            or params.get("target_user")
            or params.get("email")
            or "principal"
        )
        return f"{actor} granted {role} to {assignee}"
    return f"{actor} {event_name}"


def _metadata_uid(activity: dict[str, Any], event_name: str) -> str:
    identity = _as_dict(activity.get("id"))
    stable = {
        "applicationName": identity.get("applicationName") or _application(activity),
        "time": identity.get("time"),
        "uniqueQualifier": identity.get("uniqueQualifier"),
        "event": event_name,
    }
    return hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def validate_activity(activity: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(activity, dict):
        return False, "not a dict"
    identity = _as_dict(activity.get("id"))
    if not identity.get("time"):
        return False, "missing required field: id.time"
    application = _application(activity)
    if application not in SUPPORTED_APPLICATIONS:
        return False, f"unsupported applicationName: {application}"
    if not isinstance(activity.get("events"), list) or not activity["events"]:
        return False, "missing required field: events"
    return True, ""


def _supported_events(activity: dict[str, Any]) -> Iterable[dict[str, Any]]:
    application = _application(activity)
    for event in activity.get("events") or []:
        if not isinstance(event, dict):
            continue
        params = _parameter_map(event)
        name = _event_name(event)
        if _classify(application, name, params) is None:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="unsupported_event_name",
                message=f"skipping event: unsupported {application} event name: {name}",
                application_name=application,
                event_name=name,
            )
            continue
        yield event


def _build_canonical_event(activity: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    application = _application(activity)
    event_name = _event_name(event)
    params = _parameter_map(event)
    classified = _classify(application, event_name, params)
    if classified is None:
        raise ValueError(f"unsupported event name: {event_name}")
    class_uid, class_name, activity_id, status_id, severity_id = classified
    identity = _as_dict(activity.get("id"))

    out: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": _record_type(class_uid),
        "source_skill": SKILL_NAME,
        "event_uid": _metadata_uid(activity, event_name),
        "provider": "Google Workspace",
        "activity_id": activity_id,
        "activity_name": event_name,
        "class_uid": class_uid,
        "class_name": class_name,
        "severity_id": severity_id,
        "severity": _severity_name(severity_id),
        "status_id": status_id,
        "status": _status_name(status_id),
        "time_ms": parse_ts_ms(identity.get("time")),
        "application_name": application,
        "customer_id": identity.get("customerId"),
        "event_type": event.get("type"),
        "event_name": event_name,
        "owner_domain": activity.get("ownerDomain"),
        "parameters": params,
    }
    for key, value in (
        ("actor", _actor(activity)),
        ("user", _subject_user(activity, params)),
        ("src_endpoint", _src_endpoint(activity)),
        ("session", _session(activity)),
        ("resources", _resources(application, params)),
    ):
        if value:
            out[key] = value
    message = _message(application, event_name, params, activity)
    if message:
        out["message"] = message
    if status_id == STATUS_FAILURE:
        detail = params.get("login_failure_type") or params.get("rejection_type")
        if detail:
            out["status_detail"] = str(detail)
    return out


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    class_uid = int(canonical["class_uid"])
    out: dict[str, Any] = {
        "activity_id": canonical["activity_id"],
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": class_uid,
        "class_name": canonical["class_name"],
        "type_uid": class_uid * 100 + int(canonical["activity_id"]),
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
            "labels": ["identity", "google-workspace", "admin-reports", "ingest"],
        },
        "unmapped": {
            "google_workspace_admin": {
                "application_name": canonical["application_name"],
                "customer_id": canonical.get("customer_id"),
                "event_type": canonical.get("event_type"),
                "event_name": canonical["event_name"],
                "owner_domain": canonical.get("owner_domain"),
                "parameters": canonical.get("parameters") or {},
            }
        },
    }
    for field in (
        "actor",
        "user",
        "src_endpoint",
        "session",
        "resources",
        "message",
        "status_detail",
    ):
        if canonical.get(field):
            out[field] = canonical[field]
    return out


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["output_format"] = "native"
    return native


def convert_activity_event(
    activity: dict[str, Any], event: dict[str, Any], output_format: str = "ocsf"
) -> dict[str, Any]:
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
                unique_qualifier=str(_as_dict(activity.get("id")).get("uniqueQualifier") or ""),
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
                    unique_qualifier=str(_as_dict(activity.get("id")).get("uniqueQualifier") or ""),
                )
                continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert raw Google Workspace Admin SDK Reports API activities to OCSF or native IAM JSONL."
    )
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
