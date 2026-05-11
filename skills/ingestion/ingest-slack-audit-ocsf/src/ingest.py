"""Convert raw Slack Audit Logs API records to native or OCSF events.

Input:  Slack Audit Logs API `/audit/v1/logs` response objects, single entry
        JSON, or NDJSON.
Output: JSONL of either:
        - OCSF events spanning Authentication (3002), User Access Management
          (3005), and API Activity (6003), or
        - repo-owned native projection records.

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

SKILL_NAME = "ingest-slack-audit-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
OUTPUT_FORMATS = ("ocsf", "native")

CATEGORY_IAM_UID = 3
CATEGORY_IAM_NAME = "Identity & Access Management"
CATEGORY_APP_UID = 6
CATEGORY_APP_NAME = "Application Activity"

AUTH_CLASS_UID = 3002
AUTH_CLASS_NAME = "Authentication"
AUTH_ACTIVITY_LOGON = 1
AUTH_ACTIVITY_LOGOFF = 2
AUTH_ACTIVITY_OTHER = 99

USER_ACCESS_CLASS_UID = 3005
USER_ACCESS_CLASS_NAME = "User Access Management"
USER_ACCESS_ASSIGN = 1
USER_ACCESS_REVOKE = 2
USER_ACCESS_OTHER = 99

API_ACTIVITY_CLASS_UID = 6003
API_ACTIVITY_CLASS_NAME = "API Activity"
API_ACTIVITY_CREATE = 1
API_ACTIVITY_READ = 2
API_ACTIVITY_UPDATE = 3
API_ACTIVITY_DELETE = 4
API_ACTIVITY_OTHER = 99

STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

SEVERITY_UNKNOWN = 0
SEVERITY_INFORMATIONAL = 1


_AUTH_ACTION_MAP: dict[str, int] = {
    "user_login": AUTH_ACTIVITY_LOGON,
    "user_logout": AUTH_ACTIVITY_LOGOFF,
    "signout_all_sessions": AUTH_ACTIVITY_LOGOFF,
}

_USER_ACCESS_ACTION_MAP: dict[str, int] = {
    "workspace_user_added_to_workspace": USER_ACCESS_ASSIGN,
    "workspace_user_removed_from_workspace": USER_ACCESS_REVOKE,
    "private_channel_member_added": USER_ACCESS_ASSIGN,
    "private_channel_member_removed": USER_ACCESS_REVOKE,
    "public_channel_member_added": USER_ACCESS_ASSIGN,
    "public_channel_member_removed": USER_ACCESS_REVOKE,
    "role_change_to_admin": USER_ACCESS_ASSIGN,
    "role_change_to_owner": USER_ACCESS_ASSIGN,
    "role_change_to_user": USER_ACCESS_REVOKE,
}

_API_ACTIVITY_ACTION_MAP: dict[str, int] = {
    "app_installed": API_ACTIVITY_CREATE,
    "app_approved": API_ACTIVITY_UPDATE,
    "app_uninstalled": API_ACTIVITY_DELETE,
    "app_restricted": API_ACTIVITY_UPDATE,
    "file_downloaded": API_ACTIVITY_READ,
    "file_shared": API_ACTIVITY_UPDATE,
    "channel_created": API_ACTIVITY_CREATE,
    "private_channel_created": API_ACTIVITY_CREATE,
}


def parse_ts_ms(value: Any) -> int:
    """Slack `date_create` is UNIX seconds. Accept int / float / numeric string."""
    if value is None or value == "":
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    return int(seconds * 1000)


def _classify_action(action: str) -> tuple[int, str, int] | None:
    if action in _AUTH_ACTION_MAP:
        return AUTH_CLASS_UID, AUTH_CLASS_NAME, _AUTH_ACTION_MAP[action]
    if action in _USER_ACCESS_ACTION_MAP:
        return USER_ACCESS_CLASS_UID, USER_ACCESS_CLASS_NAME, _USER_ACCESS_ACTION_MAP[action]
    if action in _API_ACTIVITY_ACTION_MAP:
        return API_ACTIVITY_CLASS_UID, API_ACTIVITY_CLASS_NAME, _API_ACTIVITY_ACTION_MAP[action]
    return None


def _user_object(entity: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(entity, dict):
        return {}
    inner = entity.get("user") if isinstance(entity.get("user"), dict) else entity
    user: dict[str, Any] = {}
    if isinstance(inner, dict):
        uid = inner.get("id")
        if uid:
            user["uid"] = str(uid)
        name = inner.get("name") or inner.get("username") or inner.get("id") or ""
        if name:
            user["name"] = str(name)
        email = inner.get("email")
        if isinstance(email, str) and "@" in email:
            user["email_addr"] = email
        team_id = inner.get("team")
        if isinstance(team_id, str) and team_id:
            user["domain"] = team_id
    if isinstance(entity, dict) and entity.get("type"):
        user["type"] = str(entity["type"])
    return user


def _actor(event: dict[str, Any]) -> dict[str, Any]:
    actor_raw = event.get("actor") or {}
    user = _user_object(actor_raw)
    return {"user": user} if user else {}


def _entity_user(event: dict[str, Any]) -> dict[str, Any]:
    entity = event.get("entity") or {}
    if not isinstance(entity, dict):
        return {}
    if entity.get("type") == "user":
        return _user_object(entity)
    actor = event.get("actor") or {}
    if isinstance(actor, dict) and actor.get("type") == "user":
        return _user_object(actor)
    return {}


def _entity_resource(event: dict[str, Any]) -> dict[str, Any] | None:
    entity = event.get("entity") or {}
    if not isinstance(entity, dict):
        return None
    etype = str(entity.get("type") or "")
    if etype in {"", "user"}:
        return None
    inner = entity.get(etype) if isinstance(entity.get(etype), dict) else None
    name: str = ""
    uid: str = ""
    if isinstance(inner, dict):
        name = str(inner.get("name") or inner.get("id") or "")
        uid = str(inner.get("id") or "")
    if not name:
        name = etype
    resource: dict[str, Any] = {"name": name, "type": etype}
    if uid:
        resource["uid"] = uid
    return resource


def _src_endpoint(event: dict[str, Any]) -> dict[str, Any]:
    context = event.get("context") or {}
    if not isinstance(context, dict):
        return {}
    endpoint: dict[str, Any] = {}
    ip = context.get("ip_address")
    if isinstance(ip, str) and ip:
        endpoint["ip"] = ip
    ua = context.get("ua")
    if isinstance(ua, str) and ua:
        endpoint["svc_name"] = ua
    return endpoint


def _http_request(event: dict[str, Any]) -> dict[str, Any]:
    context = event.get("context") or {}
    if not isinstance(context, dict):
        return {}
    ua = context.get("ua")
    if isinstance(ua, str) and ua:
        return {"user_agent": ua}
    return {}


def _workspace(event: dict[str, Any]) -> dict[str, Any]:
    context = event.get("context") or {}
    if not isinstance(context, dict):
        return {}
    location = context.get("location") or {}
    if not isinstance(location, dict):
        return {}
    out: dict[str, Any] = {}
    if location.get("type"):
        out["type"] = str(location["type"])
    if location.get("id"):
        out["id"] = str(location["id"])
    if location.get("name"):
        out["name"] = str(location["name"])
    if location.get("domain"):
        out["domain"] = str(location["domain"])
    return out


def _channel_info(event: dict[str, Any]) -> dict[str, Any]:
    """Extract a channel object — Slack carries it under entity for channel-scoped
    actions and under details.channel for member-add/remove actions."""
    entity = event.get("entity") or {}
    details = event.get("details") or {}
    channel: dict[str, Any] = {}
    if isinstance(entity, dict) and entity.get("type") in {"channel", "workspace"}:
        inner = entity.get(entity["type"]) if isinstance(entity.get(entity["type"]), dict) else None
        if isinstance(inner, dict):
            if inner.get("id"):
                channel["id"] = str(inner["id"])
            if inner.get("name"):
                channel["name"] = str(inner["name"])
            if inner.get("privacy"):
                channel["privacy"] = str(inner["privacy"])
    if isinstance(details, dict):
        for key in ("channel", "channel_name", "channel_id"):
            if key not in details:
                continue
            value = details[key]
            if isinstance(value, dict):
                if value.get("id") and "id" not in channel:
                    channel["id"] = str(value["id"])
                if value.get("name") and "name" not in channel:
                    channel["name"] = str(value["name"])
                if value.get("privacy") and "privacy" not in channel:
                    channel["privacy"] = str(value["privacy"])
            elif isinstance(value, str) and value:
                if key == "channel_id" and "id" not in channel:
                    channel["id"] = value
                elif key in {"channel_name", "channel"} and "name" not in channel:
                    channel["name"] = value
    return channel


def _workspace_type_marker(event: dict[str, Any]) -> str:
    """Return `internal` / `external` / `` for the workspace involved in this event.

    Slack tags cross-workspace activity in Enterprise Grid by stamping
    `details.workspace_type` or `details.is_external` on entity-level actions.
    We surface both shapes so downstream detectors don't have to recheck."""
    details = event.get("details") or {}
    if isinstance(details, dict):
        wt = details.get("workspace_type")
        if isinstance(wt, str) and wt:
            return wt.lower()
        if details.get("is_external") is True:
            return "external"
        if details.get("is_external") is False:
            return "internal"
    return ""


def _unmapped_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Slack-native preservation under `unmapped.slack.*`.

    Captures fields OCSF 1.8 has no clean slot for so downstream detectors can
    reach for Slack-specific signal without re-parsing the raw audit entry.
    `details` round-trips verbatim."""
    context = event.get("context") or {}
    details = event.get("details") or {}
    payload: dict[str, Any] = {
        "action": event.get("action"),
        "entity_type": (event.get("entity") or {}).get("type") if isinstance(event.get("entity"), dict) else None,
    }
    workspace = _workspace(event)
    if workspace:
        payload["workspace"] = workspace
    channel = _channel_info(event)
    if channel:
        payload["channel"] = channel
    workspace_type = _workspace_type_marker(event)
    if workspace_type:
        payload["workspace_type"] = workspace_type
    if isinstance(context, dict):
        session_id = context.get("session_id")
        if session_id:
            payload["session_id"] = str(session_id)
    if isinstance(details, dict) and details:
        payload["details"] = details
        scopes = details.get("scopes") or details.get("new_scopes")
        if isinstance(scopes, list):
            payload["scopes"] = [str(s) for s in scopes if isinstance(s, (str, int))]
        elif isinstance(scopes, str) and scopes:
            payload["scopes"] = [part.strip() for part in scopes.split(",") if part.strip()]
        app = details.get("app")
        if isinstance(app, dict):
            app_info: dict[str, Any] = {}
            for key in ("id", "name", "is_distributed", "is_directory_approved"):
                if key in app:
                    app_info[key] = app[key]
            if app_info:
                payload["app"] = app_info
        new_role = details.get("new_role") or details.get("role")
        if isinstance(new_role, str) and new_role:
            payload["new_role"] = new_role
        old_role = details.get("previous_role") or details.get("old_role")
        if isinstance(old_role, str) and old_role:
            payload["previous_role"] = old_role
    return payload


def _metadata_uid(event: dict[str, Any]) -> str:
    natural = str(event.get("id") or "").strip()
    if natural:
        return natural
    stable = {
        "date_create": event.get("date_create", ""),
        "action": event.get("action", ""),
        "actorId": ((event.get("actor") or {}).get("user") or {}).get("id", "") if isinstance(event.get("actor"), dict) else "",
        "entityId": ((event.get("entity") or {}).get((event.get("entity") or {}).get("type") or "") or {}).get("id", "") if isinstance(event.get("entity"), dict) else "",
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _record_type(class_uid: int) -> str:
    return {
        AUTH_CLASS_UID: "authentication",
        USER_ACCESS_CLASS_UID: "user_access_management",
        API_ACTIVITY_CLASS_UID: "api_activity",
    }.get(class_uid, "slack_activity")


def _category(class_uid: int) -> tuple[int, str]:
    if class_uid == API_ACTIVITY_CLASS_UID:
        return CATEGORY_APP_UID, CATEGORY_APP_NAME
    return CATEGORY_IAM_UID, CATEGORY_IAM_NAME


def _build_canonical_event(event: dict[str, Any], class_uid: int, activity_id: int) -> dict[str, Any]:
    canonical: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": _record_type(class_uid),
        "source_skill": SKILL_NAME,
        "event_uid": _metadata_uid(event),
        "provider": "Slack",
        "activity_id": activity_id,
        "event_type": str(event.get("action") or ""),
        "severity_id": SEVERITY_INFORMATIONAL,
        "severity": "informational",
        "status_id": STATUS_SUCCESS,
        "status": "success",
        "time_ms": parse_ts_ms(event.get("date_create")),
        "message": str(event.get("action") or _record_type(class_uid)),
        "actor": _actor(event),
        "src_endpoint": _src_endpoint(event),
        "unmapped": {"slack": _unmapped_payload(event)},
    }
    http_request = _http_request(event)
    if http_request:
        canonical["http_request"] = http_request
    user = _entity_user(event)
    if user:
        canonical["user"] = user
    resource = _entity_resource(event)
    if resource:
        canonical["resources"] = [resource]
    return canonical


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    class_uid = {
        "authentication": AUTH_CLASS_UID,
        "user_access_management": USER_ACCESS_CLASS_UID,
        "api_activity": API_ACTIVITY_CLASS_UID,
    }.get(canonical["record_type"], API_ACTIVITY_CLASS_UID)
    class_name = {
        AUTH_CLASS_UID: AUTH_CLASS_NAME,
        USER_ACCESS_CLASS_UID: USER_ACCESS_CLASS_NAME,
        API_ACTIVITY_CLASS_UID: API_ACTIVITY_CLASS_NAME,
    }[class_uid]
    category_uid, category_name = _category(class_uid)
    labels: list[str] = ["saas", "slack", "audit", "ingest"]
    out: dict[str, Any] = {
        "activity_id": canonical["activity_id"],
        "category_uid": category_uid,
        "category_name": category_name,
        "class_uid": class_uid,
        "class_name": class_name,
        "type_uid": class_uid * 100 + canonical["activity_id"],
        "severity_id": canonical["severity_id"],
        "status_id": canonical["status_id"],
        "time": canonical["time_ms"],
        "message": canonical["message"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": labels,
        },
        "unmapped": canonical["unmapped"],
    }
    for field in ("actor", "src_endpoint", "user", "resources", "http_request"):
        if canonical.get(field):
            out[field] = canonical[field]
    if class_uid == API_ACTIVITY_CLASS_UID:
        out["api"] = {"operation": canonical["event_type"], "service": {"name": "slack"}}
    return out


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["output_format"] = "native"
    return native


def validate_event(event: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(event, dict):
        return False, "not a dict"
    for field in ("action", "date_create"):
        if field not in event or event.get(field) in (None, ""):
            return False, f"missing required field: {field}"
    if _classify_action(str(event.get("action") or "")) is None:
        return False, f"unsupported action: {event.get('action')}"
    return True, ""


def convert_event(event: dict[str, Any], output_format: str = "ocsf") -> dict[str, Any]:
    action = str(event.get("action") or "")
    route = _classify_action(action)
    if route is None:
        raise ValueError(f"unsupported action: {action}")
    class_uid, _class_name, activity_id = route
    canonical = _build_canonical_event(event, class_uid, activity_id)
    if output_format == "native":
        return _render_native_event(canonical)
    if output_format == "ocsf":
        return _render_ocsf_event(canonical)
    raise ValueError(f"unsupported output_format: {output_format}")


def iter_raw_events(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
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
        if isinstance(whole.get("entries"), list):
            for entry in whole.get("entries") or []:
                if isinstance(entry, dict):
                    yield entry
            return
        yield whole
        return

    if isinstance(whole, list):
        for entry in whole:
            if isinstance(entry, dict):
                yield entry
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
        if isinstance(obj, dict) and isinstance(obj.get("entries"), list):
            for entry in obj.get("entries") or []:
                if isinstance(entry, dict):
                    yield entry
        elif isinstance(obj, dict):
            yield obj
        else:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_json_shape",
                message=f"skipping line {lineno}: not a JSON object or Slack audit wrapper",
                line=lineno,
            )


def ingest(
    stream: Iterable[str],
    output_format: str = "ocsf",
    unmapped_counts: dict[str, int] | None = None,
) -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    for raw in iter_raw_events(stream):
        ok, reason = validate_event(raw)
        if not ok:
            action = str(raw.get("action") or "")
            if reason.startswith("unsupported action"):
                if unmapped_counts is not None:
                    unmapped_counts[action] = unmapped_counts.get(action, 0) + 1
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="unmapped_event_type",
                    message=f"skipping event: action not in classification map: {action}",
                    event_type=action,
                    event_uid=str(raw.get("id") or ""),
                )
            else:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="invalid_event",
                    message=f"skipping event: {reason}",
                    reason=reason,
                    event_type=action,
                    event_uid=str(raw.get("id") or ""),
                )
            continue
        try:
            yield convert_event(raw, output_format=output_format)
        except Exception as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="convert_error",
                message=f"skipping event: convert error: {exc}",
                error=str(exc),
                event_type=str(raw.get("action") or ""),
                event_uid=str(raw.get("id") or ""),
            )
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert raw Slack Audit Logs API JSON to OCSF or native JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF events (default) or the native canonical projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    unmapped_counts: dict[str, int] = {}
    try:
        for event in ingest(in_stream, output_format=args.output_format, unmapped_counts=unmapped_counts):
            out_stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    if unmapped_counts:
        top = sorted(unmapped_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
        emit_stderr_event(
            SKILL_NAME,
            level="info",
            event="unmapped_event_type_summary",
            message=(
                f"{sum(unmapped_counts.values())} events skipped across "
                f"{len(unmapped_counts)} unmapped Slack action(s)"
            ),
            distinct_event_types=len(unmapped_counts),
            total_skipped=sum(unmapped_counts.values()),
            top_unmapped=[{"event_type": et, "count": n} for et, n in top],
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
