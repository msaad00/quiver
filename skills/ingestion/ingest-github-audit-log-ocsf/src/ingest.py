"""Convert raw GitHub Organization Audit Log records to OCSF 1.8 events.

Input:  GitHub Organization Audit Log rows (JSON array, single object, NDJSON,
        or `{ "audit_log": [...] }` wrapper).
Output: JSONL of either OCSF 1.8 events or repo-owned native records.

The default route is OCSF API Activity 6003. IAM-shaped org and team
membership actions route to User Access Management 3005, and the
authentication-family actions (account.login, account.failed_login)
route to Authentication 3002. See SKILL.md for the full action list.

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

SKILL_NAME = "ingest-github-audit-log-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
OUTPUT_FORMATS = ("ocsf", "native")

API_ACTIVITY_CLASS_UID = 6003
API_ACTIVITY_CLASS_NAME = "API Activity"
API_ACTIVITY_CATEGORY_UID = 6
API_ACTIVITY_CATEGORY_NAME = "Application Activity"
API_ACTIVITY_OTHER = 99
API_ACTIVITY_CREATE = 1
API_ACTIVITY_READ = 2
API_ACTIVITY_UPDATE = 3
API_ACTIVITY_DELETE = 4

AUTH_CLASS_UID = 3002
AUTH_CLASS_NAME = "Authentication"
AUTH_CATEGORY_UID = 3
AUTH_CATEGORY_NAME = "Identity & Access Management"
AUTH_ACTIVITY_LOGON = 1
AUTH_ACTIVITY_LOGOFF = 2
AUTH_ACTIVITY_OTHER = 99

USER_ACCESS_CLASS_UID = 3005
USER_ACCESS_CLASS_NAME = "User Access Management"
USER_ACCESS_ASSIGN = 1
USER_ACCESS_REVOKE = 2
USER_ACCESS_OTHER = 99

STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

SEVERITY_UNKNOWN = 0
SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4

# IAM-shaped actions route to User Access Management 3005.
_USER_ACCESS_EVENT_MAP: dict[str, int] = {
    "org.add_member": USER_ACCESS_ASSIGN,
    "org.update_member": USER_ACCESS_OTHER,
    "org.remove_member": USER_ACCESS_REVOKE,
    "team.add_member": USER_ACCESS_ASSIGN,
    "team.remove_member": USER_ACCESS_REVOKE,
}

# Authentication-family actions route to Authentication 3002.
_AUTH_EVENT_MAP: dict[str, int] = {
    "account.login": AUTH_ACTIVITY_LOGON,
    "account.failed_login": AUTH_ACTIVITY_LOGON,
}

# Recognized API Activity actions (action → OCSF activity_id). Anything not
# in this map plus the IAM/auth maps above is treated as an unmapped action
# and counted via `unmapped_event_type` telemetry.
_API_ACTIVITY_EVENT_MAP: dict[str, int] = {
    # Org-level secrets (Actions / Codespaces / Dependabot)
    "actions.org_secret_create": API_ACTIVITY_CREATE,
    "actions.org_secret_update": API_ACTIVITY_UPDATE,
    "actions.org_secret_remove": API_ACTIVITY_DELETE,
    "codespaces.org_secret_create": API_ACTIVITY_CREATE,
    "codespaces.org_secret_update": API_ACTIVITY_UPDATE,
    "codespaces.org_secret_remove": API_ACTIVITY_DELETE,
    "dependabot_secrets.create": API_ACTIVITY_CREATE,
    "dependabot_secrets.update": API_ACTIVITY_UPDATE,
    "dependabot_secrets.remove": API_ACTIVITY_DELETE,
    # PAT family
    "personal_access_token.create": API_ACTIVITY_CREATE,
    "personal_access_token.access_granted": API_ACTIVITY_CREATE,
    "personal_access_token.access_revoked": API_ACTIVITY_DELETE,
    "personal_access_token.request_created": API_ACTIVITY_OTHER,
    "personal_access_token.request_approved": API_ACTIVITY_OTHER,
    "personal_access_token.request_denied": API_ACTIVITY_OTHER,
    # Repo + workflow family
    "repo.create": API_ACTIVITY_CREATE,
    "repo.destroy": API_ACTIVITY_DELETE,
    "repo.transfer": API_ACTIVITY_UPDATE,
    "repo.archived": API_ACTIVITY_UPDATE,
    "repo.access": API_ACTIVITY_UPDATE,
    "repo.add_member": API_ACTIVITY_UPDATE,
    "repo.remove_member": API_ACTIVITY_UPDATE,
    "workflows.completed_workflow_run": API_ACTIVITY_OTHER,
    "workflows.created_workflow_run": API_ACTIVITY_CREATE,
    "workflows.deleted_workflow_run": API_ACTIVITY_DELETE,
    # Org + team admin
    "org.create": API_ACTIVITY_CREATE,
    "org.delete": API_ACTIVITY_DELETE,
    "org.update_default_repository_permission": API_ACTIVITY_UPDATE,
    "team.create": API_ACTIVITY_CREATE,
    "team.destroy": API_ACTIVITY_DELETE,
    # Git protocol
    "git.clone": API_ACTIVITY_READ,
    "git.fetch": API_ACTIVITY_READ,
    "git.push": API_ACTIVITY_UPDATE,
    # Members (org-level)
    "members.invite": API_ACTIVITY_OTHER,
    "members.uninvite": API_ACTIVITY_OTHER,
}


def parse_ts_ms(ts: str | int | None) -> int:
    """Accept RFC3339 strings or millisecond integers (GitHub `created_at`)."""
    if ts is None:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    if isinstance(ts, (int, float)):
        # GitHub `@timestamp` is epoch ms; tolerate seconds for safety.
        value = int(ts)
        if value < 10_000_000_000:  # seconds
            value *= 1000
        return value
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (ValueError, AttributeError):
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def severity_for_action(action: str) -> int:
    """Most GitHub audit rows are informational; failed-auth is low."""
    if action == "account.failed_login":
        return SEVERITY_LOW
    return SEVERITY_INFORMATIONAL


def status_from_action(action: str) -> int:
    if action == "account.failed_login":
        return STATUS_FAILURE
    return STATUS_SUCCESS


def _classify_event(action: str) -> tuple[int, str, int] | None:
    if action in _USER_ACCESS_EVENT_MAP:
        return USER_ACCESS_CLASS_UID, USER_ACCESS_CLASS_NAME, _USER_ACCESS_EVENT_MAP[action]
    if action in _AUTH_EVENT_MAP:
        return AUTH_CLASS_UID, AUTH_CLASS_NAME, _AUTH_EVENT_MAP[action]
    if action in _API_ACTIVITY_EVENT_MAP:
        return API_ACTIVITY_CLASS_UID, API_ACTIVITY_CLASS_NAME, _API_ACTIVITY_EVENT_MAP[action]
    return None


def _actor(event: dict[str, Any]) -> dict[str, Any]:
    actor_name = str(event.get("actor") or "").strip()
    actor_id = event.get("actor_id")
    actor_location = event.get("actor_location") or {}
    user: dict[str, Any] = {}
    if actor_id is not None:
        user["uid"] = str(actor_id)
    if actor_name:
        user["name"] = actor_name
    if isinstance(actor_location, dict):
        country = actor_location.get("country_code") or actor_location.get("country")
        if isinstance(country, str) and country:
            user["domain"] = country  # OCSF user has no country slot; surface under domain
    if not user:
        return {}
    return {"user": user}


def _src_endpoint(event: dict[str, Any]) -> dict[str, Any]:
    endpoint: dict[str, Any] = {}
    ip = event.get("actor_ip") or ""
    if isinstance(ip, str) and ip:
        endpoint["ip"] = ip
    user_agent = event.get("user_agent") or ""
    if isinstance(user_agent, str) and user_agent:
        endpoint["svc_name"] = user_agent
    actor_location = event.get("actor_location") or {}
    if isinstance(actor_location, dict):
        location: dict[str, Any] = {}
        for src_key, dst_key in (
            ("country_code", "country"),
            ("country", "country"),
            ("region", "region"),
        ):
            value = actor_location.get(src_key)
            if isinstance(value, str) and value and dst_key not in location:
                location[dst_key] = value
        if location:
            endpoint["location"] = location
    return endpoint


def _http_request(event: dict[str, Any]) -> dict[str, Any]:
    user_agent = event.get("user_agent") or ""
    if not isinstance(user_agent, str) or not user_agent:
        return {}
    return {"user_agent": user_agent}


def _resources(event: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    repo = event.get("repo") or event.get("repository")
    if isinstance(repo, str) and repo:
        resources.append({"name": repo, "type": "Repository"})
    team = event.get("team")
    if isinstance(team, str) and team:
        resources.append({"name": team, "type": "Team"})
    org = event.get("org") or event.get("org_name")
    if isinstance(org, str) and org:
        resources.append({"name": org, "type": "Organization"})
    return resources


def _api_block(event: dict[str, Any]) -> dict[str, Any]:
    action = str(event.get("action") or "").strip()
    api: dict[str, Any] = {"operation": action}
    if "/" in action or "." in action:
        service_name = action.split(".", 1)[0] if "." in action else action.split("/", 1)[0]
        api["service"] = {"name": f"github.{service_name}"} if service_name else {"name": "github"}
    else:
        api["service"] = {"name": "github"}
    return api


_UNMAPPED_PASSTHROUGH_KEYS = (
    "action",
    "business",
    "business_id",
    "org",
    "org_id",
    "org_name",
    "repo",
    "repo_id",
    "team",
    "team_id",
    "external_identity_nameid",
    "external_identity_username",
    "operation_type",
    "permission",
    "visibility",
    "selected_repositories",
    "selected_repository_ids",
    "before_visibility",
    "before_selected_repositories",
    "before_selected_repository_ids",
    "secret_name",
    "secret_type",
    "workflow_id",
    "workflow_log_excerpt",
    "token_id",
    "scopes",
    "actor_session_id",
    "request_id",
    "transport_protocol",
    "transport_protocol_name",
    "hashed_token",
    "programmatic_access_type",
    "fingerprint",
)


def _unmapped_payload(event: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"action": str(event.get("action") or "")}
    for key in _UNMAPPED_PASSTHROUGH_KEYS:
        if key in event and event[key] is not None:
            payload[key] = event[key]
    return payload


def _metadata_uid(event: dict[str, Any]) -> str:
    document_id = str(event.get("_document_id") or event.get("document_id") or "").strip()
    if document_id:
        return document_id
    natural = str(event.get("id") or "").strip()
    if natural:
        return natural
    stable = {
        "@timestamp": event.get("@timestamp") or event.get("created_at") or "",
        "action": event.get("action") or "",
        "actor": event.get("actor") or "",
        "actor_id": event.get("actor_id") or "",
        "repo": event.get("repo") or "",
        "request_id": event.get("request_id") or "",
    }
    return hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _status_name(status_id: int) -> str:
    return {
        STATUS_SUCCESS: "success",
        STATUS_FAILURE: "failure",
        STATUS_UNKNOWN: "unknown",
    }.get(status_id, "unknown")


def _severity_name(severity_id: int) -> str:
    return {
        SEVERITY_INFORMATIONAL: "informational",
        SEVERITY_LOW: "low",
        SEVERITY_MEDIUM: "medium",
        SEVERITY_HIGH: "high",
        SEVERITY_UNKNOWN: "unknown",
    }.get(severity_id, "unknown")


def _record_type(class_uid: int) -> str:
    return {
        API_ACTIVITY_CLASS_UID: "api_activity",
        AUTH_CLASS_UID: "authentication",
        USER_ACCESS_CLASS_UID: "user_access_management",
    }.get(class_uid, "api_activity")


def _category_for(class_uid: int) -> tuple[int, str]:
    return {
        API_ACTIVITY_CLASS_UID: (API_ACTIVITY_CATEGORY_UID, API_ACTIVITY_CATEGORY_NAME),
        AUTH_CLASS_UID: (AUTH_CATEGORY_UID, AUTH_CATEGORY_NAME),
        USER_ACCESS_CLASS_UID: (AUTH_CATEGORY_UID, AUTH_CATEGORY_NAME),
    }.get(class_uid, (API_ACTIVITY_CATEGORY_UID, API_ACTIVITY_CATEGORY_NAME))


def _class_name_for(class_uid: int) -> str:
    return {
        API_ACTIVITY_CLASS_UID: API_ACTIVITY_CLASS_NAME,
        AUTH_CLASS_UID: AUTH_CLASS_NAME,
        USER_ACCESS_CLASS_UID: USER_ACCESS_CLASS_NAME,
    }.get(class_uid, API_ACTIVITY_CLASS_NAME)


def _privileges(event: dict[str, Any]) -> list[str]:
    permission = event.get("permission")
    if isinstance(permission, str) and permission:
        return [permission]
    role = event.get("role") or event.get("team_role")
    if isinstance(role, str) and role:
        return [role]
    return [str(event.get("action") or "")]


def _build_canonical_event(
    event: dict[str, Any], class_uid: int, activity_id: int
) -> dict[str, Any]:
    action = str(event.get("action") or "")
    status_id = status_from_action(action)
    severity_id = severity_for_action(action)
    canonical: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": _record_type(class_uid),
        "source_skill": SKILL_NAME,
        "event_uid": _metadata_uid(event),
        "provider": "GitHub",
        "activity_id": activity_id,
        "event_type": action,
        "severity_id": severity_id,
        "severity": _severity_name(severity_id),
        "status_id": status_id,
        "status": _status_name(status_id),
        "time_ms": parse_ts_ms(event.get("@timestamp") or event.get("created_at")),
        "message": str(event.get("action") or _record_type(class_uid)),
        "actor": _actor(event),
        "src_endpoint": _src_endpoint(event),
        "api": _api_block(event),
        "unmapped": {"github": _unmapped_payload(event)},
    }
    http_request = _http_request(event)
    if http_request:
        canonical["http_request"] = http_request
    resources = _resources(event)
    if resources:
        canonical["resources"] = resources
    if class_uid == USER_ACCESS_CLASS_UID:
        canonical["privileges"] = _privileges(event)
    return canonical


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    class_uid = {
        "api_activity": API_ACTIVITY_CLASS_UID,
        "authentication": AUTH_CLASS_UID,
        "user_access_management": USER_ACCESS_CLASS_UID,
    }.get(canonical["record_type"], API_ACTIVITY_CLASS_UID)
    category_uid, category_name = _category_for(class_uid)
    class_name = _class_name_for(class_uid)
    labels: list[str] = ["github", "audit-log", "ingest"]
    if class_uid == USER_ACCESS_CLASS_UID:
        labels.append("identity")
    if class_uid == AUTH_CLASS_UID:
        labels.append("authentication")
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
        "api": canonical["api"],
        "unmapped": canonical["unmapped"],
    }
    for field in (
        "actor",
        "src_endpoint",
        "resources",
        "http_request",
        "privileges",
    ):
        if canonical.get(field):
            out[field] = canonical[field]
    return out


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["output_format"] = "native"
    return native


def validate_event(event: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(event, dict):
        return False, "not a dict"
    action = event.get("action")
    if not action:
        return False, "missing required field: action"
    if not (event.get("@timestamp") or event.get("created_at")):
        return False, "missing required field: @timestamp"
    if _classify_event(str(action)) is None:
        return False, f"unsupported action: {action}"
    return True, ""


def convert_event(event: dict[str, Any], output_format: str = "ocsf") -> dict[str, Any]:
    action = str(event.get("action") or "")
    route = _classify_event(action)
    if route is None:
        raise ValueError(f"unsupported action: {action}")
    class_uid, _class_name, activity_id = route
    canonical = _build_canonical_event(event, class_uid, activity_id)
    if output_format == "native":
        return _render_native_event(canonical)
    if output_format == "ocsf":
        return _render_ocsf_event(canonical)
    raise ValueError(f"unsupported output_format `{output_format}`")


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
        # Wrapper shape: {"audit_log": [...]}.
        wrapped = whole.get("audit_log")
        if isinstance(wrapped, list):
            for event in wrapped:
                if isinstance(event, dict):
                    yield event
            return
        yield whole
        return

    if isinstance(whole, list):
        for event in whole:
            if isinstance(event, dict):
                yield event
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
        if isinstance(obj, dict) and isinstance(obj.get("audit_log"), list):
            for event in obj["audit_log"]:
                if isinstance(event, dict):
                    yield event
        elif isinstance(obj, dict):
            yield obj
        else:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_json_shape",
                message=f"skipping line {lineno}: not a JSON object or GitHub audit-log wrapper",
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
                    event_uid=str(raw.get("_document_id") or raw.get("id") or ""),
                )
            else:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="invalid_event",
                    message=f"skipping event: {reason}",
                    reason=reason,
                    event_type=action,
                    event_uid=str(raw.get("_document_id") or raw.get("id") or ""),
                )
            continue
        try:
            yield convert_event(raw, output_format=output_format)
        except Exception as exc:  # noqa: BLE001 — telemetry, then continue
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="convert_error",
                message=f"skipping event: convert error: {exc}",
                error=str(exc),
                event_type=str(raw.get("action") or ""),
                event_uid=str(raw.get("_document_id") or raw.get("id") or ""),
            )
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert raw GitHub Organization Audit Log JSON to OCSF or native JSONL.",
    )
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
        for event in ingest(
            in_stream,
            output_format=args.output_format,
            unmapped_counts=unmapped_counts,
        ):
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
                f"{len(unmapped_counts)} unmapped GitHub action(s)"
            ),
            distinct_event_types=len(unmapped_counts),
            total_skipped=sum(unmapped_counts.values()),
            top_unmapped=[{"event_type": action, "count": n} for action, n in top],
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
