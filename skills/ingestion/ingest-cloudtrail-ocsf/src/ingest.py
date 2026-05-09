"""Convert raw AWS CloudTrail events to OCSF 1.8 API Activity (class 6003).

Input:  CloudTrail JSON — either single events one-per-line (NDJSON) or the
        digest format ({"Records": [...]}). Auto-detected.
Output: JSONL of OCSF 1.8 API Activity events by default, or a documented
        native enriched event shape when --output-format native is selected.

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

SKILL_NAME = "ingest-cloudtrail-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"

# OCSF 1.8 API Activity (6003)
CLASS_UID = 6003
CLASS_NAME = "API Activity"
CATEGORY_UID = 6
CATEGORY_NAME = "Application Activity"

# Activity enum (OCSF 1.8 API Activity)
ACTIVITY_UNKNOWN = 0
ACTIVITY_CREATE = 1
ACTIVITY_READ = 2
ACTIVITY_UPDATE = 3
ACTIVITY_DELETE = 4
ACTIVITY_OTHER = 99

# Status enum
STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

# Severity enum
SEVERITY_INFORMATIONAL = 1


# ---------------------------------------------------------------------------
# Verb → activity_id table
# ---------------------------------------------------------------------------

# Order matters: longer prefixes first so 'Update' matches before 'U'.
_VERB_TABLE = (
    (("Create", "Run", "Start", "Issue", "Provision", "Generate", "Allocate", "Register"), ACTIVITY_CREATE),
    (("Get", "List", "Describe", "View", "Lookup", "Search", "Head", "Read", "Test", "Validate"), ACTIVITY_READ),
    (
        (
            "Update",
            "Modify",
            "Put",
            "Set",
            "Edit",
            "Attach",
            "Associate",
            "Add",
            "Enable",
            "Tag",
            "Untag",
            "Activate",
            "Promote",
            "Restore",
            "Reset",
        ),
        ACTIVITY_UPDATE,
    ),
    (
        (
            "Delete",
            "Remove",
            "Terminate",
            "Stop",
            "Detach",
            "Disable",
            "Disassociate",
            "Cancel",
            "Reject",
            "Revoke",
            "Deregister",
        ),
        ACTIVITY_DELETE,
    ),
)


def infer_activity_id(event_name: str) -> int:
    """Map a CloudTrail eventName to an OCSF API Activity activity_id.

    >>> infer_activity_id("CreateAccessKey")
    1
    >>> infer_activity_id("ListBuckets")
    2
    >>> infer_activity_id("PutBucketPolicy")
    3
    >>> infer_activity_id("DeleteUser")
    4
    >>> infer_activity_id("ConsoleLogin")
    99
    """
    for prefixes, activity in _VERB_TABLE:
        for p in prefixes:
            if event_name.startswith(p):
                return activity
    return ACTIVITY_OTHER


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def parse_ts_ms(ts: str | None) -> int:
    """Parse an ISO-8601 timestamp to Unix epoch milliseconds (UTC).

    Falls back to 'now' if missing or unparseable.
    """
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


# ---------------------------------------------------------------------------
# Resource projection
# ---------------------------------------------------------------------------


def _project_resources(request_params: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Project a CloudTrail requestParameters dict into an OCSF resources[] array.

    Only top-level scalar fields are kept (no recursion). The goal is to give
    detection skills enough context to write rules without dragging the entire
    request body along.
    """
    if not request_params or not isinstance(request_params, dict):
        return []
    out: list[dict[str, Any]] = []
    for key, val in request_params.items():
        if isinstance(val, (str, int, bool, float)) and val != "":
            out.append({"name": str(val), "type": key})
    return out


# ---------------------------------------------------------------------------
# Actor / src_endpoint / api builders
# ---------------------------------------------------------------------------


def _build_actor(user_identity: dict[str, Any]) -> dict[str, Any]:
    """Map CloudTrail userIdentity to an OCSF actor object."""
    actor: dict[str, Any] = {}
    user: dict[str, Any] = {}

    name = user_identity.get("userName") or user_identity.get("principalId") or ""
    if name:
        user["name"] = name
    user_type = user_identity.get("type", "")
    if user_type:
        user["type"] = user_type
    if "arn" in user_identity:
        user["uid"] = user_identity["arn"]
    if "accountId" in user_identity:
        user["account"] = {"uid": user_identity["accountId"]}
    if user:
        actor["user"] = user

    session: dict[str, Any] = {}
    if "accessKeyId" in user_identity:
        session["uid"] = user_identity["accessKeyId"]
    session_ctx = user_identity.get("sessionContext") or {}
    attrs = session_ctx.get("attributes") or {}
    if "creationDate" in attrs:
        session["created_time"] = parse_ts_ms(attrs["creationDate"])
    if "mfaAuthenticated" in attrs:
        session["mfa"] = attrs["mfaAuthenticated"] == "true"
    if session:
        actor["session"] = session

    return actor


def _build_src_endpoint(event: dict[str, Any]) -> dict[str, Any]:
    src: dict[str, Any] = {}
    if "sourceIPAddress" in event:
        src["ip"] = event["sourceIPAddress"]
    if "userAgent" in event:
        src["svc_name"] = event["userAgent"]
    return src


def _build_api(event: dict[str, Any]) -> dict[str, Any]:
    api: dict[str, Any] = {
        "operation": event.get("eventName", ""),
        "service": {"name": event.get("eventSource", "")},
    }
    if "eventID" in event:
        api["request"] = {"uid": event["eventID"]}
    return api


def _build_cloud(event: dict[str, Any]) -> dict[str, Any]:
    cloud: dict[str, Any] = {"provider": "AWS"}
    if "recipientAccountId" in event:
        cloud["account"] = {"uid": event["recipientAccountId"]}
    if "awsRegion" in event:
        cloud["region"] = event["awsRegion"]
    return cloud


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------


def _build_canonical_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert one raw CloudTrail event into the repo's canonical event shape."""
    event_name = raw.get("eventName", "")
    activity_id = infer_activity_id(event_name)
    error_code = raw.get("errorCode")
    status_id = STATUS_FAILURE if error_code else STATUS_SUCCESS

    event_uid = str(raw.get("eventID") or "").strip() or hashlib.sha256(
        json.dumps(
            {
                "eventSource": raw.get("eventSource", ""),
                "eventName": event_name,
                "eventTime": raw.get("eventTime", ""),
                "recipientAccountId": raw.get("recipientAccountId", ""),
                "requestID": raw.get("requestID", ""),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    canonical: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "api_activity",
        "event_uid": event_uid,
        "provider": "AWS",
        "account_uid": raw.get("recipientAccountId", ""),
        "region": raw.get("awsRegion", ""),
        "time_ms": parse_ts_ms(raw.get("eventTime")),
        "event_name": event_name,
        "operation": event_name,
        "service_name": raw.get("eventSource", ""),
        "activity_id": activity_id,
        "activity_name": {1: "create", 2: "read", 3: "update", 4: "delete", 99: "other"}.get(activity_id, "unknown"),
        "status_id": status_id,
        "status": "failure" if error_code else "success",
        "actor": _build_actor(raw.get("userIdentity") or {}),
        "src": _build_src_endpoint(raw),
        "resources": _project_resources(raw.get("requestParameters")),
        "source": {
            "kind": "aws.cloudtrail",
            "request_id": raw.get("requestID", ""),
            "event_id": raw.get("eventID", ""),
            "event_category": raw.get("eventCategory", ""),
        },
    }
    if error_code:
        canonical["status_detail"] = f"{error_code}: {raw.get('errorMessage', '')}".strip(": ").strip()
    return canonical


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    """Render the canonical CloudTrail event as OCSF API Activity."""
    activity_id = int(canonical["activity_id"])
    status_id = int(canonical["status_id"])
    event: dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + activity_id,
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": status_id,
        "time": canonical["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "aws", "cloudtrail", "ingest"],
        },
        "actor": canonical["actor"],
        "src_endpoint": canonical["src"],
        "api": {
            "operation": canonical["operation"],
            "service": {"name": canonical["service_name"]},
            "request": {"uid": canonical["event_uid"]},
        },
        "resources": canonical["resources"],
        "cloud": {
            "provider": canonical["provider"],
            "account": {"uid": canonical["account_uid"]} if canonical["account_uid"] else {},
            "region": canonical["region"],
        },
    }

    cloud = event["cloud"]
    if not cloud.get("account"):
        cloud.pop("account")
    if canonical.get("status_detail"):
        event["status_detail"] = canonical["status_detail"]

    return event


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    """Render the canonical CloudTrail event as the repo's native enriched shape."""
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["source_skill"] = SKILL_NAME
    native["output_format"] = "native"
    return native


def convert_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert one raw CloudTrail event into one OCSF API Activity event."""
    return _render_ocsf_event(_build_canonical_event(raw))


def convert_event_native(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert one raw CloudTrail event into the native enriched event shape."""
    return _render_native_event(_build_canonical_event(raw))


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def iter_raw_events(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    """Yield raw CloudTrail event dicts from a JSONL or Records-wrapped stream.

    Auto-detects the format:
      - whole-document parse first: handles `{"Records": [...]}` (CloudTrail
        digest format), a single event dict, or a top-level array of events.
      - falls back to line-by-line NDJSON if the whole-document parse fails.
      - blank lines and parse failures are skipped (warning to stderr).
    """
    buf: list[str] = list(stream)
    if not buf:
        return

    # Reconstruct the full text with explicit newlines so the line-by-line
    # fallback works whether the input came from a real file (lines already
    # end in \n) or from a list of pre-split strings (no newlines).
    full = "\n".join(line.rstrip("\n") for line in buf).strip()
    if not full:
        return

    # First try whole-document parse (CloudTrail digest files are single
    # multi-line JSON objects, not NDJSON).
    try:
        whole = json.loads(full)
    except json.JSONDecodeError:
        whole = None

    if isinstance(whole, dict) and "Records" in whole:
        for r in whole.get("Records") or []:
            if isinstance(r, dict):
                yield r
        return
    if isinstance(whole, dict):
        yield whole
        return
    if isinstance(whole, list):
        for r in whole:
            if isinstance(r, dict):
                yield r
        return

    # Fall back to line-by-line NDJSON, iterating the ORIGINAL buffer so
    # each entry is parsed independently.
    for lineno, raw_line in enumerate(buf, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=f"skipping line {lineno}: json parse failed: {e}",
                line=lineno,
            )
            continue
        if isinstance(obj, dict) and "Records" in obj:
            for r in obj.get("Records") or []:
                if isinstance(r, dict):
                    yield r
        elif isinstance(obj, dict):
            yield obj
        else:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_json_shape",
                message=f"skipping line {lineno}: not a JSON object or Records wrapper",
                line=lineno,
            )


def ingest(stream: Iterable[str], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    for raw in iter_raw_events(stream):
        try:
            canonical = _build_canonical_event(raw)
            if output_format == "native":
                yield _render_native_event(canonical)
            else:
                yield _render_ocsf_event(canonical)
        except Exception as e:  # defence-in-depth — never crash the pipeline
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="convert_error",
                message=f"skipping event: convert error: {e}",
            )
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert raw CloudTrail JSON to OCSF 1.8 API Activity JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument("--output-format", choices=("ocsf", "native"), default="ocsf", help="Render OCSF events or the native enriched event shape.")
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
