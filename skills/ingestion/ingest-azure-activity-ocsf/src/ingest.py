"""Convert raw Azure Activity Logs to OCSF or repo-native API Activity."""

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

SKILL_NAME = "ingest-azure-activity-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"

CLASS_UID = 6003
CLASS_NAME = "API Activity"
CATEGORY_UID = 6
CATEGORY_NAME = "Application Activity"

ACTIVITY_UNKNOWN = 0
ACTIVITY_CREATE = 1
ACTIVITY_READ = 2
ACTIVITY_UPDATE = 3
ACTIVITY_DELETE = 4
ACTIVITY_OTHER = 99

STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

SEVERITY_INFORMATIONAL = 1

_VERB_MAP = {
    "WRITE": ACTIVITY_CREATE,
    "CREATE": ACTIVITY_CREATE,
    "REGENERATE": ACTIVITY_CREATE,
    "GENERATEKEY": ACTIVITY_CREATE,
    "READ": ACTIVITY_READ,
    "LIST": ACTIVITY_READ,
    "GET": ACTIVITY_READ,
    "LISTKEYS": ACTIVITY_READ,
    "LISTACCOUNTSAS": ACTIVITY_READ,
    "LISTSERVICESAS": ACTIVITY_READ,
    "VALIDATE": ACTIVITY_READ,
    "UPDATE": ACTIVITY_UPDATE,
    "MOVE": ACTIVITY_UPDATE,
    "RESTART": ACTIVITY_UPDATE,
    "START": ACTIVITY_UPDATE,
    "DELETE": ACTIVITY_DELETE,
    "STOP": ACTIVITY_DELETE,
    "DEALLOCATE": ACTIVITY_DELETE,
}


def infer_activity_id(operation_name: str) -> int:
    if not operation_name:
        return ACTIVITY_OTHER
    segments = [s.upper() for s in operation_name.split("/") if s]
    for segment in reversed(segments):
        if segment == "ACTION":
            continue
        if segment in _VERB_MAP:
            return _VERB_MAP[segment]
    return ACTIVITY_OTHER


def _service_name_from_operation(operation_name: str) -> str:
    if not operation_name:
        return ""
    return operation_name.split("/", 1)[0].lower()


def _resource_type_from_operation(operation_name: str) -> str:
    parts = operation_name.split("/")
    if len(parts) >= 2:
        return parts[1].lower()
    return ""


def parse_ts_ms(ts: str | None) -> int:
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = ts.replace("Z", "+00:00")
        if "." in cleaned:
            head, _, tail = cleaned.partition(".")
            frac, sep, tz = tail.partition("+")
            if not sep:
                frac, sep, tz = tail.partition("-")
            if frac and len(frac) > 6:
                frac = frac[:6]
            cleaned = head + "." + frac + (sep + tz if sep else "")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _status_id_and_detail(entry: dict[str, Any]) -> tuple[int, str | None]:
    result_type = (entry.get("resultType") or "").lower()
    result_signature = entry.get("resultSignature") or ""

    if result_type == "success":
        return STATUS_SUCCESS, None
    if result_type == "failure":
        return STATUS_FAILURE, result_signature or None

    props = entry.get("properties") or {}
    code = props.get("statusCode") or ""
    if isinstance(code, str):
        if code.isdigit():
            n = int(code)
            if 200 <= n < 300:
                return STATUS_SUCCESS, None
            if 400 <= n < 600:
                return STATUS_FAILURE, code
        elif code in ("OK", "Accepted", "Created", "NoContent"):
            return STATUS_SUCCESS, None
        elif code in ("Forbidden", "Unauthorized", "BadRequest", "NotFound", "InternalServerError"):
            return STATUS_FAILURE, code

    return STATUS_UNKNOWN, None


def _build_actor(entry: dict[str, Any]) -> dict[str, Any]:
    actor: dict[str, Any] = {}
    user: dict[str, Any] = {}
    identity = entry.get("identity") or {}
    claims = identity.get("claims") or {}
    upn_key = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
    name = claims.get(upn_key) or claims.get("upn") or claims.get("name") or claims.get("appid") or entry.get("caller", "")
    if name:
        user["name"] = name
    appid = claims.get("appid")
    if appid:
        user["uid"] = appid
        if not (claims.get(upn_key) or claims.get("upn") or claims.get("name")):
            user["type"] = "ServicePrincipal"
    if user:
        actor["user"] = user
    return actor


def _build_src_endpoint(entry: dict[str, Any]) -> dict[str, Any]:
    src: dict[str, Any] = {}
    if "callerIpAddress" in entry and entry["callerIpAddress"]:
        src["ip"] = entry["callerIpAddress"]
    return src


def _build_api(entry: dict[str, Any]) -> dict[str, Any]:
    op = entry.get("operationName", "")
    api: dict[str, Any] = {
        "operation": op,
        "service": {"name": _service_name_from_operation(op)},
    }
    if "correlationId" in entry:
        api["request"] = {"uid": entry["correlationId"]}
    return api


def _build_resources(entry: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    rid = entry.get("resourceId") or ""
    if rid:
        rtype = _resource_type_from_operation(entry.get("operationName", ""))
        resources.append({"name": rid, "type": rtype})
    return resources


def _extract_subscription_id(resource_id: str) -> str:
    if not resource_id:
        return ""
    parts = resource_id.upper().split("/")
    try:
        idx = parts.index("SUBSCRIPTIONS")
        if idx + 1 < len(parts):
            return parts[idx + 1].lower()
    except ValueError:
        pass
    return ""


def _build_cloud(entry: dict[str, Any]) -> dict[str, Any]:
    cloud: dict[str, Any] = {"provider": "Azure"}
    sub = _extract_subscription_id(entry.get("resourceId") or "")
    if sub:
        cloud["account"] = {"uid": sub}
    props = entry.get("properties") or {}
    if isinstance(props, dict) and "location" in props:
        cloud["region"] = props["location"]
    return cloud


def _build_canonical_event(entry: dict[str, Any]) -> dict[str, Any]:
    operation_name = entry.get("operationName", "")
    activity_id = infer_activity_id(operation_name)
    status_id, status_detail = _status_id_and_detail(entry)
    event_uid = str(entry.get("eventDataId") or entry.get("correlationId") or "").strip() or hashlib.sha256(
        json.dumps(
            {
                "time": entry.get("time", ""),
                "operationName": operation_name,
                "resourceId": entry.get("resourceId", ""),
                "caller": entry.get("caller", ""),
                "correlationId": entry.get("correlationId", ""),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    cloud = _build_cloud(entry)
    account_uid = ((cloud.get("account") or {}).get("uid")) or ""
    region = cloud.get("region") or ""

    return {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "api_activity",
        "event_uid": event_uid,
        "provider": "Azure",
        "account_uid": account_uid,
        "region": region,
        "time_ms": parse_ts_ms(entry.get("time")),
        "event_name": operation_name,
        "operation": operation_name,
        "service_name": _service_name_from_operation(operation_name),
        "activity_id": activity_id,
        "activity_name": {1: "create", 2: "read", 3: "update", 4: "delete", 99: "other"}.get(activity_id, "unknown"),
        "status_id": status_id,
        "status": {STATUS_SUCCESS: "success", STATUS_FAILURE: "failure"}.get(status_id, "unknown"),
        "status_detail": status_detail or "",
        "actor": _build_actor(entry),
        "src": _build_src_endpoint(entry),
        "api": _build_api(entry),
        "resources": _build_resources(entry),
        "cloud": cloud,
        "source": {
            "kind": "azure.activity-log",
            "category": entry.get("category", ""),
            "correlation_id": entry.get("correlationId", ""),
        },
    }


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    event: dict[str, Any] = {
        "activity_id": canonical["activity_id"],
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + canonical["activity_id"],
        "severity_id": SEVERITY_INFORMATIONAL,
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
            "labels": ["detection-engineering", "azure", "activity-log", "ingest"],
        },
        "actor": canonical["actor"],
        "src_endpoint": canonical["src"],
        "api": canonical["api"],
        "resources": canonical["resources"],
        "cloud": canonical["cloud"],
    }
    if canonical["status_detail"]:
        event["status_detail"] = canonical["status_detail"]
    return event


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["source_skill"] = SKILL_NAME
    native["output_format"] = "native"
    return native


def convert_event(entry: dict[str, Any]) -> dict[str, Any]:
    return _render_ocsf_event(_build_canonical_event(entry))


def convert_event_native(entry: dict[str, Any]) -> dict[str, Any]:
    return _render_native_event(_build_canonical_event(entry))


def iter_raw_entries(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    buf: list[str] = list(stream)
    if not buf:
        return

    full = "\n".join(line.rstrip("\n") for line in buf).strip()
    if not full:
        return

    try:
        whole = json.loads(full)
    except json.JSONDecodeError:
        whole = None

    if isinstance(whole, list):
        for record in whole:
            if isinstance(record, dict):
                yield record
        return
    if isinstance(whole, dict):
        if "records" in whole and isinstance(whole["records"], list):
            for record in whole["records"]:
                if isinstance(record, dict):
                    yield record
            return
        yield whole
        return

    for lineno, raw_line in enumerate(buf, start=1):
        line = raw_line.strip()
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


def ingest(stream: Iterable[str], *, output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    for raw in iter_raw_entries(stream):
        try:
            event = convert_event_native(raw) if output_format == "native" else convert_event(raw)
        except Exception as exc:
            print(f"[{SKILL_NAME}] skipping entry: convert error: {exc}", file=sys.stderr)
            continue
        yield event


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert raw Azure Activity Logs to API Activity JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=("ocsf", "native"),
        default="ocsf",
        help="Output wire format. Default: ocsf.",
    )
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
