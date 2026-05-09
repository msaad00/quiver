"""Convert raw Kubernetes audit logs to API activity events.

Input:  K8s audit.k8s.io/v1 Event objects — either JSONL (one per line) or a
        top-level array. The skill filters for ResponseComplete / Panic stages.
Output: JSONL of OCSF 1.8 API Activity events by default, or a documented
        native enriched event shape when --output-format native is selected.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import copy
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

SKILL_NAME = "ingest-k8s-audit-ocsf"
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
OUTPUT_FORMATS = ("ocsf", "native")

TERMINAL_STAGES = {"ResponseComplete", "Panic"}
K8S_API_GROUP = "audit.k8s.io/v1"
SERVICE_ACCOUNT_PREFIX = "system:serviceaccount:"


# ---------------------------------------------------------------------------
# Verb → activity_id (K8s verbs are standard, no prefix matching needed)
# ---------------------------------------------------------------------------

_VERB_MAP = {
    "create": ACTIVITY_CREATE,
    "get": ACTIVITY_READ,
    "list": ACTIVITY_READ,
    "watch": ACTIVITY_READ,
    "proxy": ACTIVITY_READ,
    "update": ACTIVITY_UPDATE,
    "patch": ACTIVITY_UPDATE,
    "delete": ACTIVITY_DELETE,
    "deletecollection": ACTIVITY_DELETE,
}


def infer_activity_id(verb: str) -> int:
    """Map a K8s audit verb to an OCSF API Activity activity_id.

    >>> infer_activity_id("list")
    2
    >>> infer_activity_id("create")
    1
    >>> infer_activity_id("delete")
    4
    >>> infer_activity_id("connect")
    99
    """
    return _VERB_MAP.get((verb or "").lower(), ACTIVITY_OTHER)


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def _status_id_and_detail(response_status: dict[str, Any] | None) -> tuple[int, str | None]:
    if not response_status:
        return STATUS_UNKNOWN, None
    code = response_status.get("code")
    if code is None:
        return STATUS_UNKNOWN, None
    try:
        c = int(code)
    except (TypeError, ValueError):
        return STATUS_UNKNOWN, None
    if 200 <= c < 300:
        return STATUS_SUCCESS, None
    if 400 <= c < 600:
        msg = response_status.get("message") or ""
        reason = response_status.get("reason") or ""
        detail_parts = [p for p in (reason, msg) if p]
        return STATUS_FAILURE, ": ".join(detail_parts) if detail_parts else None
    return STATUS_UNKNOWN, None


# ---------------------------------------------------------------------------
# Service-account helpers
# ---------------------------------------------------------------------------


def is_service_account(username: str) -> bool:
    """True iff the username matches system:serviceaccount:<ns>:<name>."""
    return bool(username) and username.startswith(SERVICE_ACCOUNT_PREFIX)


def service_account_namespace(username: str) -> str | None:
    """Extract the namespace from a service account username, or None."""
    if not is_service_account(username):
        return None
    rest = username[len(SERVICE_ACCOUNT_PREFIX) :]
    parts = rest.split(":", 1)
    return parts[0] if parts else None


# ---------------------------------------------------------------------------
# Field builders
# ---------------------------------------------------------------------------


def _build_actor(entry: dict[str, Any]) -> dict[str, Any]:
    user_obj = entry.get("user") or {}
    actor: dict[str, Any] = {}
    user: dict[str, Any] = {}

    username = user_obj.get("username", "")
    if username:
        user["name"] = username

    uid = user_obj.get("uid")
    if uid:
        user["uid"] = uid

    groups = user_obj.get("groups") or []
    if groups:
        user["groups"] = [{"name": g} for g in groups]

    if is_service_account(username):
        user["type"] = "ServiceAccount"

    if user:
        actor["user"] = user

    return actor


def _build_src_endpoint(entry: dict[str, Any]) -> dict[str, Any]:
    src: dict[str, Any] = {}
    ips = entry.get("sourceIPs") or []
    if ips:
        src["ip"] = ips[0]
    if entry.get("userAgent"):
        src["svc_name"] = entry["userAgent"]
    return src


def _build_api(entry: dict[str, Any]) -> dict[str, Any]:
    api: dict[str, Any] = {
        "operation": (entry.get("verb") or "").lower(),
        "service": {"name": "kubernetes"},
    }
    if "auditID" in entry:
        api["request"] = {"uid": entry["auditID"]}
    return api


def _build_resources(entry: dict[str, Any]) -> list[dict[str, Any]]:
    obj_ref = entry.get("objectRef") or {}
    if not obj_ref:
        return []
    r: dict[str, Any] = {}
    res_type = obj_ref.get("resource") or ""
    name = obj_ref.get("name") or ""
    if res_type:
        r["type"] = res_type
    if name:
        r["name"] = name
    if obj_ref.get("namespace"):
        r["namespace"] = obj_ref["namespace"]
    if obj_ref.get("apiGroup"):
        r["group"] = obj_ref["apiGroup"]
    if obj_ref.get("apiVersion"):
        r["version"] = obj_ref["apiVersion"]
    if obj_ref.get("subresource"):
        r["subresource"] = obj_ref["subresource"]
    return [r] if r else []


def _build_cloud() -> dict[str, Any]:
    return {"provider": "Kubernetes"}


def _metadata_labels(entry: dict[str, Any]) -> list[str]:
    labels = ["detection-engineering", "kubernetes", "audit-log", "ingest"]
    annotations = entry.get("annotations") or {}
    decision = annotations.get("authorization.k8s.io/decision")
    if decision == "allow":
        labels.append("authz-allow")
    elif decision == "forbid":
        labels.append("authz-deny")
    return labels


def _unmapped_payload(entry: dict[str, Any]) -> dict[str, Any]:
    """Preserve raw K8s audit fields with no clean first-class OCSF slot."""
    payload: dict[str, Any] = {}
    request_object = entry.get("requestObject")
    if request_object is not None:
        payload["request_object"] = copy.deepcopy(request_object)
    response_object = entry.get("responseObject")
    if response_object is not None:
        payload["response_object"] = copy.deepcopy(response_object)
    object_ref = entry.get("objectRef")
    if object_ref is not None:
        payload["object_ref"] = copy.deepcopy(object_ref)
    return payload


def _activity_name(activity_id: int) -> str:
    return {
        ACTIVITY_CREATE: "create",
        ACTIVITY_READ: "read",
        ACTIVITY_UPDATE: "update",
        ACTIVITY_DELETE: "delete",
        ACTIVITY_OTHER: "other",
    }.get(activity_id, "unknown")


def _status_name(status_id: int) -> str:
    return {
        STATUS_SUCCESS: "success",
        STATUS_FAILURE: "failure",
        STATUS_UNKNOWN: "unknown",
    }.get(status_id, "unknown")


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------


def _build_canonical_event(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one K8s audit Event into the repo's canonical event shape."""
    if entry.get("kind") != "Event":
        return None
    if entry.get("apiVersion") != K8S_API_GROUP:
        return None
    if entry.get("stage") not in TERMINAL_STAGES:
        return None

    verb = entry.get("verb", "")
    activity_id = infer_activity_id(verb)
    status_id, status_detail = _status_id_and_detail(entry.get("responseStatus"))
    obj_ref = entry.get("objectRef") or {}
    metadata_uid = str(entry.get("auditID") or "").strip() or hashlib.sha256(
        json.dumps(
            {
                "requestReceivedTimestamp": entry.get("requestReceivedTimestamp", ""),
                "verb": verb,
                "username": ((entry.get("user") or {}).get("username")) or "",
                "resource": obj_ref.get("resource", ""),
                "namespace": obj_ref.get("namespace", ""),
                "name": obj_ref.get("name", ""),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    canonical: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "api_activity",
        "event_uid": metadata_uid,
        "provider": "Kubernetes",
        "account_uid": "",
        "region": "",
        "time_ms": parse_ts_ms(entry.get("requestReceivedTimestamp")),
        "activity_id": activity_id,
        "activity_name": _activity_name(activity_id),
        "status_id": status_id,
        "status": _status_name(status_id),
        "operation": verb.lower(),
        "service_name": "kubernetes",
        "actor": _build_actor(entry),
        "src": _build_src_endpoint(entry),
        "resources": _build_resources(entry),
        "source": {
            "kind": "kubernetes.audit",
            "audit_id": entry.get("auditID", ""),
            "stage": entry.get("stage", ""),
            "request_uri": entry.get("requestURI", ""),
            "api_version": entry.get("apiVersion", ""),
        },
        "metadata_labels": _metadata_labels(entry),
    }

    if status_detail:
        canonical["status_detail"] = status_detail

    unmapped = _unmapped_payload(entry)
    if unmapped:
        canonical["unmapped"] = {"k8s": unmapped}

    # Service-account namespace as a custom marker for downstream detectors.
    sa_ns = service_account_namespace(((entry.get("user") or {}).get("username")) or "")
    if sa_ns is not None:
        canonical["k8s"] = {"service_account_namespace": sa_ns}

    return canonical


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    activity_id = int(canonical["activity_id"])
    event: dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + activity_id,
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": int(canonical["status_id"]),
        "time": canonical["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": canonical["metadata_labels"],
        },
        "actor": canonical["actor"],
        "src_endpoint": canonical["src"],
        "api": {
            "operation": canonical["operation"],
            "service": {"name": canonical["service_name"]},
            "request": {"uid": canonical["source"]["audit_id"]},
        },
        "resources": canonical["resources"],
        "cloud": _build_cloud(),
    }
    if canonical.get("status_detail"):
        event["status_detail"] = canonical["status_detail"]
    if canonical.get("k8s"):
        event["k8s"] = canonical["k8s"]
    if canonical.get("unmapped"):
        event["unmapped"] = canonical["unmapped"]
    return event


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native.pop("metadata_labels", None)
    native["schema_mode"] = "native"
    native["source_skill"] = SKILL_NAME
    native["output_format"] = "native"
    return native


def convert_event(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one K8s audit Event to one OCSF API Activity event."""
    canonical = _build_canonical_event(entry)
    if canonical is None:
        return None
    return _render_ocsf_event(canonical)


def convert_event_native(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one K8s audit Event to the repo's native enriched event shape."""
    canonical = _build_canonical_event(entry)
    if canonical is None:
        return None
    return _render_native_event(canonical)


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


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
        for r in whole:
            if isinstance(r, dict):
                yield r
        return
    if isinstance(whole, dict):
        yield whole
        return

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
        if isinstance(obj, dict):
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
    for raw in iter_raw_entries(stream):
        try:
            canonical = _build_canonical_event(raw)
        except Exception as e:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="convert_error",
                message=f"skipping entry: convert error: {e}",
            )
            continue
        if canonical is None:
            continue
        if output_format == "native":
            yield _render_native_event(canonical)
        else:
            yield _render_ocsf_event(canonical)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert raw K8s audit logs to OCSF 1.8 API Activity JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default="ocsf", help="Render OCSF events or the native enriched event shape.")
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
