"""Convert raw MCP proxy logs to canonical or OCSF Application Activity records.

Input:  JSONL as emitted by `agent-bom proxy --log-format jsonl`
Output: JSONL of OCSF 1.8 Application Activity events with the
        cloud_security_mcp custom profile.

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

SKILL_NAME = "ingest-mcp-proxy-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
MCP_PROFILE = "cloud_security_mcp"
OUTPUT_FORMATS = ("ocsf", "native")

# OCSF 1.8 Application Activity (6002) — unchanged from 1.3 for this class.
CLASS_UID = 6002
CLASS_NAME = "Application Activity"
CATEGORY_UID = 6
CATEGORY_NAME = "Application Activity"

# Activity enum (OCSF 1.8 Application Activity)
ACTIVITY_CREATE = 1  # a new record (e.g. tools/list response)
ACTIVITY_READ = 2  # a read-style call (e.g. tools/call request)
ACTIVITY_UNKNOWN = 0


# ---------------------------------------------------------------------------
# Fingerprinting — the cross-skill pivot point for tool drift detection
# ---------------------------------------------------------------------------


def tool_fingerprint(tool: dict[str, Any]) -> str:
    """Stable sha256 over (name, description, inputSchema, annotations).

    Any change to any of these fields is considered a tool drift event.
    Sorted keys ensure the same tool produces the same fingerprint regardless
    of dict ordering in the raw JSON.
    """
    canonical = json.dumps(
        {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "inputSchema": tool.get("inputSchema", {}),
            "annotations": tool.get("annotations", {}),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def input_schema_fingerprint(tool: dict[str, Any]) -> str:
    canonical = json.dumps(tool.get("inputSchema", {}), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def parse_ts_ms(ts: str | None) -> int:
    """Parse an ISO-8601 timestamp to Unix epoch milliseconds.

    Falls back to 'now' if missing or unparseable. Always returns UTC.
    """
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        # Handle trailing Z
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


# ---------------------------------------------------------------------------
# OCSF event builder
# ---------------------------------------------------------------------------


def _event_uid(raw: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "timestamp": raw.get("timestamp", ""),
                "session_id": raw.get("session_id", "sess-unknown"),
                "method": raw.get("method", ""),
                "direction": raw.get("direction", ""),
                "params": raw.get("params", {}),
                "body": raw.get("body", {}),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _activity_name(activity_id: int) -> str:
    return {
        ACTIVITY_CREATE: "create",
        ACTIVITY_READ: "read",
        ACTIVITY_UNKNOWN: "unknown",
    }.get(activity_id, "unknown")


def _status_name(status_id: int) -> str:
    return {1: "success", 0: "unknown"}.get(status_id, "unknown")


def _build_canonical_event(raw: dict[str, Any], activity_id: int) -> dict[str, Any]:
    """Populate the stable repo-owned canonical activity shape."""
    event_uid = _event_uid(raw)
    return {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "application_activity",
        "source_skill": SKILL_NAME,
        "event_uid": event_uid,
        "provider": "MCP",
        "time_ms": parse_ts_ms(raw.get("timestamp")),
        "activity_id": activity_id,
        "activity_name": _activity_name(activity_id),
        "severity": "informational",
        "severity_id": 1,
        "status": _status_name(1),
        "status_id": 1,
        "profile": MCP_PROFILE,
        "session_uid": raw.get("session_id", "sess-unknown"),
        "method": raw.get("method", "unknown"),
        "direction": raw.get("direction", "unknown"),
        "params": raw.get("params") or {},
        "body": raw.get("body") or {},
    }


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    """Project the canonical activity shape into the pinned OCSF envelope."""
    event = {
        "activity_id": canonical["activity_id"],
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + canonical["activity_id"],
        "severity_id": canonical["severity_id"],
        "status_id": canonical["status_id"],
        "time": canonical["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "profiles": [MCP_PROFILE],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "mcp", "ingest"],
        },
        "mcp": {
            "session_uid": canonical["session_uid"],
            "method": canonical["method"],
            "direction": canonical["direction"],
        },
    }
    if canonical.get("tool"):
        event["mcp"]["tool"] = dict(canonical["tool"])
    return event


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["output_format"] = "native"
    return native


def _with_tool(canonical: dict[str, Any], tool: dict[str, Any]) -> dict[str, Any]:
    event = dict(canonical)
    event["tool"] = {
        "name": tool.get("name", ""),
        "description": tool.get("description", ""),
        "input_schema_sha256": input_schema_fingerprint(tool),
        "fingerprint": tool_fingerprint(tool),
    }
    return event


def convert_event(raw: dict[str, Any], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    """Convert one raw proxy line into zero or more application activity events.

    - tools/list response -> one OCSF event per tool in the response (Create)
    - tools/call request  -> one OCSF event (Read) carrying the called tool's
      name so a detector can cross-reference the last known fingerprint for
      that tool in the same session.
    - Other methods/directions -> one OCSF event with no tool payload.
    """
    method = raw.get("method", "")
    direction = raw.get("direction", "")

    if method == "tools/list" and direction == "response":
        tools = (raw.get("body") or {}).get("tools") or []
        if not tools:
            canonical = _build_canonical_event(raw, ACTIVITY_CREATE)
            yield _render_native_event(canonical) if output_format == "native" else _render_ocsf_event(canonical)
            return
        for tool in tools:
            canonical = _with_tool(_build_canonical_event(raw, ACTIVITY_CREATE), tool)
            yield _render_native_event(canonical) if output_format == "native" else _render_ocsf_event(canonical)
        return

    if method == "tools/call" and direction == "request":
        called_name = ((raw.get("params") or {}).get("name")) or ""
        event = _build_canonical_event(raw, ACTIVITY_READ)
        if called_name:
            # Do NOT populate a fingerprint here — this is a call, not a
            # declaration. The detector pairs the call to the last-seen
            # fingerprint in the same session.
            event["tool"] = {"name": called_name}
        yield _render_native_event(event) if output_format == "native" else _render_ocsf_event(event)
        return

    # Anything else — emit a base event so the downstream pipeline stays
    # aware of activity on the session.
    canonical = _build_canonical_event(raw, ACTIVITY_UNKNOWN)
    yield _render_native_event(canonical) if output_format == "native" else _render_ocsf_event(canonical)


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def ingest(lines: Iterable[str], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    """Yield activity records for a stream of raw JSONL lines."""
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    for lineno, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {e}", file=sys.stderr)
            continue
        if not isinstance(raw, dict):
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)
            continue
        try:
            yield from convert_event(raw, output_format=output_format)
        except Exception as e:  # defence-in-depth — never crash the pipeline
            print(f"[{SKILL_NAME}] skipping line {lineno}: convert error: {e}", file=sys.stderr)
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert raw MCP proxy JSONL to OCSF or native Application Activity JSONL."
    )
    parser.add_argument("input", nargs="?", help="Input JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF Application Activity (default) or the native canonical projection.",
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
