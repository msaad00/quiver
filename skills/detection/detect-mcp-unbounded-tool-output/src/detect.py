"""Detect MCP tools whose responses repeatedly cross output ceilings.

Reads OCSF 1.8 Application Activity (class 6002) events emitted by
`ingest-mcp-proxy-ocsf`. For each event carrying
`unmapped.mcp.response_size_bytes` or `unmapped.mcp.response_line_count`,
records a breach against the per-(session, tool) counter. When the counter
reaches `MCP_TOOL_OUTPUT_REPEATED_BREACH_THRESHOLD`, emits one Detection
Finding tagged OWASP LLM10 (Unbounded Resource Consumption) and ATLAS
AML.T0034 (Cost Harvesting).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "detect-mcp-unbounded-tool-output"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"
OUTPUT_FORMATS = ("ocsf", "native")

APPLICATION_ACTIVITY_UID = 6002
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE
SEVERITY_MEDIUM = 3

DEFAULT_BYTES_THRESHOLD = 10 * 1024 * 1024  # 10 MiB
DEFAULT_LINES_THRESHOLD = 50_000
DEFAULT_REPEATED_BREACH_THRESHOLD = 5

ATLAS_VERSION = "current"
ATLAS_TACTIC_UID = "AML.TA0007"
ATLAS_TACTIC_NAME = "ML Attack Staging"
ATLAS_TECHNIQUE_UID = "AML.T0034"
ATLAS_TECHNIQUE_NAME = "Cost Harvesting"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        parsed = int(raw)
        return parsed if parsed > 0 else default
    except ValueError:
        return default


def bytes_threshold() -> int:
    return _env_int("MCP_TOOL_OUTPUT_BYTES_THRESHOLD", DEFAULT_BYTES_THRESHOLD)


def lines_threshold() -> int:
    return _env_int("MCP_TOOL_OUTPUT_LINES_THRESHOLD", DEFAULT_LINES_THRESHOLD)


def repeated_breach_threshold() -> int:
    return _env_int(
        "MCP_TOOL_OUTPUT_REPEATED_BREACH_THRESHOLD",
        DEFAULT_REPEATED_BREACH_THRESHOLD,
    )


def _unmapped_mcp(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped")
    if isinstance(unmapped, dict):
        mcp = unmapped.get("mcp")
        if isinstance(mcp, dict):
            return mcp
    return {}


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != APPLICATION_ACTIVITY_UID:
            return None
        unmapped_mcp = _unmapped_mcp(event)
        mcp = event.get("mcp") or {}
        session_uid = str(mcp.get("session_uid") or unmapped_mcp.get("session_uid") or "sess-unknown")
        tool_name = str(
            unmapped_mcp.get("tool_name")
            or (mcp.get("tool") or {}).get("name")
            or ""
        )
        if not tool_name:
            return None
        response_bytes = _safe_int(unmapped_mcp.get("response_size_bytes"))
        response_lines = _safe_int(unmapped_mcp.get("response_line_count"))
        if response_bytes <= 0 and response_lines <= 0:
            return None
        return {
            "session_uid": session_uid,
            "tool_name": tool_name,
            "response_bytes": response_bytes,
            "response_lines": response_lines,
            "time_ms": _safe_int(event.get("time")),
            "raw_event": event,
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"canonical", "native"}:
        return None
    record_type = str(event.get("record_type") or "").strip().lower()
    if record_type and record_type != "application_activity":
        return None
    unmapped_mcp = _unmapped_mcp(event)
    session_uid = str(event.get("session_uid") or unmapped_mcp.get("session_uid") or "sess-unknown")
    raw_tool = event.get("tool")
    native_tool: dict[str, Any] = raw_tool if isinstance(raw_tool, dict) else {}
    tool_name = str(
        native_tool.get("name")
        or event.get("tool_name")
        or unmapped_mcp.get("tool_name")
        or ""
    )
    if not tool_name:
        return None
    response_bytes = _safe_int(
        unmapped_mcp.get("response_size_bytes") or event.get("response_size_bytes")
    )
    response_lines = _safe_int(
        unmapped_mcp.get("response_line_count") or event.get("response_line_count")
    )
    if response_bytes <= 0 and response_lines <= 0:
        return None
    return {
        "session_uid": session_uid,
        "tool_name": tool_name,
        "response_bytes": response_bytes,
        "response_lines": response_lines,
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "raw_event": event,
    }


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _finding_uid(session_uid: str, tool_name: str) -> str:
    return f"det-mcp-unbounded-tool-output-{session_uid}-{tool_name}"


def _build_native_finding(
    session_uid: str,
    tool_name: str,
    breach_count: int,
    bytes_thr: int,
    lines_thr: int,
    repeat_thr: int,
    first_time_ms: int,
    last_time_ms: int,
    max_bytes: int,
    max_lines: int,
) -> dict[str, Any]:
    uid = _finding_uid(session_uid, tool_name)
    desc = (
        f"MCP tool '{tool_name}' in session '{session_uid}' produced {breach_count} "
        f"oversized responses (threshold: {bytes_thr} bytes OR {lines_thr} lines per "
        f"call). The cumulative pattern crossed the operator's repeat threshold "
        f"({repeat_thr}). Tighten the per-tool RLIMIT or quarantine the tool — this "
        f"is the OWASP LLM10 Unbounded Resource Consumption / ATLAS AML.T0034 Cost "
        f"Harvesting pattern on the tool-output side of the loop."
    )
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": uid,
        "event_uid": uid,
        "provider": "MCP",
        "time_ms": int(last_time_ms or _now_ms()),
        "severity": "medium",
        "severity_id": SEVERITY_MEDIUM,
        "status": "success",
        "status_id": 1,
        "activity_id": FINDING_ACTIVITY_CREATE,
        "title": "MCP tool response repeatedly exceeded output ceiling",
        "description": desc,
        "finding_types": ["mcp-unbounded-tool-output", "llm-unbounded-consumption"],
        "first_seen_time_ms": int(first_time_ms or 0),
        "last_seen_time_ms": int(last_time_ms or 0),
        "session_uid": session_uid,
        "tool_name": tool_name,
        "breach_count": breach_count,
        "bytes_threshold": bytes_thr,
        "lines_threshold": lines_thr,
        "repeated_breach_threshold": repeat_thr,
        "max_response_bytes": max_bytes,
        "max_response_lines": max_lines,
        "mitre_attacks": [
            {
                "version": ATLAS_VERSION,
                "tactic_uid": ATLAS_TACTIC_UID,
                "tactic_name": ATLAS_TACTIC_NAME,
                "technique_uid": ATLAS_TECHNIQUE_UID,
                "technique_name": ATLAS_TECHNIQUE_NAME,
            }
        ],
        "observables": [
            {"name": "session.uid", "type": "Other", "value": session_uid},
            {"name": "tool.name", "type": "Other", "value": tool_name},
            {"name": "breach.count", "type": "Other", "value": str(breach_count)},
            {"name": "bytes.threshold", "type": "Other", "value": str(bytes_thr)},
            {"name": "lines.threshold", "type": "Other", "value": str(lines_thr)},
        ],
        "evidence_count": breach_count,
    }


def _render_ocsf_finding(native: dict[str, Any]) -> dict[str, Any]:
    attack = native["mitre_attacks"][0]
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": native["severity_id"],
        "status_id": native["status_id"],
        "time": native["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native["event_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "mcp", "ai", "llm-unbounded-consumption"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": native["title"],
            "desc": native["description"],
            "types": native["finding_types"],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": attack["version"],
                    "tactic": {"uid": attack["tactic_uid"], "name": attack["tactic_name"]},
                    "technique": {"uid": attack["technique_uid"], "name": attack["technique_name"]},
                }
            ],
        },
        "observables": native["observables"],
        "evidence": {
            "events_observed": native["evidence_count"],
            "breach_count": native["breach_count"],
            "bytes_threshold": native["bytes_threshold"],
            "lines_threshold": native["lines_threshold"],
            "max_response_bytes": native["max_response_bytes"],
            "max_response_lines": native["max_response_lines"],
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    output_format: str = "ocsf",
    *,
    bytes_threshold_override: int | None = None,
    lines_threshold_override: int | None = None,
    repeated_breach_override: int | None = None,
) -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    bytes_thr = bytes_threshold_override if bytes_threshold_override is not None else bytes_threshold()
    lines_thr = lines_threshold_override if lines_threshold_override is not None else lines_threshold()
    repeat_thr = (
        repeated_breach_override if repeated_breach_override is not None else repeated_breach_threshold()
    )

    normalized: list[dict[str, Any]] = []
    for event in events:
        n = _normalize_event(event)
        if n is not None:
            normalized.append(n)
    normalized.sort(key=lambda e: (e["session_uid"], e["tool_name"], e["time_ms"]))

    # state[(session, tool)] = {"count": int, "first_ms": int, "last_ms": int,
    #                            "fired": bool, "max_bytes": int, "max_lines": int}
    state: dict[tuple[str, str], dict[str, int]] = {}

    for event in normalized:
        breached = (
            event["response_bytes"] > bytes_thr
            or event["response_lines"] > lines_thr
        )
        if not breached:
            continue
        key = (event["session_uid"], event["tool_name"])
        slot = state.setdefault(
            key,
            {
                "count": 0,
                "first_ms": event["time_ms"],
                "last_ms": event["time_ms"],
                "fired": 0,
                "max_bytes": 0,
                "max_lines": 0,
            },
        )
        slot["count"] += 1
        slot["last_ms"] = event["time_ms"]
        if event["response_bytes"] > slot["max_bytes"]:
            slot["max_bytes"] = event["response_bytes"]
        if event["response_lines"] > slot["max_lines"]:
            slot["max_lines"] = event["response_lines"]
        if slot["count"] >= repeat_thr and not slot["fired"]:
            slot["fired"] = 1
            native = _build_native_finding(
                event["session_uid"],
                event["tool_name"],
                slot["count"],
                bytes_thr,
                lines_thr,
                repeat_thr,
                slot["first_ms"],
                slot["last_ms"],
                slot["max_bytes"],
                slot["max_lines"],
            )
            yield native if output_format == "native" else _render_ocsf_finding(native)


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="OCSF JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL path. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")
    try:
        events = list(load_jsonl(in_stream))
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
