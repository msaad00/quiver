"""Detect credential-looking material leaked in MCP tool-call responses.

Consumes the native/canonical MCP application-activity records emitted by
`ingest-mcp-proxy-ocsf --output-format native`. Fires on `tools/call`
response events whose `body` contains strings matching high-confidence
credential/token patterns. Emits one Detection Finding per leaking tool result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-agent-credential-leak-mcp"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402

OUTPUT_FORMATS = ("ocsf", "native")
INGEST_SKILL = "ingest-mcp-proxy-ocsf"

APPLICATION_ACTIVITY_UID = 6002
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE
SEVERITY_HIGH = 4

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key-id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("github-token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
    ("openai-key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b")),
    ("slack-token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _source_skill(event: dict[str, Any]) -> str:
    if event.get("source_skill"):
        return str(event["source_skill"])
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _event_uid(event: dict[str, Any]) -> str:
    if event.get("event_uid"):
        return str(event["event_uid"])
    metadata = event.get("metadata") or {}
    return str(metadata.get("uid") or "")


def _tool_name(event: dict[str, Any], params: dict[str, Any]) -> str:
    tool = event.get("tool") or {}
    return str(tool.get("name") or params.get("name") or event.get("tool_name") or "")


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != APPLICATION_ACTIVITY_UID:
            return None
        body = event.get("body")
        params = event.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        return {
            "source_format": "ocsf",
            "source_skill": _source_skill(event),
            "event_uid": _event_uid(event),
            "time_ms": _safe_int(event.get("time")),
            "session_uid": str(((event.get("mcp") or {}).get("session_uid")) or "sess-unknown"),
            "method": str(((event.get("mcp") or {}).get("method")) or ""),
            "direction": str(((event.get("mcp") or {}).get("direction")) or ""),
            "tool_name": _tool_name(event, params),
            "body": body,
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"canonical", "native"}:
        return None
    record_type = str(event.get("record_type") or "").strip().lower()
    if record_type and record_type != "application_activity":
        return None
    params = event.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    return {
        "source_format": schema_mode or "native",
        "source_skill": _source_skill(event),
        "event_uid": _event_uid(event),
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "session_uid": str(event.get("session_uid") or "sess-unknown"),
        "method": str(event.get("method") or ""),
        "direction": str(event.get("direction") or ""),
        "tool_name": _tool_name(event, params),
        "body": event.get("body"),
    }


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
        return
    if isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-4:]


def _sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _matched_secrets(body: Any) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for text in _iter_strings(body):
        for signal, pattern in PATTERNS:
            for match in pattern.finditer(text):
                secret = match.group(1)
                key = (signal, secret)
                if key in seen:
                    continue
                seen.add(key)
                matches.append(
                    {
                        "signal": signal,
                        "masked": _mask(secret),
                        "fingerprint": _sha(secret),
                    }
                )
    return matches


def _credential_leak_event(event: dict[str, Any]) -> dict[str, Any] | None:
    normalized = _normalize_event(event)
    if normalized is None:
        return None
    if normalized["source_skill"] != INGEST_SKILL:
        return None
    if normalized["method"] != "tools/call" or normalized["direction"] != "response":
        return None
    if normalized["source_format"] == "ocsf" and normalized["body"] is None:
        return None
    body = normalized["body"]
    if body is None:
        return None
    matches = _matched_secrets(body)
    if not matches:
        return None
    normalized["matches"] = matches
    return normalized


def _finding_uid(session_uid: str, tool_name: str, event_uid: str, matches: list[dict[str, str]]) -> str:
    material = f"{session_uid}|{tool_name}|{event_uid}|{'|'.join(sorted(m['fingerprint'] for m in matches))}"
    return f"det-mcp-credential-leak-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _build_native_finding(event: dict[str, Any]) -> dict[str, Any]:
    session_uid = str(event["session_uid"])
    tool_name = str(event["tool_name"] or "tool-unknown")
    event_uid = str(event["event_uid"] or "event-unknown")
    matches = list(event["matches"])
    finding_uid = _finding_uid(session_uid, tool_name, event_uid, matches)
    signal_names = [item["signal"] for item in matches]
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "MCP",
        "time_ms": int(event.get("time_ms") or _now_ms()),
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": 1,
        "activity_id": FINDING_ACTIVITY_CREATE,
        "title": "MCP tool response leaked credential-looking material",
        "description": (
            f"Tool '{tool_name}' returned credential-like output in session '{session_uid}'. "
            f"Matched signals: {', '.join(signal_names)}. The finding stores only masked previews "
            f"and fingerprints, never the raw secret values."
        ),
        "finding_types": ["mcp-credential-exposure", "credential-exposure-in-tools"],
        "first_seen_time_ms": int(event.get("time_ms") or 0),
        "last_seen_time_ms": int(event.get("time_ms") or 0),
        "session_uid": session_uid,
        "tool_name": tool_name,
        "tool_event_uid": event_uid,
        "matched_signals": signal_names,
        "matches": matches,
        "observables": [
            {"name": "session.uid", "type": "Other", "value": session_uid},
            {"name": "tool.name", "type": "Other", "value": tool_name},
            {"name": "tool.event_uid", "type": "Other", "value": event_uid},
        ]
        + [
            {"name": f"credential.{item['signal']}.fingerprint", "type": "Fingerprint", "value": item["fingerprint"]}
            for item in matches
        ],
        "evidence": {
            "matched_signals": signal_names,
            "matches": matches,
            "events_observed": 1,
            "raw_event_uids": [event_uid],
        },
    }


def _render_ocsf_finding(native_finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": native_finding["severity_id"],
        "status_id": native_finding["status_id"],
        "time": native_finding["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native_finding["event_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "mcp", "credential-exposure", "ai-native"],
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "first_seen_time": native_finding["first_seen_time_ms"],
            "last_seen_time": native_finding["last_seen_time_ms"],
        },
        "observables": native_finding["observables"],
        "evidence": {
            "events_observed": 1,
            "matched_signals": native_finding["matched_signals"],
            "matches": native_finding["matches"],
            "raw_event_uids": [native_finding["tool_event_uid"]],
        },
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    for event in events:
        suspicious = _credential_leak_event(event)
        if suspicious is None:
            continue
        native = _build_native_finding(suspicious)
        yield native if output_format == "native" else _render_ocsf_finding(native)


def load_jsonl(path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
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
                )
                continue
            if not isinstance(obj, dict):
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="invalid_json_shape",
                    message=f"skipping line {lineno}: expected JSON object",
                    line=lineno,
                )
                continue
            records.append(obj)
    return records


def _stream_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
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
            )
            continue
        if isinstance(obj, dict):
            yield obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect credential-looking material leaked in MCP tool-call responses."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="Emit OCSF Detection Finding (default) or native projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")
    try:
        for finding in detect(_stream_jsonl(in_stream), output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
