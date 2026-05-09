"""Detect leaked system-prompt material in MCP tool-call responses."""

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

SKILL_NAME = "detect-system-prompt-extraction"
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

ATLAS_VERSION = "current"
ATLAS_TACTIC_UID = "AML.TA0005"
ATLAS_TACTIC_NAME = "Execution"

ATLAS_TECHNIQUES = (
    {
        "version": ATLAS_VERSION,
        "tactic_uid": ATLAS_TACTIC_UID,
        "tactic_name": ATLAS_TACTIC_NAME,
        "technique_uid": "AML.T0004",
        "technique_name": "Prompt Extraction",
    },
    {
        "version": ATLAS_VERSION,
        "tactic_uid": ATLAS_TACTIC_UID,
        "tactic_name": ATLAS_TACTIC_NAME,
        "technique_uid": "AML.T0041",
        "technique_name": "LLM Prompt Extraction",
    },
)

LEAK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("xml-system-prompt", re.compile(r"<system_prompt>.*?</system_prompt>", re.IGNORECASE | re.DOTALL)),
    ("system-prompt-phrase", re.compile(r"\bsystem prompt\b", re.IGNORECASE)),
    ("developer-message", re.compile(r"\bdeveloper message\b", re.IGNORECASE)),
    ("hidden-instructions", re.compile(r"\bhidden instructions?\b", re.IGNORECASE)),
    ("assistant-role-preface", re.compile(r"\bYou are (?:ChatGPT|Claude|an AI assistant)\b", re.IGNORECASE)),
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


def _matched_signals(body: Any) -> tuple[list[str], str]:
    matched: list[str] = []
    excerpt = ""
    for text in _iter_strings(body):
        for signal, pattern in LEAK_PATTERNS:
            if pattern.search(text):
                matched.append(signal)
                if not excerpt:
                    excerpt = text
        if excerpt and matched:
            break
    return sorted(set(matched)), excerpt


def _prompt_extraction_event(event: dict[str, Any]) -> dict[str, Any] | None:
    normalized = _normalize_event(event)
    if normalized is None:
        return None
    if normalized["source_skill"] != INGEST_SKILL:
        return None
    if normalized["method"] != "tools/call" or normalized["direction"] != "response":
        return None
    body = normalized["body"]
    if body is None:
        return None
    matched, excerpt = _matched_signals(body)
    if not matched:
        return None
    normalized["matched_signals"] = matched
    normalized["excerpt"] = excerpt
    return normalized


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _excerpt(text: str, limit: int = 180) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "…"


def _fingerprint(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _finding_uid(session_uid: str, tool_name: str, event_uid: str, matched_signals: list[str]) -> str:
    material = f"{session_uid}|{tool_name}|{event_uid}|{'|'.join(sorted(matched_signals))}"
    return f"det-system-prompt-extraction-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(event: dict[str, Any]) -> dict[str, Any]:
    session_uid = str(event["session_uid"])
    tool_name = str(event["tool_name"] or "tool-unknown")
    event_uid = str(event["event_uid"] or "event-unknown")
    matched = list(event["matched_signals"])
    excerpt = _excerpt(str(event["excerpt"] or ""))
    finding_uid = _finding_uid(session_uid, tool_name, event_uid, matched)

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
        "title": "MCP tool response leaked system-prompt material",
        "description": (
            f"Tool '{tool_name}' returned content in session '{session_uid}' that looks like leaked "
            f"system-prompt or hidden-instruction material. Matched signals: {', '.join(matched)}. "
            "The finding stores only a short excerpt and fingerprint, never the full body."
        ),
        "finding_types": ["system-prompt-extraction", "llm-system-prompt-leakage"],
        "first_seen_time_ms": int(event.get("time_ms") or 0),
        "last_seen_time_ms": int(event.get("time_ms") or 0),
        "session_uid": session_uid,
        "tool_name": tool_name,
        "tool_event_uid": event_uid,
        "matched_signals": matched,
        "excerpt": excerpt,
        "excerpt_fingerprint": _fingerprint(excerpt),
        "mitre_attacks": list(ATLAS_TECHNIQUES),
        "observables": [
            {"name": "session.uid", "type": "Other", "value": session_uid},
            {"name": "tool.name", "type": "Other", "value": tool_name},
            {"name": "tool.event_uid", "type": "Other", "value": event_uid},
            {"name": "excerpt.sha256", "type": "Fingerprint", "value": _fingerprint(excerpt)},
        ],
        "evidence": {
            "matched_signals": matched,
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
            "labels": ["detection-engineering", "mcp", "ai", "system-prompt-leakage"],
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "first_seen_time": native_finding["first_seen_time_ms"],
            "last_seen_time": native_finding["last_seen_time_ms"],
            "attacks": native_finding["mitre_attacks"],
        },
        "observables": native_finding["observables"],
        "evidence": {
            "events_observed": 1,
            "matched_signals": native_finding["matched_signals"],
            "raw_event_uids": native_finding["evidence"]["raw_event_uids"],
        },
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    for raw in events:
        event = _prompt_extraction_event(raw)
        if event is None:
            normalized = _normalize_event(raw)
            if normalized and normalized["source_skill"] != INGEST_SKILL:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="wrong_source",
                    message=f"skipping event from non-mcp producer `{normalized['source_skill']}`",
                )
            continue
        finding = _build_native_finding(event)
        yield finding if output_format == "native" else _render_ocsf_finding(finding)


def _iter_jsonl(path: str | None) -> Iterable[dict[str, Any]]:
    handle = open(path, "r", encoding="utf-8") if path else sys.stdin
    with handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="invalid_json",
                    message=f"skipping line {line_number}: invalid JSON ({exc.msg})",
                )
                continue
            if isinstance(obj, dict):
                yield obj
            else:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="wrong_shape",
                    message=f"skipping line {line_number}: expected JSON object",
                )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", help="optional JSONL input path; defaults to stdin")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="emit OCSF Detection Finding 2004 (default) or native findings",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    for finding in detect(_iter_jsonl(args.path), output_format=args.output_format):
        json.dump(finding, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
