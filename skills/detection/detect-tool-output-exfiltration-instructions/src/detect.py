"""Detect explicit exfiltration instructions in MCP tool-call responses."""

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

SKILL_NAME = "detect-tool-output-exfiltration-instructions"
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
ATLAS_TECHNIQUE_UID = "AML.T0051"
ATLAS_TECHNIQUE_NAME = "Prompt Injection"

EXFIL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "history-exfiltration",
        re.compile(
            r"\b(send|upload|exfiltrat(?:e|ion)|export|post|copy)\b.{0,40}\b("
            r"conversation history|chat history|all messages|messages|transcript|full context|entire conversation"
            r")\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "file-exfiltration",
        re.compile(
            r"\b(send|upload|copy|attach|forward|post)\b.{0,40}\b("
            r"local files|workspace files|project files|attached documents|documents|artifacts"
            r")\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "secret-exfiltration",
        re.compile(
            r"\b(send|upload|exfiltrat(?:e|ion)|export|post)\b.{0,40}\b("
            r"tokens?|credentials?|api keys?|secrets?|environment variables|env vars"
            r")\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "prompt-exfiltration",
        re.compile(
            r"\b(send|upload|export|post|dump|reveal)\b.{0,40}\b("
            r"system prompt|developer (?:message|prompt)|hidden instructions?"
            r")\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
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
        for signal, pattern in EXFIL_PATTERNS:
            if pattern.search(text):
                matched.append(signal)
                if not excerpt:
                    excerpt = text
        if excerpt and matched:
            break
    return sorted(set(matched)), excerpt


def _exfiltration_instruction_event(event: dict[str, Any]) -> dict[str, Any] | None:
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
    return f"det-tool-output-exfiltration-instructions-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


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
        "title": "MCP tool response attempted data exfiltration instructions",
        "description": (
            f"Tool '{tool_name}' returned content in session '{session_uid}' that appears to "
            f"instruct an agent to exfiltrate conversation history, prompts, files, or secrets. "
            f"Matched signals: {', '.join(matched)}. The finding stores only a short excerpt "
            "and fingerprint, never the full body."
        ),
        "finding_types": ["mcp-tool-output-exfiltration", "llm-prompt-injection"],
        "first_seen_time_ms": int(event.get("time_ms") or 0),
        "last_seen_time_ms": int(event.get("time_ms") or 0),
        "session_uid": session_uid,
        "tool_name": tool_name,
        "tool_event_uid": event_uid,
        "matched_signals": matched,
        "excerpt": excerpt,
        "excerpt_fingerprint": _fingerprint(excerpt),
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
    attack = native_finding["mitre_attacks"][0]
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "type_name": "Detection Finding: Create",
        "time": native_finding["time_ms"],
        "severity_id": native_finding["severity_id"],
        "severity": native_finding["severity"].capitalize(),
        "status_id": native_finding["status_id"],
        "status": native_finding["status"].capitalize(),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native_finding["event_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": SKILL_NAME},
            },
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "attacks": [
                {
                    "version": attack["version"],
                    "tactic": {
                        "uid": attack["tactic_uid"],
                        "name": attack["tactic_name"],
                    },
                    "technique": {
                        "uid": attack["technique_uid"],
                        "name": attack["technique_name"],
                    },
                }
            ],
        },
        "message": native_finding["description"],
        "observables": [
            {"name": obs["name"], "type": obs["type"], "value": obs["value"]}
            for obs in native_finding["observables"]
        ],
        "raw_data": {
            "session_uid": native_finding["session_uid"],
            "tool_name": native_finding["tool_name"],
            "tool_event_uid": native_finding["tool_event_uid"],
            "matched_signals": native_finding["matched_signals"],
            "excerpt": native_finding["excerpt"],
            "excerpt_fingerprint": native_finding["excerpt_fingerprint"],
        },
    }


def detect(events: Iterable[dict[str, Any]], *, output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format: {output_format}")

    warned_non_mcp = False
    for event in events:
        normalized = _normalize_event(event)
        if normalized and normalized["source_skill"] and normalized["source_skill"] != INGEST_SKILL and not warned_non_mcp:
            warned_non_mcp = True
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="detect.non_mcp_source",
                message="Skipping events from non-mcp producer.",
                source_skill=normalized["source_skill"],
            )
        suspicious = _exfiltration_instruction_event(event)
        if suspicious is None:
            continue
        native = _build_native_finding(suspicious)
        yield native if output_format == "native" else _render_ocsf_finding(native)


def _iter_json_lines(paths: list[str]) -> Iterable[dict[str, Any]]:
    if not paths:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)
        return
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect explicit exfiltration instructions in MCP tool-call responses.")
    parser.add_argument("paths", nargs="*", help="Optional JSONL input paths; reads stdin when omitted.")
    parser.add_argument("--output-format", default="ocsf", choices=OUTPUT_FORMATS)
    args = parser.parse_args(argv)

    for finding in detect(_iter_json_lines(args.paths), output_format=args.output_format):
        print(json.dumps(finding, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
