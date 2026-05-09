"""Detect suspicious prompt-injection language in MCP tool descriptions.

Reads OCSF 1.8 Application Activity (class 6002) events or the native MCP
application-activity projection produced by ingest-mcp-proxy-ocsf and emits one
Detection Finding per suspicious `tools/list` tool declaration.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "detect-prompt-injection-mcp-proxy"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402

OUTPUT_FORMATS = ("ocsf", "native")

APPLICATION_ACTIVITY_UID = 6002
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
INGEST_SKILL = "ingest-mcp-proxy-ocsf"

ATLAS_VERSION = "current"
ATLAS_TACTIC_UID = "AML.TA0005"
ATLAS_TACTIC_NAME = "Execution"
ATLAS_TECHNIQUE_UID = "AML.T0051"
ATLAS_TECHNIQUE_NAME = "Prompt Injection"

SUSPICIOUS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction-override",
        re.compile(
            r"\b(ignore|disregard|forget)\b.{0,32}\b("
            r"previous instructions|prior instructions|system prompt|developer (?:message|prompt)"
            r")\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "prompt-exfiltration",
        re.compile(
            r"\b(reveal|show|print|output|dump)\b.{0,32}\b("
            r"system prompt|developer (?:message|prompt)|hidden prompt|internal instructions?"
            r")\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "guardrail-bypass",
        re.compile(
            r"\b(bypass|disable|ignore)\b.{0,24}\b("
            r"safety|guardrails?|restrictions?|policy|policies"
            r")\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "secret-exfiltration",
        re.compile(
            r"\b(exfiltrat(?:e|ion)|leak|send)\b.{0,32}\b("
            r"secrets?|credentials?|tokens?|api keys?|conversation history|chat history"
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


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != APPLICATION_ACTIVITY_UID:
            return None
        mcp = event.get("mcp") or {}
        tool = mcp.get("tool") or {}
        return {
            "source_format": "ocsf",
            "source_skill": _source_skill(event),
            "event_uid": _event_uid(event),
            "time_ms": _safe_int(event.get("time")),
            "session_uid": str(mcp.get("session_uid") or "sess-unknown"),
            "method": str(mcp.get("method") or ""),
            "direction": str(mcp.get("direction") or ""),
            "tool_name": str(tool.get("name") or ""),
            "tool_description": str(tool.get("description") or ""),
            "raw_event": event,
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"canonical", "native"}:
        return None
    record_type = str(event.get("record_type") or "").strip().lower()
    if record_type and record_type != "application_activity":
        return None
    tool = event.get("tool") or {}
    return {
        "source_format": schema_mode or "native",
        "source_skill": _source_skill(event),
        "event_uid": _event_uid(event),
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "session_uid": str(event.get("session_uid") or "sess-unknown"),
        "method": str(event.get("method") or ""),
        "direction": str(event.get("direction") or ""),
        "tool_name": str(tool.get("name") or event.get("tool_name") or ""),
        "tool_description": str(tool.get("description") or event.get("tool_description") or ""),
        "raw_event": event,
    }


def _matched_signals(description: str) -> list[str]:
    matched: list[str] = []
    for signal, pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(description):
            matched.append(signal)
    return matched


def _suspicious_tool_declaration(event: dict[str, Any]) -> dict[str, Any] | None:
    normalized = _normalize_event(event)
    if normalized is None:
        return None
    if normalized["source_skill"] != INGEST_SKILL:
        return None
    if normalized["method"] != "tools/list" or normalized["direction"] != "response":
        return None
    if not normalized["tool_name"] or not normalized["tool_description"]:
        return None
    signals = _matched_signals(normalized["tool_description"])
    if not signals:
        return None
    normalized["matched_signals"] = signals
    return normalized


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _finding_uid(session_uid: str, tool_name: str, event_uid: str, matched_signals: list[str]) -> str:
    material = f"{session_uid}|{tool_name}|{event_uid}|{'|'.join(sorted(matched_signals))}"
    return f"det-mcp-prompt-injection-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _description_excerpt(description: str, limit: int = 180) -> str:
    collapsed = " ".join(description.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "…"


def _build_native_finding(event: dict[str, Any]) -> dict[str, Any]:
    session_uid = str(event["session_uid"])
    tool_name = str(event["tool_name"])
    event_uid = str(event["event_uid"] or "event-unknown")
    matched_signals = list(event["matched_signals"])
    description = str(event["tool_description"])
    finding_uid = _finding_uid(session_uid, tool_name, event_uid, matched_signals)

    signal_list = ", ".join(matched_signals)
    excerpt = _description_excerpt(description)
    desc = (
        f"Tool '{tool_name}' in session '{session_uid}' advertised MCP metadata that looks like "
        f"prompt-injection or instruction-smuggling content ({signal_list}). The tool description "
        f"contains explicit override, prompt-reveal, guardrail-bypass, or secret-exfiltration "
        f"language that an agent could ingest as trusted instructions. Excerpt: {excerpt}"
    )

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
        "title": "Suspicious MCP tool description suggests prompt injection",
        "description": desc,
        "finding_types": ["mcp-prompt-injection", "llm-prompt-injection"],
        "first_seen_time_ms": int(event.get("time_ms") or 0),
        "last_seen_time_ms": int(event.get("time_ms") or 0),
        "session_uid": session_uid,
        "tool_name": tool_name,
        "tool_event_uid": event_uid,
        "matched_signals": matched_signals,
        "description_excerpt": excerpt,
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
            {
                "name": "tool.description_sha256",
                "type": "Fingerprint",
                "value": "sha256:" + hashlib.sha256(description.encode("utf-8")).hexdigest(),
            },
            {"name": "tool.event_uid", "type": "Other", "value": event_uid},
        ],
        "evidence": {
            "matched_signals": matched_signals,
            "raw_event_uids": [event_uid],
            "events_observed": 1,
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
            "labels": ["detection-engineering", "mcp", "ai", "prompt-injection"],
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "first_seen_time": native_finding["first_seen_time_ms"],
            "last_seen_time": native_finding["last_seen_time_ms"],
            "attacks": [
                {
                    "version": attack["version"],
                    "tactic": {"uid": attack["tactic_uid"], "name": attack["tactic_name"]},
                    "technique": {"uid": attack["technique_uid"], "name": attack["technique_name"]},
                }
            ],
        },
        "observables": native_finding["observables"],
        "evidence": native_finding["evidence"],
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    seen_findings: set[str] = set()
    listed: list[dict[str, Any]] = []
    for event in events:
        suspicious = _suspicious_tool_declaration(event)
        if suspicious is not None:
            listed.append(suspicious)
    listed.sort(key=lambda e: (str(e.get("session_uid") or ""), int(e.get("time_ms") or 0), str(e.get("tool_name") or "")))

    for event in listed:
        native_finding = _build_native_finding(event)
        if native_finding["finding_uid"] in seen_findings:
            continue
        seen_findings.add(native_finding["finding_uid"])
        yield native_finding if output_format == "native" else _render_ocsf_finding(native_finding)


def load_jsonl(path: str | None) -> list[dict[str, Any]]:
    if path:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.readlines()

    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            loaded = json.loads(stripped)
        except json.JSONDecodeError as exc:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {exc}", file=sys.stderr)
            continue
        if not isinstance(loaded, dict):
            print(f"[{SKILL_NAME}] skipping line {lineno}: expected JSON object", file=sys.stderr)
            continue
        records.append(loaded)
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect suspicious prompt-injection language in MCP tool descriptions."
    )
    parser.add_argument("input", nargs="?", help="Input JSONL file. Reads stdin when omitted.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Emit OCSF Detection Finding (default) or the native finding projection.",
    )
    args = parser.parse_args(argv)

    for finding in detect(load_jsonl(args.input), output_format=args.output_format):
        print(json.dumps(finding, separators=(",", ":"), sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
