"""Detect MCP tool schema drift mid-session from OCSF or native activity streams.

Reads OCSF 1.8 Application Activity events (class 6002) or the native MCP
application-activity projection produced by the sibling ingest skill, tracks
tool fingerprints per (session, tool name), and emits one Detection Finding per
drift event.

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

SKILL_NAME = "detect-mcp-tool-drift"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
OUTPUT_FORMATS = ("ocsf", "native")

# Detection Finding (2004) — the replacement for the deprecated
# Security Finding (2001) since OCSF 1.1.0.
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1  # 1 Create · 2 Update · 3 Close · 99 Other (OCSF 1.8)
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

# Severity: High — drift is a strong signal and actionable immediately.
SEVERITY_HIGH = 4

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0001"
MITRE_TACTIC_NAME = "Initial Access"
MITRE_TECHNIQUE_UID = "T1195.001"
MITRE_TECHNIQUE_NAME = "Supply Chain Compromise: Compromise Software Supply Chain"


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _short(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:8]


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != 6002:
            return None
        mcp = event.get("mcp") or {}
        tool = mcp.get("tool") or {}
        return {
            "source_format": "ocsf",
            "session_uid": str(mcp.get("session_uid") or "sess-unknown"),
            "method": str(mcp.get("method") or ""),
            "direction": str(mcp.get("direction") or ""),
            "time_ms": _safe_int(event.get("time")),
            "tool_name": str(tool.get("name") or ""),
            "fingerprint": str(tool.get("fingerprint") or ""),
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
        "session_uid": str(event.get("session_uid") or "sess-unknown"),
        "method": str(event.get("method") or ""),
        "direction": str(event.get("direction") or ""),
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "tool_name": str(tool.get("name") or event.get("tool_name") or ""),
        "fingerprint": str(tool.get("fingerprint") or event.get("tool_fingerprint") or ""),
        "raw_event": event,
    }


def _is_tools_list_response_with_fingerprint(event: dict[str, Any]) -> bool:
    """True iff the event is a tools/list response with a populated tool fingerprint."""
    normalized = _normalize_event(event)
    if not normalized:
        return False
    if normalized["method"] != "tools/list" or normalized["direction"] != "response":
        return False
    return bool(normalized["tool_name"]) and bool(normalized["fingerprint"])


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------


def _build_finding(
    session_uid: str,
    tool_name: str,
    before_event: dict[str, Any],
    after_event: dict[str, Any],
) -> dict[str, Any]:
    """Produce one native detection finding describing a single drift."""
    before_fp = before_event["fingerprint"]
    after_fp = after_event["fingerprint"]

    # Deterministic ID so re-running on the same input is idempotent.
    uid = f"det-mcp-drift-{session_uid}-{tool_name}-{before_fp.split(':')[-1][:8]}-{after_fp.split(':')[-1][:8]}"

    title = "MCP tool schema drift detected mid-session"
    desc = (
        f"Tool '{tool_name}' changed fingerprint between tools/list responses in session "
        f"'{session_uid}'. Before: {before_fp}; after: {after_fp}. This is the MCP "
        f"tool-poisoning / rug-pull pattern (MITRE T1195.001). The agent may have already "
        f"called this tool under the previous schema and will trust the new one."
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
        "time_ms": after_event.get("time_ms") or _now_ms(),
        "severity": "high",
        "activity_id": FINDING_ACTIVITY_CREATE,
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": 1,
        "title": title,
        "description": desc,
        "finding_types": ["mcp-tool-drift"],
        "first_seen_time_ms": before_event.get("time_ms"),
        "last_seen_time_ms": after_event.get("time_ms"),
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": MITRE_TACTIC_UID,
                "tactic_name": MITRE_TACTIC_NAME,
                "technique_uid": MITRE_TECHNIQUE_UID,
                "technique_name": MITRE_TECHNIQUE_NAME,
            }
        ],
        "session_uid": session_uid,
        "tool_name": tool_name,
        "before_fingerprint": before_fp,
        "after_fingerprint": after_fp,
        "observables": [
            {"name": "session.uid", "type": "Other", "value": session_uid},
            {"name": "tool.name", "type": "Other", "value": tool_name},
            {"name": "tool.before_fingerprint", "type": "Fingerprint", "value": before_fp},
            {"name": "tool.after_fingerprint", "type": "Fingerprint", "value": after_fp},
        ],
        "evidence_count": 2,
    }


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------


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
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "mcp", "supply-chain", "tool-drift"],
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
                    "tactic": {"name": attack["tactic_name"], "uid": attack["tactic_uid"]},
                    "technique": {"name": attack["technique_name"], "uid": attack["technique_uid"]},
                }
            ],
        },
        "observables": native_finding["observables"],
        "evidence": {
            "events_observed": native_finding["evidence_count"],
            "before_event_time": native_finding["first_seen_time_ms"],
            "after_event_time": native_finding["last_seen_time_ms"],
            "raw_events": [],
        },
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    """Walk events in order; yield a finding per (session, tool) drift.

    State is minimal: one last-seen fingerprint per (session, tool name). We also
    cache the event that produced the last fingerprint so the finding can cite
    exact evidence.
    """
    # (session_uid, tool_name) -> (last_fingerprint, last_event)
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    state: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}

    # Materialise and stable-sort by time so out-of-order JSONL still works.
    listed = []
    for event in events:
        if not _is_tools_list_response_with_fingerprint(event):
            continue
        normalized = _normalize_event(event)
        if normalized:
            listed.append(normalized)
    listed.sort(key=lambda e: (e.get("session_uid", ""), e.get("time_ms", 0)))

    for event in listed:
        session_uid = event["session_uid"]
        tool_name = event["tool_name"]
        fingerprint = event["fingerprint"]

        key = (session_uid, tool_name)
        prior = state.get(key)
        if prior is None:
            state[key] = (fingerprint, event)
            continue

        prior_fp, prior_event = prior
        if prior_fp == fingerprint:
            # Republished with same fingerprint — no drift.
            continue

        finding = _build_finding(session_uid, tool_name, prior_event, event)
        yield _render_ocsf_finding(finding) if output_format == "ocsf" else finding
        # Update state so we only raise ONCE per distinct transition.
        # A subsequent re-drift will produce a new finding because the "before"
        # fingerprint has moved forward.
        state[key] = (fingerprint, event)


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {e}", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect MCP tool schema drift from OCSF or native activity events.")
    parser.add_argument("input", nargs="?", help="OCSF or native JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Detection Finding JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF Detection Finding (default) or the native canonical projection.",
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
