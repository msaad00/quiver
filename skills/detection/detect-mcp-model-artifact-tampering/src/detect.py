"""Detect MCP tool calls whose model artifact SHA-256 diverges from a baseline.

Reads OCSF 1.8 Application Activity (class 6002) events emitted by
`ingest-mcp-proxy-ocsf`. Per session, the first event carrying
`unmapped.mcp.model_artifact_sha256` sets the baseline; the first later event
whose hash differs emits one Detection Finding tagged with MITRE ATLAS
AML.T0010 (ML Supply Chain Compromise) and OWASP LLM03 (Supply Chain).

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

SKILL_NAME = "detect-mcp-model-artifact-tampering"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"
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
ATLAS_TACTIC_UID = "AML.TA0006"
ATLAS_TACTIC_NAME = "ML Supply Chain"
ATLAS_TECHNIQUE_UID = "AML.T0010"
ATLAS_TECHNIQUE_NAME = "ML Supply Chain Compromise"


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _short(value: str) -> str:
    cleaned = (value or "").split(":")[-1]
    return cleaned[:8] if cleaned else "00000000"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _unmapped_mcp(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped")
    if isinstance(unmapped, dict):
        mcp = unmapped.get("mcp")
        if isinstance(mcp, dict):
            return mcp
    return {}


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Project the input into the fields this detector consumes."""
    if "class_uid" in event:
        if event.get("class_uid") != APPLICATION_ACTIVITY_UID:
            return None
        mcp = event.get("mcp") or {}
        unmapped_mcp = _unmapped_mcp(event)
        session_uid = str(
            mcp.get("session_uid") or unmapped_mcp.get("session_uid") or "sess-unknown"
        )
        tool_name = str(unmapped_mcp.get("tool_name") or (mcp.get("tool") or {}).get("name") or "")
        artifact_sha = str(unmapped_mcp.get("model_artifact_sha256") or "")
        return {
            "source_format": "ocsf",
            "session_uid": session_uid,
            "tool_name": tool_name,
            "artifact_sha256": artifact_sha,
            "time_ms": _safe_int(event.get("time")),
            "raw_event": event,
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"canonical", "native"}:
        return None
    record_type = str(event.get("record_type") or "").strip().lower()
    if record_type and record_type != "application_activity":
        return None
    mcp = event.get("mcp") or {}
    unmapped_mcp = _unmapped_mcp(event)
    return {
        "source_format": schema_mode or "native",
        "session_uid": str(
            event.get("session_uid") or unmapped_mcp.get("session_uid") or "sess-unknown"
        ),
        "tool_name": str(unmapped_mcp.get("tool_name") or event.get("tool_name") or ""),
        "artifact_sha256": str(
            unmapped_mcp.get("model_artifact_sha256") or event.get("model_artifact_sha256") or ""
        ),
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "raw_event": event,
    }


def _is_artifact_event(event: dict[str, Any]) -> bool:
    n = _normalize_event(event)
    if not n:
        return False
    return bool(n["tool_name"]) and bool(n["artifact_sha256"])


def _finding_uid(session_uid: str, tool_name: str, before: str, after: str) -> str:
    return (
        f"det-mcp-model-tamper-{_short(session_uid)}-{_short(tool_name)}-"
        f"{_short(before)}-{_short(after)}"
    )


def _build_native_finding(
    session_uid: str,
    tool_name: str,
    before_event: dict[str, Any],
    after_event: dict[str, Any],
) -> dict[str, Any]:
    before = before_event["artifact_sha256"]
    after = after_event["artifact_sha256"]
    uid = _finding_uid(session_uid, tool_name, before, after)
    desc = (
        f"MCP tool '{tool_name}' in session '{session_uid}' returned a model artifact "
        f"hash that diverged from the session baseline. Baseline: {before}; observed: "
        f"{after}. The session-trusted artifact has been swapped or tampered with mid-"
        f"flight (ATLAS AML.T0010 · OWASP LLM03 supply-chain compromise)."
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
        "time_ms": int(after_event.get("time_ms") or _now_ms()),
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": 1,
        "activity_id": FINDING_ACTIVITY_CREATE,
        "title": "MCP model artifact hash diverged from session baseline",
        "description": desc,
        "finding_types": ["mcp-model-artifact-tampering", "llm-supply-chain"],
        "first_seen_time_ms": int(before_event.get("time_ms") or 0),
        "last_seen_time_ms": int(after_event.get("time_ms") or 0),
        "session_uid": session_uid,
        "tool_name": tool_name,
        "before_artifact_sha256": before,
        "after_artifact_sha256": after,
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
            {"name": "model.before_artifact_sha256", "type": "Fingerprint", "value": before},
            {"name": "model.after_artifact_sha256", "type": "Fingerprint", "value": after},
        ],
        "evidence_count": 2,
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
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "mcp", "ai", "supply-chain", "model-tamper"],
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
        "evidence": {
            "events_observed": native_finding["evidence_count"],
            "before_event_time": native_finding["first_seen_time_ms"],
            "after_event_time": native_finding["last_seen_time_ms"],
        },
    }


def detect(
    events: Iterable[dict[str, Any]], output_format: str = "ocsf"
) -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    # session_uid -> (baseline_artifact, baseline_event)
    state: dict[str, tuple[str, dict[str, Any]]] = {}

    materialised: list[dict[str, Any]] = []
    for event in events:
        if not _is_artifact_event(event):
            continue
        n = _normalize_event(event)
        if n is not None:
            materialised.append(n)
    materialised.sort(key=lambda e: (e.get("session_uid", ""), e.get("time_ms", 0)))

    for event in materialised:
        session_uid = event["session_uid"]
        tool_name = event["tool_name"]
        artifact = event["artifact_sha256"]
        prior = state.get(session_uid)
        if prior is None:
            state[session_uid] = (artifact, event)
            continue
        prior_artifact, prior_event = prior
        if prior_artifact == artifact:
            continue
        native = _build_native_finding(session_uid, tool_name, prior_event, event)
        yield native if output_format == "native" else _render_ocsf_finding(native)
        state[session_uid] = (artifact, event)


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            print(
                f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {exc}", file=sys.stderr
            )
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
        help="Render OCSF Detection Finding (default) or the native projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    # touch hashlib to keep the import live for downstream extensions
    _ = hashlib.sha256

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
