"""Detect MCP tools whose declaration diverges from a registered baseline.

Reads OCSF 1.8 Application Activity (class 6002) events emitted by
`ingest-mcp-proxy-ocsf`, hashes each live tool's `description` and
`inputSchema`, and compares against the baseline file at
`MCP_TOOL_BASELINE_PATH`. Emits one Detection Finding per
(session, tool) when either hash diverges from the baseline value.
"""

from __future__ import annotations

import argparse
import hashlib
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

SKILL_NAME = "detect-mcp-shadow-tool-injection"
# Framework depth markers (coverage_summary.py)
# control_id="MCP02"
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
SEVERITY_HIGH = 4

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0001"
MITRE_TACTIC_NAME = "Initial Access"
MITRE_TECHNIQUE_UID = "T1195.001"
MITRE_TECHNIQUE_NAME = "Supply Chain Compromise: Compromise Software Supply Chain"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stable_schema_json(schema: Any) -> str:
    return json.dumps(schema, sort_keys=True, separators=(",", ":"))


def baseline_path() -> Path | None:
    raw = os.environ.get("MCP_TOOL_BASELINE_PATH", "").strip()
    if not raw:
        return None
    return Path(raw)


def load_baseline(path: Path | None) -> dict[str, dict[str, str]]:
    """Load the baseline file. Returns {tool_name: {description_sha256, schema_sha256, registered_at}}.

    Missing/malformed/empty → returns {} (callers handle the fail-open).
    """
    if path is None:
        return {}
    if not path.exists():
        print(
            f"[{SKILL_NAME}] baseline file not found at {path} — failing open.",
            file=sys.stderr,
        )
        return {}
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        print(
            f"[{SKILL_NAME}] baseline file at {path} is malformed JSON: {exc} — failing open.",
            file=sys.stderr,
        )
        return {}
    if not isinstance(raw, dict):
        print(
            f"[{SKILL_NAME}] baseline file at {path} is not a JSON object — failing open.",
            file=sys.stderr,
        )
        return {}
    tools = raw.get("tools")
    if not isinstance(tools, dict):
        print(
            f"[{SKILL_NAME}] baseline file at {path} missing `tools` map — failing open.",
            file=sys.stderr,
        )
        return {}
    cleaned: dict[str, dict[str, str]] = {}
    for name, entry in tools.items():
        if not isinstance(entry, dict):
            continue
        desc_hash = str(entry.get("description_sha256") or "").strip()
        schema_hash = str(entry.get("schema_sha256") or "").strip()
        registered = str(entry.get("registered_at") or "")
        if not desc_hash and not schema_hash:
            continue
        cleaned[str(name)] = {
            "description_sha256": desc_hash,
            "schema_sha256": schema_hash,
            "registered_at": registered,
        }
    return cleaned


def _tool_obj(event: dict[str, Any]) -> dict[str, Any]:
    mcp = event.get("mcp") or {}
    tool = mcp.get("tool")
    if isinstance(tool, dict):
        return tool
    return {}


def _input_schema(tool: dict[str, Any]) -> Any:
    for key in ("inputSchema", "input_schema"):
        candidate = tool.get(key)
        if candidate is not None:
            return candidate
    return None


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != APPLICATION_ACTIVITY_UID:
            return None
        mcp = event.get("mcp") or {}
        method = str(mcp.get("method") or "")
        direction = str(mcp.get("direction") or "")
        if method != "tools/list" or direction != "response":
            return None
        tool = _tool_obj(event)
        tool_name = str(tool.get("name") or "")
        if not tool_name:
            return None
        return {
            "session_uid": str(mcp.get("session_uid") or "sess-unknown"),
            "tool_name": tool_name,
            "description": str(tool.get("description") or ""),
            "input_schema": _input_schema(tool),
            "time_ms": _safe_int(event.get("time")),
            "raw_event": event,
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"canonical", "native"}:
        return None
    record_type = str(event.get("record_type") or "").strip().lower()
    if record_type and record_type != "application_activity":
        return None
    if str(event.get("method") or "") != "tools/list":
        return None
    if str(event.get("direction") or "") != "response":
        return None
    raw_tool = event.get("tool")
    native_tool: dict[str, Any] = raw_tool if isinstance(raw_tool, dict) else {}
    tool_name = str(native_tool.get("name") or event.get("tool_name") or "")
    if not tool_name:
        return None
    return {
        "session_uid": str(event.get("session_uid") or "sess-unknown"),
        "tool_name": tool_name,
        "description": str(native_tool.get("description") or event.get("description") or ""),
        "input_schema": _input_schema(native_tool) if native_tool else event.get("input_schema"),
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "raw_event": event,
    }


def _finding_uid(
    session_uid: str,
    tool_name: str,
    baseline_desc: str,
    baseline_schema: str,
    live_desc: str,
    live_schema: str,
) -> str:
    pair = f"{baseline_desc[:8]}{baseline_schema[:8]}{live_desc[:8]}{live_schema[:8]}"
    return f"det-mcp-shadow-tool-{session_uid}-{tool_name}-{pair}"


def _build_native_finding(
    session_uid: str,
    tool_name: str,
    baseline: dict[str, str],
    live_desc_hash: str,
    live_schema_hash: str,
    diverged_parts: list[str],
    time_ms: int,
) -> dict[str, Any]:
    uid = _finding_uid(
        session_uid,
        tool_name,
        baseline.get("description_sha256", ""),
        baseline.get("schema_sha256", ""),
        live_desc_hash,
        live_schema_hash,
    )
    diverged_str = " + ".join(diverged_parts)
    desc = (
        f"MCP tool '{tool_name}' in session '{session_uid}' diverged from the "
        f"server-registered baseline ({diverged_str}). Baseline registered at "
        f"{baseline.get('registered_at') or 'unknown'} — a poisoned or shadow "
        f"tool has been substituted in the live `tools/list` response. This is "
        f"the OWASP MCP Top 10 Tool Poisoning class (MITRE T1195.001 Compromise "
        f"Software Supply Chain). The agent should NOT trust this tool until the "
        f"MCP server re-publishes a baseline that matches the live declaration."
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
        "time_ms": int(time_ms or _now_ms()),
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": 1,
        "activity_id": FINDING_ACTIVITY_CREATE,
        "title": "MCP tool declaration diverged from the server-registered baseline",
        "description": desc,
        "finding_types": ["mcp-shadow-tool-injection", "mcp-tool-poisoning"],
        "first_seen_time_ms": int(time_ms or 0),
        "last_seen_time_ms": int(time_ms or 0),
        "session_uid": session_uid,
        "tool_name": tool_name,
        "diverged_parts": diverged_parts,
        "baseline_description_sha256": baseline.get("description_sha256", ""),
        "baseline_schema_sha256": baseline.get("schema_sha256", ""),
        "live_description_sha256": live_desc_hash,
        "live_schema_sha256": live_schema_hash,
        "baseline_registered_at": baseline.get("registered_at", ""),
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": MITRE_TACTIC_UID,
                "tactic_name": MITRE_TACTIC_NAME,
                "technique_uid": MITRE_TECHNIQUE_UID,
                "technique_name": MITRE_TECHNIQUE_NAME,
            }
        ],
        "observables": [
            {"name": "session.uid", "type": "Other", "value": session_uid},
            {"name": "tool.name", "type": "Other", "value": tool_name},
            {"name": "diverged.parts", "type": "Other", "value": ",".join(diverged_parts)},
            {
                "name": "baseline.description_sha256",
                "type": "Fingerprint",
                "value": baseline.get("description_sha256", ""),
            },
            {
                "name": "baseline.schema_sha256",
                "type": "Fingerprint",
                "value": baseline.get("schema_sha256", ""),
            },
            {"name": "live.description_sha256", "type": "Fingerprint", "value": live_desc_hash},
            {"name": "live.schema_sha256", "type": "Fingerprint", "value": live_schema_hash},
        ],
        "evidence_count": 1,
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
            "labels": ["detection-engineering", "mcp", "supply-chain", "tool-poisoning"],
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
            "diverged_parts": native["diverged_parts"],
            "baseline_description_sha256": native["baseline_description_sha256"],
            "baseline_schema_sha256": native["baseline_schema_sha256"],
            "live_description_sha256": native["live_description_sha256"],
            "live_schema_sha256": native["live_schema_sha256"],
            "baseline_registered_at": native["baseline_registered_at"],
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    output_format: str = "ocsf",
    *,
    baseline: dict[str, dict[str, str]] | None = None,
) -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    bl = baseline if baseline is not None else load_baseline(baseline_path())
    if not bl:
        return

    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for event in events:
        n = _normalize_event(event)
        if n is not None:
            normalized.append(n)
    normalized.sort(key=lambda e: (e["session_uid"], e["time_ms"], e["tool_name"]))

    for event in normalized:
        tool_name = event["tool_name"]
        baseline_entry = bl.get(tool_name)
        if baseline_entry is None:
            continue
        live_desc_hash = _sha256_hex(event["description"])
        live_schema_hash = _sha256_hex(_stable_schema_json(event["input_schema"]))
        diverged: list[str] = []
        if (
            baseline_entry.get("description_sha256")
            and live_desc_hash != baseline_entry["description_sha256"]
        ):
            diverged.append("description")
        if (
            baseline_entry.get("schema_sha256")
            and live_schema_hash != baseline_entry["schema_sha256"]
        ):
            diverged.append("schema")
        if not diverged:
            continue
        native = _build_native_finding(
            event["session_uid"],
            tool_name,
            baseline_entry,
            live_desc_hash,
            live_schema_hash,
            diverged,
            event["time_ms"],
        )
        uid = native["finding_uid"]
        if uid in seen:
            continue
        seen.add(uid)
        yield native if output_format == "native" else _render_ocsf_finding(native)


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
