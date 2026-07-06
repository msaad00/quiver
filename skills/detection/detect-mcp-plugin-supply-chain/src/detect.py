"""Detect MCP tools whose inputSchema references a non-allowlisted hostname.

Reads OCSF 1.8 Application Activity (class 6002) `tools/list` events emitted
by `ingest-mcp-proxy-ocsf`, recursively walks each tool's `inputSchema`
(including `oneOf` / `anyOf` / `allOf` / `properties` / `items` / `$ref` /
`default` / `description`), extracts every URL-shaped string, and emits a
Detection Finding for each `(session_uid, host)` pair whose hostname is not
in `MCP_PLUGIN_ALLOWED_HOSTS`.

When the allowlist is empty, the detector logs a single stderr warning and
fails open — operators are expected to populate the allowlist explicitly.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "detect-mcp-plugin-supply-chain"
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

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0001"
MITRE_TACTIC_NAME = "Initial Access"
MITRE_TECHNIQUE_UID = "T1195.001"
MITRE_TECHNIQUE_NAME = "Supply Chain Compromise: Compromise Software Supply Chain"

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
URL_FIELDS = ("$ref", "default", "description")


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def allowed_hosts() -> frozenset[str]:
    raw = os.environ.get("MCP_PLUGIN_ALLOWED_HOSTS", "").strip()
    if not raw:
        return frozenset()
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _tool_obj(event: dict[str, Any]) -> dict[str, Any]:
    mcp = event.get("mcp") or {}
    tool = mcp.get("tool")
    if isinstance(tool, dict):
        return tool
    return {}


def _input_schema(tool: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("inputSchema", "input_schema"):
        candidate = tool.get(key)
        if isinstance(candidate, dict):
            return candidate
    return None


def _walk_schema_for_urls(node: Any, source_field: str = "schema") -> Iterable[tuple[str, str]]:
    """Yield (url, source_field_label) tuples from anywhere in the schema."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in URL_FIELDS and isinstance(value, str):
                for match in URL_RE.findall(value):
                    yield match, key
            elif key in ("oneOf", "anyOf", "allOf") and isinstance(value, list):
                for item in value:
                    yield from _walk_schema_for_urls(item, key)
            elif key == "properties" and isinstance(value, dict):
                for prop_value in value.values():
                    yield from _walk_schema_for_urls(prop_value, "properties")
            elif key == "items":
                yield from _walk_schema_for_urls(value, "items")
            elif isinstance(value, (dict, list)):
                yield from _walk_schema_for_urls(
                    value, key if isinstance(key, str) else source_field
                )
            elif isinstance(value, str):
                # Catch URL-shaped strings anywhere — covers things like enum
                # entries or any string-typed default that didn't land under
                # the named keys above.
                for match in URL_RE.findall(value):
                    yield match, str(key)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_schema_for_urls(item, source_field)


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
        session_uid = str(mcp.get("session_uid") or "sess-unknown")
        tool_name = str(tool.get("name") or "")
        if not tool_name:
            return None
        return {
            "source_format": "ocsf",
            "session_uid": session_uid,
            "tool_name": tool_name,
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
        "source_format": schema_mode or "native",
        "session_uid": str(event.get("session_uid") or "sess-unknown"),
        "tool_name": tool_name,
        "input_schema": _input_schema(native_tool) if native_tool else None,
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "raw_event": event,
    }


def _finding_uid(session_uid: str, host: str) -> str:
    safe_host = host.replace(".", "-").replace(":", "-")
    return f"det-mcp-plugin-supply-chain-{session_uid}-{safe_host}"


def _build_native_finding(
    session_uid: str,
    tool_name: str,
    host: str,
    url: str,
    source_field: str,
    time_ms: int,
) -> dict[str, Any]:
    uid = _finding_uid(session_uid, host)
    desc = (
        f"MCP tool '{tool_name}' in session '{session_uid}' declared an inputSchema "
        f"that referenced disallowed host '{host}' (URL: {url}, source: {source_field}). "
        f"The hostname is not in MCP_PLUGIN_ALLOWED_HOSTS — the tool's declaration is "
        f"reaching outside the operator trust boundary (OWASP LLM05 supply chain via "
        f"plugins/tools, MITRE T1195.001 software supply-chain compromise)."
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
        "title": "MCP tool inputSchema references a non-allowlisted host",
        "description": desc,
        "finding_types": ["mcp-plugin-supply-chain", "llm-supply-chain"],
        "first_seen_time_ms": int(time_ms or 0),
        "last_seen_time_ms": int(time_ms or 0),
        "session_uid": session_uid,
        "tool_name": tool_name,
        "disallowed_host": host,
        "source_field": source_field,
        "matched_url": url,
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
            {"name": "schema.host", "type": "Hostname", "value": host},
            {"name": "schema.source_field", "type": "Other", "value": source_field},
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
            "labels": ["detection-engineering", "mcp", "ai", "supply-chain", "plugin"],
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
            "matched_url": native["matched_url"],
        },
    }


_warned_empty_allowlist = False


def _warn_empty_allowlist_once() -> None:
    global _warned_empty_allowlist
    if _warned_empty_allowlist:
        return
    print(
        f"[{SKILL_NAME}] MCP_PLUGIN_ALLOWED_HOSTS is empty — failing open. "
        "Populate the env var with a comma-separated host allowlist to enforce.",
        file=sys.stderr,
    )
    _warned_empty_allowlist = True


def detect(
    events: Iterable[dict[str, Any]],
    output_format: str = "ocsf",
    *,
    allowlist: frozenset[str] | None = None,
) -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    hosts = allowlist if allowlist is not None else allowed_hosts()
    if not hosts:
        _warn_empty_allowlist_once()
        return

    seen: set[tuple[str, str]] = set()

    normalized = []
    for event in events:
        n = _normalize_event(event)
        if n is not None and n["input_schema"] is not None:
            normalized.append(n)
    normalized.sort(key=lambda e: (e["session_uid"], e["time_ms"], e["tool_name"]))

    for event in normalized:
        session_uid = event["session_uid"]
        tool_name = event["tool_name"]
        for url, source_field in _walk_schema_for_urls(event["input_schema"]):
            host = (urlparse(url).hostname or "").lower()
            if not host or host in hosts:
                continue
            key = (session_uid, host)
            if key in seen:
                continue
            seen.add(key)
            native = _build_native_finding(
                session_uid, tool_name, host, url, source_field, event["time_ms"]
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
