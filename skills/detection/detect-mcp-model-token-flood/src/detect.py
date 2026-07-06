"""Detect prompt-token flooding against a model endpoint over MCP.

Reads OCSF 1.8 Application Activity (class 6002) events emitted by
`ingest-mcp-proxy-ocsf`. Maintains a sliding window per
`(actor.user.uid, model_name)`, sums `unmapped.mcp.prompt_tokens`, and emits a
Detection Finding when the per-window total crosses
`MCP_PROMPT_TOKEN_BUDGET` inside `MCP_PROMPT_TOKEN_WINDOW_MIN` minutes.
Maps to OWASP LLM04 / LLM10.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "detect-mcp-model-token-flood"
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

DEFAULT_BUDGET = 200_000
DEFAULT_WINDOW_MIN = 5

# ATLAS Cost Harvesting is the closest fit when the flood is cost-motivated;
# the primary mapping is the OWASP LLM Top 10 entries.
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


def budget() -> int:
    return _env_int("MCP_PROMPT_TOKEN_BUDGET", DEFAULT_BUDGET)


def window_min() -> int:
    return _env_int("MCP_PROMPT_TOKEN_WINDOW_MIN", DEFAULT_WINDOW_MIN)


def _unmapped_mcp(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped")
    if isinstance(unmapped, dict):
        mcp = unmapped.get("mcp")
        if isinstance(mcp, dict):
            return mcp
    return {}


def _user_uid(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or actor.get("uid") or "user-unknown")


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != APPLICATION_ACTIVITY_UID:
            return None
        unmapped_mcp = _unmapped_mcp(event)
        prompt_tokens = _safe_int(unmapped_mcp.get("prompt_tokens"))
        model_name = str(unmapped_mcp.get("model_name") or "")
        if prompt_tokens <= 0 or not model_name:
            return None
        return {
            "user_uid": _user_uid(event),
            "model_name": model_name,
            "prompt_tokens": prompt_tokens,
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
    prompt_tokens = _safe_int(unmapped_mcp.get("prompt_tokens") or event.get("prompt_tokens"))
    model_name = str(unmapped_mcp.get("model_name") or event.get("model_name") or "")
    if prompt_tokens <= 0 or not model_name:
        return None
    actor = event.get("actor") or {}
    user = actor.get("user") if isinstance(actor, dict) else None
    user_uid = ""
    if isinstance(user, dict):
        user_uid = str(user.get("uid") or "")
    if not user_uid:
        user_uid = str(event.get("user_uid") or "user-unknown")
    return {
        "user_uid": user_uid,
        "model_name": model_name,
        "prompt_tokens": prompt_tokens,
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "raw_event": event,
    }


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _finding_uid(user_uid: str, model_name: str, window_start_ms: int) -> str:
    return f"det-mcp-token-flood-{user_uid}-{model_name}-{window_start_ms}"


def _build_native_finding(
    user_uid: str,
    model_name: str,
    window_events: list[dict[str, Any]],
    total_tokens: int,
    threshold: int,
    window_minutes: int,
) -> dict[str, Any]:
    first_time = window_events[0]["time_ms"]
    last_time = window_events[-1]["time_ms"]
    uid = _finding_uid(user_uid, model_name, first_time)
    desc = (
        f"User '{user_uid}' submitted {total_tokens} prompt tokens against model "
        f"'{model_name}' over the past {window_minutes} minute(s), exceeding the "
        f"MCP_PROMPT_TOKEN_BUDGET ({threshold}). This is the OWASP LLM04 / LLM10 "
        f"prompt-token flood pattern — agents or adversaries amplifying cost or "
        f"saturating the model endpoint with cumulative volume that no single "
        f"per-call RLIMIT would block."
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
        "time_ms": int(last_time or _now_ms()),
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": 1,
        "activity_id": FINDING_ACTIVITY_CREATE,
        "title": "MCP prompt-token flood against a single model endpoint",
        "description": desc,
        "finding_types": ["mcp-model-token-flood", "llm-model-dos"],
        "first_seen_time_ms": int(first_time or 0),
        "last_seen_time_ms": int(last_time or 0),
        "user_uid": user_uid,
        "model_name": model_name,
        "total_tokens": total_tokens,
        "threshold_tokens": threshold,
        "window_minutes": window_minutes,
        "event_count": len(window_events),
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
            {"name": "user.uid", "type": "Other", "value": user_uid},
            {"name": "model.name", "type": "Other", "value": model_name},
            {"name": "prompt_tokens.total", "type": "Other", "value": str(total_tokens)},
            {"name": "window.start_ms", "type": "Other", "value": str(first_time)},
            {"name": "window.end_ms", "type": "Other", "value": str(last_time)},
        ],
        "evidence_count": len(window_events),
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
            "labels": ["detection-engineering", "mcp", "ai", "llm-dos", "unbounded-consumption"],
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
            "total_tokens": native["total_tokens"],
            "threshold_tokens": native["threshold_tokens"],
            "window_minutes": native["window_minutes"],
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    output_format: str = "ocsf",
    *,
    token_budget: int | None = None,
    window_minutes: int | None = None,
) -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    threshold = token_budget if token_budget is not None else budget()
    window = window_minutes if window_minutes is not None else window_min()
    window_ms = window * 60_000

    normalized: list[dict[str, Any]] = []
    for event in events:
        n = _normalize_event(event)
        if n is not None:
            normalized.append(n)
    normalized.sort(
        key=lambda e: (e.get("user_uid", ""), e.get("model_name", ""), e.get("time_ms", 0))
    )

    # Group by (user, model)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in normalized:
        key = (event["user_uid"], event["model_name"])
        groups.setdefault(key, []).append(event)

    for (user_uid, model_name), group in groups.items():
        # Sliding window
        window_events: deque[dict[str, Any]] = deque()
        running = 0
        emitted_for_current_window = False
        for event in group:
            t = event["time_ms"]
            # evict events older than window
            while window_events and t - window_events[0]["time_ms"] > window_ms:
                running -= window_events[0]["prompt_tokens"]
                window_events.popleft()
                # On window slide, reset the emission flag so a NEW flood window
                # gets its own finding.
                emitted_for_current_window = False
            window_events.append(event)
            running += event["prompt_tokens"]
            if running > threshold and not emitted_for_current_window:
                native = _build_native_finding(
                    user_uid,
                    model_name,
                    list(window_events),
                    running,
                    threshold,
                    window,
                )
                yield native if output_format == "native" else _render_ocsf_finding(native)
                emitted_for_current_window = True


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
