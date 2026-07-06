"""Detect Snowflake warehouse resize bursts from OCSF 1.8 API Activity.

Reads OCSF 1.8 API Activity (class 6003) records carrying the Snowflake-shaped
`unmapped.snowflake.{warehouse_name,warehouse_size_from,warehouse_size_to}`
block and emits OCSF 1.8 Detection Finding (class 2004) tagged with MITRE
ATT&CK T1496 Resource Hijacking when a warehouse jumps >= N sizes inside the
configured window.

Contract: see ../SKILL.md and ../REFERENCES.md
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

from skills._shared.env import env_int  # noqa: E402
from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

_log = get_logger(__name__, skill="detect-snowflake-warehouse-resize-burst", layer="detection")

SKILL_NAME = "detect-snowflake-warehouse-resize-burst"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"

OUTPUT_FORMATS = ("ocsf", "native")

API_ACTIVITY_CLASS_UID = 6003
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_MEDIUM = 3
STATUS_SUCCESS = 1

ANCHOR_OPERATION = "ALTER_WAREHOUSE"

# Snowflake warehouse sizes in ascending order. Index = ordinal scale.
SIZE_LADDER: tuple[str, ...] = (
    "XSMALL",
    "SMALL",
    "MEDIUM",
    "LARGE",
    "XLARGE",
    "X2LARGE",
    "X3LARGE",
    "X4LARGE",
    "X5LARGE",
    "X6LARGE",
)
SIZE_INDEX: dict[str, int] = {size: i for i, size in enumerate(SIZE_LADDER)}

WINDOW_MIN_DEFAULT = 60
SIZE_JUMP_DEFAULT = 3

WINDOW_MIN_ENV = "SNOWFLAKE_RESIZE_WINDOW_MIN"
SIZE_JUMP_ENV = "SNOWFLAKE_RESIZE_MIN_SIZE_JUMP"

ACCEPTED_PRODUCERS = frozenset(
    {
        "ingest-snowflake-query-history-ocsf",
        "ingest-snowflake-access-history-ocsf",
        "source-snowflake-query",
    }
)

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0040"
MITRE_TACTIC_NAME = "Impact"
MITRE_TECHNIQUE_UID = "T1496"
MITRE_TECHNIQUE_NAME = "Resource Hijacking"

OWASP_FINDING_TYPE = "OWASP-Top-10-A04"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _event_time(event: dict[str, Any]) -> int:
    raw = event.get("time")
    if raw is None:
        raw = event.get("time_ms") or 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _metadata_uid(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    return str(metadata.get("uid") or "")


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "").upper()


def _actor_uid(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("name") or "").strip()


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "").strip()


def _snowflake_block(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    block = unmapped.get("snowflake") or {}
    return block if isinstance(block, dict) else {}


def _warehouse_name(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("warehouse_name") or "").strip()


def _size_from(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("warehouse_size_from") or "").strip().upper()


def _size_to(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("warehouse_size_to") or "").strip().upper()


def _size_index(size: str) -> int | None:
    return SIZE_INDEX.get(size)


def _is_relevant(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _producer(event) not in ACCEPTED_PRODUCERS:
        return False
    if _api_operation(event) != ANCHOR_OPERATION:
        return False
    if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
        return False
    if not _warehouse_name(event):
        return False
    if _size_index(_size_from(event)) is None:
        return False
    if _size_index(_size_to(event)) is None:
        return False
    return True


def _finding_uid(warehouse_name: str, window_start_ms: int, window_end_ms: int) -> str:
    material = f"{warehouse_name}|{window_start_ms}|{window_end_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-snowflake-resize-burst-{digest}"


def _build_native_finding(
    warehouse_name: str,
    burst: list[dict[str, Any]],
) -> dict[str, Any]:
    first = burst[0]
    last = burst[-1]
    min_index = min(item["size_from_index"] for item in burst)
    max_index = max(item["size_to_index"] for item in burst)
    min_size = SIZE_LADDER[min_index]
    max_size = SIZE_LADDER[max_index]
    actor_uid = last["actor_uid"]
    actor_name = last["actor_name"]
    event_uids = [item["event_uid"] for item in burst if item["event_uid"]]
    finding_uid = _finding_uid(warehouse_name, first["time_ms"], last["time_ms"])

    description = (
        f"Snowflake warehouse '{warehouse_name}' scaled from {min_size} to {max_size} "
        f"(jump of {max_index - min_index} sizes) across {len(burst)} ALTER_WAREHOUSE "
        f"event(s) in a {_window_minutes()}-minute window, driven by principal "
        f"'{actor_name or actor_uid}'. Sustained queries at this size are billed "
        "per second of active compute and may indicate resource hijacking."
    )

    observables: list[dict[str, Any]] = [
        {"name": "snowflake.warehouse_name", "type": "Resource UID", "value": warehouse_name},
        {"name": "snowflake.size_from", "type": "Other", "value": min_size},
        {"name": "snowflake.size_to", "type": "Other", "value": max_size},
        {"name": "snowflake.size_jump", "type": "Other", "value": str(max_index - min_index)},
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
        {"name": "actor.user.name", "type": "User Name", "value": actor_name or actor_uid},
    ]

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Snowflake",
        "time_ms": last["time_ms"] or _now_ms(),
        "severity": "medium",
        "severity_id": SEVERITY_MEDIUM,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": f"Snowflake warehouse '{warehouse_name}' resize burst ({min_size} -> {max_size})",
        "description": description,
        "finding_types": ["snowflake-warehouse-resize-burst", OWASP_FINDING_TYPE],
        "first_seen_time_ms": first["time_ms"],
        "last_seen_time_ms": last["time_ms"],
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": MITRE_TACTIC_UID,
                "tactic_name": MITRE_TACTIC_NAME,
                "technique_uid": MITRE_TECHNIQUE_UID,
                "technique_name": MITRE_TECHNIQUE_NAME,
            }
        ],
        "observables": observables,
        "evidence": {
            "warehouse_name": warehouse_name,
            "min_size": min_size,
            "max_size": max_size,
            "size_jump": max_index - min_index,
            "events_observed": len(burst),
            "raw_event_uids": event_uids,
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
            "labels": ["data-warehouse", "snowflake", "impact", "detection", "resource-hijacking"],
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
        "evidence": native_finding["evidence"],
    }


def coverage_metadata() -> dict[str, Any]:
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14", "OWASP Top 10"),
        "providers": ("snowflake",),
        "asset_classes": ("warehouse", "compute", "identities"),
        "attack_coverage": {
            "snowflake": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": [ANCHOR_OPERATION],
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "window_minutes": _window_minutes(),
            "min_size_jump": _min_size_jump(),
        },
    }


def detect(
    events: Iterable[dict[str, Any]], output_format: str = "ocsf"
) -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(
            f"unsupported output_format: {output_format}",
            hint=f"choose one of: {', '.join(OUTPUT_FORMATS)}",
        )

    dedupe: set[str] = set()
    relevant: list[dict[str, Any]] = []
    for event in events:
        if not _is_relevant(event):
            continue
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in dedupe:
            continue
        if meta_uid:
            dedupe.add(meta_uid)
        relevant.append(
            {
                "event_uid": meta_uid,
                "time_ms": _event_time(event),
                "warehouse_name": _warehouse_name(event),
                "actor_uid": _actor_uid(event),
                "actor_name": _actor_name(event),
                "size_from_index": SIZE_INDEX[_size_from(event)],
                "size_to_index": SIZE_INDEX[_size_to(event)],
            }
        )

    relevant.sort(key=lambda item: (item["warehouse_name"], item["time_ms"], item["event_uid"]))

    window_ms = _window_minutes() * 60_000
    size_jump = _min_size_jump()

    states: dict[str, list[dict[str, Any]]] = {}
    cooldown_until: dict[str, int] = {}

    for item in relevant:
        warehouse = item["warehouse_name"]
        cur_time = item["time_ms"]
        burst = states.setdefault(warehouse, [])

        cutoff = cur_time - window_ms
        burst[:] = [entry for entry in burst if entry["time_ms"] >= cutoff]
        burst.append(item)

        cooldown = cooldown_until.get(warehouse, 0)
        if cur_time < cooldown:
            continue

        min_index = min(entry["size_from_index"] for entry in burst)
        max_index = max(entry["size_to_index"] for entry in burst)
        if (max_index - min_index) >= size_jump:
            native_finding = _build_native_finding(warehouse, list(burst))
            if output_format == "native":
                yield native_finding
            else:
                yield _render_ocsf_finding(native_finding)
            cooldown_until[warehouse] = cur_time + window_ms
            burst.clear()


def _env_int(name: str, default: int) -> int:
    value = env_int(name, default, skill_name=SKILL_NAME)
    return value if value > 0 else default


def _window_minutes() -> int:
    return _env_int(WINDOW_MIN_ENV, WINDOW_MIN_DEFAULT)


def _min_size_jump() -> int:
    return _env_int(SIZE_JUMP_ENV, SIZE_JUMP_DEFAULT)


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
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
                error=str(exc),
            )
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_json_shape",
                message=f"skipping line {lineno}: not a JSON object",
                line=lineno,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect Snowflake warehouse resize bursts from OCSF 1.8 API Activity input."
    )
    parser.add_argument(
        "input", nargs="?", help="OCSF 1.8 API Activity 6003 JSONL input. Defaults to stdin."
    )
    parser.add_argument(
        "--output", "-o", help="Detection Finding JSONL output. Defaults to stdout."
    )
    parser.add_argument(
        "--output-format", choices=OUTPUT_FORMATS, default="ocsf", help="Output format."
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    findings_emitted = 0
    try:
        events = list(load_jsonl(in_stream))
        _log.info(
            "detect-snowflake-warehouse-resize-burst starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-snowflake-warehouse-resize-burst complete",
            extra={"findings_emitted": findings_emitted},
        )
    except SkillError as exc:
        return emit_error(SKILL_NAME, exc)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return emit_error(
            SKILL_NAME,
            ContractError(
                f"input is not JSONL: {exc}",
                hint="ensure each input line is a valid OCSF 1.8 API Activity 6003 JSON object",
            ),
        )
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
