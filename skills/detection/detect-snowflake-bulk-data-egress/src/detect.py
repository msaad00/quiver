"""Detect single-principal Snowflake bulk data egress from OCSF 1.8 events.

Reads OCSF 1.8 API Activity (class 6003) records carrying the Snowflake-shaped
`unmapped.snowflake.{rows_unloaded,bytes_scanned,stage_name}` block and emits
OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1567
Exfiltration Over Web Service whenever a principal crosses the configured
volume + stage-fan-out thresholds inside a sliding window.

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

_log = get_logger(__name__, skill="detect-snowflake-bulk-data-egress", layer="detection")

SKILL_NAME = "detect-snowflake-bulk-data-egress"
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

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

# Thresholds. Defaults are deliberately conservative; operators tune via env.
WINDOW_MIN_DEFAULT = 60
BYTE_THRESHOLD_DEFAULT = 5 * 1024 * 1024 * 1024  # 5 GiB
ROW_THRESHOLD_DEFAULT = 1_000_000
MIN_STAGES_DEFAULT = 3

WINDOW_MIN_ENV = "SNOWFLAKE_EGRESS_WINDOW_MIN"
BYTE_THRESHOLD_ENV = "SNOWFLAKE_EGRESS_BYTE_THRESHOLD"
ROW_THRESHOLD_ENV = "SNOWFLAKE_EGRESS_ROW_THRESHOLD"
MIN_STAGES_ENV = "SNOWFLAKE_EGRESS_MIN_STAGES"

# Source skills whose normalized output we trust as "Snowflake API Activity".
# We accept either a dedicated `ingest-snowflake-*` ingest skill or the
# read-only `source-snowflake-query` adapter when the events carry the
# Snowflake-shaped `unmapped.snowflake` block.
ACCEPTED_PRODUCERS = frozenset(
    {
        "ingest-snowflake-query-history-ocsf",
        "ingest-snowflake-access-history-ocsf",
        "source-snowflake-query",
    }
)

# Snowflake `COPY INTO <location>` and `GET` operations that materialize data
# off the Snowflake side. The detector aggregates across all of them — if a
# legit batch ETL uses one of these against one stage it stays under the
# fan-out threshold; an attacker fanning out across stages crosses it.
EGRESS_OPERATIONS = frozenset(
    {
        "COPY_INTO_LOCATION",
        "COPY_UNLOAD",
        "GET",
        "UNLOAD",
    }
)

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0010"
MITRE_TACTIC_NAME = "Exfiltration"
MITRE_TECHNIQUE_UID = "T1567"
MITRE_TECHNIQUE_NAME = "Exfiltration Over Web Service"

# OWASP Top 10
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


def _bytes_scanned(event: dict[str, Any]) -> int:
    raw = _snowflake_block(event).get("bytes_scanned")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def _rows_unloaded(event: dict[str, Any]) -> int:
    raw = _snowflake_block(event).get("rows_unloaded")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def _stage_name(event: dict[str, Any]) -> str:
    raw = _snowflake_block(event).get("stage_name")
    return str(raw or "").strip()


def _is_relevant(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _producer(event) not in ACCEPTED_PRODUCERS:
        return False
    if _api_operation(event) not in EGRESS_OPERATIONS:
        return False
    if not _actor_uid(event):
        return False
    if not _stage_name(event):
        return False
    if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
        return False
    return True


def _finding_uid(actor_uid: str, window_start_ms: int, window_end_ms: int) -> str:
    material = f"{actor_uid}|{window_start_ms}|{window_end_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-snowflake-bulk-egress-{digest}"


def _build_native_finding(
    actor_uid: str,
    actor_name: str,
    burst: list[dict[str, Any]],
) -> dict[str, Any]:
    first = burst[0]
    last = burst[-1]
    cumulative_bytes = sum(item["bytes_scanned"] for item in burst)
    cumulative_rows = sum(item["rows_unloaded"] for item in burst)
    stage_names = sorted({item["stage_name"] for item in burst if item["stage_name"]})
    event_uids = [item["event_uid"] for item in burst if item["event_uid"]]
    operations = sorted({item["api_operation"] for item in burst if item["api_operation"]})
    finding_uid = _finding_uid(actor_uid, first["time_ms"], last["time_ms"])

    bytes_gib = cumulative_bytes / (1024.0 * 1024.0 * 1024.0)
    description = (
        f"Snowflake principal '{actor_name or actor_uid}' moved approximately "
        f"{bytes_gib:.2f} GiB across {cumulative_rows:,} unloaded rows through "
        f"{len(stage_names)} distinct stage(s) ({', '.join(stage_names) or 'n/a'}) "
        f"over a {_window_minutes()}-minute window using {', '.join(operations) or 'COPY/GET'}. "
        "This pattern aligns with bulk data exfiltration via external stages."
    )

    observables: list[dict[str, Any]] = [
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
        {"name": "actor.user.name", "type": "User Name", "value": actor_name or actor_uid},
        {"name": "snowflake.bytes_scanned", "type": "Other", "value": str(cumulative_bytes)},
        {"name": "snowflake.rows_unloaded", "type": "Other", "value": str(cumulative_rows)},
        {"name": "snowflake.stage_count", "type": "Other", "value": str(len(stage_names))},
    ]
    observables.extend(
        {"name": "snowflake.stage_name", "type": "Resource UID", "value": stage}
        for stage in stage_names
    )

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
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": "Snowflake principal bulk data egress across multiple stages",
        "description": description,
        "finding_types": ["snowflake-bulk-data-egress", OWASP_FINDING_TYPE],
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
            "events_observed": len(burst),
            "bytes_scanned": cumulative_bytes,
            "rows_unloaded": cumulative_rows,
            "stage_names": stage_names,
            "api_operations": operations,
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
            "labels": ["data-warehouse", "snowflake", "exfiltration", "detection"],
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
        "asset_classes": ("warehouse", "queries", "external-stages", "identities"),
        "attack_coverage": {
            "snowflake": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": sorted(EGRESS_OPERATIONS),
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "window_minutes": _window_minutes(),
            "byte_threshold": _byte_threshold(),
            "row_threshold": _row_threshold(),
            "min_stages": _min_stages(),
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
        actor_uid = _actor_uid(event)
        relevant.append(
            {
                "event_uid": meta_uid,
                "time_ms": _event_time(event),
                "actor_uid": actor_uid,
                "actor_name": _actor_name(event),
                "api_operation": _api_operation(event),
                "stage_name": _stage_name(event),
                "bytes_scanned": _bytes_scanned(event),
                "rows_unloaded": _rows_unloaded(event),
            }
        )

    relevant.sort(key=lambda item: (item["actor_uid"], item["time_ms"], item["event_uid"]))

    window_ms = _window_minutes() * 60_000
    byte_threshold = _byte_threshold()
    row_threshold = _row_threshold()
    min_stages = _min_stages()

    states: dict[str, list[dict[str, Any]]] = {}
    cooldown_until: dict[str, int] = {}

    for item in relevant:
        actor_uid = item["actor_uid"]
        cur_time = item["time_ms"]
        burst = states.setdefault(actor_uid, [])

        # Drop cooled-down entries past the window so we re-arm cleanly once
        # the principal has been quiet for `window_ms`.
        cutoff = cur_time - window_ms
        burst[:] = [entry for entry in burst if entry["time_ms"] >= cutoff]
        burst.append(item)

        cooldown = cooldown_until.get(actor_uid, 0)
        if cur_time < cooldown:
            continue

        cum_bytes = sum(entry["bytes_scanned"] for entry in burst)
        cum_rows = sum(entry["rows_unloaded"] for entry in burst)
        stages = {entry["stage_name"] for entry in burst if entry["stage_name"]}
        volume_threshold_met = cum_bytes >= byte_threshold or cum_rows >= row_threshold
        if volume_threshold_met and len(stages) >= min_stages:
            native_finding = _build_native_finding(actor_uid, item["actor_name"], list(burst))
            if output_format == "native":
                yield native_finding
            else:
                yield _render_ocsf_finding(native_finding)
            cooldown_until[actor_uid] = cur_time + window_ms
            burst.clear()


def _env_int(name: str, default: int) -> int:
    value = env_int(name, default, skill_name=SKILL_NAME)
    return value if value > 0 else default


def _window_minutes() -> int:
    return _env_int(WINDOW_MIN_ENV, WINDOW_MIN_DEFAULT)


def _byte_threshold() -> int:
    return _env_int(BYTE_THRESHOLD_ENV, BYTE_THRESHOLD_DEFAULT)


def _row_threshold() -> int:
    return _env_int(ROW_THRESHOLD_ENV, ROW_THRESHOLD_DEFAULT)


def _min_stages() -> int:
    return _env_int(MIN_STAGES_ENV, MIN_STAGES_DEFAULT)


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
        description="Detect Snowflake bulk data egress across external stages from OCSF 1.8 API Activity input."
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
            "detect-snowflake-bulk-data-egress starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-snowflake-bulk-data-egress complete",
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
