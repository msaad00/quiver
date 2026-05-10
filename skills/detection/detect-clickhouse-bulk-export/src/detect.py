"""Detect single-principal ClickHouse bulk row export from OCSF 1.8 events.

Reads OCSF 1.8 API Activity (class 6003) records carrying the ClickHouse-shaped
`unmapped.clickhouse.{query_kind,read_bytes,read_rows,written_bytes,
written_rows,query,exception}` block and emits OCSF 1.8 Detection Finding
(class 2004) tagged with MITRE ATT&CK T1567 Exfiltration Over Web Service
whenever a principal crosses the configured cumulative-bytes threshold inside
a sliding window for queries that match an external-export pattern
(`INTO OUTFILE`, `INSERT INTO FUNCTION s3(`, `URL(`).

Contract: see ../SKILL.md and ../REFERENCES.md
"""

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

from skills._shared.env import env_int  # noqa: E402
from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

_log = get_logger(__name__, skill="detect-clickhouse-bulk-export", layer="detection")

SKILL_NAME = "detect-clickhouse-bulk-export"
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
BYTE_THRESHOLD_DEFAULT = 10 * 1024 * 1024 * 1024  # 10 GiB

WINDOW_MIN_ENV = "CLICKHOUSE_EXPORT_WINDOW_MIN"
BYTE_THRESHOLD_ENV = "CLICKHOUSE_EXPORT_BYTE_THRESHOLD"

# We anchor on `metadata.product.vendor_name == "ClickHouse"` rather than a
# producer-skill allowlist. The companion ingester (`ingest-clickhouse-query-
# log-ocsf`) is not yet on main; any normalized `system.query_log` source that
# correctly stamps the OCSF product vendor identifies as ClickHouse on the
# wire and is welcome upstream.
CLICKHOUSE_VENDOR = "ClickHouse"

# SQL-text patterns that mark a `system.query_log` row as a row-exporting
# query. Case-insensitive substring match against the raw query text. We
# intentionally do not parse SQL — `query_log.query` is the literal statement
# the engine ran, and these substrings are unambiguous markers of the export
# surfaces documented in the SKILL.md attack pattern.
EXPORT_PATTERNS: tuple[str, ...] = (
    "INTO OUTFILE",
    "INSERT INTO FUNCTION S3(",
    "URL(",
)

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0010"
MITRE_TACTIC_NAME = "Exfiltration"
MITRE_TECHNIQUE_UID = "T1567"
MITRE_TECHNIQUE_NAME = "Exfiltration Over Web Service"

# OWASP Top 10
OWASP_FINDING_TYPE = "OWASP-Top-10-A04"

# Compiled regex for cheap export-target extraction from the SQL text. We try
# each pattern; whichever fires first wins the "export target" label that
# lands in the finding evidence. Best-effort only — if nothing matches, the
# event still counts and the target falls back to the matched marker token.
_TARGET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"INTO\s+OUTFILE\s+'([^']+)'", re.IGNORECASE), "outfile"),
    (re.compile(r'INTO\s+OUTFILE\s+"([^"]+)"', re.IGNORECASE), "outfile"),
    (re.compile(r"INSERT\s+INTO\s+FUNCTION\s+s3\(\s*'([^']+)'", re.IGNORECASE), "s3"),
    (re.compile(r'INSERT\s+INTO\s+FUNCTION\s+s3\(\s*"([^"]+)"', re.IGNORECASE), "s3"),
    (re.compile(r"\bURL\s*\(\s*'([^']+)'", re.IGNORECASE), "url"),
    (re.compile(r'\bURL\s*\(\s*"([^"]+)"', re.IGNORECASE), "url"),
)


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


def _vendor_name(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    return str(product.get("vendor_name") or "")


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


def _clickhouse_block(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    block = unmapped.get("clickhouse") or {}
    return block if isinstance(block, dict) else {}


def _read_bytes(event: dict[str, Any]) -> int:
    raw = _clickhouse_block(event).get("read_bytes")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def _read_rows(event: dict[str, Any]) -> int:
    raw = _clickhouse_block(event).get("read_rows")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def _written_bytes(event: dict[str, Any]) -> int:
    raw = _clickhouse_block(event).get("written_bytes")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def _written_rows(event: dict[str, Any]) -> int:
    raw = _clickhouse_block(event).get("written_rows")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def _query_kind(event: dict[str, Any]) -> str:
    return str(_clickhouse_block(event).get("query_kind") or "").strip()


def _query_text(event: dict[str, Any]) -> str:
    return str(_clickhouse_block(event).get("query") or "")


def _exception(event: dict[str, Any]) -> str:
    return str(_clickhouse_block(event).get("exception") or "").strip()


def _matched_export_pattern(query: str) -> str | None:
    upper = query.upper()
    for marker in EXPORT_PATTERNS:
        if marker in upper:
            return marker
    return None


def _export_target(query: str, marker: str) -> str:
    """Pull the destination string from the query, or fall back to the marker."""
    for pattern, _label in _TARGET_PATTERNS:
        match = pattern.search(query)
        if match:
            return match.group(1)
    # Fall back: surface the matched marker so the finding still names what
    # tripped it, even if we couldn't pluck a literal URL/path out.
    return marker.strip("(").strip().lower()


def _is_relevant(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _vendor_name(event).strip().lower() != CLICKHOUSE_VENDOR.lower():
        return False
    if not _actor_uid(event):
        return False
    if _exception(event):
        # Failed query — never moved any rows out. Skip.
        return False
    if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
        return False
    if _matched_export_pattern(_query_text(event)) is None:
        return False
    return True


def _finding_uid(actor_uid: str, window_start_ms: int, window_end_ms: int) -> str:
    material = f"{actor_uid}|{window_start_ms}|{window_end_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-clickhouse-bulk-export-{digest}"


def _build_native_finding(
    actor_uid: str,
    actor_name: str,
    burst: list[dict[str, Any]],
) -> dict[str, Any]:
    first = burst[0]
    last = burst[-1]
    cumulative_read_bytes = sum(item["read_bytes"] for item in burst)
    cumulative_read_rows = sum(item["read_rows"] for item in burst)
    cumulative_written_bytes = sum(item["written_bytes"] for item in burst)
    cumulative_written_rows = sum(item["written_rows"] for item in burst)
    export_targets = sorted({item["export_target"] for item in burst if item["export_target"]})
    event_uids = [item["event_uid"] for item in burst if item["event_uid"]]
    operations = sorted({item["api_operation"] for item in burst if item["api_operation"]})
    query_kinds = sorted({item["query_kind"] for item in burst if item["query_kind"]})
    finding_uid = _finding_uid(actor_uid, first["time_ms"], last["time_ms"])

    bytes_gib = cumulative_read_bytes / (1024.0 * 1024.0 * 1024.0)
    description = (
        f"ClickHouse principal '{actor_name or actor_uid}' read approximately "
        f"{bytes_gib:.2f} GiB across {cumulative_read_rows:,} rows and exported "
        f"to {len(export_targets)} distinct destination(s) "
        f"({', '.join(export_targets) or 'n/a'}) over a "
        f"{_window_minutes()}-minute window. This pattern aligns with bulk "
        "row export via INTO OUTFILE / INSERT INTO FUNCTION s3(...) / URL(...) "
        "and is consistent with data exfiltration over a web service."
    )

    observables: list[dict[str, Any]] = [
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
        {"name": "actor.user.name", "type": "User Name", "value": actor_name or actor_uid},
        {"name": "clickhouse.read_bytes", "type": "Other", "value": str(cumulative_read_bytes)},
        {"name": "clickhouse.read_rows", "type": "Other", "value": str(cumulative_read_rows)},
        {"name": "clickhouse.written_bytes", "type": "Other", "value": str(cumulative_written_bytes)},
        {"name": "clickhouse.written_rows", "type": "Other", "value": str(cumulative_written_rows)},
        {"name": "clickhouse.export_target_count", "type": "Other", "value": str(len(export_targets))},
    ]
    observables.extend(
        {"name": "clickhouse.export_target", "type": "Resource UID", "value": target}
        for target in export_targets
    )

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "ClickHouse",
        "time_ms": last["time_ms"] or _now_ms(),
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": "ClickHouse principal bulk row export to external destination",
        "description": description,
        "finding_types": ["clickhouse-bulk-export", OWASP_FINDING_TYPE],
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
            "read_bytes": cumulative_read_bytes,
            "read_rows": cumulative_read_rows,
            "written_bytes": cumulative_written_bytes,
            "written_rows": cumulative_written_rows,
            "export_targets": export_targets,
            "api_operations": operations,
            "query_kinds": query_kinds,
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
            "labels": ["data-warehouse", "clickhouse", "exfiltration", "detection"],
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
        "providers": ("clickhouse",),
        "asset_classes": ("warehouse", "queries", "external-endpoints", "identities"),
        "attack_coverage": {
            "clickhouse": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_patterns": list(EXPORT_PATTERNS),
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "window_minutes": _window_minutes(),
            "byte_threshold": _byte_threshold(),
        },
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
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
        query_text = _query_text(event)
        marker = _matched_export_pattern(query_text) or ""
        relevant.append(
            {
                "event_uid": meta_uid,
                "time_ms": _event_time(event),
                "actor_uid": actor_uid,
                "actor_name": _actor_name(event),
                "api_operation": _api_operation(event),
                "query_kind": _query_kind(event),
                "export_target": _export_target(query_text, marker),
                "read_bytes": _read_bytes(event),
                "read_rows": _read_rows(event),
                "written_bytes": _written_bytes(event),
                "written_rows": _written_rows(event),
            }
        )

    relevant.sort(key=lambda item: (item["actor_uid"], item["time_ms"], item["event_uid"]))

    window_ms = _window_minutes() * 60_000
    byte_threshold = _byte_threshold()

    states: dict[str, list[dict[str, Any]]] = {}
    cooldown_until: dict[str, int] = {}

    for item in relevant:
        actor_uid = item["actor_uid"]
        cur_time = item["time_ms"]
        burst = states.setdefault(actor_uid, [])

        # Drop entries outside the sliding window so a quiet principal re-arms
        # cleanly once their cooldown expires.
        cutoff = cur_time - window_ms
        burst[:] = [entry for entry in burst if entry["time_ms"] >= cutoff]
        burst.append(item)

        cooldown = cooldown_until.get(actor_uid, 0)
        if cur_time < cooldown:
            continue

        cum_read_bytes = sum(entry["read_bytes"] for entry in burst)
        if cum_read_bytes >= byte_threshold:
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
        description="Detect ClickHouse bulk row export to external destinations from OCSF 1.8 API Activity input."
    )
    parser.add_argument("input", nargs="?", help="OCSF 1.8 API Activity 6003 JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Detection Finding JSONL output. Defaults to stdout.")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default="ocsf", help="Output format.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    findings_emitted = 0
    try:
        events = list(load_jsonl(in_stream))
        _log.info(
            "detect-clickhouse-bulk-export starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-clickhouse-bulk-export complete",
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
