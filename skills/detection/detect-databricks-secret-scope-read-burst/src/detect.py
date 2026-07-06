"""Detect Databricks secret-scope read bursts from OCSF 1.8 events.

Reads OCSF 1.8 API Activity (class 6003) records emitted by the upstream
Databricks audit-log ingest pipeline and emits OCSF 1.8 Detection Finding
(class 2004) tagged with MITRE ATT&CK T1552.001 (Credentials In Files) when
a single principal reads N+ distinct secrets from the same scope inside a
sliding window — the canonical pre-exfil credential-enumeration signature.

Contract: see ../SKILL.md and ../REFERENCES.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.env import env_int  # noqa: E402
from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

_log = get_logger(__name__, skill="detect-databricks-secret-scope-read-burst", layer="detection")

SKILL_NAME = "detect-databricks-secret-scope-read-burst"
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

DATABRICKS_VENDOR_NAME = "Databricks"

ACCEPTED_PRODUCERS = frozenset(
    {
        "ingest-databricks-audit-ocsf",
        "source-databricks-query",
    }
)

ANCHOR_OPERATION = "secrets.getSecret"

THRESHOLD_ENV = "DATABRICKS_SECRET_READ_THRESHOLD"
THRESHOLD_DEFAULT = 30
WINDOW_MIN_ENV = "DATABRICKS_SECRET_READ_WINDOW_MIN"
WINDOW_MIN_DEFAULT = 10

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0006"
MITRE_TACTIC_NAME = "Credential Access"
MITRE_TECHNIQUE_UID = "T1552.001"
MITRE_TECHNIQUE_NAME = "Credentials In Files"

OWASP_FINDING_TYPE = "OWASP-Top-10-A07"


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


def _vendor_name(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    return str(product.get("vendor_name") or "")


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "").strip()


def _actor_uid(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("email_addr") or user.get("name") or "").strip()


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("email_addr") or user.get("uid") or "").strip()


def _databricks_block(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    block = unmapped.get("databricks") or {}
    return block if isinstance(block, dict) else {}


def _workspace_id(event: dict[str, Any]) -> str:
    return str(_databricks_block(event).get("workspace_id") or "").strip()


def _secret_scope(event: dict[str, Any]) -> str:
    return str(_databricks_block(event).get("secret_scope") or "").strip()


def _secret_key(event: dict[str, Any]) -> str:
    return str(_databricks_block(event).get("secret_key") or "").strip()


def _is_databricks_event(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _vendor_name(event) == DATABRICKS_VENDOR_NAME:
        return True
    return _producer(event) in ACCEPTED_PRODUCERS


def _threshold() -> int:
    value = env_int(THRESHOLD_ENV, THRESHOLD_DEFAULT, skill_name=SKILL_NAME)
    return value if value > 0 else THRESHOLD_DEFAULT


def _window_ms() -> int:
    minutes = env_int(WINDOW_MIN_ENV, WINDOW_MIN_DEFAULT, skill_name=SKILL_NAME)
    if minutes <= 0:
        minutes = WINDOW_MIN_DEFAULT
    return minutes * 60_000


def _finding_uid(actor_uid: str, scope: str, window_start_ms: int, window_end_ms: int) -> str:
    material = f"{SKILL_NAME}|{actor_uid}|{scope}|{window_start_ms}|{window_end_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-databricks-secret-read-burst-{digest}"


def _build_native_finding(
    *,
    actor_uid: str,
    actor_name: str,
    workspace_id: str,
    scope: str,
    burst_events: list[dict[str, Any]],
    threshold: int,
    window_minutes: int,
) -> dict[str, Any]:
    first = burst_events[0]
    last = burst_events[-1]
    distinct_keys = sorted({item["secret_key"] for item in burst_events})
    event_uids = [item["event_uid"] for item in burst_events if item["event_uid"]]
    time_ms = last["time_ms"] or _now_ms()
    finding_uid = _finding_uid(actor_uid, scope, first["time_ms"], last["time_ms"])

    description = (
        f"Databricks principal '{actor_name or actor_uid}' read {len(distinct_keys)} "
        f"distinct secrets from scope '{scope}' in workspace "
        f"'{workspace_id or 'unknown'}' inside a {window_minutes}-minute window "
        f"(threshold={threshold}). Fan-out enumeration of a secret scope is the "
        "canonical pre-exfil credential-harvesting signature."
    )

    observables: list[dict[str, Any]] = [
        {"name": "cloud.provider", "type": "Other", "value": "Databricks"},
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
    ]
    if actor_name and actor_name != actor_uid:
        observables.append({"name": "actor.user.name", "type": "User Name", "value": actor_name})
    if workspace_id:
        observables.append(
            {"name": "databricks.workspace_id", "type": "Resource UID", "value": workspace_id}
        )
    observables.append({"name": "databricks.secret_scope", "type": "Resource UID", "value": scope})
    observables.append(
        {"name": "databricks.distinct_keys_read", "type": "Other", "value": str(len(distinct_keys))}
    )
    for key in distinct_keys:
        observables.append({"name": "databricks.secret_key", "type": "Other", "value": key})

    evidence: dict[str, Any] = {
        "events_observed": len(burst_events),
        "distinct_keys_read": len(distinct_keys),
        "secret_keys": distinct_keys,
        "secret_scope": scope,
        "workspace_id": workspace_id,
        "window_start_ms": first["time_ms"],
        "window_end_ms": last["time_ms"],
        "window_minutes": window_minutes,
        "threshold": threshold,
        "raw_event_uids": event_uids,
    }

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Databricks",
        "time_ms": time_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": (
            f"Databricks principal '{actor_uid}' enumerated {len(distinct_keys)} "
            f"secrets from scope '{scope}'"
        ),
        "description": description,
        "finding_types": ["databricks-secret-scope-read-burst", OWASP_FINDING_TYPE],
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
        "evidence": evidence,
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
            "labels": [
                "data-warehouse",
                "databricks",
                "secrets",
                "credential-access",
                "detection",
            ],
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
        "providers": ("databricks",),
        "asset_classes": ("warehouse", "secrets", "credentials"),
        "attack_coverage": {
            "databricks": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": [ANCHOR_OPERATION],
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "distinct_key_threshold": _threshold(),
            "window_minutes": _window_ms() // 60_000,
        },
    }


def _is_relevant(event: dict[str, Any]) -> bool:
    if not _is_databricks_event(event):
        return False
    if _api_operation(event) != ANCHOR_OPERATION:
        return False
    if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
        return False
    if not _actor_uid(event):
        return False
    if not _secret_scope(event):
        return False
    if not _secret_key(event):
        return False
    return True


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(
            f"unsupported output_format: {output_format}",
            hint=f"choose one of: {', '.join(OUTPUT_FORMATS)}",
        )

    threshold = _threshold()
    window_ms = _window_ms()
    window_minutes = window_ms // 60_000

    # Gather relevant events and sort for deterministic windowing.
    relevant: list[dict[str, Any]] = []
    seen_event_uids: set[str] = set()
    for event in events:
        if not _is_relevant(event):
            continue
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in seen_event_uids:
            continue
        if meta_uid:
            seen_event_uids.add(meta_uid)
        relevant.append(
            {
                "event_uid": meta_uid,
                "time_ms": _event_time(event),
                "actor_uid": _actor_uid(event),
                "actor_name": _actor_name(event),
                "workspace_id": _workspace_id(event),
                "secret_scope": _secret_scope(event),
                "secret_key": _secret_key(event),
            }
        )

    relevant.sort(
        key=lambda item: (
            item["actor_uid"],
            item["secret_scope"],
            item["time_ms"],
            item["event_uid"],
        )
    )

    # State per (actor_uid, scope): rolling list of recent events.
    burst_state: dict[tuple[str, str], list[dict[str, Any]]] = {}
    cooldown_until: dict[tuple[str, str], int] = {}

    for item in relevant:
        key = (item["actor_uid"], item["secret_scope"])
        cur_time = item["time_ms"]
        burst = burst_state.setdefault(key, [])

        cutoff = cur_time - window_ms
        burst[:] = [entry for entry in burst if entry["time_ms"] >= cutoff]
        burst.append(item)

        cooldown = cooldown_until.get(key, 0)
        if cur_time < cooldown:
            continue

        distinct_keys = {entry["secret_key"] for entry in burst}
        if len(distinct_keys) >= threshold:
            native_finding = _build_native_finding(
                actor_uid=item["actor_uid"],
                actor_name=item["actor_name"],
                workspace_id=item["workspace_id"],
                scope=item["secret_scope"],
                burst_events=list(burst),
                threshold=threshold,
                window_minutes=window_minutes,
            )
            if output_format == "native":
                yield native_finding
            else:
                yield _render_ocsf_finding(native_finding)
            cooldown_until[key] = cur_time + window_ms
            burst.clear()


def load_jsonl(stream: Iterable[str]) -> Iterator[dict[str, Any]]:
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
        description=(
            "Detect Databricks secret-scope read bursts from OCSF 1.8 API Activity 6003 input."
        )
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
            "detect-databricks-secret-scope-read-burst starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-databricks-secret-scope-read-burst complete",
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
