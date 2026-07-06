"""Detect Databricks MLflow model-artifact exfiltration from OCSF 1.8 events.

Reads OCSF 1.8 API Activity (class 6003) records emitted by the upstream
Databricks audit-log ingest pipeline and emits OCSF 1.8 Detection Finding
(class 2004) tagged with MITRE ATLAS AML.T0040 (ML Model Inference /
Stealing) and MITRE ATT&CK T1567 (Exfiltration Over Web Service) when an
MLflow model artifact is downloaded or a model version is transitioned to
a workspace outside the producing workspace's trust boundary.

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

_log = get_logger(__name__, skill="detect-databricks-mlflow-model-exfil", layer="detection")

SKILL_NAME = "detect-databricks-mlflow-model-exfil"
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

DEDUPE_WINDOW_MIN_ENV = "DATABRICKS_MLFLOW_DEDUPE_WINDOW_MIN"
DEDUPE_WINDOW_MIN_DEFAULT = 1440  # 24h

DOWNLOAD_OPERATIONS = frozenset(
    {
        "mlflow.downloadArtifact",
        "mlflow.getModelVersionDownloadUri",
    }
)
TRANSITION_OPERATION = "mlflow.transitionModelVersionStage"
ANCHOR_OPERATIONS = DOWNLOAD_OPERATIONS | {TRANSITION_OPERATION}

# MITRE ATLAS — the model-stealing technique anchors the AI-native dimension.
ATLAS_VERSION = "2024"
ATLAS_TACTIC_UID = "AML.TA0010"
ATLAS_TACTIC_NAME = "Exfiltration"
ATLAS_TECHNIQUE_UID = "AML.T0040"
ATLAS_TECHNIQUE_NAME = "ML Model Inference"

# MITRE ATT&CK v14 — paired classic-cyber technique for SIEM rule joins.
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0010"
MITRE_TACTIC_NAME = "Exfiltration"
MITRE_TECHNIQUE_UID = "T1567"
MITRE_TECHNIQUE_NAME = "Exfiltration Over Web Service"

OWASP_FINDING_TYPE = "OWASP-LLM-Top-10-LLM06"


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
    return str(user.get("email_addr") or user.get("uid") or user.get("name") or "").strip()


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


def _target_workspace_id(event: dict[str, Any]) -> str:
    return str(_databricks_block(event).get("target_workspace_id") or "").strip()


def _model_name(event: dict[str, Any]) -> str:
    return str(_databricks_block(event).get("model_name") or "").strip()


def _model_version(event: dict[str, Any]) -> str:
    return str(_databricks_block(event).get("model_version") or "").strip()


def _target_stage(event: dict[str, Any]) -> str:
    return str(_databricks_block(event).get("target_stage") or "").strip()


def _is_databricks_event(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _vendor_name(event) == DATABRICKS_VENDOR_NAME:
        return True
    return _producer(event) in ACCEPTED_PRODUCERS


def _dedupe_window_ms() -> int:
    minutes = env_int(DEDUPE_WINDOW_MIN_ENV, DEDUPE_WINDOW_MIN_DEFAULT, skill_name=SKILL_NAME)
    if minutes <= 0:
        minutes = DEDUPE_WINDOW_MIN_DEFAULT
    return minutes * 60_000


def _finding_uid(model_name: str, actor_uid: str, window_start_ms: int) -> str:
    material = f"{SKILL_NAME}|{model_name}|{actor_uid}|{window_start_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-databricks-mlflow-exfil-{digest}"


def _build_native_finding(
    event: dict[str, Any],
    *,
    window_start_ms: int,
    download_count: int,
    operations_seen: list[str],
    raw_event_uids: list[str],
) -> dict[str, Any]:
    actor_uid = _actor_uid(event)
    actor_name = _actor_name(event)
    workspace_id = _workspace_id(event)
    target_workspace_id = _target_workspace_id(event)
    model_name = _model_name(event)
    model_version = _model_version(event)
    target_stage = _target_stage(event)
    operation = _api_operation(event)
    time_ms = _event_time(event) or _now_ms()
    finding_uid = _finding_uid(model_name, actor_uid, window_start_ms)

    description = (
        f"Databricks principal '{actor_name or actor_uid}' performed MLflow "
        f"model-artifact action '{operation}' against registered model '{model_name}'"
    )
    if model_version:
        description += f" (version {model_version})"
    if operation == TRANSITION_OPERATION and target_workspace_id:
        description += (
            f", transitioning to stage '{target_stage or 'unknown'}' in workspace "
            f"'{target_workspace_id}' (source workspace '{workspace_id or 'unknown'}'). "
            "Cross-workspace stage transition smuggles the artifact across the trust boundary."
        )
    else:
        description += (
            f" in workspace '{workspace_id or 'unknown'}'. Once a model artifact is "
            "downloaded the weights + config live outside the workspace's audit and access controls."
        )
    if download_count > 1:
        description += f" Observed {download_count} matching events in the dedupe window."

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
    if target_workspace_id:
        observables.append(
            {
                "name": "databricks.target_workspace_id",
                "type": "Resource UID",
                "value": target_workspace_id,
            }
        )
    observables.append(
        {"name": "databricks.model_name", "type": "Resource UID", "value": model_name}
    )
    if model_version:
        observables.append(
            {"name": "databricks.model_version", "type": "Other", "value": model_version}
        )
    if target_stage:
        observables.append(
            {"name": "databricks.target_stage", "type": "Other", "value": target_stage}
        )
    for op in operations_seen:
        observables.append({"name": "api.operation", "type": "Other", "value": op})

    evidence: dict[str, Any] = {
        "events_observed": download_count,
        "model_name": model_name,
        "model_version": model_version,
        "workspace_id": workspace_id,
        "target_workspace_id": target_workspace_id,
        "target_stage": target_stage,
        "api_operations": operations_seen,
        "raw_event_uids": raw_event_uids,
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
        "title": f"Databricks MLflow model '{model_name}' artifact exfiltration",
        "description": description,
        "finding_types": ["databricks-mlflow-model-exfil", OWASP_FINDING_TYPE],
        "first_seen_time_ms": window_start_ms,
        "last_seen_time_ms": time_ms,
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": MITRE_TACTIC_UID,
                "tactic_name": MITRE_TACTIC_NAME,
                "technique_uid": MITRE_TECHNIQUE_UID,
                "technique_name": MITRE_TECHNIQUE_NAME,
            },
            {
                "version": ATLAS_VERSION,
                "tactic_uid": ATLAS_TACTIC_UID,
                "tactic_name": ATLAS_TACTIC_NAME,
                "technique_uid": ATLAS_TECHNIQUE_UID,
                "technique_name": ATLAS_TECHNIQUE_NAME,
            },
        ],
        "observables": observables,
        "evidence": evidence,
    }


def _render_ocsf_finding(native_finding: dict[str, Any]) -> dict[str, Any]:
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
                "mlflow",
                "model-artifact",
                "exfiltration",
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
                for attack in native_finding["mitre_attacks"]
            ],
        },
        "observables": native_finding["observables"],
        "evidence": native_finding["evidence"],
    }


def coverage_metadata() -> dict[str, Any]:
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14", "MITRE ATLAS", "OWASP LLM Top 10"),
        "providers": ("databricks",),
        "asset_classes": ("warehouse", "mlflow", "ml-models"),
        "attack_coverage": {
            "databricks": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": sorted(ANCHOR_OPERATIONS),
                "techniques": [MITRE_TECHNIQUE_UID, ATLAS_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "dedupe_window_minutes": _dedupe_window_ms() // 60_000,
        },
    }


def _is_relevant(event: dict[str, Any]) -> bool:
    if not _is_databricks_event(event):
        return False
    if _api_operation(event) not in ANCHOR_OPERATIONS:
        return False
    if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
        return False
    if not _actor_uid(event):
        return False
    if not _model_name(event):
        return False
    if _api_operation(event) == TRANSITION_OPERATION:
        # Only the cross-workspace transition is an exfil anchor.
        if not _target_workspace_id(event):
            return False
        if _target_workspace_id(event) == _workspace_id(event):
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

    window_ms = _dedupe_window_ms()

    relevant: list[dict[str, Any]] = []
    seen_event_uids: set[str] = set()
    for event in events:
        if not _is_relevant(event):
            continue
        event_uid = _metadata_uid(event)
        if event_uid and event_uid in seen_event_uids:
            continue
        if event_uid:
            seen_event_uids.add(event_uid)
        relevant.append(event)

    # Sort by (model_name, actor_uid, time_ms) for deterministic windowing.
    relevant.sort(
        key=lambda ev: (_model_name(ev), _actor_uid(ev), _event_time(ev), _metadata_uid(ev))
    )

    # State per (model_name, actor_uid).
    State = dict[str, Any]
    states: dict[tuple[str, str], State] = {}

    for event in relevant:
        model_name = _model_name(event)
        actor_uid = _actor_uid(event)
        key = (model_name, actor_uid)
        time_ms = _event_time(event)
        state = states.get(key)
        if state is None or (time_ms - state["window_start_ms"]) >= window_ms:
            # Start a new window; emit one finding for this principal-model pair.
            states[key] = {
                "window_start_ms": time_ms,
                "first_event": event,
                "operations_seen": [_api_operation(event)],
                "raw_event_uids": [_metadata_uid(event)] if _metadata_uid(event) else [],
                "count": 1,
            }
            native_finding = _build_native_finding(
                event,
                window_start_ms=time_ms,
                download_count=1,
                operations_seen=[_api_operation(event)],
                raw_event_uids=[_metadata_uid(event)] if _metadata_uid(event) else [],
            )
            if output_format == "native":
                yield native_finding
            else:
                yield _render_ocsf_finding(native_finding)
            continue
        # Within the same dedupe window — accumulate, do not re-emit.
        op = _api_operation(event)
        if op not in state["operations_seen"]:
            state["operations_seen"].append(op)
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid not in state["raw_event_uids"]:
            state["raw_event_uids"].append(meta_uid)
        state["count"] += 1


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
            "Detect Databricks MLflow model-artifact exfiltration from OCSF 1.8 "
            "API Activity 6003 input."
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
            "detect-databricks-mlflow-model-exfil starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-databricks-mlflow-model-exfil complete",
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
