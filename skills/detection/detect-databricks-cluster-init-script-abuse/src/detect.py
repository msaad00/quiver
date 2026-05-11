"""Detect Databricks cluster init-script abuse from OCSF 1.8 events.

Reads OCSF 1.8 API Activity (class 6003) records emitted by the upstream
Databricks audit-log ingest pipeline and emits OCSF 1.8 Detection Finding
(class 2004) tagged with MITRE ATT&CK T1059.004 (Unix Shell) + T1546
(Boot or Logon Initialization Scripts) when a cluster init script is
attached or modified to point at a remote, off-DBFS, or shell-command-
encoding destination.

Contract: see ../SKILL.md and ../REFERENCES.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

_log = get_logger(__name__, skill="detect-databricks-cluster-init-script-abuse", layer="detection")

SKILL_NAME = "detect-databricks-cluster-init-script-abuse"
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

ANCHOR_OPERATIONS = frozenset({"clusters.create", "clusters.edit"})

ALLOWED_PATHS_ENV = "DATABRICKS_INIT_SCRIPT_ALLOWED_PATHS"
DEFAULT_ALLOWED_PATHS = (
    r"^(dbfs:/databricks/init/|s3://databricks-workspace-[a-z0-9-]+-internal/)"
)

UNSAFE_SHELL_PATTERN = re.compile(r"\b(curl|wget|http|https|nc|netcat)\b", re.IGNORECASE)

# MITRE ATT&CK v14 — Unix Shell as the primary execution technique, with
# Boot or Logon Initialization Scripts as the persistence sub-technique.
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0002"
MITRE_TACTIC_NAME = "Execution"
MITRE_TECHNIQUE_UID = "T1059.004"
MITRE_TECHNIQUE_NAME = "Unix Shell"

MITRE_PERSISTENCE_TACTIC_UID = "TA0003"
MITRE_PERSISTENCE_TACTIC_NAME = "Persistence"
MITRE_PERSISTENCE_TECHNIQUE_UID = "T1546"
MITRE_PERSISTENCE_TECHNIQUE_NAME = "Boot or Logon Initialization Scripts"

OWASP_FINDING_TYPE = "OWASP-Top-10-A08"


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


def _cluster_config(event: dict[str, Any]) -> dict[str, Any]:
    block = _databricks_block(event).get("cluster_config") or {}
    return block if isinstance(block, dict) else {}


def _cluster_id(event: dict[str, Any]) -> str:
    return str(_cluster_config(event).get("cluster_id") or "").strip()


def _cluster_name(event: dict[str, Any]) -> str:
    return str(_cluster_config(event).get("cluster_name") or "").strip()


def _init_scripts(event: dict[str, Any]) -> list[dict[str, Any]]:
    raw = _cluster_config(event).get("init_scripts") or []
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _destination(script: dict[str, Any]) -> str:
    # Init-script entries may carry the destination directly or under a
    # sub-key (dbfs / s3 / file). Normalize to a single URI string.
    raw = script.get("destination")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    for sub_key in ("dbfs", "s3", "file", "gcs", "abfss", "workspace"):
        sub = script.get(sub_key)
        if isinstance(sub, dict):
            inner = sub.get("destination")
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
    return ""


def _allowed_paths_pattern() -> re.Pattern[str]:
    raw = os.environ.get(ALLOWED_PATHS_ENV, "").strip()
    if not raw:
        return re.compile(DEFAULT_ALLOWED_PATHS)
    try:
        return re.compile(raw)
    except re.error as exc:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="invalid_allowed_paths_regex",
            message=(
                f"{ALLOWED_PATHS_ENV}={raw!r} did not compile as a regex ({exc}); "
                "falling back to the default allowed-paths pattern."
            ),
            env=ALLOWED_PATHS_ENV,
            raw=raw,
            error=str(exc),
        )
        return re.compile(DEFAULT_ALLOWED_PATHS)


def _is_databricks_event(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _vendor_name(event) == DATABRICKS_VENDOR_NAME:
        return True
    return _producer(event) in ACCEPTED_PRODUCERS


def _finding_uid(cluster_id: str, destination: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{cluster_id}|{destination}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-databricks-init-script-abuse-{digest}"


def _build_native_finding(
    event: dict[str, Any],
    *,
    destination: str,
    reasons: list[str],
) -> dict[str, Any]:
    actor_uid = _actor_uid(event)
    actor_name = _actor_name(event)
    workspace_id = _workspace_id(event)
    cluster_id = _cluster_id(event)
    cluster_name = _cluster_name(event)
    operation = _api_operation(event)
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(cluster_id or cluster_name or operation, destination, time_ms)

    description = (
        f"Databricks principal '{actor_name or actor_uid}' attached an init script to "
        f"cluster '{cluster_name or cluster_id or 'unknown'}' in workspace "
        f"'{workspace_id or 'unknown'}' whose destination '{destination}' "
        f"violates the init-script trust policy ({', '.join(reasons)}). Init scripts "
        "run on every cluster node at boot under the Databricks service identity."
    )

    observables: list[dict[str, Any]] = [
        {"name": "cloud.provider", "type": "Other", "value": "Databricks"},
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
    ]
    if actor_name and actor_name != actor_uid:
        observables.append({"name": "actor.user.name", "type": "User Name", "value": actor_name})
    if workspace_id:
        observables.append({"name": "databricks.workspace_id", "type": "Resource UID", "value": workspace_id})
    if cluster_id:
        observables.append({"name": "databricks.cluster_id", "type": "Resource UID", "value": cluster_id})
    if cluster_name:
        observables.append({"name": "databricks.cluster_name", "type": "Other", "value": cluster_name})
    observables.append({"name": "api.operation", "type": "Other", "value": operation})
    observables.append({"name": "databricks.init_script_destination", "type": "URL String", "value": destination})
    for reason in reasons:
        observables.append({"name": "databricks.init_script_violation", "type": "Other", "value": reason})

    evidence: dict[str, Any] = {
        "events_observed": 1,
        "api_operation": operation,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "workspace_id": workspace_id,
        "init_script_destination": destination,
        "violations": reasons,
        "raw_event_uids": [event_uid] if event_uid else [],
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
            f"Databricks cluster init script points to unsafe destination '{destination}'"
        ),
        "description": description,
        "finding_types": ["databricks-cluster-init-script-abuse", OWASP_FINDING_TYPE],
        "first_seen_time_ms": time_ms,
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
                "version": MITRE_VERSION,
                "tactic_uid": MITRE_PERSISTENCE_TACTIC_UID,
                "tactic_name": MITRE_PERSISTENCE_TACTIC_NAME,
                "technique_uid": MITRE_PERSISTENCE_TECHNIQUE_UID,
                "technique_name": MITRE_PERSISTENCE_TECHNIQUE_NAME,
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
                "clusters",
                "init-scripts",
                "execution",
                "persistence",
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
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14", "OWASP Top 10"),
        "providers": ("databricks",),
        "asset_classes": ("warehouse", "clusters", "init-scripts"),
        "attack_coverage": {
            "databricks": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": sorted(ANCHOR_OPERATIONS),
                "techniques": [MITRE_TECHNIQUE_UID, MITRE_PERSISTENCE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "allowed_paths_default": DEFAULT_ALLOWED_PATHS,
            "unsafe_shell_pattern": UNSAFE_SHELL_PATTERN.pattern,
        },
    }


def _classify_destination(
    destination: str, allowed_pattern: re.Pattern[str]
) -> list[str]:
    reasons: list[str] = []
    if not allowed_pattern.match(destination):
        reasons.append("destination outside DATABRICKS_INIT_SCRIPT_ALLOWED_PATHS")
    if UNSAFE_SHELL_PATTERN.search(destination):
        reasons.append("destination matches unsafe shell-command pattern")
    return reasons


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

    allowed_pattern = _allowed_paths_pattern()
    seen: set[tuple[str, str, str]] = set()

    for event in events:
        if not _is_databricks_event(event):
            continue
        operation = _api_operation(event)
        if operation not in ANCHOR_OPERATIONS:
            continue
        if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
            continue
        scripts = _init_scripts(event)
        if not scripts:
            continue
        meta_uid = _metadata_uid(event)
        cluster_id = _cluster_id(event) or _cluster_name(event) or operation
        for script in scripts:
            destination = _destination(script)
            if not destination:
                continue
            reasons = _classify_destination(destination, allowed_pattern)
            if not reasons:
                continue
            key = (meta_uid, cluster_id, destination)
            if key in seen:
                continue
            seen.add(key)
            native_finding = _build_native_finding(event, destination=destination, reasons=reasons)
            if output_format == "native":
                yield native_finding
            else:
                yield _render_ocsf_finding(native_finding)


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
            "Detect Databricks cluster init-script abuse from OCSF 1.8 API Activity "
            "6003 input."
        )
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
            "detect-databricks-cluster-init-script-abuse starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-databricks-cluster-init-script-abuse complete",
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
