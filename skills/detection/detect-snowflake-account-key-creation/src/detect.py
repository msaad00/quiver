"""Detect addition of RSA / public-key auth to a Snowflake user from OCSF 1.8.

Reads OCSF 1.8 API Activity (class 6003) records carrying the Snowflake-shaped
`unmapped.snowflake.{target_user,statement_kind,rsa_public_key_set}` block and
emits OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK
T1098.001 Additional Cloud Credentials.

Contract: see ../SKILL.md and ../REFERENCES.md
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

from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

_log = get_logger(__name__, skill="detect-snowflake-account-key-creation", layer="detection")

SKILL_NAME = "detect-snowflake-account-key-creation"
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

ANCHOR_OPERATION = "ALTER_USER"
DEFAULT_KEY_STATEMENT_HINTS = ("RSA_PUBLIC_KEY", "RSA_PUBLIC_KEY_2")
KEY_STATEMENT_HINTS_ENV = "SNOWFLAKE_KEY_STATEMENT_HINTS"

ACCEPTED_PRODUCERS = frozenset(
    {
        "ingest-snowflake-query-history-ocsf",
        "ingest-snowflake-access-history-ocsf",
        "source-snowflake-query",
    }
)

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0003"
MITRE_TACTIC_NAME = "Persistence"
MITRE_TECHNIQUE_UID = "T1098.001"
MITRE_TECHNIQUE_NAME = "Additional Cloud Credentials"

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


def _target_user(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("target_user") or "").strip()


def _statement_kind(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("statement_kind") or "").strip().upper()


def _rsa_public_key_set(event: dict[str, Any]) -> bool:
    raw = _snowflake_block(event).get("rsa_public_key_set")
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _key_statement_hints() -> tuple[str, ...]:
    raw = os.environ.get(KEY_STATEMENT_HINTS_ENV, "")
    if not raw.strip():
        return DEFAULT_KEY_STATEMENT_HINTS
    parsed = tuple(part.strip().upper() for part in raw.split(",") if part.strip())
    return parsed or DEFAULT_KEY_STATEMENT_HINTS


def _matched_key_slot(event: dict[str, Any]) -> str:
    statement = _statement_kind(event)
    # The Snowflake statement_kind exposes RSA_PUBLIC_KEY / RSA_PUBLIC_KEY_2 at the
    # end of the canonical operation name. Match strict suffix so RSA_PUBLIC_KEY
    # does not collide with RSA_PUBLIC_KEY_2. Try longer hints first.
    for hint in sorted(_key_statement_hints(), key=len, reverse=True):
        if statement.endswith("_" + hint) or statement == hint:
            return hint
    if _rsa_public_key_set(event):
        return DEFAULT_KEY_STATEMENT_HINTS[0]
    return ""


def _is_relevant(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _producer(event) not in ACCEPTED_PRODUCERS:
        return False
    if _api_operation(event) != ANCHOR_OPERATION:
        return False
    if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
        return False
    if not _actor_uid(event):
        return False
    if not _target_user(event):
        return False
    if not _matched_key_slot(event):
        return False
    return True


def _finding_uid(actor_uid: str, target_user: str, time_ms: int, slot: str) -> str:
    material = f"{actor_uid}|{target_user}|{time_ms}|{slot}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-snowflake-account-key-{digest}"


def _build_native_finding(event: dict[str, Any]) -> dict[str, Any]:
    actor_uid = _actor_uid(event)
    actor_name = _actor_name(event)
    target_user = _target_user(event)
    statement_kind = _statement_kind(event)
    key_slot = _matched_key_slot(event)
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(actor_uid, target_user, time_ms, key_slot)

    description = (
        f"Snowflake principal '{actor_name or actor_uid}' bound an RSA public key "
        f"(slot {key_slot}) to user '{target_user}'. The holder of the matching "
        "private key can now authenticate via driver / SQL API / JDBC without an "
        "interactive login or MFA prompt."
    )
    title = f"Snowflake RSA key-pair credential added to user '{target_user}'"

    observables: list[dict[str, Any]] = [
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
        {"name": "actor.user.name", "type": "User Name", "value": actor_name or actor_uid},
        {"name": "snowflake.target_user", "type": "User Name", "value": target_user},
        {"name": "snowflake.key_slot", "type": "Other", "value": key_slot},
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
        "time_ms": time_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": title,
        "description": description,
        "finding_types": ["snowflake-account-key-creation", OWASP_FINDING_TYPE],
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
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
            "target_user": target_user,
            "key_slot": key_slot,
            "statement_kind": statement_kind,
            "raw_event_uids": [event_uid] if event_uid else [],
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
            "labels": ["data-warehouse", "snowflake", "persistence", "detection", "credential"],
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
        "asset_classes": ("warehouse", "identities", "credentials"),
        "attack_coverage": {
            "snowflake": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": [ANCHOR_OPERATION],
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "key_statement_hints": list(_key_statement_hints()),
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
    for event in events:
        if not _is_relevant(event):
            continue
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in dedupe:
            continue
        if meta_uid:
            dedupe.add(meta_uid)
        native_finding = _build_native_finding(event)
        if output_format == "native":
            yield native_finding
        else:
            yield _render_ocsf_finding(native_finding)


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
        description="Detect Snowflake RSA public-key auth additions from OCSF 1.8 API Activity input."
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
            "detect-snowflake-account-key-creation starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-snowflake-account-key-creation complete",
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
