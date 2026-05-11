"""Detect external-workspace guest added to a sensitive Slack channel.

Reads OCSF 1.8 User Access Management (class 3005) records normalized from
Slack Audit Logs API events and emits OCSF 1.8 Detection Finding (class 2004)
tagged with MITRE ATT&CK T1078.004.

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
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

_log = get_logger(__name__, skill="detect-slack-external-channel-add", layer="detection")

SKILL_NAME = "detect-slack-external-channel-add"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"

OUTPUT_FORMATS = ("ocsf", "native")

USER_ACCESS_CLASS_UID = 3005
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

ANCHOR_ACTIONS = frozenset(
    {
        "private_channel_member_added",
        "public_channel_member_added",
        "workspace_user_added_to_workspace",
    }
)

DEFAULT_SENSITIVE_PATTERN = r"(?i)(security|sec-ops|finance|legal|engineering-leads|exec)"
SENSITIVE_PATTERNS_ENV = "SLACK_SENSITIVE_CHANNEL_PATTERNS"

ACCEPTED_PRODUCERS = frozenset({"ingest-slack-audit-ocsf"})

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0001"
MITRE_TACTIC_NAME = "Initial Access"
MITRE_TECHNIQUE_UID = "T1078.004"
MITRE_TECHNIQUE_NAME = "Valid Accounts: Cloud Accounts"

OWASP_FINDING_TYPE = "OWASP-Top-10-A01"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _event_time(event: dict[str, Any]) -> int:
    raw = event.get("time") or event.get("time_ms") or 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _metadata_uid(event: dict[str, Any]) -> str:
    return str((event.get("metadata") or {}).get("uid") or event.get("event_uid") or "")


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or event.get("source_skill") or "")


def _slack_block(event: dict[str, Any]) -> dict[str, Any]:
    block = (event.get("unmapped") or {}).get("slack") or {}
    return block if isinstance(block, dict) else {}


def _action(event: dict[str, Any]) -> str:
    return str(_slack_block(event).get("action") or event.get("event_type") or "")


def _workspace_type(event: dict[str, Any]) -> str:
    return str(_slack_block(event).get("workspace_type") or "").lower()


def _channel(event: dict[str, Any]) -> dict[str, Any]:
    channel = _slack_block(event).get("channel") or {}
    return channel if isinstance(channel, dict) else {}


def _actor_user(event: dict[str, Any]) -> tuple[str, str]:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    uid = str(user.get("uid") or user.get("name") or "").strip()
    name = str(user.get("name") or user.get("uid") or "").strip()
    return uid, name


def _added_user(event: dict[str, Any]) -> tuple[str, str]:
    user = event.get("user") or {}
    uid = str(user.get("uid") or user.get("name") or "").strip()
    name = str(user.get("email_addr") or user.get("name") or user.get("uid") or "").strip()
    return uid, name


def _compile_pattern() -> re.Pattern[str]:
    raw = os.environ.get(SENSITIVE_PATTERNS_ENV, "").strip() or DEFAULT_SENSITIVE_PATTERN
    try:
        return re.compile(raw)
    except re.error as exc:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="invalid_sensitive_pattern",
            message=f"falling back to default sensitive-channel pattern: {exc}",
            error=str(exc),
        )
        return re.compile(DEFAULT_SENSITIVE_PATTERN)


def _is_relevant(event: dict[str, Any], pattern: re.Pattern[str]) -> bool:
    if event.get("class_uid") != USER_ACCESS_CLASS_UID:
        return False
    if _producer(event) not in ACCEPTED_PRODUCERS:
        return False
    if _action(event) not in ANCHOR_ACTIONS:
        return False
    if _workspace_type(event) != "external":
        return False
    channel = _channel(event)
    channel_name = str(channel.get("name") or "").strip()
    if not channel_name:
        return False
    if not pattern.search(channel_name):
        return False
    actor_uid, _ = _actor_user(event)
    added_uid, _ = _added_user(event)
    if not actor_uid or not added_uid:
        return False
    return True


def _finding_uid(adder: str, added: str, channel_name: str, time_ms: int) -> str:
    material = f"{adder}|{added}|{channel_name}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-slack-external-channel-add-{digest}"


def _build_native_finding(event: dict[str, Any], pattern_source: str) -> dict[str, Any]:
    adder_uid, adder_name = _actor_user(event)
    added_uid, added_name = _added_user(event)
    channel = _channel(event)
    channel_name = str(channel.get("name") or "")
    channel_id = str(channel.get("id") or "")
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(adder_uid, added_uid, channel_name, time_ms)

    description = (
        f"Slack guest '{added_name or added_uid}' from an external workspace was added by "
        f"'{adder_name or adder_uid}' to sensitive channel '{channel_name}'. The channel "
        f"name matches the configured sensitive-channel pattern ({pattern_source!r}); "
        f"external membership creates an immediate DLP exposure and a persistent "
        f"cross-tenant insider-threat surface until the membership is revoked."
    )

    observables: list[dict[str, Any]] = [
        {"name": "actor.user.uid", "type": "User Name", "value": adder_uid},
        {"name": "user.uid", "type": "User Name", "value": added_uid},
        {"name": "slack.channel.name", "type": "Resource Name", "value": channel_name},
    ]
    if channel_id:
        observables.append({"name": "slack.channel.id", "type": "Resource Name", "value": channel_id})

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Slack",
        "time_ms": time_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": f"External Slack guest added to sensitive channel '{channel_name}'",
        "description": description,
        "finding_types": ["slack-external-channel-add", OWASP_FINDING_TYPE],
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
            "adder": adder_uid,
            "added_user": added_uid,
            "channel_name": channel_name,
            "channel_id": channel_id,
            "workspace_type": _workspace_type(event),
            "action": _action(event),
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
            "labels": ["saas", "slack", "initial-access", "detection", "dlp"],
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
        "providers": ("slack",),
        "asset_classes": ("identities", "channels", "saas"),
        "attack_coverage": {
            "slack": {
                "principal_types": ["external-guests"],
                "anchor_actions": sorted(ANCHOR_ACTIONS),
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "sensitive_pattern": os.environ.get(SENSITIVE_PATTERNS_ENV, "").strip() or DEFAULT_SENSITIVE_PATTERN,
        },
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(
            f"unsupported output_format: {output_format}",
            hint=f"choose one of: {', '.join(OUTPUT_FORMATS)}",
        )

    pattern = _compile_pattern()
    pattern_source = os.environ.get(SENSITIVE_PATTERNS_ENV, "").strip() or DEFAULT_SENSITIVE_PATTERN

    dedupe: set[str] = set()
    for event in events:
        if not _is_relevant(event, pattern):
            continue
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in dedupe:
            continue
        if meta_uid:
            dedupe.add(meta_uid)
        native = _build_native_finding(event, pattern_source)
        if output_format == "native":
            yield native
        else:
            yield _render_ocsf_finding(native)


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
        description="Detect external Slack guest added to a sensitive channel from OCSF 1.8 input."
    )
    parser.add_argument("input", nargs="?", help="OCSF 1.8 User Access Management 3005 JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Detection Finding JSONL output. Defaults to stdout.")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default="ocsf", help="Output format.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    findings_emitted = 0
    try:
        events = list(load_jsonl(in_stream))
        _log.info(
            "detect-slack-external-channel-add starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-slack-external-channel-add complete",
            extra={"findings_emitted": findings_emitted},
        )
    except SkillError as exc:
        return emit_error(SKILL_NAME, exc)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return emit_error(
            SKILL_NAME,
            ContractError(
                f"input is not JSONL: {exc}",
                hint="ensure each input line is a valid OCSF 1.8 User Access Management 3005 JSON object",
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
