"""Detect Slack third-party app installs that grant broad OAuth scopes.

Reads OCSF 1.8 API Activity (class 6003) records normalized from Slack Audit
Logs `app_installed` / `app_approved` events and emits OCSF 1.8 Detection
Finding (class 2004) tagged with MITRE ATT&CK T1098.005.

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

_log = get_logger(__name__, skill="detect-slack-oauth-app-install-broad-scope", layer="detection")

SKILL_NAME = "detect-slack-oauth-app-install-broad-scope"
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

ANCHOR_ACTIONS = frozenset({"app_installed", "app_approved"})

WRITE_SCOPE = "chat:write"
READ_SCOPES = frozenset({"files:read", "channels:read", "groups:read", "im:read"})
WILDCARD_SUFFIX = ":write"

PREAPPROVED_APP_IDS_ENV = "SLACK_PREAPPROVED_APP_IDS"

ACCEPTED_PRODUCERS = frozenset({"ingest-slack-audit-ocsf"})

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0003"
MITRE_TACTIC_NAME = "Persistence"
MITRE_TECHNIQUE_UID = "T1098.005"
MITRE_TECHNIQUE_NAME = "Account Manipulation: Device Registration"

OWASP_FINDING_TYPE = "OWASP-Top-10-A05"


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


def _scopes(event: dict[str, Any]) -> list[str]:
    block = _slack_block(event)
    raw = block.get("scopes")
    if isinstance(raw, list):
        return [str(s) for s in raw if isinstance(s, (str, int))]
    if isinstance(raw, str) and raw:
        return [part.strip() for part in raw.split(",") if part.strip()]
    return []


def _app_info(event: dict[str, Any]) -> tuple[str, str]:
    app = _slack_block(event).get("app") or {}
    if not isinstance(app, dict):
        return "", ""
    return str(app.get("id") or ""), str(app.get("name") or "")


def _installer(event: dict[str, Any]) -> tuple[str, str]:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    uid = str(user.get("uid") or user.get("name") or "").strip()
    name = str(user.get("email_addr") or user.get("name") or user.get("uid") or "").strip()
    return uid, name


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _preapproved_app_ids() -> frozenset[str]:
    return _parse_env_set(PREAPPROVED_APP_IDS_ENV)


def _broad_scope_reason(scopes: list[str]) -> str:
    scope_set = set(scopes)
    wildcards = [s for s in scope_set if s.startswith("*") and s.endswith(WILDCARD_SUFFIX)]
    if wildcards:
        return f"wildcard scope: {sorted(wildcards)[0]}"
    if WRITE_SCOPE in scope_set and scope_set & READ_SCOPES:
        intersected = sorted(scope_set & READ_SCOPES)
        return f"chat:write + read scope ({intersected[0]})"
    return ""


def _is_relevant(event: dict[str, Any], allowlist: frozenset[str]) -> tuple[bool, str]:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False, ""
    if _producer(event) not in ACCEPTED_PRODUCERS:
        return False, ""
    if _action(event) not in ANCHOR_ACTIONS:
        return False, ""
    app_id, _ = _app_info(event)
    if not app_id:
        return False, ""
    if app_id in allowlist:
        return False, ""
    scopes = _scopes(event)
    if not scopes:
        return False, ""
    reason = _broad_scope_reason(scopes)
    if not reason:
        return False, ""
    return True, reason


def _finding_uid(app_id: str, installer: str, time_ms: int) -> str:
    material = f"{app_id}|{installer}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-slack-oauth-app-broad-scope-{digest}"


def _build_native_finding(event: dict[str, Any], reason: str) -> dict[str, Any]:
    installer_uid, installer_name = _installer(event)
    app_id, app_name = _app_info(event)
    scopes = _scopes(event)
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(app_id, installer_uid, time_ms)

    description = (
        f"Slack third-party app '{app_name or app_id}' was installed/approved by "
        f"'{installer_name or installer_uid}' with broad OAuth scopes ({reason}). "
        f"The app id is not on the SLACK_PREAPPROVED_APP_IDS allow-list, so the "
        f"detector treats this install as a potential SaaS-exfiltration vector. "
        f"Granted scopes: {sorted(scopes)}."
    )

    observables: list[dict[str, Any]] = [
        {"name": "actor.user.uid", "type": "User Name", "value": installer_uid},
        {"name": "slack.app.id", "type": "Resource UID", "value": app_id},
    ]
    if app_name:
        observables.append({"name": "slack.app.name", "type": "Resource Name", "value": app_name})
    for scope in sorted(scopes):
        observables.append({"name": "slack.scope", "type": "Other", "value": scope})

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
        "title": f"Slack app '{app_name or app_id}' installed with broad OAuth scopes",
        "description": description,
        "finding_types": ["slack-oauth-app-install-broad-scope", OWASP_FINDING_TYPE],
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
            "installer": installer_uid,
            "app_id": app_id,
            "app_name": app_name,
            "scopes": sorted(scopes),
            "broad_scope_reason": reason,
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
            "labels": ["saas", "slack", "persistence", "detection", "oauth"],
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
        "asset_classes": ("identities", "oauth-apps", "saas"),
        "attack_coverage": {
            "slack": {
                "principal_types": ["human-installers", "admins"],
                "anchor_actions": sorted(ANCHOR_ACTIONS),
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "preapproved_app_count": len(_preapproved_app_ids()),
            "read_scopes": sorted(READ_SCOPES),
            "write_scope": WRITE_SCOPE,
        },
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(
            f"unsupported output_format: {output_format}",
            hint=f"choose one of: {', '.join(OUTPUT_FORMATS)}",
        )

    allowlist = _preapproved_app_ids()
    dedupe: set[str] = set()
    for event in events:
        is_rel, reason = _is_relevant(event, allowlist)
        if not is_rel:
            continue
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in dedupe:
            continue
        if meta_uid:
            dedupe.add(meta_uid)
        native = _build_native_finding(event, reason)
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
        description="Detect Slack OAuth app install/approval with broad scopes from OCSF 1.8 input."
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
            "detect-slack-oauth-app-install-broad-scope starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-slack-oauth-app-install-broad-scope complete",
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
