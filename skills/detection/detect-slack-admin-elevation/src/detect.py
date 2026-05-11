"""Detect Slack admin/owner role grants outside authorized identities or window.

Reads OCSF 1.8 User Access Management (class 3005) records normalized from
Slack Audit Logs `role_change_to_admin` / `role_change_to_owner` events and
emits OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK
T1098.003.

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

_log = get_logger(__name__, skill="detect-slack-admin-elevation", layer="detection")

SKILL_NAME = "detect-slack-admin-elevation"
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

ANCHOR_ACTIONS = frozenset({"role_change_to_admin", "role_change_to_owner"})

AUTHORIZED_GRANTERS_ENV = "SLACK_AUTHORIZED_GRANTERS"
GRANT_WINDOW_ENV = "SLACK_GRANT_WINDOW_HOURS_UTC"
DEFAULT_WINDOW = "08-18"

ACCEPTED_PRODUCERS = frozenset({"ingest-slack-audit-ocsf"})

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0003"
MITRE_TACTIC_NAME = "Persistence"
MITRE_TECHNIQUE_UID = "T1098.003"
MITRE_TECHNIQUE_NAME = "Additional Cloud Roles"

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


def _new_role(event: dict[str, Any]) -> str:
    return str(_slack_block(event).get("new_role") or "").strip()


def _granter(event: dict[str, Any]) -> tuple[str, str]:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    uid = str(user.get("uid") or user.get("name") or "").strip()
    name = str(user.get("name") or user.get("uid") or "").strip()
    return uid, name


def _grantee(event: dict[str, Any]) -> tuple[str, str]:
    user = event.get("user") or {}
    uid = str(user.get("uid") or user.get("name") or "").strip()
    name = str(user.get("email_addr") or user.get("name") or user.get("uid") or "").strip()
    return uid, name


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _authorized_granters() -> frozenset[str]:
    return _parse_env_set(AUTHORIZED_GRANTERS_ENV)


def _parse_window(raw: str) -> tuple[int, int]:
    """Parse `HH-HH` UTC window string; fall back to default on any error."""
    try:
        start_str, end_str = raw.split("-", 1)
        start = int(start_str)
        end = int(end_str)
        if 0 <= start < 24 and 0 < end <= 24 and start < end:
            return start, end
    except (ValueError, AttributeError):
        pass
    return _parse_window(DEFAULT_WINDOW) if raw != DEFAULT_WINDOW else (8, 18)


def _grant_window() -> tuple[int, int]:
    raw = (os.environ.get(GRANT_WINDOW_ENV, "") or DEFAULT_WINDOW).strip() or DEFAULT_WINDOW
    return _parse_window(raw)


def _hour_outside_window(time_ms: int, window: tuple[int, int]) -> bool:
    if time_ms <= 0:
        return False
    dt = datetime.fromtimestamp(time_ms / 1000, tz=timezone.utc)
    start, end = window
    return not (start <= dt.hour < end)


def _is_relevant(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != USER_ACCESS_CLASS_UID:
        return False
    if _producer(event) not in ACCEPTED_PRODUCERS:
        return False
    if _action(event) not in ANCHOR_ACTIONS:
        return False
    granter_uid, _ = _granter(event)
    grantee_uid, _ = _grantee(event)
    if not granter_uid or not grantee_uid:
        return False
    return True


def _finding_uid(granter: str, grantee: str, new_role: str, time_ms: int) -> str:
    material = f"{granter}|{grantee}|{new_role}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-slack-admin-elevation-{digest}"


def _build_native_finding(
    event: dict[str, Any],
    allowlist_mode: str,
    window_violation: bool,
    window: tuple[int, int],
) -> dict[str, Any]:
    granter_uid, granter_name = _granter(event)
    grantee_uid, grantee_name = _grantee(event)
    new_role = _new_role(event) or ("admin" if _action(event) == "role_change_to_admin" else "owner")
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(granter_uid, grantee_uid, new_role, time_ms)

    reasons: list[str] = []
    if allowlist_mode == "fail-open":
        reasons.append(
            "SLACK_AUTHORIZED_GRANTERS is empty; firing in fail-open mode on every admin/owner grant"
        )
    elif allowlist_mode == "enforced-violation":
        reasons.append("granter is not on SLACK_AUTHORIZED_GRANTERS")
    if window_violation:
        reasons.append(f"event time is outside UTC change window {window[0]:02d}-{window[1]:02d}")
    description = (
        f"Slack principal '{granter_name or granter_uid}' granted '{new_role}' role to "
        f"'{grantee_name or grantee_uid}'. " + "; ".join(reasons) + "."
    )

    observables: list[dict[str, Any]] = [
        {"name": "actor.user.uid", "type": "User Name", "value": granter_uid},
        {"name": "user.uid", "type": "User Name", "value": grantee_uid},
        {"name": "slack.new_role", "type": "Role", "value": new_role},
    ]

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
        "title": f"Slack '{new_role}' role granted by unauthorized identity or outside change window",
        "description": description,
        "finding_types": ["slack-admin-elevation", OWASP_FINDING_TYPE],
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
            "granter": granter_uid,
            "grantee": grantee_uid,
            "new_role": new_role,
            "action": _action(event),
            "allowlist_mode": allowlist_mode,
            "window_violation": window_violation,
            "change_window_utc": f"{window[0]:02d}-{window[1]:02d}",
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
            "labels": ["saas", "slack", "persistence", "detection", "rbac"],
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
    allowlist = _authorized_granters()
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14", "OWASP Top 10"),
        "providers": ("slack",),
        "asset_classes": ("identities", "rbac", "saas"),
        "attack_coverage": {
            "slack": {
                "principal_types": ["human-admins"],
                "anchor_actions": sorted(ANCHOR_ACTIONS),
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "authorized_granter_count": len(allowlist),
            "allowlist_mode": "fail-open" if not allowlist else "enforced",
            "change_window_utc": "{:02d}-{:02d}".format(*_grant_window()),
        },
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(
            f"unsupported output_format: {output_format}",
            hint=f"choose one of: {', '.join(OUTPUT_FORMATS)}",
        )

    allowlist = _authorized_granters()
    window = _grant_window()
    if not allowlist:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="allowlist_fail_open",
            message=(
                "SLACK_AUTHORIZED_GRANTERS is empty; firing on every admin/owner role grant. "
                "Set the allow-list to scope the detection to break-glass identities."
            ),
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
        granter_uid, _ = _granter(event)
        granter_authorized = granter_uid in allowlist if allowlist else False
        window_violation = _hour_outside_window(_event_time(event), window)
        if allowlist:
            if granter_authorized and not window_violation:
                continue
            allowlist_mode = "enforced-violation" if not granter_authorized else "enforced-window-only"
        else:
            allowlist_mode = "fail-open"
        native = _build_native_finding(event, allowlist_mode, window_violation, window)
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
        description="Detect Slack admin/owner role grants by unauthorized identities or outside the change window."
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
            "detect-slack-admin-elevation starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-slack-admin-elevation complete",
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
