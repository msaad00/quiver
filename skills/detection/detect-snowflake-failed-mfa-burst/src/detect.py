"""Detect high-velocity failed-MFA bursts on Snowflake user accounts.

Reads OCSF 1.8 Authentication (class 3002) records normalized from
`account_usage.login_history` carrying the Snowflake-shaped
`unmapped.snowflake.{authentication_method,error_code,is_success}` block and
emits OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1110
Brute Force and T1621 Multi-Factor Authentication Request Generation whenever
a single principal crosses the configured failed-MFA count inside a sliding
window.

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

_log = get_logger(__name__, skill="detect-snowflake-failed-mfa-burst", layer="detection")

SKILL_NAME = "detect-snowflake-failed-mfa-burst"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"

OUTPUT_FORMATS = ("ocsf", "native")

AUTH_CLASS_UID = 3002
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

# Thresholds. Defaults are deliberately conservative; operators tune via env.
WINDOW_MIN_DEFAULT = 10
FAIL_THRESHOLD_DEFAULT = 8

WINDOW_MIN_ENV = "SNOWFLAKE_MFA_FAIL_WINDOW_MIN"
FAIL_THRESHOLD_ENV = "SNOWFLAKE_MFA_FAIL_THRESHOLD"

ACCEPTED_PRODUCERS = frozenset(
    {
        "ingest-snowflake-login-history-ocsf",
        "ingest-snowflake-query-history-ocsf",
        "source-snowflake-query",
    }
)

# Snowflake authentication methods that carry an MFA factor. Matching is
# case-insensitive and operates on the prefix so values like
# `KEYPAIR; MFA = duo` still register as MFA.
MFA_AUTH_METHOD_MARKERS = frozenset(
    {
        "mfa",
        "duo",
        "okta",
        "totp",
        "webauthn",
        "passcode",
        "push",
    }
)

# MITRE ATT&CK v14 — primary tag.
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0006"
MITRE_TACTIC_NAME = "Credential Access"
MITRE_TECHNIQUE_UID = "T1110"
MITRE_TECHNIQUE_NAME = "Brute Force"
MITRE_SECONDARY_TECHNIQUE_UID = "T1621"
MITRE_SECONDARY_TECHNIQUE_NAME = "Multi-Factor Authentication Request Generation"

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


def _authentication_method(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("authentication_method") or "").strip()


def _error_code(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("error_code") or "").strip()


def _is_success(event: dict[str, Any]) -> bool:
    block = _snowflake_block(event)
    raw = block.get("is_success")
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().upper() in {"YES", "TRUE", "1"}
    # Fallback to top-level status_id.
    status_id = event.get("status_id")
    return status_id == STATUS_SUCCESS


def _source_ip(event: dict[str, Any]) -> str:
    return str((event.get("src_endpoint") or {}).get("ip") or "")


def _has_mfa_marker(method: str) -> bool:
    lowered = method.lower()
    if not lowered:
        return False
    return any(marker in lowered for marker in MFA_AUTH_METHOD_MARKERS)


def _is_relevant(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != AUTH_CLASS_UID:
        return False
    if _producer(event) not in ACCEPTED_PRODUCERS:
        return False
    if not _actor_uid(event):
        return False
    if _is_success(event):
        return False
    if not _has_mfa_marker(_authentication_method(event)):
        return False
    return True


def _finding_uid(actor_uid: str, window_start_ms: int, window_end_ms: int) -> str:
    material = f"{actor_uid}|{window_start_ms}|{window_end_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-snowflake-failed-mfa-burst-{digest}"


def _build_native_finding(
    actor_uid: str,
    actor_name: str,
    burst: list[dict[str, Any]],
) -> dict[str, Any]:
    first = burst[0]
    last = burst[-1]
    failed_count = len(burst)
    error_codes = sorted({item["error_code"] for item in burst if item["error_code"]})
    authentication_methods = sorted(
        {item["authentication_method"] for item in burst if item["authentication_method"]}
    )
    source_ips = sorted({item["src_ip"] for item in burst if item["src_ip"]})
    event_uids = [item["event_uid"] for item in burst if item["event_uid"]]
    finding_uid = _finding_uid(actor_uid, first["time_ms"], last["time_ms"])

    description = (
        f"Snowflake principal '{actor_name or actor_uid}' failed MFA {failed_count} time(s) "
        f"across {len(authentication_methods)} authentication method(s) "
        f"({', '.join(authentication_methods) or 'n/a'}) from {len(source_ips)} source IP(s) "
        f"over a {_window_minutes()}-minute window. Snowflake error codes observed: "
        f"{', '.join(error_codes) or 'n/a'}. This pattern aligns with credential stuffing "
        "or MFA bombing against the Snowflake login surface."
    )

    observables: list[dict[str, Any]] = [
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
        {"name": "actor.user.name", "type": "User Name", "value": actor_name or actor_uid},
        {"name": "snowflake.failed_mfa_count", "type": "Other", "value": str(failed_count)},
    ]
    observables.extend({"name": "src.ip", "type": "IP Address", "value": ip} for ip in source_ips)
    observables.extend(
        {"name": "snowflake.authentication_method", "type": "Other", "value": method}
        for method in authentication_methods
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
        "title": "Snowflake principal failed-MFA burst",
        "description": description,
        "finding_types": ["snowflake-failed-mfa-burst", OWASP_FINDING_TYPE],
        "first_seen_time_ms": first["time_ms"],
        "last_seen_time_ms": last["time_ms"],
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
                "tactic_uid": MITRE_TACTIC_UID,
                "tactic_name": MITRE_TACTIC_NAME,
                "technique_uid": MITRE_SECONDARY_TECHNIQUE_UID,
                "technique_name": MITRE_SECONDARY_TECHNIQUE_NAME,
            },
        ],
        "observables": observables,
        "evidence": {
            "failed_event_count": failed_count,
            "error_codes": error_codes,
            "authentication_methods": authentication_methods,
            "source_ips": source_ips,
            "raw_event_uids": event_uids,
        },
    }


def _render_ocsf_finding(native_finding: dict[str, Any]) -> dict[str, Any]:
    attacks = native_finding["mitre_attacks"]
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
            "labels": ["data-warehouse", "snowflake", "credential-access", "mfa", "detection"],
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
                for attack in attacks
            ],
        },
        "observables": native_finding["observables"],
        "evidence": native_finding["evidence"],
    }


def coverage_metadata() -> dict[str, Any]:
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14", "OWASP Top 10"),
        "providers": ("snowflake",),
        "asset_classes": ("warehouse", "identities", "authentication", "mfa"),
        "attack_coverage": {
            "snowflake": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_event_types": ["account_usage.login_history.failure"],
                "techniques": [MITRE_TECHNIQUE_UID, MITRE_SECONDARY_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "window_minutes": _window_minutes(),
            "fail_threshold": _fail_threshold(),
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
                "authentication_method": _authentication_method(event),
                "error_code": _error_code(event),
                "src_ip": _source_ip(event),
            }
        )

    relevant.sort(key=lambda item: (item["actor_uid"], item["time_ms"], item["event_uid"]))

    window_ms = _window_minutes() * 60_000
    fail_threshold = _fail_threshold()

    states: dict[str, list[dict[str, Any]]] = {}
    cooldown_until: dict[str, int] = {}

    for item in relevant:
        actor_uid = item["actor_uid"]
        cur_time = item["time_ms"]
        burst = states.setdefault(actor_uid, [])

        cutoff = cur_time - window_ms
        burst[:] = [entry for entry in burst if entry["time_ms"] >= cutoff]
        burst.append(item)

        cooldown = cooldown_until.get(actor_uid, 0)
        if cur_time < cooldown:
            continue

        if len(burst) >= fail_threshold:
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


def _fail_threshold() -> int:
    return _env_int(FAIL_THRESHOLD_ENV, FAIL_THRESHOLD_DEFAULT)


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
        description="Detect Snowflake failed-MFA bursts from OCSF 1.8 Authentication 3002 input."
    )
    parser.add_argument(
        "input", nargs="?", help="OCSF 1.8 Authentication 3002 JSONL input. Defaults to stdin."
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
            "detect-snowflake-failed-mfa-burst starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-snowflake-failed-mfa-burst complete",
            extra={"findings_emitted": findings_emitted},
        )
    except SkillError as exc:
        return emit_error(SKILL_NAME, exc)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return emit_error(
            SKILL_NAME,
            ContractError(
                f"input is not JSONL: {exc}",
                hint="ensure each input line is a valid OCSF 1.8 Authentication 3002 JSON object",
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
