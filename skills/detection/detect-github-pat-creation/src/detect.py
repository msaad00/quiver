"""Detect GitHub personal access token (PAT) creation from OCSF 1.8 events.

Reads OCSF 1.8 API Activity (class 6003) records emitted by the upstream
`ingest-github-audit-log-ocsf` pipeline and emits one OCSF 1.8 Detection
Finding (class 2004) tagged with MITRE ATT&CK T1098.001 (Additional Cloud
Credentials) per successful PAT issuance.

PAT issuance is the GitHub-org persistence anchor (same pattern as the
Databricks PAT detector, see `detect-databricks-token-creation/`). Once
issued, a PAT lets a principal call the GitHub REST/GraphQL API without
going through an interactive SSO/OIDC login.

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

from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

_log = get_logger(__name__, skill="detect-github-pat-creation", layer="detection")

SKILL_NAME = "detect-github-pat-creation"
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

GITHUB_VENDOR_FEATURE = "ingest-github-audit-log-ocsf"
ACCEPTED_PRODUCERS = frozenset({GITHUB_VENDOR_FEATURE})

PAT_CREATE_OPERATIONS = frozenset(
    {
        "personal_access_token.create",
        "personal_access_token.access_granted",
    }
)
PAT_FAMILY_PREFIX = "personal_access_token."
KNOWN_PAT_OPERATIONS = frozenset(
    {
        "personal_access_token.create",
        "personal_access_token.access_granted",
        "personal_access_token.access_revoked",
        "personal_access_token.request_created",
        "personal_access_token.request_approved",
        "personal_access_token.request_denied",
    }
)

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0003"
MITRE_TACTIC_NAME = "Persistence"
MITRE_TECHNIQUE_UID = "T1098"
MITRE_TECHNIQUE_NAME = "Account Manipulation"
MITRE_SUBTECHNIQUE_UID = "T1098.001"
MITRE_SUBTECHNIQUE_NAME = "Additional Cloud Credentials"

OWASP_FINDING_TYPE = "OWASP-LLM-Top-10-LLM02"


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
    return str(api.get("operation") or "").strip()


def _actor_uid(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("name") or "").strip()


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "").strip()


def _github_block(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    block = unmapped.get("github") or {}
    return block if isinstance(block, dict) else {}


def _org_name(event: dict[str, Any]) -> str:
    block = _github_block(event)
    return str(block.get("org") or block.get("org_name") or "").strip()


def _token_id(event: dict[str, Any]) -> str:
    block = _github_block(event)
    return str(block.get("token_id") or block.get("hashed_token") or "").strip()


def _pat_kind(event: dict[str, Any]) -> str:
    block = _github_block(event)
    return str(block.get("programmatic_access_type") or "").strip()


def _scopes(event: dict[str, Any]) -> list[str]:
    block = _github_block(event)
    scopes = block.get("scopes")
    if isinstance(scopes, list):
        return [str(s) for s in scopes if isinstance(s, (str, int, float))]
    return []


def _src_ip(event: dict[str, Any]) -> str:
    endpoint = event.get("src_endpoint") or {}
    return str(endpoint.get("ip") or "").strip()


def _is_github_event(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    return _producer(event) in ACCEPTED_PRODUCERS


def _finding_uid(event_uid: str, actor_uid: str, org: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{actor_uid}|{org}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-github-pat-create-{digest}"


def _build_native_finding(event: dict[str, Any]) -> dict[str, Any]:
    time_ms = _event_time(event) or _now_ms()
    actor_uid = _actor_uid(event)
    actor_name = _actor_name(event)
    org = _org_name(event)
    token_id = _token_id(event)
    pat_kind = _pat_kind(event) or "personal_access_token"
    scopes = _scopes(event)
    src_ip = _src_ip(event)
    operation = _api_operation(event)
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(event_uid, actor_uid, org, time_ms)

    scope_phrase = (
        f"scopes={','.join(scopes)}" if scopes else "scopes not surfaced by upstream"
    )
    description = (
        f"GitHub principal '{actor_name or actor_uid}' successfully created a "
        f"{pat_kind} in organization '{org or 'unknown'}' ({scope_phrase}). "
        f"Once issued, a GitHub PAT grants headless REST/GraphQL access at the "
        f"principal's scope until explicitly revoked."
    )

    observables: list[dict[str, Any]] = [
        {"name": "cloud.provider", "type": "Other", "value": "GitHub"},
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
    ]
    if org:
        observables.append({"name": "github.org", "type": "Resource UID", "value": org})
    observables.append({"name": "api.operation", "type": "Other", "value": operation})
    if token_id:
        observables.append({"name": "github.token_id", "type": "Resource UID", "value": token_id})
    if pat_kind:
        observables.append(
            {"name": "github.programmatic_access_type", "type": "Other", "value": pat_kind}
        )
    if scopes:
        observables.append({"name": "github.scopes", "type": "Other", "value": ",".join(scopes)})
    if src_ip:
        observables.append({"name": "src.ip", "type": "IP Address", "value": src_ip})

    evidence: dict[str, Any] = {
        "events_observed": 1,
        "api_operation": operation,
        "org": org,
        "raw_event_uids": [event_uid] if event_uid else [],
    }
    if token_id:
        evidence["token_id"] = token_id
    if pat_kind:
        evidence["programmatic_access_type"] = pat_kind
    if scopes:
        evidence["scopes"] = scopes

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "GitHub",
        "time_ms": time_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": "GitHub personal access token created",
        "description": description,
        "finding_types": ["github-pat-creation", OWASP_FINDING_TYPE],
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": MITRE_TACTIC_UID,
                "tactic_name": MITRE_TACTIC_NAME,
                "technique_uid": MITRE_TECHNIQUE_UID,
                "technique_name": MITRE_TECHNIQUE_NAME,
                "sub_technique_uid": MITRE_SUBTECHNIQUE_UID,
                "sub_technique_name": MITRE_SUBTECHNIQUE_NAME,
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
            "labels": ["github", "credentials", "persistence", "detection"],
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
                    "sub_technique": {
                        "name": attack["sub_technique_name"],
                        "uid": attack["sub_technique_uid"],
                    },
                }
            ],
        },
        "observables": native_finding["observables"],
        "evidence": native_finding["evidence"],
    }


def coverage_metadata() -> dict[str, Any]:
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14", "OWASP LLM Top 10"),
        "providers": ("github",),
        "asset_classes": ("source-control", "tokens", "identities"),
        "attack_coverage": {
            "github": {
                "principal_types": ["human-users", "machine-users"],
                "anchor_operations": sorted(PAT_CREATE_OPERATIONS),
                "techniques": [MITRE_TECHNIQUE_UID, MITRE_SUBTECHNIQUE_UID],
            }
        },
    }


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

    seen_uids: set[str] = set()
    for event in events:
        if not _is_github_event(event):
            continue
        operation = _api_operation(event)
        if not operation:
            continue
        op_lower = operation.lower()
        if op_lower not in PAT_CREATE_OPERATIONS:
            if op_lower.startswith(PAT_FAMILY_PREFIX) and op_lower not in KNOWN_PAT_OPERATIONS:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="unmapped_event_type",
                    message=(
                        f"unrecognized GitHub PAT operation `{operation}`; treating as no-fire — "
                        "propose a mapping if this should anchor a finding"
                    ),
                    api_operation=operation,
                    event_uid=_metadata_uid(event),
                )
            continue
        if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
            continue
        if not _actor_uid(event):
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_actor",
                message="skipping PAT-create event with no actor.user.uid or name",
                event_uid=_metadata_uid(event),
            )
            continue
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in seen_uids:
            continue
        if meta_uid:
            seen_uids.add(meta_uid)

        native_finding = _build_native_finding(event)
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
            "Detect GitHub personal access token creation from OCSF 1.8 "
            "API Activity 6003 input."
        )
    )
    parser.add_argument("input", nargs="?", help="OCSF 1.8 API Activity 6003 JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Detection Finding JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Output format.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    findings_emitted = 0
    try:
        events = list(load_jsonl(in_stream))
        _log.info(
            "detect-github-pat-creation starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-github-pat-creation complete",
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
