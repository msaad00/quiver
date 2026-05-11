"""Detect GitHub org-level secret scope reduction.

Reads OCSF 1.8 API Activity (class 6003) records emitted by the upstream
`ingest-github-audit-log-ocsf` pipeline and emits OCSF 1.8 Detection
Finding (class 2004) tagged with MITRE ATT&CK T1078.004 (Cloud Accounts)
when an org-level GitHub Actions / Codespaces / Dependabot secret has
its scope widened.

Triggers:

- `visibility` flips from `selected` to `all` — HIGH severity
- `selected_repositories` list expands by more than
  `GITHUB_ORG_SECRET_REPO_DELTA` repos (default 5) in one event without
  flipping to `all` — MEDIUM severity

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
from typing import Any, Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

_log = get_logger(__name__, skill="detect-github-org-secret-exposure", layer="detection")

SKILL_NAME = "detect-github-org-secret-exposure"
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

SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

GITHUB_VENDOR_FEATURE = "ingest-github-audit-log-ocsf"
ACCEPTED_PRODUCERS = frozenset({GITHUB_VENDOR_FEATURE})

# Org-secret operations the detector inspects.
ORG_SECRET_OPERATIONS = frozenset(
    {
        "actions.org_secret_create",
        "actions.org_secret_update",
        "codespaces.org_secret_create",
        "codespaces.org_secret_update",
        "dependabot_secrets.create",
        "dependabot_secrets.update",
    }
)

DEFAULT_REPO_DELTA = 5

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0001"
MITRE_TACTIC_NAME = "Initial Access"
MITRE_TECHNIQUE_UID = "T1078"
MITRE_TECHNIQUE_NAME = "Valid Accounts"
MITRE_SUBTECHNIQUE_UID = "T1078.004"
MITRE_SUBTECHNIQUE_NAME = "Cloud Accounts"

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


def _secret_name(event: dict[str, Any]) -> str:
    return str(_github_block(event).get("secret_name") or "").strip()


def _org_name(event: dict[str, Any]) -> str:
    block = _github_block(event)
    return str(block.get("org") or block.get("org_name") or "").strip()


def _visibility(event: dict[str, Any]) -> str:
    return str(_github_block(event).get("visibility") or "").strip().lower()


def _before_visibility(event: dict[str, Any]) -> str:
    return str(_github_block(event).get("before_visibility") or "").strip().lower()


def _selected_repos(event: dict[str, Any]) -> list:
    block = _github_block(event)
    repos = (
        block.get("selected_repositories")
        or block.get("selected_repository_ids")
        or []
    )
    return list(repos) if isinstance(repos, list) else []


def _before_selected_repos(event: dict[str, Any]) -> list:
    block = _github_block(event)
    repos = (
        block.get("before_selected_repositories")
        or block.get("before_selected_repository_ids")
        or []
    )
    return list(repos) if isinstance(repos, list) else []


def _src_ip(event: dict[str, Any]) -> str:
    endpoint = event.get("src_endpoint") or {}
    return str(endpoint.get("ip") or "").strip()


def _is_github_event(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    return _producer(event) in ACCEPTED_PRODUCERS


def _repo_delta_threshold() -> int:
    raw = os.environ.get("GITHUB_ORG_SECRET_REPO_DELTA")
    if raw is None:
        return DEFAULT_REPO_DELTA
    try:
        value = int(raw)
        return max(1, value)
    except ValueError:
        return DEFAULT_REPO_DELTA


def _finding_uid(event_uid: str, actor_uid: str, secret: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{actor_uid}|{secret}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-github-org-secret-exposure-{digest}"


def _build_native_finding(
    event: dict[str, Any],
    *,
    reason: str,
    severity_id: int,
    repo_delta: int,
) -> dict[str, Any]:
    time_ms = _event_time(event) or _now_ms()
    actor_uid = _actor_uid(event)
    actor_name = _actor_name(event)
    secret = _secret_name(event)
    org = _org_name(event)
    visibility = _visibility(event)
    before_visibility = _before_visibility(event)
    selected = _selected_repos(event)
    before_selected = _before_selected_repos(event)
    operation = _api_operation(event)
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(event_uid, actor_uid, secret, time_ms)
    src_ip = _src_ip(event)

    if reason == "visibility_flip_to_all":
        description = (
            f"GitHub principal '{actor_name or actor_uid}' widened the visibility of "
            f"org secret '{secret or 'unknown'}' in organization '{org or 'unknown'}' "
            f"from `{before_visibility or 'unknown'}` to `all`. The secret is now "
            f"readable from every repository in the org."
        )
        severity = "high"
    else:
        description = (
            f"GitHub principal '{actor_name or actor_uid}' expanded `selected_repositories` "
            f"of org secret '{secret or 'unknown'}' in organization '{org or 'unknown'}' "
            f"by {repo_delta} repos in a single event (threshold "
            f"{_repo_delta_threshold()}). Visibility stayed `{visibility or before_visibility or 'selected'}`."
        )
        severity = "medium"

    observables: list[dict[str, Any]] = [
        {"name": "cloud.provider", "type": "Other", "value": "GitHub"},
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
    ]
    if org:
        observables.append({"name": "github.org", "type": "Resource UID", "value": org})
    if secret:
        observables.append({"name": "github.secret_name", "type": "Resource UID", "value": secret})
    observables.append({"name": "api.operation", "type": "Other", "value": operation})
    if visibility:
        observables.append({"name": "github.visibility", "type": "Other", "value": visibility})
    if before_visibility:
        observables.append(
            {"name": "github.before_visibility", "type": "Other", "value": before_visibility}
        )
    if src_ip:
        observables.append({"name": "src.ip", "type": "IP Address", "value": src_ip})

    evidence: dict[str, Any] = {
        "events_observed": 1,
        "api_operation": operation,
        "org": org,
        "secret_name": secret,
        "reason": reason,
        "visibility": visibility,
        "before_visibility": before_visibility,
        "selected_repositories_count": len(selected),
        "before_selected_repositories_count": len(before_selected),
        "repo_delta": repo_delta,
        "repo_delta_threshold": _repo_delta_threshold(),
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
        "provider": "GitHub",
        "time_ms": time_ms,
        "severity": severity,
        "severity_id": severity_id,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": "GitHub org secret scope widened",
        "description": description,
        "finding_types": ["github-org-secret-exposure", OWASP_FINDING_TYPE],
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
            "labels": ["github", "secrets", "scope-reduction", "detection"],
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
        "asset_classes": ("source-control", "secrets", "actions"),
        "attack_coverage": {
            "github": {
                "principal_types": ["human-users", "machine-users"],
                "anchor_operations": sorted(ORG_SECRET_OPERATIONS),
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

    threshold = _repo_delta_threshold()
    seen_uids: set[str] = set()
    for event in events:
        if not _is_github_event(event):
            continue
        operation = _api_operation(event)
        if operation.lower() not in ORG_SECRET_OPERATIONS:
            continue
        if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
            continue
        if not _actor_uid(event):
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_actor",
                message="skipping org-secret event with no actor.user.uid or name",
                event_uid=_metadata_uid(event),
            )
            continue

        visibility = _visibility(event)
        before_visibility = _before_visibility(event)
        selected = _selected_repos(event)
        before_selected = _before_selected_repos(event)
        repo_delta = max(0, len(selected) - len(before_selected))

        reason: str | None = None
        severity_id: int = SEVERITY_MEDIUM
        if visibility == "all" and before_visibility and before_visibility != "all":
            reason = "visibility_flip_to_all"
            severity_id = SEVERITY_HIGH
        elif repo_delta > threshold and visibility != "all":
            reason = "selected_repositories_expanded"
            severity_id = SEVERITY_MEDIUM

        if reason is None:
            continue

        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in seen_uids:
            continue
        if meta_uid:
            seen_uids.add(meta_uid)

        native_finding = _build_native_finding(
            event,
            reason=reason,
            severity_id=severity_id,
            repo_delta=repo_delta,
        )
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
            "Detect GitHub org-level secret scope widening from OCSF 1.8 "
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
            "detect-github-org-secret-exposure starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-github-org-secret-exposure complete",
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
