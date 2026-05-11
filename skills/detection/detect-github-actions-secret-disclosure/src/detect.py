"""Detect GitHub Actions workflow runs that log a secret value to stdout.

Reads OCSF 1.8 API Activity (class 6003) records emitted by the upstream
GitHub Actions log feed (assumed to share the
`ingest-github-audit-log-ocsf` producer envelope) carrying
`unmapped.github.workflow_log_excerpt` with a redacted job log excerpt.

The classic CI exfil vector: a workflow accidentally echoes
`$MY_SECRET` to stdout. GitHub's redactor replaces the literal value
with `***`. The interesting failure mode is when the secret is logged
in an *encoded* form (base64, hex, JWT) that the redactor cannot match
against the secret store — the operator sees an opaque blob in the
log, but anyone with read access to the workflow log can decode it.

Strict heuristic — fire ONLY when:

  1. The job log excerpt contains `***` (GitHub's redaction marker —
     proves a secret was present in the run),
  2. The same excerpt contains at least one high-entropy substring of
     ≥ 32 chars that looks like base64 or hex,
  3. AND the workflow run completed successfully
     (`unmapped.github.workflow_status == "completed"` or `status_id == 1`).

Maps to MITRE ATT&CK T1552.004 (Private Keys / Credentials in Logs).
Severity CRITICAL.

Contract: see ../SKILL.md and ../REFERENCES.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
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

_log = get_logger(__name__, skill="detect-github-actions-secret-disclosure", layer="detection")

SKILL_NAME = "detect-github-actions-secret-disclosure"
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

SEVERITY_CRITICAL = 5
STATUS_SUCCESS = 1

GITHUB_VENDOR_FEATURE = "ingest-github-audit-log-ocsf"
ACCEPTED_PRODUCERS = frozenset({GITHUB_VENDOR_FEATURE})

REDACTION_MARKER = "***"
MIN_ENCODED_LENGTH = 32

_BASE64_RE = re.compile(rb"[A-Za-z0-9+/=_-]{32,}")
_HEX_RE = re.compile(rb"\b[0-9a-fA-F]{32,}\b")
_JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}")

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0006"
MITRE_TACTIC_NAME = "Credential Access"
MITRE_TECHNIQUE_UID = "T1552"
MITRE_TECHNIQUE_NAME = "Unsecured Credentials"
MITRE_SUBTECHNIQUE_UID = "T1552.004"
MITRE_SUBTECHNIQUE_NAME = "Private Keys"

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


def _workflow_log_excerpt(event: dict[str, Any]) -> str:
    block = _github_block(event)
    return str(block.get("workflow_log_excerpt") or "")


def _workflow_id(event: dict[str, Any]) -> str:
    return str(_github_block(event).get("workflow_id") or "").strip()


def _workflow_status(event: dict[str, Any]) -> str:
    return str(_github_block(event).get("workflow_status") or "").strip().lower()


def _repo_name(event: dict[str, Any]) -> str:
    block = _github_block(event)
    return str(block.get("repo") or block.get("repository") or "").strip()


def _src_ip(event: dict[str, Any]) -> str:
    endpoint = event.get("src_endpoint") or {}
    return str(endpoint.get("ip") or "").strip()


def _is_github_event(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    return _producer(event) in ACCEPTED_PRODUCERS


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freqs: dict[int, int] = {}
    for byte in data:
        freqs[byte] = freqs.get(byte, 0) + 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in freqs.values())


def _is_high_entropy(candidate: bytes) -> bool:
    """≥ 32 chars AND Shannon entropy ≥ 3.5 bits/byte (well above English prose)."""
    if len(candidate) < MIN_ENCODED_LENGTH:
        return False
    return _shannon_entropy(candidate) >= 3.5


def _find_high_entropy_candidates(log_excerpt: str) -> list[str]:
    """Return up to 5 distinct high-entropy hits — JWT, base64-ish, or hex."""
    if not log_excerpt:
        return []
    blob = log_excerpt.encode("utf-8", errors="ignore")
    hits: list[bytes] = []
    seen: set[bytes] = set()
    for pattern in (_JWT_RE, _BASE64_RE, _HEX_RE):
        for match in pattern.finditer(blob):
            candidate = match.group(0)
            if candidate in seen:
                continue
            if not _is_high_entropy(candidate):
                continue
            hits.append(candidate)
            seen.add(candidate)
            if len(hits) >= 5:
                break
        if len(hits) >= 5:
            break
    return [c.decode("utf-8", errors="replace") for c in hits]


def _has_redaction_marker(log_excerpt: str) -> bool:
    return REDACTION_MARKER in log_excerpt


def _workflow_completed_successfully(event: dict[str, Any]) -> bool:
    status = _workflow_status(event)
    if status in {"completed", "success", "succeeded"}:
        return True
    if not status and event.get("status_id", STATUS_SUCCESS) == STATUS_SUCCESS:
        return True
    return False


def _finding_uid(event_uid: str, actor_uid: str, workflow_id: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{actor_uid}|{workflow_id}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-github-actions-secret-disclosure-{digest}"


def _build_native_finding(
    event: dict[str, Any],
    *,
    candidates: list[str],
) -> dict[str, Any]:
    time_ms = _event_time(event) or _now_ms()
    actor_uid = _actor_uid(event)
    actor_name = _actor_name(event)
    workflow_id = _workflow_id(event)
    repo = _repo_name(event)
    operation = _api_operation(event)
    event_uid = _metadata_uid(event)
    src_ip = _src_ip(event)
    finding_uid = _finding_uid(event_uid, actor_uid, workflow_id, time_ms)

    # Truncate previews so the finding never carries a full secret on the wire.
    previews = [c[:8] + "..." + c[-4:] if len(c) > 16 else "***" for c in candidates]

    description = (
        f"GitHub Actions workflow run '{workflow_id or 'unknown'}' in repo "
        f"'{repo or 'unknown'}' (actor '{actor_name or actor_uid}') completed "
        f"successfully and the captured log excerpt contains BOTH GitHub's "
        f"redaction marker `***` AND a high-entropy substring the redactor "
        f"did not mask. This is the classic CI exfil-via-encoding vector "
        f"(T1552.004). Treat the workflow secret(s) as compromised and "
        f"rotate immediately. Length-truncated previews of the unredacted "
        f"high-entropy substrings: {previews}."
    )

    observables: list[dict[str, Any]] = [
        {"name": "cloud.provider", "type": "Other", "value": "GitHub"},
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
    ]
    if repo:
        observables.append({"name": "github.repo", "type": "Resource UID", "value": repo})
    if workflow_id:
        observables.append({"name": "github.workflow_id", "type": "Resource UID", "value": workflow_id})
    observables.append({"name": "api.operation", "type": "Other", "value": operation})
    if src_ip:
        observables.append({"name": "src.ip", "type": "IP Address", "value": src_ip})

    evidence: dict[str, Any] = {
        "events_observed": 1,
        "api_operation": operation,
        "repo": repo,
        "workflow_id": workflow_id,
        "high_entropy_substrings_observed": len(candidates),
        "previews": previews,
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
        "severity": "critical",
        "severity_id": SEVERITY_CRITICAL,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": "GitHub Actions workflow log discloses encoded secret",
        "description": description,
        "finding_types": ["github-actions-secret-disclosure", OWASP_FINDING_TYPE],
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
            "labels": ["github", "actions", "secrets", "exfil", "detection"],
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
        "asset_classes": ("actions", "workflow-logs", "secrets"),
        "attack_coverage": {
            "github": {
                "principal_types": ["human-users", "machine-users"],
                "anchor_operations": ["workflows.completed_workflow_run"],
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
        log_excerpt = _workflow_log_excerpt(event)
        if not log_excerpt:
            continue
        if not _has_redaction_marker(log_excerpt):
            # No `***` → no secret was in this run; nothing to detect.
            continue
        candidates = _find_high_entropy_candidates(log_excerpt)
        if not candidates:
            # `***` is present but no surviving high-entropy substring — the
            # redactor caught everything. Stay quiet.
            continue
        if not _workflow_completed_successfully(event):
            # Failed/cancelled runs are noisy and the operator already saw it.
            continue
        if not _actor_uid(event):
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_actor",
                message="skipping workflow event with no actor.user.uid or name",
                event_uid=_metadata_uid(event),
            )
            continue

        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in seen_uids:
            continue
        if meta_uid:
            seen_uids.add(meta_uid)

        native_finding = _build_native_finding(event, candidates=candidates)
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
            "Detect GitHub Actions workflow log secret disclosure from OCSF 1.8 "
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
            "detect-github-actions-secret-disclosure starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-github-actions-secret-disclosure complete",
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
