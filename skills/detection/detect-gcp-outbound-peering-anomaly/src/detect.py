"""Detect GCP VPC network peering created with an external project.

Reads OCSF 1.8 API Activity (class 6003) records produced by
`ingest-gcp-audit-ocsf` and fires when a `compute.networks.addPeering`
event introduces a peer network whose project prefix differs from the
source network's project prefix — an egress lateral path that can be
used for `T1071.001` (Application Layer Protocol — Web) and `T1041`
(Exfiltration Over C2 Channel).

The allow-list `GCP_PEERING_AUTHORIZED_PROJECTS` (comma-separated GCP
project IDs; default empty = fail-open with a stderr warning) narrows
the rule to peers in projects the operator has not approved.

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

SKILL_NAME = "detect-gcp-outbound-peering-anomaly"
CANONICAL_VERSION = "2026-04"
OCSF_VERSION = "1.8.0"
REPO_NAME = "cloud-ai-security-skills"

_log = get_logger(__name__, skill=SKILL_NAME, layer="detection")

API_ACTIVITY_CLASS_UID = 6003
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

MITRE_VERSION = "v14"
PRIMARY_TACTIC_UID = "TA0011"
PRIMARY_TACTIC_NAME = "Command and Control"
PRIMARY_TECHNIQUE_UID = "T1071.001"
PRIMARY_TECHNIQUE_NAME = "Web Protocols"
SECONDARY_TACTIC_UID = "TA0010"
SECONDARY_TACTIC_NAME = "Exfiltration"
SECONDARY_TECHNIQUE_UID = "T1041"
SECONDARY_TECHNIQUE_NAME = "Exfiltration Over C2 Channel"

ACCEPTED_PRODUCERS = frozenset({"ingest-gcp-audit-ocsf"})
ANCHOR_OPERATION = "compute.networks.addPeering"
OUTPUT_FORMATS = frozenset({"ocsf", "native"})

AUTHORIZED_PROJECTS_ENV = "GCP_PEERING_AUTHORIZED_PROJECTS"

# projects/{project}/global/networks/{network}
_PROJECT_PATTERN = re.compile(r"^projects/(?P<project>[^/]+)/")


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "")


def _is_success(event: dict[str, Any]) -> bool:
    return event.get("status_id") == STATUS_SUCCESS


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _gcp_block(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    block = unmapped.get("gcp") if isinstance(unmapped, dict) else None
    return block if isinstance(block, dict) else {}


def _source_network(event: dict[str, Any]) -> str:
    return str(_gcp_block(event).get("network") or "")


def _peer_network(event: dict[str, Any]) -> str:
    block = _gcp_block(event)
    return str(block.get("peer_network") or block.get("peerNetwork") or "")


def _peering_name(event: dict[str, Any]) -> str:
    block = _gcp_block(event)
    return str(block.get("peering_name") or block.get("name") or "")


def _project_from_network(uri: str) -> str:
    m = _PROJECT_PATTERN.match(uri or "")
    return m.group("project") if m else ""


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def _authorized_projects() -> frozenset[str]:
    return _parse_env_set(AUTHORIZED_PROJECTS_ENV)


def _is_authorized(project: str, allowlist: frozenset[str]) -> bool:
    return project.strip().lower() in allowlist


def _finding_uid(
    *, source_network: str, peer_network: str, peering_name: str, time_ms: int
) -> str:
    material = f"{SKILL_NAME}|{source_network}|{peer_network}|{peering_name}|{time_ms}"
    return f"gcppeer-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(
    *,
    event: dict[str, Any],
    source_network: str,
    peer_network: str,
    peering_name: str,
    source_project: str,
    peer_project: str,
    allowlist_mode: str,
) -> dict[str, Any]:
    time_ms = int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)
    event_uid = str((event.get("metadata") or {}).get("uid") or "")
    finding_uid = _finding_uid(
        source_network=source_network,
        peer_network=peer_network,
        peering_name=peering_name,
        time_ms=time_ms,
    )
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "api_operation": ANCHOR_OPERATION,
        "source_network": source_network,
        "peer_network": peer_network,
        "peering_name": peering_name,
        "source_project": source_project,
        "peer_project": peer_project,
        "allowlist_mode": allowlist_mode,
        "actor_name": _actor_name(event),
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "raw_event_uid": event_uid,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    description = (
        f"Actor `{native['actor_name'] or 'unknown'}` added a VPC peering "
        f"`{native['peering_name']}` between source network "
        f"`{native['source_network']}` (project `{native['source_project']}`) and "
        f"external peer `{native['peer_network']}` (project `{native['peer_project']}`). "
        f"Allow-list mode: {native['allowlist_mode']}."
    )
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "GCP"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "api.operation", "type": "Other", "value": native["api_operation"]},
        {"name": "source.network", "type": "Other", "value": native["source_network"]},
        {"name": "peer.network", "type": "Other", "value": native["peer_network"]},
        {"name": "source.project", "type": "Other", "value": native["source_project"]},
        {"name": "peer.project", "type": "Other", "value": native["peer_project"]},
        {"name": "peering.name", "type": "Other", "value": native["peering_name"]},
    ]
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_HIGH,
        "status_id": STATUS_SUCCESS,
        "time": native["first_seen_time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native["finding_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["gcp", "vpc", "peering", "exfiltration", "c2"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": (
                f"GCP VPC peering to external project `{native['peer_project']}`"
            ),
            "desc": description,
            "types": [
                "gcp-outbound-peering-anomaly",
                f"peer-project-{native['peer_project'] or 'unknown'}",
            ],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic": {
                        "name": PRIMARY_TACTIC_NAME,
                        "uid": PRIMARY_TACTIC_UID,
                    },
                    "technique": {
                        "name": PRIMARY_TECHNIQUE_NAME,
                        "uid": PRIMARY_TECHNIQUE_UID,
                    },
                },
                {
                    "version": MITRE_VERSION,
                    "tactic": {
                        "name": SECONDARY_TACTIC_NAME,
                        "uid": SECONDARY_TACTIC_UID,
                    },
                    "technique": {
                        "name": SECONDARY_TECHNIQUE_NAME,
                        "uid": SECONDARY_TECHNIQUE_UID,
                    },
                },
            ],
        },
        "observables": observables,
        "evidence": {
            "events_observed": 1,
            "api_operation": native["api_operation"],
            "source_network": native["source_network"],
            "peer_network": native["peer_network"],
            "source_project": native["source_project"],
            "peer_project": native["peer_project"],
            "peering_name": native["peering_name"],
            "allowlist_mode": native["allowlist_mode"],
        },
    }


def coverage_metadata() -> dict[str, Any]:
    allowlist = _authorized_projects()
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14"),
        "providers": ("gcp",),
        "asset_classes": ("vpc", "networks", "peerings"),
        "attack_coverage": {
            "gcp": {
                "anchor_operations": [ANCHOR_OPERATION],
                "techniques": [PRIMARY_TECHNIQUE_UID, SECONDARY_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "authorized_project_count": len(allowlist),
            "allowlist_mode": "fail-open" if not allowlist else "enforced",
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(
            f"unsupported output_format `{output_format}`",
            hint=f"choose one of: {', '.join(sorted(OUTPUT_FORMATS))}",
        )

    allowlist = _authorized_projects()
    allowlist_mode = "enforced" if allowlist else "fail-open"
    if allowlist_mode == "fail-open":
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="allowlist_fail_open",
            message=(
                "GCP_PEERING_AUTHORIZED_PROJECTS is empty; firing on every "
                "cross-project peering. Set the allow-list to scope the "
                "detection to approved peer projects."
            ),
        )

    dedupe: set[str] = set()
    for event in events:
        producer = _producer(event)
        if producer not in ACCEPTED_PRODUCERS:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="wrong_source",
                message=f"skipping event from non-gcp-audit producer `{producer}`",
            )
            continue
        if _api_operation(event) != ANCHOR_OPERATION:
            continue
        if not _is_success(event):
            continue

        meta_uid = str((event.get("metadata") or {}).get("uid") or "")
        if meta_uid and meta_uid in dedupe:
            continue
        if meta_uid:
            dedupe.add(meta_uid)

        source_network = _source_network(event)
        peer_network = _peer_network(event)
        peering_name = _peering_name(event)
        if not source_network or not peer_network:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_peer_pointer",
                message="addPeering event missing source or peer network; skipping",
            )
            continue

        source_project = _project_from_network(source_network)
        peer_project = _project_from_network(peer_network)
        if not source_project or not peer_project:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="malformed_network_uri",
                message=(
                    f"could not parse project from network URIs "
                    f"({source_network!r} / {peer_network!r}); skipping"
                ),
            )
            continue
        if source_project == peer_project:
            continue

        if allowlist_mode == "enforced" and _is_authorized(peer_project, allowlist):
            continue

        native = _build_native_finding(
            event=event,
            source_network=source_network,
            peer_network=peer_network,
            peering_name=peering_name,
            source_project=source_project,
            peer_project=peer_project,
            allowlist_mode=allowlist_mode,
        )
        yield native if output_format == "native" else _to_ocsf(native)


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
            )
            continue
        if isinstance(obj, dict):
            yield obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect GCP outbound VPC peering anomalies (cross-project peer)."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="Emit OCSF Detection Finding (default) or native projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    findings_emitted = 0
    try:
        events = list(load_jsonl(in_stream))
        _log.info(
            f"{SKILL_NAME} starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            f"{SKILL_NAME} complete",
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
