"""Detect Azure private endpoint creation that pins the link to an external subscription.

Reads OCSF 1.8 API Activity (class 6003) records produced by
`ingest-azure-activity-ocsf` and fires when a
`Microsoft.Network/privateEndpoints/write` event carries a
`privateLinkServiceConnections[]` entry whose target service lives in a
subscription outside `AZURE_PRIVATE_ENDPOINT_AUTHORIZED_SUBS`. Each entry
in the connections array names a target service via its
`privateLinkServiceId` — the first GUID after `/subscriptions/` in that
resource id identifies the **target subscription** that owns the service.

The detector backs MITRE ATT&CK T1071.001 (Application Layer Protocol —
Web) and T1567 (Exfiltration Over Web Service) — the private-link path is
the cloud provider's own backbone, fully encrypted, fully native.

The allow-list `AZURE_PRIVATE_ENDPOINT_AUTHORIZED_SUBS` (comma-separated
subscription GUIDs; default empty = fail-open with a stderr warning,
mirroring `detect-snowflake-unauthorized-grant`) narrows the rule to
target subscriptions the operator has not approved.

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

SKILL_NAME = "detect-azure-private-endpoint-to-external-sub"
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
PRIMARY_TECHNIQUE_NAME = "Application Layer Protocol: Web Protocols"
SECONDARY_TACTIC_UID = "TA0010"
SECONDARY_TACTIC_NAME = "Exfiltration"
SECONDARY_TECHNIQUE_UID = "T1567"
SECONDARY_TECHNIQUE_NAME = "Exfiltration Over Web Service"

ACCEPTED_PRODUCERS = frozenset({"ingest-azure-activity-ocsf"})
ANCHOR_OPERATION = "microsoft.network/privateendpoints/write"
OUTPUT_FORMATS = frozenset({"ocsf", "native"})

AUTHORIZED_SUBS_ENV = "AZURE_PRIVATE_ENDPOINT_AUTHORIZED_SUBS"

# Resource ids look like /subscriptions/<guid>/resourceGroups/.../providers/...
# We grab the first GUID following `/subscriptions/` case-insensitively. Anchor
# on `/subscriptions/` so a bare GUID elsewhere in the string never matches.
_SUB_PATTERN = re.compile(
    r"/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "")


def _normalized_operation(event: dict[str, Any]) -> str:
    return _api_operation(event).strip().lower()


def _is_success(event: dict[str, Any]) -> bool:
    return event.get("status_id") == STATUS_SUCCESS


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _source_subscription(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    account = cloud.get("account") or {}
    return str(account.get("uid") or "").lower()


def _source_region(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    return str(cloud.get("region") or "")


def _resource_uid(event: dict[str, Any]) -> str:
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        name = str(resource.get("name") or resource.get("uid") or "")
        if name:
            return name
    return ""


def _private_link_connections(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract `unmapped.azure.privateLinkServiceConnections[]`."""
    unmapped = event.get("unmapped") or {}
    azure = unmapped.get("azure") if isinstance(unmapped, dict) else None
    if not isinstance(azure, dict):
        return []
    raw = azure.get("privateLinkServiceConnections")
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [conn for conn in raw if isinstance(conn, dict)]


def _extract_subscription(resource_id: str) -> str:
    m = _SUB_PATTERN.search(resource_id or "")
    return m.group(1).lower() if m else ""


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def _authorized_subs() -> frozenset[str]:
    return _parse_env_set(AUTHORIZED_SUBS_ENV)


def _finding_uid(
    *, resource_uid: str, target_subscription: str, source_subscription: str, time_ms: int
) -> str:
    material = f"{SKILL_NAME}|{resource_uid}|{target_subscription}|{source_subscription}|{time_ms}"
    return f"azpe-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(
    *,
    event: dict[str, Any],
    resource_uid: str,
    source_subscription: str,
    source_region: str,
    connection: dict[str, Any],
    target_subscription: str,
    private_link_service_id: str,
    allowlist_mode: str,
) -> dict[str, Any]:
    time_ms = int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)
    event_uid = str((event.get("metadata") or {}).get("uid") or "")
    finding_uid = _finding_uid(
        resource_uid=resource_uid,
        target_subscription=target_subscription,
        source_subscription=source_subscription,
        time_ms=time_ms,
    )
    actor = _actor_name(event)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "connection_name": str(connection.get("name") or ""),
        "api_operation": _api_operation(event),
        "resource_uid": resource_uid,
        "source_subscription": source_subscription,
        "source_region": source_region,
        "target_subscription": target_subscription,
        "private_link_service_id": private_link_service_id,
        "boundary": "cross-subscription",
        "allowlist_mode": allowlist_mode,
        "actor_name": actor,
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "raw_event_uid": event_uid,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    resource_label = native["resource_uid"] or "<unknown>"
    target_label = native["target_subscription"] or "<unknown>"
    description = (
        f"Actor `{native['actor_name'] or 'unknown'}` created Azure private "
        f"endpoint `{resource_label}` in subscription "
        f"`{native['source_subscription'] or 'unknown'}` (region "
        f"`{native['source_region'] or 'unspecified'}`) whose private-link "
        f"service connection `{native['connection_name'] or 'default'}` "
        f"pins traffic to a service in subscription `{target_label}` via "
        f"`{native['private_link_service_id'] or 'unknown'}`. Boundary: "
        f"{native['boundary']}. Allow-list mode: {native['allowlist_mode']}."
    )
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "Azure"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "api.operation", "type": "Other", "value": native["api_operation"]},
        {"name": "resource.uid", "type": "Other", "value": native["resource_uid"]},
        {"name": "source.subscription", "type": "Other", "value": native["source_subscription"]},
        {"name": "target.subscription", "type": "Other", "value": native["target_subscription"]},
        {
            "name": "private_link.service_id",
            "type": "Other",
            "value": native["private_link_service_id"],
        },
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
            "labels": ["azure", "private-link", "exfiltration", "c2"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": (
                f"Azure private endpoint `{native['resource_uid']}` pinned to "
                f"external subscription `{native['target_subscription']}`"
            ),
            "desc": description,
            "types": [
                "azure-private-endpoint-to-external-sub",
                f"boundary-{native['boundary']}",
            ],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": PRIMARY_TACTIC_NAME, "uid": PRIMARY_TACTIC_UID},
                    "technique": {
                        "name": PRIMARY_TECHNIQUE_NAME,
                        "uid": PRIMARY_TECHNIQUE_UID,
                    },
                },
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": SECONDARY_TACTIC_NAME, "uid": SECONDARY_TACTIC_UID},
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
            "resource_uid": native["resource_uid"],
            "source_subscription": native["source_subscription"],
            "source_region": native["source_region"],
            "target_subscription": native["target_subscription"],
            "private_link_service_id": native["private_link_service_id"],
            "connection_name": native["connection_name"],
            "boundary": native["boundary"],
            "allowlist_mode": native["allowlist_mode"],
        },
    }


def coverage_metadata() -> dict[str, Any]:
    allowlist = _authorized_subs()
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14"),
        "providers": ("azure",),
        "asset_classes": ("private-link", "network", "subscriptions"),
        "attack_coverage": {
            "azure": {
                "anchor_operations": [ANCHOR_OPERATION],
                "techniques": [PRIMARY_TECHNIQUE_UID, SECONDARY_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "authorized_subscription_count": len(allowlist),
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

    allowlist = _authorized_subs()
    allowlist_mode = "enforced" if allowlist else "fail-open"
    if allowlist_mode == "fail-open":
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="allowlist_fail_open",
            message=(
                "AZURE_PRIVATE_ENDPOINT_AUTHORIZED_SUBS is empty; firing on every "
                "cross-subscription private-link connection. Set the allow-list to "
                "scope the detection to approved target subscriptions."
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
                message=f"skipping event from non-azure-activity producer `{producer}`",
            )
            continue
        if _normalized_operation(event) != ANCHOR_OPERATION:
            continue
        if not _is_success(event):
            continue

        meta_uid = str((event.get("metadata") or {}).get("uid") or "")
        if meta_uid and meta_uid in dedupe:
            continue
        if meta_uid:
            dedupe.add(meta_uid)

        connections = _private_link_connections(event)
        if not connections:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_private_link_connections",
                message=(
                    "Microsoft.Network/privateEndpoints/write event carries no "
                    "`unmapped.azure.privateLinkServiceConnections`; skipping"
                ),
            )
            continue

        resource_uid = _resource_uid(event)
        source_subscription = _source_subscription(event)
        source_region = _source_region(event)

        # Deduplicate (resource_uid, target_subscription) tuples within one event
        # so the same target sub seen via two connection entries does not double-fire.
        seen_targets: set[str] = set()
        for connection in connections:
            link_id = str(connection.get("privateLinkServiceId") or "")
            target_subscription = _extract_subscription(link_id)
            if not target_subscription:
                continue
            if source_subscription and target_subscription == source_subscription:
                # same-subscription private link is the documented happy path
                continue
            if target_subscription in seen_targets:
                continue
            seen_targets.add(target_subscription)
            if allowlist_mode == "enforced" and target_subscription in allowlist:
                continue
            native = _build_native_finding(
                event=event,
                resource_uid=resource_uid,
                source_subscription=source_subscription,
                source_region=source_region,
                connection=connection,
                target_subscription=target_subscription,
                private_link_service_id=link_id,
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
        description=(
            "Detect Azure Microsoft.Network/privateEndpoints/write events pinned "
            "to an external subscription."
        )
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
