"""Detect Azure NSG inbound security rules opened to the internet on risky ports.

Reads OCSF 1.8 API Activity (class 6003) records emitted by
`ingest-azure-activity-ocsf` from stdin or a file. Fires on
`Microsoft.Network/networkSecurityGroups/securityRules/write`
operations whose rule body has `direction=Inbound`, `access=Allow`,
a public source prefix (`*`, `Internet`, `0.0.0.0/0`, `::/0`), and a
destination port range that overlaps a risky port. Emits OCSF 1.8
Detection Finding (class 2004) tagged with MITRE ATT&CK T1190
(Exploit Public-Facing Application).

Why include the public-source prefix + risky-ports list:
- Inbound `*` / `Internet` / `0.0.0.0/0` / `::/0` on port 22, 3389, 3306,
  5432, 6379, 9200 etc. is the most common Azure breach vector
- Some intentionally open services (HTTPS:443 on a public endpoint) are
  not findings; they're known patterns
- Operators tag intentional exposures via NSG tag `intentionally-open`
  (the remediator's deny-list refuses to revoke such rules)

Rule:
1. event.api.operation == "Microsoft.Network/networkSecurityGroups/securityRules/write"
2. event.status_id == 1 (success)
3. parsed rule body has direction=Inbound AND access=Allow
4. source prefix overlaps {*, Internet, 0.0.0.0/0, ::/0}
5. destination port range overlaps a risky port (configurable; defaults below)

Output: OCSF Detection Finding 2004, with `target.uid` = the rule's
fully-qualified Azure Resource Manager id and `target.name` = the rule
name. The remediator (`remediate-azure-nsg-revoke`) consumes these
findings to delete or patch the offending rule.
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

from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-azure-open-nsg"
CANONICAL_VERSION = "2026-04"
OCSF_VERSION = "1.8.0"
REPO_NAME = "cloud-ai-security-skills"
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402

# OCSF Detection Finding 2004
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
TACTIC_UID = "TA0001"
TACTIC_NAME = "Initial Access"
TECHNIQUE_UID = "T1190"
TECHNIQUE_NAME = "Exploit Public-Facing Application"

ACCEPTED_PRODUCERS = frozenset({"ingest-azure-activity-ocsf"})

NSG_RULE_WRITE_OPERATION = (
    "Microsoft.Network/networkSecurityGroups/securityRules/write"
)

# Default risky ports — admin / database / cache / search surfaces. Same set as
# the AWS / GCP siblings to keep cross-cloud parity.
DEFAULT_RISKY_PORTS = (
    22,     # SSH
    23,     # Telnet
    3306,   # MySQL
    3389,   # RDP
    5432,   # Postgres
    5984,   # CouchDB
    6379,   # Redis
    9200,   # Elasticsearch
    11211,  # Memcached
    27017,  # MongoDB
)

# Source-address-prefix tokens that mean "the open internet" in NSG semantics.
# Azure accepts a literal CIDR (`0.0.0.0/0`, `::/0`), the wildcard `*`, and the
# service tag `Internet`. All four are equivalent for ingress exposure.
PUBLIC_SOURCE_PREFIXES = frozenset({"*", "internet", "0.0.0.0/0", "::/0"})

OUTPUT_FORMATS = frozenset({"ocsf", "native"})


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "")


def _is_success(event: dict[str, Any]) -> bool:
    return event.get("status_id") == 1


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _rule_properties(event: dict[str, Any]) -> dict[str, Any]:
    """Azure activity log rule body. After ingest-azure-activity-ocsf
    normalization it lives under `unmapped.azure.properties`. Fall back to
    `api.request.data.properties` for ingest paths that put the request body
    on the api node directly."""
    unmapped = event.get("unmapped") or {}
    azure = unmapped.get("azure") if isinstance(unmapped, dict) else None
    if isinstance(azure, dict):
        props = azure.get("properties")
        if isinstance(props, dict):
            return props
    api = event.get("api") or {}
    request = api.get("request") or {}
    data = request.get("data") if isinstance(request, dict) else None
    if isinstance(data, dict):
        props = data.get("properties")
        if isinstance(props, dict):
            return props
    return {}


def _resource_id(event: dict[str, Any]) -> str:
    """Rule's fully-qualified Azure Resource Manager id, e.g.
    /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/
    networkSecurityGroups/<nsg>/securityRules/<rule>."""
    resources = event.get("resources") or []
    if isinstance(resources, list):
        for resource in resources:
            if isinstance(resource, dict):
                name = resource.get("name") or resource.get("uid") or ""
                if name:
                    return str(name)
    return ""


def _rule_name_from_resource_id(resource_id: str) -> str:
    if not resource_id:
        return ""
    parts = resource_id.rstrip("/").split("/")
    return parts[-1] if parts else ""


def _iter_source_prefixes(props: dict[str, Any]) -> Iterator[str]:
    one = props.get("sourceAddressPrefix")
    if isinstance(one, str) and one.strip():
        yield one.strip()
    many = props.get("sourceAddressPrefixes")
    if isinstance(many, list):
        for item in many:
            if isinstance(item, str) and item.strip():
                yield item.strip()


def _iter_destination_port_strings(props: dict[str, Any]) -> Iterator[str]:
    one = props.get("destinationPortRange")
    if isinstance(one, str) and one.strip():
        yield one.strip()
    many = props.get("destinationPortRanges")
    if isinstance(many, list):
        for item in many:
            if isinstance(item, str) and item.strip():
                yield item.strip()


def _port_string_overlaps_risky(
    port_string: str, risky_ports: Iterable[int]
) -> tuple[bool, list[int]]:
    """A port string is one of:
    - "*" (all ports — every risky port is hit)
    - "<n>" (single port)
    - "<lo>-<hi>" (inclusive range; 22 is in "22-25")
    Returns (overlap, hit_ports).
    """
    risky = sorted(risky_ports)
    s = (port_string or "").strip()
    if not s:
        return False, []
    if s == "*":
        return True, risky
    if "-" in s:
        lo_str, _, hi_str = s.partition("-")
        try:
            lo = int(lo_str)
            hi = int(hi_str)
        except ValueError:
            return False, []
        if lo > hi:
            lo, hi = hi, lo
        hits = [p for p in risky if lo <= p <= hi]
        return bool(hits), hits
    try:
        n = int(s)
    except ValueError:
        return False, []
    return (n in risky), ([n] if n in risky else [])


def _rule_overlaps_risky(
    props: dict[str, Any], risky_ports: Iterable[int]
) -> tuple[bool, list[int]]:
    risky = tuple(sorted(set(risky_ports)))
    all_hits: set[int] = set()
    overlap = False
    for port_string in _iter_destination_port_strings(props):
        ok, hits = _port_string_overlaps_risky(port_string, risky)
        if ok:
            overlap = True
            all_hits.update(hits)
    return overlap, sorted(all_hits)


def _public_source_hits(props: dict[str, Any]) -> list[str]:
    hits: list[str] = []
    for prefix in _iter_source_prefixes(props):
        if prefix.lower() in PUBLIC_SOURCE_PREFIXES:
            hits.append(prefix)
    # Stable ordering for deterministic finding UIDs
    return sorted(set(hits))


def _actor(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _account(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    account = cloud.get("account") or {}
    return str(account.get("uid") or "")


def _region(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    return str(cloud.get("region") or "")


def _src_ip(event: dict[str, Any]) -> str:
    src = event.get("src_endpoint") or {}
    return str(src.get("ip") or "")


def _finding_uid(event_uid: str, rule_uid: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{rule_uid}|{time_ms}"
    return f"ansg-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(
    *,
    event: dict[str, Any],
    rule_uid: str,
    rule_name: str,
    public_sources_hit: list[str],
    risky_ports_hit: list[int],
    rule_props: dict[str, Any],
) -> dict[str, Any]:
    time_ms = int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)
    event_uid = str((event.get("metadata") or {}).get("uid") or "")
    finding_uid = _finding_uid(event_uid, rule_uid, time_ms)
    actor = _actor(event)
    account = _account(event)
    region = _region(event)
    src_ip = _src_ip(event)

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": "open-nsg-inbound",
        "rule_uid": rule_uid,
        "rule_name": rule_name,
        "actor_name": actor,
        "account_uid": account,
        "region": region,
        "src_ip": src_ip,
        "public_sources_hit": public_sources_hit,
        "risky_ports_hit": risky_ports_hit,
        "nsg_rule": rule_props,
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    """Wrap a native finding as an OCSF 1.8 Detection Finding (class 2004)."""
    title = (
        f"Azure NSG rule {native['rule_name'] or native['rule_uid']} opened to the "
        f"internet on risky port(s) {native['risky_ports_hit']}"
    )
    description = (
        f"Actor `{native['actor_name']}` in subscription `{native['account_uid']}` "
        f"({native['region']}) wrote an Inbound/Allow NSG rule `{native['rule_uid']}` "
        f"with source prefix(es) {native['public_sources_hit']} covering risky ports "
        f"{native['risky_ports_hit']}. Source IP: {native['src_ip'] or '<unknown>'}."
    )

    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "Azure"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "api.operation", "type": "Other", "value": NSG_RULE_WRITE_OPERATION},
        {"name": "rule", "type": "Other", "value": native["rule"]},
        {"name": "target.uid", "type": "Other", "value": native["rule_uid"]},
        {"name": "target.name", "type": "Other", "value": native["rule_name"] or native["rule_uid"]},
        {"name": "target.type", "type": "Other", "value": "NetworkSecurityRule"},
        {"name": "account.uid", "type": "Other", "value": native["account_uid"]},
        {"name": "region", "type": "Other", "value": native["region"]},
    ]
    if native["src_ip"]:
        observables.append({"name": "src.ip", "type": "IP Address", "value": native["src_ip"]})
    for prefix in native["public_sources_hit"]:
        observables.append({"name": "rule.source_prefix", "type": "Other", "value": prefix})
    protocol = str((native["nsg_rule"] or {}).get("protocol") or "")
    if protocol:
        observables.append({"name": "rule.protocol", "type": "Other", "value": protocol})
    direction = str((native["nsg_rule"] or {}).get("direction") or "")
    if direction:
        observables.append({"name": "rule.direction", "type": "Other", "value": direction})
    access = str((native["nsg_rule"] or {}).get("access") or "")
    if access:
        observables.append({"name": "rule.access", "type": "Other", "value": access})
    priority = (native["nsg_rule"] or {}).get("priority")
    if priority is not None:
        observables.append({"name": "rule.priority", "type": "Other", "value": str(priority)})
    for port in native["risky_ports_hit"]:
        observables.append({"name": "rule.port", "type": "Other", "value": str(port)})

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
            "labels": ["azure", "nsg", "exposure"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": title,
            "desc": description,
            "types": ["open-nsg-inbound"],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic_uid": TACTIC_UID,
                    "tactic_name": TACTIC_NAME,
                    "technique_uid": TECHNIQUE_UID,
                    "technique_name": TECHNIQUE_NAME,
                }
            ],
        },
        "observables": observables,
        "evidence": {
            "events_observed": 1,
            "nsg_rule": native["nsg_rule"],
            "public_sources_hit": native["public_sources_hit"],
            "risky_ports_hit": native["risky_ports_hit"],
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
    risky_ports: Iterable[int] = DEFAULT_RISKY_PORTS,
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    risky_ports = tuple(sorted(set(risky_ports)))

    for event in events:
        producer = _producer(event)
        if producer not in ACCEPTED_PRODUCERS:
            emit_stderr_event(
                SKILL_NAME, level="warning", event="wrong_source",
                message=f"skipping event from non-azure-activity producer `{producer}`",
            )
            continue

        if _api_operation(event) != NSG_RULE_WRITE_OPERATION:
            continue
        if not _is_success(event):
            continue

        props = _rule_properties(event)
        if not props:
            continue

        direction = str(props.get("direction") or "").strip().lower()
        access = str(props.get("access") or "").strip().lower()
        if direction != "inbound":
            continue
        if access != "allow":
            continue

        public_sources = _public_source_hits(props)
        if not public_sources:
            continue

        overlaps, port_hits = _rule_overlaps_risky(props, risky_ports)
        if not overlaps:
            continue

        rule_uid = _resource_id(event)
        rule_name = _rule_name_from_resource_id(rule_uid)
        if not rule_uid:
            emit_stderr_event(
                SKILL_NAME, level="warning", event="no_rule_id",
                message="NSG rule write missing target resource id; skipping",
            )
            continue

        native = _build_native_finding(
            event=event, rule_uid=rule_uid, rule_name=rule_name,
            public_sources_hit=public_sources, risky_ports_hit=port_hits,
            rule_props=props,
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
                SKILL_NAME, level="warning", event="json_parse_failed",
                message=f"skipping line {lineno}: json parse failed: {exc}", line=lineno,
            )
            continue
        if isinstance(obj, dict):
            yield obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect Azure NSG inbound rules opened to * / Internet / 0.0.0.0/0 / ::/0 on risky ports."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format", choices=sorted(OUTPUT_FORMATS), default="ocsf",
        help="Emit OCSF Detection Finding (default) or native projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        for finding in detect(load_jsonl(in_stream), output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
