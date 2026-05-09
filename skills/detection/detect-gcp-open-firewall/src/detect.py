"""Detect GCP VPC firewall rules opened to the internet (0.0.0.0/0 or ::/0).

Reads OCSF 1.8 API Activity (class 6003) records emitted by
`ingest-gcp-audit-ocsf` from stdin or a file. Fires on
`compute.firewalls.insert` and `compute.firewalls.patch` calls that grant
INGRESS access from 0.0.0.0/0 or ::/0 to a risky port on a non-disabled
rule. Emits OCSF 1.8 Detection Finding (class 2004) tagged with MITRE
ATT&CK T1190 (Exploit Public-Facing Application).

GCP firewall rules differ from AWS Security Groups:
- INGRESS / EGRESS direction is explicit; this detector is INGRESS-only
- A rule may be `disabled: true`, in which case it grants nothing live
- The grant is described by `allowed[]` entries (each carrying
  `IPProtocol` + optional `ports[]`)
- The targeting tuple is `(project, firewall_rule_name)` — there is no
  region (firewalls are project-wide) and no AWS-style "security group id"

Rule:
1. event.api.operation in {compute.firewalls.insert, compute.firewalls.patch}
2. event.status_id == 1 (success)
3. unmapped.gcp.request.direction == "INGRESS"
4. not unmapped.gcp.request.disabled
5. unmapped.gcp.request.sourceRanges includes 0.0.0.0/0 OR ::/0
6. unmapped.gcp.request.allowed[].ports overlaps a risky port (protocol
   `all` or no `ports` means "all ports", which counts as a hit)

Output: OCSF Detection Finding 2004, with `target.uid` = the firewall
rule name and `target.name` = the same name. The remediator
(`remediate-gcp-firewall-revoke`) consumes these findings to disable
or delete the offending rule.
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

SKILL_NAME = "detect-gcp-open-firewall"
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

ACCEPTED_PRODUCERS = frozenset({"ingest-gcp-audit-ocsf"})

ACCEPTED_OPERATIONS = frozenset(
    {
        "compute.firewalls.insert",
        "compute.firewalls.patch",
        # Some audit-log emitters use bare method names; tolerate both.
        "v1.compute.firewalls.insert",
        "v1.compute.firewalls.patch",
    }
)

# Default risky ports — admin / database / cache / search surfaces. Same
# list as the AWS detector so operators see uniform behaviour across clouds.
DEFAULT_RISKY_PORTS = (
    22,     # SSH
    23,     # Telnet
    135,    # MSRPC
    445,    # SMB
    1433,   # MSSQL
    1521,   # Oracle
    2049,   # NFS
    3306,   # MySQL
    3389,   # RDP
    5432,   # Postgres
    5984,   # CouchDB
    6379,   # Redis
    8086,   # InfluxDB
    9042,   # Cassandra
    9092,   # Kafka
    9200,   # Elasticsearch
    11211,  # Memcached
    27017,  # MongoDB
)

PUBLIC_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

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


def _request_payload(event: dict[str, Any]) -> dict[str, Any]:
    """The compute.firewalls.insert/patch request body lives under
    `unmapped.gcp.request` after ingest-gcp-audit-ocsf normalization
    (or `api.request.data` on some emit paths).
    """
    unmapped = event.get("unmapped") or {}
    if isinstance(unmapped, dict):
        gcp = unmapped.get("gcp")
        if isinstance(gcp, dict):
            req = gcp.get("request")
            if isinstance(req, dict):
                return req
    api = event.get("api") or {}
    request = api.get("request") or {}
    if isinstance(request, dict):
        data = request.get("data")
        if isinstance(data, dict):
            return data
    return {}


def _firewall_name(event: dict[str, Any], request: dict[str, Any]) -> str:
    """Firewall name lives in the request body (`name`) and/or the audit
    log resourceName (`projects/<p>/global/firewalls/<name>`)."""
    name = str(request.get("name") or "")
    if name:
        return name
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        rname = str(resource.get("name") or "")
        if "/global/firewalls/" in rname:
            return rname.rsplit("/", 1)[-1]
        if "/firewalls/" in rname:
            return rname.rsplit("/", 1)[-1]
    return ""


def _network_self_link(request: dict[str, Any]) -> str:
    return str(request.get("network") or "")


def _direction(request: dict[str, Any]) -> str:
    return str(request.get("direction") or "INGRESS").upper()


def _is_disabled(request: dict[str, Any]) -> bool:
    val = request.get("disabled")
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() == "true"
    return False


def _source_ranges(request: dict[str, Any]) -> list[str]:
    raw = request.get("sourceRanges") or []
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if isinstance(item, (str, bytes))]


def _iter_allowed(request: dict[str, Any]) -> Iterator[dict[str, Any]]:
    raw = request.get("allowed") or []
    if not isinstance(raw, list):
        return
    for item in raw:
        if isinstance(item, dict):
            yield item


def _ports_overlap_risky(
    allowed_entry: dict[str, Any], risky_ports: Iterable[int]
) -> tuple[bool, list[int]]:
    """A GCP `allowed[]` entry has `IPProtocol` and optional `ports[]`.
    Each `ports[]` element is either `"22"` or `"1000-2000"`. If `ports`
    is missing, the rule covers ALL ports for that protocol. Protocol
    `all` covers all protocols + ports.
    """
    protocol = str(allowed_entry.get("IPProtocol") or "").lower()
    risky_sorted = sorted(risky_ports)
    if protocol == "all":
        return True, risky_sorted
    # GCP only carries ports[] meaningfully for tcp / udp / sctp; for
    # icmp / esp / ah / etc. there is no port concept and the rule covers
    # every packet of that protocol — but icmp/esp/ah are NOT TCP services
    # at risky ports, so we don't fire on them here.
    if protocol not in ("tcp", "udp", "sctp"):
        return False, []
    ports_field = allowed_entry.get("ports")
    if not ports_field:
        # No ports[] = all ports for this protocol = every risky port hit
        return True, risky_sorted
    if not isinstance(ports_field, list):
        return False, []
    hits: set[int] = set()
    for spec in ports_field:
        spec_str = str(spec).strip()
        if not spec_str:
            continue
        if "-" in spec_str:
            lo_s, hi_s = spec_str.split("-", 1)
            try:
                lo = int(lo_s)
                hi = int(hi_s)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            for p in risky_sorted:
                if lo <= p <= hi:
                    hits.add(p)
        else:
            try:
                p = int(spec_str)
            except ValueError:
                continue
            if p in risky_sorted:
                hits.add(p)
    return bool(hits), sorted(hits)


def _actor(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _account(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    account = cloud.get("account") or {}
    return str(account.get("uid") or "")


def _src_ip(event: dict[str, Any]) -> str:
    src = event.get("src_endpoint") or {}
    return str(src.get("ip") or "")


def _finding_uid(event_uid: str, fw_name: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{fw_name}|{time_ms}"
    return f"gfw-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(
    *,
    event: dict[str, Any],
    fw_name: str,
    network: str,
    public_cidrs_hit: list[str],
    risky_ports_hit: list[int],
    allowed_entry: dict[str, Any],
) -> dict[str, Any]:
    time_ms = int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)
    event_uid = str((event.get("metadata") or {}).get("uid") or "")
    finding_uid = _finding_uid(event_uid, fw_name, time_ms)
    actor = _actor(event)
    account = _account(event)
    src_ip = _src_ip(event)

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": "open-gcp-firewall-ingress",
        "firewall_name": fw_name,
        "network": network,
        "actor_name": actor,
        "account_uid": account,
        "src_ip": src_ip,
        "public_cidrs_hit": public_cidrs_hit,
        "risky_ports_hit": risky_ports_hit,
        "allowed": allowed_entry,
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    """Wrap a native finding as an OCSF 1.8 Detection Finding (class 2004)."""
    title = (
        f"GCP firewall rule {native['firewall_name']} opened to the internet on risky port(s) "
        f"{native['risky_ports_hit']}"
    )
    description = (
        f"Actor `{native['actor_name']}` in project `{native['account_uid']}` "
        f"opened firewall rule `{native['firewall_name']}` to "
        f"{native['public_cidrs_hit']} covering risky ports {native['risky_ports_hit']}. "
        f"Source IP: {native['src_ip'] or '<unknown>'}."
    )

    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "GCP"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "api.operation", "type": "Other", "value": "compute.firewalls.insert_or_patch"},
        {"name": "rule", "type": "Other", "value": native["rule"]},
        {"name": "target.uid", "type": "Other", "value": native["firewall_name"]},
        {"name": "target.name", "type": "Other", "value": native["firewall_name"]},
        {"name": "target.type", "type": "Other", "value": "GcpFirewallRule"},
        {"name": "account.uid", "type": "Other", "value": native["account_uid"]},
        {"name": "region", "type": "Other", "value": "global"},
    ]
    if native["network"]:
        observables.append({"name": "target.network", "type": "Other", "value": native["network"]})
    if native["src_ip"]:
        observables.append({"name": "src.ip", "type": "IP Address", "value": native["src_ip"]})
    for cidr in native["public_cidrs_hit"]:
        observables.append({"name": "permission.cidr", "type": "Other", "value": cidr})
    protocol = str((native["allowed"] or {}).get("IPProtocol") or "")
    if protocol:
        observables.append({"name": "permission.protocol", "type": "Other", "value": protocol})
    ports_field = (native["allowed"] or {}).get("ports")
    if isinstance(ports_field, list):
        for ps in ports_field:
            observables.append({"name": "permission.port_spec", "type": "Other", "value": str(ps)})
    for port in native["risky_ports_hit"]:
        observables.append({"name": "permission.port", "type": "Other", "value": str(port)})

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
            "labels": ["gcp", "firewall", "exposure"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": title,
            "desc": description,
            "types": ["open-gcp-firewall"],
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
            "allowed": native["allowed"],
            "public_cidrs_hit": native["public_cidrs_hit"],
            "risky_ports_hit": native["risky_ports_hit"],
            "network": native["network"],
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
                message=f"skipping event from non-gcp-audit producer `{producer}`",
            )
            continue

        op = _api_operation(event)
        if op not in ACCEPTED_OPERATIONS:
            continue
        if not _is_success(event):
            continue

        request = _request_payload(event)
        if not request:
            continue

        # Direction must be INGRESS (default per GCP API when missing)
        if _direction(request) != "INGRESS":
            continue
        if _is_disabled(request):
            continue

        sources = _source_ranges(request)
        public_hits = sorted(c for c in sources if c in PUBLIC_CIDRS)
        if not public_hits:
            continue

        fw_name = _firewall_name(event, request)
        if not fw_name:
            emit_stderr_event(
                SKILL_NAME, level="warning", event="no_firewall_name",
                message="firewalls.insert/patch finding missing rule name; skipping",
            )
            continue

        network = _network_self_link(request)

        for allowed_entry in _iter_allowed(request):
            overlaps, port_hits = _ports_overlap_risky(allowed_entry, risky_ports)
            if not overlaps:
                continue
            native = _build_native_finding(
                event=event, fw_name=fw_name, network=network,
                public_cidrs_hit=public_hits, risky_ports_hit=port_hits,
                allowed_entry=allowed_entry,
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
        description="Detect GCP VPC firewall rules opened to 0.0.0.0/0 or ::/0 on risky ports."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format", choices=sorted(OUTPUT_FORMATS), default="ocsf",
        help="Emit OCSF Detection Finding (default) or native projection.",
    )
    parser.add_argument(
        "--input-format", choices=("ocsf",), default="ocsf",
        help="Only OCSF input is accepted; reserved for forward compatibility.",
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
