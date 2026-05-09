"""Detect cloud lateral movement by joining API and network telemetry.

Reads a merged JSONL stream containing either:
  - OCSF API Activity / Network Activity events, or
  - native canonical-ish events from supported upstream skills

Emits OCSF 1.8 Detection Finding (class 2004) for each distinct
(provider, session, internal destination) tuple where a privileged-identity
anchor precedes a meaningful east-west flow within the correlation window.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
from bisect import bisect_left
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.env import env_int  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-lateral-movement"
OCSF_VERSION = "1.8.0"
REPO_NAME = "cloud-ai-security-skills"
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402

# Detection Finding (2004)
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
# T1021 — Remote Services (Lateral Movement tactic TA0008)
T1021_TACTIC_UID = "TA0008"
T1021_TACTIC_NAME = "Lateral Movement"
T1021_TECH_UID = "T1021"
T1021_TECH_NAME = "Remote Services"
# T1078.004 — Valid Accounts: Cloud Accounts (Persistence tactic TA0003 primary)
T1078_TACTIC_UID = "TA0003"
T1078_TACTIC_NAME = "Persistence"
T1078_TECH_UID = "T1078"
T1078_TECH_NAME = "Valid Accounts"
T1078_SUB_UID = "T1078.004"
T1078_SUB_NAME = "Cloud Accounts"

# Input class filters
API_ACTIVITY_CLASS = 6003
NETWORK_ACTIVITY_CLASS = 4001

# Network Activity activity_id 6 == ACCEPT (traffic allowed)
NET_ACTIVITY_ACCEPT = 6

# Correlation window: 15 minutes post-anchor
CORRELATION_WINDOW_MS = 15 * 60 * 1000

# Byte threshold — filter out scan probes / 3-way handshake noise
MIN_BYTES = 1024
OUTPUT_FORMATS = ("ocsf", "native")
WINDOW_ENV = "DETECT_LATERAL_MOVEMENT_WINDOW_MS"
MIN_BYTES_ENV = "DETECT_LATERAL_MOVEMENT_MIN_BYTES"

# Cloud identity-pivot operations we anchor on
ASSUME_ROLE_OPERATIONS = {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}
GCP_IDENTITY_PIVOT_SUFFIXES = (
    "GenerateAccessToken",
    "GenerateIdToken",
    "SignJwt",
    "SignBlob",
    "CreateServiceAccountKey",
)
AZURE_ACTIVITY_IDENTITY_PIVOT_OPERATIONS = {
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
    "MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION",
    "MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/ASSIGN/ACTION",
}
AZURE_ENTRA_SERVICE_NAMES = {
    "GRAPH.MICROSOFT.COM",
    "MICROSOFT GRAPH",
    "MICROSOFT ENTRA ID",
    "CORE DIRECTORY",
}
AZURE_ENTRA_EXACT_OPERATIONS = {
    "ADD SERVICE PRINCIPAL CREDENTIALS",
    "UPDATE APPLICATION - CERTIFICATES AND SECRETS MANAGEMENT",
    "ADD APP ROLE ASSIGNMENT TO SERVICE PRINCIPAL",
    "CREATE FEDERATED IDENTITY CREDENTIAL",
    "ADD FEDERATED IDENTITY CREDENTIAL",
}

FRAMEWORKS = ("OCSF 1.8.0", "MITRE ATT&CK v14")
PROVIDERS = ("aws", "azure", "gcp", "multi")
ASSET_CLASSES = (
    "iam-roles",
    "role-sessions",
    "applications",
    "service-accounts",
    "service-account-keys",
    "iam-credentials",
    "service-principals",
    "managed-identities",
    "federated-credentials",
    "app-role-assignments",
    "sessions",
    "api",
    "network",
)
ATTACK_COVERAGE = {
    "aws": {
        "principal_types": ["iam-roles", "federated-role-sessions"],
        "anchor_operations": sorted(ASSUME_ROLE_OPERATIONS),
        "techniques": ["T1021", "T1078.004"],
    },
    "gcp": {
        "principal_types": ["service-accounts"],
        "anchor_operations": [f"*{suffix}" for suffix in GCP_IDENTITY_PIVOT_SUFFIXES],
        "techniques": ["T1021", "T1078.004"],
    },
    "azure": {
        "principal_types": ["applications", "service-principals", "managed-identities"],
        "operation_families": {
            "azure-activity": sorted(AZURE_ACTIVITY_IDENTITY_PIVOT_OPERATIONS),
            "entra-graph": [
                "Add service principal credentials",
                "Update application - Certificates and secrets management",
                "Add app role assignment to service principal",
                "Create federated identity credential",
                "POST /applications/{id}/addPassword",
                "POST /applications/{id}/addKey",
                "POST /servicePrincipals/{id}/addPassword",
                "POST /servicePrincipals/{id}/addKey",
                "POST /servicePrincipals/{id}/appRoleAssignments",
                "POST /servicePrincipals/{id}/appRoleAssignedTo",
                "POST /applications/{id}/federatedIdentityCredentials",
            ],
        },
        "anchor_operations": sorted(
            list(AZURE_ACTIVITY_IDENTITY_PIVOT_OPERATIONS)
            + [
                "Add service principal credentials",
                "Update application - Certificates and secrets management",
                "Add app role assignment to service principal",
                "Create federated identity credential",
            ]
        ),
        "techniques": ["T1021", "T1078.004"],
    },
}

# RFC1918 private ranges + CGNAT shared-address range
_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_rfc1918(ip_str: str) -> bool:
    """True iff `ip_str` is inside any of the private / CGNAT ranges."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)


def _short(s: str) -> str:
    return hashlib.sha256((s or "").encode()).hexdigest()[:8]


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _provider_display(provider: str) -> str:
    return {"AWS": "AWS", "GCP": "GCP", "AZURE": "Azure"}.get(provider, provider.title() or "Cloud")


def _normalize_token(value: str) -> str:
    return " ".join((value or "").upper().replace("_", " ").split())


def _compact_token(value: str) -> str:
    return _normalize_token(value).replace(" ", "")


def _is_azure_entra_pivot(service: str, operation: str) -> bool:
    service_norm = _normalize_token(service)
    operation_norm = _normalize_token(operation)
    operation_compact = operation_norm.replace(" ", "")

    if service_norm not in AZURE_ENTRA_SERVICE_NAMES:
        return False

    if operation_norm in AZURE_ENTRA_EXACT_OPERATIONS:
        return True

    if any(marker in operation_compact for marker in ("ADDPASSWORD", "ADDKEY")):
        return True

    if operation_norm.startswith("POST /") and any(
        marker in operation_compact for marker in ("APPROLEASSIGNMENTS", "APPROLEASSIGNEDTO")
    ):
        return True

    return operation_norm.startswith("POST /APPLICATIONS/") and "FEDERATEDIDENTITYCREDENTIALS" in operation_compact


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_native_event(event: dict[str, Any]) -> dict[str, Any] | None:
    record_type = str(event.get("record_type") or event.get("event_kind") or "").strip().lower()
    if not record_type:
        if "dst_ip" in event or "traffic_bytes" in event or "bytes" in event:
            record_type = "network_activity"
        elif "operation" in event or "service_name" in event:
            record_type = "api_activity"
        else:
            return None

    normalized: dict[str, Any] = {
        "source_format": "native",
        "event_kind": record_type,
        "provider": str(event.get("provider") or event.get("cloud_provider") or "").upper(),
        "account_uid": str(event.get("account_uid") or event.get("cloud_account_uid") or event.get("account") or ""),
        "time_ms": _safe_int(event.get("time_ms") or event.get("time") or event.get("event_time")),
        "session_uid": str(
            event.get("session_uid")
            or event.get("session_id")
            or (((event.get("actor") or {}).get("session") or {}).get("uid"))
            or ""
        ),
        "actor_name": str(
            event.get("actor_name")
            or (((event.get("actor") or {}).get("user") or {}).get("name"))
            or ""
        ),
        "operation": str(event.get("operation") or event.get("api_operation") or ""),
        "service_name": str(event.get("service_name") or event.get("api_service") or ""),
        "src_ip": str(event.get("src_ip") or ""),
        "src_instance_uid": str(event.get("src_instance_uid") or event.get("instance_uid") or ""),
        "dst_ip": str(event.get("dst_ip") or ""),
        "dst_port": int(event["dst_port"]) if event.get("dst_port") is not None else None,
        "traffic_bytes": _safe_int(event.get("traffic_bytes") or event.get("bytes")),
        "activity_id": _safe_int(event.get("activity_id")),
        "disposition": str(event.get("disposition") or ""),
        "raw": event,
    }
    if record_type == "network_activity" and not normalized["activity_id"]:
        disposition = normalized["disposition"].upper()
        if disposition in {"ACCEPT", "ALLOWED", "ALLOW"}:
            normalized["activity_id"] = NET_ACTIVITY_ACCEPT
    return normalized


def _normalize_ocsf_event(event: dict[str, Any]) -> dict[str, Any] | None:
    class_uid = event.get("class_uid")
    if class_uid == API_ACTIVITY_CLASS:
        return {
            "source_format": "ocsf",
            "event_kind": "api_activity",
            "provider": ((((event.get("cloud") or {}).get("provider")) or "")).upper(),
            "account_uid": ((((event.get("cloud") or {}).get("account")) or {}).get("uid")) or "",
            "time_ms": _safe_int(event.get("time")),
            "session_uid": (((event.get("actor") or {}).get("session") or {}).get("uid")) or "",
            "actor_name": (((event.get("actor") or {}).get("user") or {}).get("name")) or "",
            "operation": ((event.get("api") or {}).get("operation")) or "",
            "service_name": ((((event.get("api") or {}).get("service")) or {}).get("name")) or "",
            "src_ip": (event.get("src_endpoint") or {}).get("ip") or "",
            "src_instance_uid": (event.get("src_endpoint") or {}).get("instance_uid") or "",
            "dst_ip": "",
            "dst_port": None,
            "traffic_bytes": 0,
            "activity_id": _safe_int(event.get("activity_id")),
            "disposition": "",
            "raw": event,
        }
    if class_uid == NETWORK_ACTIVITY_CLASS:
        dst_port = (event.get("dst_endpoint") or {}).get("port")
        return {
            "source_format": "ocsf",
            "event_kind": "network_activity",
            "provider": ((((event.get("cloud") or {}).get("provider")) or "")).upper(),
            "account_uid": ((((event.get("cloud") or {}).get("account")) or {}).get("uid")) or "",
            "time_ms": _safe_int(event.get("time")),
            "session_uid": "",
            "actor_name": "",
            "operation": "",
            "service_name": "",
            "src_ip": (event.get("src_endpoint") or {}).get("ip") or "",
            "src_instance_uid": (event.get("src_endpoint") or {}).get("instance_uid") or "",
            "dst_ip": (event.get("dst_endpoint") or {}).get("ip") or "",
            "dst_port": int(dst_port) if dst_port is not None else None,
            "traffic_bytes": _safe_int((event.get("traffic") or {}).get("bytes")),
            "activity_id": _safe_int(event.get("activity_id")),
            "disposition": "",
            "raw": event,
        }
    return None


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        return _normalize_ocsf_event(event)
    return _normalize_native_event(event)


def is_identity_pivot_anchor(event: dict[str, Any]) -> bool:
    """Return True when an API-activity event is a high-signal pivot anchor."""
    normalized = _normalize_event(event)
    if normalized is None or normalized["event_kind"] != "api_activity":
        return False

    provider = str(normalized["provider"])
    operation = str(normalized["operation"])
    service = str(normalized["service_name"])

    if provider == "AWS":
        return operation in ASSUME_ROLE_OPERATIONS

    if provider == "GCP":
        if service not in {"iamcredentials.googleapis.com", "iam.googleapis.com"}:
            return False
        last = operation.rsplit(".", 1)[-1]
        return any(last.endswith(suffix) for suffix in GCP_IDENTITY_PIVOT_SUFFIXES)

    if provider == "AZURE":
        service_norm = _normalize_token(service)
        operation_norm = _normalize_token(operation)
        if operation_norm in AZURE_ACTIVITY_IDENTITY_PIVOT_OPERATIONS:
            return True
        return _is_azure_entra_pivot(service_norm, operation_norm)

    return False


def coverage_metadata() -> dict[str, object]:
    """Return machine-readable ATT&CK and provider coverage for the detector."""
    correlation_window_ms = _correlation_window_ms()
    min_bytes = _min_bytes()
    return {
        "frameworks": list(FRAMEWORKS),
        "providers": list(PROVIDERS),
        "asset_classes": list(ASSET_CLASSES),
        "attack_coverage": ATTACK_COVERAGE,
        "correlation_window_seconds": correlation_window_ms // 1000,
        "min_flow_bytes": min_bytes,
    }


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------


def _build_native_finding(
    *,
    anchor_event: dict[str, Any],
    flow_event: dict[str, Any],
) -> dict[str, Any]:
    session = str(anchor_event["session_uid"])
    principal = str(anchor_event["actor_name"])
    provider_code = str(anchor_event["provider"])
    provider = _provider_display(provider_code)
    provider_key = (provider_code or "cloud").lower()
    account = str(anchor_event["account_uid"])
    dst_ip = str(flow_event["dst_ip"])
    dst_port = flow_event["dst_port"]
    src_instance = str(flow_event["src_instance_uid"])
    src_ip = str(flow_event["src_ip"])
    flow_bytes = _safe_int(flow_event["traffic_bytes"])
    operation = str(anchor_event["operation"])
    correlation_window_ms = _correlation_window_ms()

    dst_key = f"{dst_ip}:{dst_port}"
    uid = f"det-lm-{_short(provider_key)}-{_short(session)}-{_short(dst_key)}"

    desc = (
        f"Principal '{principal}' triggered identity pivot operation '{operation}' "
        f"(session '{session}'), and within the "
        f"{correlation_window_ms // 60000}-minute correlation window an "
        f"accepted east-west flow moved {flow_bytes} bytes from "
        f"{src_instance or src_ip} to {dst_ip}:{dst_port}. This is the "
        f"canonical {provider} lateral movement pattern (MITRE T1021 Remote "
        f"Services via T1078.004 Cloud Accounts) — the API anchor alone looks "
        f"routine and the flow alone looks like normal intra-cloud traffic, "
        f"but together they tell the full pivot story."
    )

    return {
        "schema_mode": "native",
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": uid,
        "event_uid": uid,
        "provider": provider_code,
        "account_uid": account,
        "time_ms": int(flow_event["time_ms"]) or _now_ms(),
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": 1,
        "title": f"{provider} lateral movement: identity pivot followed by east-west traffic",
        "description": desc,
        "finding_types": ["cloud-lateral-movement"],
        "first_seen_time_ms": int(anchor_event["time_ms"]),
        "last_seen_time_ms": int(flow_event["time_ms"]),
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": T1021_TACTIC_UID,
                "tactic_name": T1021_TACTIC_NAME,
                "technique_uid": T1021_TECH_UID,
                "technique_name": T1021_TECH_NAME,
            },
            {
                "version": MITRE_VERSION,
                "tactic_uid": T1078_TACTIC_UID,
                "tactic_name": T1078_TACTIC_NAME,
                "technique_uid": T1078_TECH_UID,
                "technique_name": T1078_TECH_NAME,
                "sub_technique_uid": T1078_SUB_UID,
                "sub_technique_name": T1078_SUB_NAME,
            },
        ],
        "session_uid": session,
        "actor_name": principal,
        "anchor_operation": operation,
        "src_instance_uid": src_instance,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "traffic_bytes": flow_bytes,
        "window_seconds": correlation_window_ms // 1000,
        "rule_name": "cloud-lateral-movement",
    }


def _render_ocsf_finding(native_finding: dict[str, Any]) -> dict[str, Any]:
    provider_code = str(native_finding["provider"])
    provider = _provider_display(provider_code)
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_HIGH,
        "status_id": 1,
        "time": int(native_finding["time_ms"]) or _now_ms(),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native_finding["event_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", provider_code.lower(), "lateral-movement", "multi-source"],
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "first_seen_time": int(native_finding["first_seen_time_ms"]),
            "last_seen_time": int(native_finding["last_seen_time_ms"]),
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": T1021_TACTIC_NAME, "uid": T1021_TACTIC_UID},
                    "technique": {"name": T1021_TECH_NAME, "uid": T1021_TECH_UID},
                },
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": T1078_TACTIC_NAME, "uid": T1078_TACTIC_UID},
                    "technique": {"name": T1078_TECH_NAME, "uid": T1078_TECH_UID},
                    "sub_technique": {"name": T1078_SUB_NAME, "uid": T1078_SUB_UID},
                },
            ],
        },
        "observables": [
            {"name": "cloud.provider", "type": "Other", "value": provider},
            {"name": "cloud.account", "type": "Other", "value": native_finding["account_uid"]},
            {"name": "session.uid", "type": "Other", "value": native_finding["session_uid"]},
            {"name": "actor.name", "type": "Other", "value": native_finding["actor_name"]},
            {"name": "anchor.operation", "type": "Other", "value": native_finding["anchor_operation"]},
            {"name": "src.instance_uid", "type": "Other", "value": native_finding["src_instance_uid"]},
            {"name": "src.ip", "type": "Other", "value": native_finding["src_ip"]},
            {"name": "dst.ip", "type": "Other", "value": native_finding["dst_ip"]},
            {"name": "dst.port", "type": "Other", "value": str(native_finding["dst_port"] or "")},
            {"name": "traffic.bytes", "type": "Other", "value": str(native_finding["traffic_bytes"])},
            {"name": "window.seconds", "type": "Other", "value": str(native_finding["window_seconds"])},
            {"name": "rule", "type": "Other", "value": native_finding["rule_name"]},
        ],
        "evidence": {
            "events_observed": 2,
            "first_seen_time": int(native_finding["first_seen_time_ms"]),
            "last_seen_time": int(native_finding["last_seen_time_ms"]),
            "raw_events": [],
        },
    }


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------


def _is_candidate_flow(event: dict[str, Any]) -> bool:
    if event["event_kind"] != "network_activity" or int(event["activity_id"]) != NET_ACTIVITY_ACCEPT:
        return False
    if _safe_int(event["traffic_bytes"]) < _min_bytes():
        return False
    return is_rfc1918(str(event["dst_ip"]))


def _index_candidate_flows(flows: Iterable[dict[str, Any]]) -> dict[str, dict[str, dict[tuple[str, int | None], dict[str, Any]]]]:
    indexed: dict[str, dict[str, dict[tuple[str, int | None], dict[str, Any]]]] = {}
    for flow in flows:
        provider = str(flow["provider"])
        account = str(flow["account_uid"])
        dst_key = (str(flow["dst_ip"]), flow["dst_port"])
        provider_bucket = indexed.setdefault(provider, {})
        account_bucket = provider_bucket.setdefault(account, {})
        record = account_bucket.setdefault(dst_key, {"times": [], "flows": []})
        record["times"].append(int(flow["time_ms"]))
        record["flows"].append(flow)
    return indexed


def _iter_matching_flow_buckets(
    indexed_flows: dict[str, dict[str, dict[tuple[str, int | None], dict[str, Any]]]],
    anchor_provider: str,
    anchor_account: str,
) -> Iterable[dict[tuple[str, int | None], dict[str, Any]]]:
    if anchor_provider:
        provider_bucket = indexed_flows.get(anchor_provider, {})
        if anchor_account:
            exact = provider_bucket.get(anchor_account)
            if exact:
                yield exact
            shared = provider_bucket.get("")
            if shared and shared is not exact:
                yield shared
            return
        yield from provider_bucket.values()
        return

    for provider_bucket in indexed_flows.values():
        if anchor_account:
            exact = provider_bucket.get(anchor_account)
            if exact:
                yield exact
            shared = provider_bucket.get("")
            if shared and shared is not exact:
                yield shared
            continue
        yield from provider_bucket.values()


def _find_earliest_flow_in_window(
    bucket: dict[str, Any],
    anchor_time: int,
    window_end: int,
) -> dict[str, Any] | None:
    times: list[int] = bucket["times"]
    flows: list[dict[str, Any]] = bucket["flows"]
    index = bisect_left(times, anchor_time)
    if index >= len(times):
        return None
    if times[index] > window_end:
        return None
    return flows[index]


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    """Walk a merged stream. Yield one finding per (session, dst) pair.

    Deterministic output order: findings are yielded in anchor-event-time
    order (then by dst IP and port as tiebreaker).
    """
    events_list = [normalized for event in events if (normalized := _normalize_event(event)) is not None]
    identity_anchors: list[dict[str, Any]] = []
    candidate_flows: list[dict[str, Any]] = []
    for ev in events_list:
        if is_identity_pivot_anchor(ev):
            identity_anchors.append(ev)
        elif _is_candidate_flow(ev):
            candidate_flows.append(ev)

    identity_anchors.sort(key=lambda event: int(event["time_ms"]))
    indexed_flows = _index_candidate_flows(candidate_flows)

    seen: set[str] = set()
    findings: list[dict[str, Any]] = []

    for anchor in identity_anchors:
        anchor_time = int(anchor["time_ms"])
        window_end = anchor_time + _correlation_window_ms()
        anchor_provider = str(anchor["provider"])
        anchor_account = str(anchor["account_uid"])
        session = str(anchor["session_uid"])

        for account_bucket in _iter_matching_flow_buckets(indexed_flows, anchor_provider, anchor_account):
            for (dst, dst_port), flow_bucket in account_bucket.items():
                dedup_key = f"{anchor_provider}|{session}|{dst}|{dst_port}"
                if dedup_key in seen:
                    continue
                flow = _find_earliest_flow_in_window(flow_bucket, anchor_time, window_end)
                if flow is None:
                    continue
                seen.add(dedup_key)
                native_finding = _build_native_finding(anchor_event=anchor, flow_event=flow)
                findings.append(_render_ocsf_finding(native_finding) if output_format == "ocsf" else native_finding)

    # Final deterministic ordering by anchor time, dst ip, dst port
    findings.sort(
        key=lambda f: (
            str(f.get("provider") or next((o["value"] for o in f.get("observables", []) if o["name"] == "cloud.provider"), "")),
            str(f.get("session_uid") or next((o["value"] for o in f.get("observables", []) if o["name"] == "session.uid"), "")),
            str(f.get("dst_ip") or next((o["value"] for o in f.get("observables", []) if o["name"] == "dst.ip"), "")),
            str(f.get("dst_port") or next((o["value"] for o in f.get("observables", []) if o["name"] == "dst.port"), "")),
        )
    )
    yield from findings


def _env_int(name: str, default: int) -> int:
    value = env_int(name, default, skill_name=SKILL_NAME)
    return value if value > 0 else default


def _correlation_window_ms() -> int:
    return _env_int(WINDOW_ENV, CORRELATION_WINDOW_MS)


def _min_bytes() -> int:
    return _env_int(MIN_BYTES_ENV, MIN_BYTES)


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=f"skipping line {lineno}: json parse failed: {e}",
                line=lineno,
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
    parser = argparse.ArgumentParser(description="Detect cloud lateral movement (API Activity + Network Activity join).")
    parser.add_argument("input", nargs="?", help="Merged native or OCSF JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Detection Finding JSONL output. Defaults to stdout.")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default="ocsf", help="Render OCSF detection findings or the native detection-finding shape.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        events = list(load_jsonl(in_stream))
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
