"""Convert raw AWS GuardDuty findings to OCSF 1.8 Detection Finding (class 2004).

Input:  GuardDuty finding JSON — single findings, `{"Findings": [...]}` wrapper,
        or EventBridge envelopes with `{"detail": {...}, "detail-type": "GuardDuty Finding"}`.
        Auto-detected.
Output: JSONL of OCSF 1.8 Detection Finding events by default, or the repo's
        native enriched finding shape when --output-format native is selected.

GuardDuty is already a detection engine; this skill is a *passthrough* ingester
that normalises its native finding format into the OCSF wire contract shared by
every other skill in this category. MITRE ATT&CK technique and tactic are
extracted from the GuardDuty finding Type string; severity is mapped from the
1.0–8.9 scale to the OCSF severity_id enum.

Contract: see ../OCSF_CONTRACT.md
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

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "ingest-guardduty-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"

# OCSF 1.8 Detection Finding (2004)
CLASS_UID = 2004
CLASS_NAME = "Detection Finding"
CATEGORY_UID = 2
CATEGORY_NAME = "Findings"
ACTIVITY_CREATE = 1
TYPE_UID = CLASS_UID * 100 + ACTIVITY_CREATE

STATUS_SUCCESS = 1

# Severity enum (OCSF 1.8)
SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5

MITRE_VERSION = "v14"


# ---------------------------------------------------------------------------
# MITRE mapping tables
# ---------------------------------------------------------------------------

# ThreatPurpose prefix → (tactic_name, tactic_uid)
_THREAT_PURPOSE_TACTIC: dict[str, tuple[str, str]] = {
    "Backdoor": ("Command and Control", "TA0011"),
    "Behavior": ("Defense Evasion", "TA0005"),
    "CredentialAccess": ("Credential Access", "TA0006"),
    "CryptoCurrency": ("Impact", "TA0040"),
    "DefenseEvasion": ("Defense Evasion", "TA0005"),
    "Discovery": ("Discovery", "TA0007"),
    "Execution": ("Execution", "TA0002"),
    "Exfiltration": ("Exfiltration", "TA0010"),
    "Impact": ("Impact", "TA0040"),
    "InitialAccess": ("Initial Access", "TA0001"),
    "Persistence": ("Persistence", "TA0003"),
    "Policy": ("Defense Evasion", "TA0005"),
    "PrivilegeEscalation": ("Privilege Escalation", "TA0004"),
    "Recon": ("Reconnaissance", "TA0043"),
    "ResourceConsumption": ("Impact", "TA0040"),
    "Stealth": ("Defense Evasion", "TA0005"),
    "Trojan": ("Execution", "TA0002"),
    "UnauthorizedAccess": ("Initial Access", "TA0001"),
}

# Full GuardDuty finding Type → (technique_uid, technique_name, sub_uid?, sub_name?)
# Curated high-signal mappings; unknown types fall back to tactic-only.
_TYPE_TECHNIQUE: dict[str, tuple[str, str, str | None, str | None]] = {
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS": (
        "T1552",
        "Unsecured Credentials",
        "T1552.005",
        "Cloud Instance Metadata API",
    ),
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS": (
        "T1552",
        "Unsecured Credentials",
        "T1552.005",
        "Cloud Instance Metadata API",
    ),
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom": (
        "T1078",
        "Valid Accounts",
        "T1078.004",
        "Cloud Accounts",
    ),
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B": (
        "T1078",
        "Valid Accounts",
        "T1078.004",
        "Cloud Accounts",
    ),
    "UnauthorizedAccess:EC2/SSHBruteForce": ("T1110", "Brute Force", None, None),
    "UnauthorizedAccess:EC2/RDPBruteForce": ("T1110", "Brute Force", None, None),
    "Backdoor:EC2/C&CActivity.B": ("T1071", "Application Layer Protocol", None, None),
    "Backdoor:EC2/C&CActivity.B!DNS": ("T1071", "Application Layer Protocol", "T1071.004", "DNS"),
    "Backdoor:EC2/DenialOfService.Tcp": ("T1499", "Endpoint Denial of Service", None, None),
    "Trojan:EC2/DNSDataExfiltration": ("T1048", "Exfiltration Over Alternative Protocol", None, None),
    "Trojan:EC2/DropPoint": ("T1071", "Application Layer Protocol", None, None),
    "CryptoCurrency:EC2/BitcoinTool.B": ("T1496", "Resource Hijacking", None, None),
    "CryptoCurrency:EC2/BitcoinTool.B!DNS": ("T1496", "Resource Hijacking", None, None),
    "Recon:IAMUser/MaliciousIPCaller.Custom": ("T1580", "Cloud Infrastructure Discovery", None, None),
    "Recon:EC2/PortProbeUnprotectedPort": ("T1595", "Active Scanning", None, None),
    "Recon:EC2/Portscan": ("T1046", "Network Service Discovery", None, None),
    "Discovery:S3/MaliciousIPCaller.Custom": ("T1580", "Cloud Infrastructure Discovery", None, None),
    "Discovery:S3/TorIPCaller": ("T1580", "Cloud Infrastructure Discovery", None, None),
    "Exfiltration:S3/ObjectRead.Unusual": ("T1530", "Data from Cloud Storage Object", None, None),
    "Exfiltration:S3/MaliciousIPCaller": ("T1530", "Data from Cloud Storage Object", None, None),
    "Impact:S3/MaliciousIPCaller.Custom": ("T1485", "Data Destruction", None, None),
    "Stealth:IAMUser/CloudTrailLoggingDisabled": (
        "T1562",
        "Impair Defenses",
        "T1562.008",
        "Disable or Modify Cloud Logs",
    ),
    "Stealth:IAMUser/LoggingConfigurationModified": (
        "T1562",
        "Impair Defenses",
        "T1562.008",
        "Disable or Modify Cloud Logs",
    ),
    "Stealth:S3/ServerAccessLoggingDisabled": (
        "T1562",
        "Impair Defenses",
        "T1562.008",
        "Disable or Modify Cloud Logs",
    ),
    "Policy:S3/BucketBlockPublicAccessDisabled": (
        "T1578",
        "Modify Cloud Compute Infrastructure",
        None,
        None,
    ),
    "PrivilegeEscalation:IAMUser/AdministrativePermissions": (
        "T1098",
        "Account Manipulation",
        "T1098.003",
        "Additional Cloud Roles",
    ),
    "Persistence:IAMUser/AnomalousBehavior": ("T1098", "Account Manipulation", None, None),
}


def parse_threat_purpose(finding_type: str) -> str:
    """Return the ThreatPurpose prefix from a GuardDuty finding Type string.

    >>> parse_threat_purpose("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS")
    'UnauthorizedAccess'
    >>> parse_threat_purpose("")
    ''
    """
    if not finding_type or ":" not in finding_type:
        return ""
    return finding_type.split(":", 1)[0]


def map_type_to_attacks(finding_type: str) -> list[dict[str, Any]]:
    """Return an OCSF-compatible attacks[] array for a GuardDuty finding Type.

    Returns a single-element list with:
      - tactic  (always, from ThreatPurpose table)
      - technique (always, from either exact-match table or tactic-only fallback)
      - sub_technique (when the exact-match table provides one)

    If ThreatPurpose is unknown, returns an empty list — the finding is still
    emitted, but without MITRE annotations, so downstream pivots don't break.
    """
    purpose = parse_threat_purpose(finding_type)
    tactic = _THREAT_PURPOSE_TACTIC.get(purpose)
    if not tactic:
        return []

    tactic_name, tactic_uid = tactic
    attack: dict[str, Any] = {
        "version": MITRE_VERSION,
        "tactic": {"name": tactic_name, "uid": tactic_uid},
    }

    exact = _TYPE_TECHNIQUE.get(finding_type)
    if exact:
        tech_uid, tech_name, sub_uid, sub_name = exact
        attack["technique"] = {"name": tech_name, "uid": tech_uid}
        if sub_uid and sub_name:
            attack["sub_technique"] = {"name": sub_name, "uid": sub_uid}
    else:
        # Tactic-only fallback: no technique known for this exact Type.
        # Still emit the tactic so downstream pivots work.
        attack["technique"] = {"name": "Unknown", "uid": ""}

    return [attack]


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


def severity_to_id(severity: float | int | str | None) -> int:
    """Map the GuardDuty 1.0–8.9 severity scale to OCSF severity_id.

    >>> severity_to_id(8.5)
    5
    >>> severity_to_id(6.0)
    4
    >>> severity_to_id(4.5)
    3
    >>> severity_to_id(3.0)
    2
    >>> severity_to_id(1.5)
    1
    >>> severity_to_id(None)
    1
    """
    if severity is None:
        return SEVERITY_INFORMATIONAL
    try:
        v = float(severity)
    except (TypeError, ValueError):
        return SEVERITY_INFORMATIONAL
    if v >= 8.0:
        return SEVERITY_CRITICAL
    if v >= 6.0:
        return SEVERITY_HIGH
    if v >= 4.0:
        return SEVERITY_MEDIUM
    if v >= 2.0:
        return SEVERITY_LOW
    return SEVERITY_INFORMATIONAL


# ---------------------------------------------------------------------------
# Time parsing
# ---------------------------------------------------------------------------


def parse_ts_ms(ts: str | None) -> int:
    """Parse an ISO-8601 timestamp to Unix epoch milliseconds (UTC).

    Falls back to 'now' if missing or unparseable.
    """
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


# ---------------------------------------------------------------------------
# Resource projection
# ---------------------------------------------------------------------------


def _build_resources(resource: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Project a GuardDuty Resource object into an OCSF resources[] array.

    Only the ResourceType tag and the primary identifier (if locatable) are
    kept. Fine-grained fields are out of scope for v0.1.
    """
    if not isinstance(resource, dict):
        return []
    rtype = resource.get("ResourceType", "") or ""
    if not rtype:
        return []

    # Lift the most important identifier for each supported resource type.
    uid = ""
    if rtype == "AccessKey":
        details = resource.get("AccessKeyDetails") or {}
        uid = details.get("AccessKeyId", "") or details.get("UserName", "")
    elif rtype == "Instance":
        details = resource.get("InstanceDetails") or {}
        uid = details.get("InstanceId", "")
    elif rtype == "S3Bucket":
        bucket_list = resource.get("S3BucketDetails") or []
        if bucket_list and isinstance(bucket_list, list):
            uid = (bucket_list[0] or {}).get("Name", "") or (bucket_list[0] or {}).get("Arn", "")
    elif rtype == "EksCluster":
        details = resource.get("EksClusterDetails") or {}
        uid = details.get("Name", "") or details.get("Arn", "")

    out: dict[str, Any] = {"type": rtype}
    if uid:
        out["uid"] = uid
        out["name"] = uid
    return [out]


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------


def _short(s: str) -> str:
    return hashlib.sha256((s or "").encode()).hexdigest()[:8]


def _build_canonical_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert one raw GuardDuty finding into the repo's canonical finding shape."""
    gd_id = raw.get("Id", "") or ""
    finding_type = raw.get("Type", "") or ""
    title = raw.get("Title", "") or finding_type
    desc = raw.get("Description", "") or title
    created = raw.get("CreatedAt")
    updated = raw.get("UpdatedAt") or created
    service = raw.get("Service") or {}
    first_seen = service.get("EventFirstSeen") or created
    last_seen = service.get("EventLastSeen") or updated
    severity_float = raw.get("Severity")

    account_id = raw.get("AccountId", "") or ""
    region = raw.get("Region", "") or ""
    resource = raw.get("Resource") or {}
    resource_type = resource.get("ResourceType", "") or ""

    attacks = map_type_to_attacks(finding_type)

    finding_uid = f"det-gd-{_short(gd_id)}"

    return {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "event_uid": gd_id or finding_uid,
        "finding_uid": finding_uid,
        "provider": "AWS",
        "account_uid": account_id,
        "region": region,
        "time_ms": parse_ts_ms(updated),
        "severity_id": severity_to_id(severity_float),
        "severity": str(severity_float) if severity_float is not None else "",
        "status_id": STATUS_SUCCESS,
        "status": "success",
        "title": title,
        "description": desc,
        "finding_types": [finding_type] if finding_type else [],
        "first_seen_time_ms": parse_ts_ms(first_seen),
        "last_seen_time_ms": parse_ts_ms(last_seen),
        "attacks": attacks,
        "resources": _build_resources(resource),
        "cloud": {
            "provider": "AWS",
            "account": {"uid": account_id},
            "region": region,
        },
        "source": {
            "kind": "aws.guardduty",
            "finding_id": gd_id,
            "finding_arn": raw.get("Arn", "") or "",
            "finding_type": finding_type,
            "resource_type": resource_type,
        },
        "evidence": {
            "events_observed": int(service.get("Count") or 1),
            "first_seen_time": parse_ts_ms(first_seen),
            "last_seen_time": parse_ts_ms(last_seen),
            "raw_events": [
                {
                    "uid": gd_id,
                    "arn": raw.get("Arn", "") or "",
                    "product": "aws-guardduty",
                }
            ],
        },
    }


def _render_ocsf_finding(canonical: dict[str, Any]) -> dict[str, Any]:
    """Render the canonical GuardDuty finding as OCSF Detection Finding."""
    finding: dict[str, Any] = {
        "activity_id": ACTIVITY_CREATE,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": TYPE_UID,
        "severity_id": canonical["severity_id"],
        "status_id": canonical["status_id"],
        "time": canonical["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "aws", "guardduty", "ingest", "passthrough"],
        },
        "finding_info": {
            "uid": canonical["finding_uid"],
            "title": canonical["title"],
            "desc": canonical["description"],
            "types": canonical["finding_types"],
            "first_seen_time": canonical["first_seen_time_ms"],
            "last_seen_time": canonical["last_seen_time_ms"],
            "attacks": canonical["attacks"],
        },
        "resources": canonical["resources"],
        "cloud": {
            "provider": canonical["provider"],
            "account": {"uid": canonical["account_uid"]},
            "region": canonical["region"],
        },
        "evidence": canonical["evidence"],
        "observables": [
            {"name": "gd.finding_id", "type": "Other", "value": canonical["source"]["finding_id"]},
            {"name": "gd.type", "type": "Other", "value": canonical["source"]["finding_type"]},
            {"name": "gd.severity", "type": "Other", "value": canonical["severity"]},
            {"name": "resource.type", "type": "Other", "value": canonical["source"]["resource_type"]},
            {"name": "aws.account", "type": "Other", "value": canonical["account_uid"]},
            {"name": "aws.region", "type": "Other", "value": canonical["region"]},
        ],
    }

    if not canonical["account_uid"]:
        finding["cloud"].pop("account")
    return finding


def _render_native_finding(canonical: dict[str, Any]) -> dict[str, Any]:
    """Render the canonical GuardDuty finding as the repo's native enriched shape."""
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["source_skill"] = SKILL_NAME
    native["output_format"] = "native"
    return native


def convert_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert one raw GuardDuty finding into one OCSF Detection Finding event."""
    return _render_ocsf_finding(_build_canonical_finding(raw))


def convert_finding_native(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert one raw GuardDuty finding into the native enriched finding shape."""
    return _render_native_finding(_build_canonical_finding(raw))


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def iter_raw_findings(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    """Yield raw GuardDuty finding dicts from a JSONL / Findings-wrapped / EventBridge stream.

    Auto-detects the format:
      - whole-document parse first: handles `{"Findings": [...]}` (API wrapper),
        `{"detail": {...}, "detail-type": "GuardDuty Finding"}` (EventBridge),
        a single finding dict, or a top-level array.
      - falls back to line-by-line NDJSON if the whole-document parse fails.
      - blank lines and parse failures are skipped (warning to stderr).
    """
    buf: list[str] = list(stream)
    if not buf:
        return

    full = "\n".join(line.rstrip("\n") for line in buf).strip()
    if not full:
        return

    try:
        whole = json.loads(full)
    except json.JSONDecodeError:
        whole = None

    def _unwrap(obj: Any) -> Iterable[dict[str, Any]]:
        if isinstance(obj, dict):
            if "Findings" in obj and isinstance(obj["Findings"], list):
                for f in obj["Findings"]:
                    if isinstance(f, dict):
                        yield f
                return
            # EventBridge envelope: {"detail-type": "GuardDuty Finding", "detail": {...}}
            if obj.get("detail-type") == "GuardDuty Finding" and isinstance(obj.get("detail"), dict):
                yield obj["detail"]
                return
            yield obj
            return
        if isinstance(obj, list):
            for f in obj:
                if isinstance(f, dict):
                    yield from _unwrap(f)

    if whole is not None:
        yield from _unwrap(whole)
        return

    # Fall back to line-by-line NDJSON.
    for lineno, raw_line in enumerate(buf, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {e}", file=sys.stderr)
            continue
        yield from _unwrap(obj)


def ingest(stream: Iterable[str], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    for raw in iter_raw_findings(stream):
        try:
            canonical = _build_canonical_finding(raw)
            if output_format == "native":
                yield _render_native_finding(canonical)
            else:
                yield _render_ocsf_finding(canonical)
        except Exception as e:  # defence-in-depth — never crash the pipeline
            print(f"[{SKILL_NAME}] skipping finding: convert error: {e}", file=sys.stderr)
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert raw GuardDuty findings to OCSF 1.8 Detection Finding JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument("--output-format", choices=("ocsf", "native"), default="ocsf", help="Output shape. Defaults to ocsf.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        for finding in ingest(in_stream, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
