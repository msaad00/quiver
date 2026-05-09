"""Convert raw AWS Security Hub ASFF findings to OCSF 1.8 Detection Finding (2004).

Input:  ASFF finding JSON — single findings, `{"Findings": [...]}` BatchImport
        wrapper, or EventBridge envelopes with
        `{"detail-type": "Security Hub Findings - Imported", "detail": {"findings": [...]}}`.
        Auto-detected.
Output: JSONL of OCSF 1.8 Detection Finding events by default, or the repo's
        native enriched finding shape when --output-format native is selected.

Security Hub is an aggregator that collects ASFF-formatted findings from
GuardDuty, Inspector, Macie, Config, Firewall Manager, and third-party
products. This skill validates the ASFF required fields and transforms them
into the OCSF wire contract shared by every other skill in this category.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "ingest-security-hub-ocsf"
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

# Severity enum
SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5

MITRE_VERSION = "v14"

# ASFF required fields per AWS Security Hub user guide
# https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
ASFF_REQUIRED_FIELDS: tuple[str, ...] = (
    "SchemaVersion",
    "Id",
    "ProductArn",
    "GeneratorId",
    "AwsAccountId",
    "Types",
    "CreatedAt",
    "UpdatedAt",
    "Severity",
    "Title",
    "Description",
    "Resources",
)

# MITRE tactic name → uid (for Types[] taxonomy walk)
_TACTIC_NAME_TO_UID: dict[str, str] = {
    "Reconnaissance": "TA0043",
    "Resource Development": "TA0042",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}

# Regex for MITRE technique IDs embedded in ProductFields values
_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


# ---------------------------------------------------------------------------
# ASFF validation
# ---------------------------------------------------------------------------


def validate_asff(finding: dict[str, Any]) -> tuple[bool, str]:
    """Return (is_valid, reason). Empty reason on valid."""
    if not isinstance(finding, dict):
        return False, "not a dict"
    for field in ASFF_REQUIRED_FIELDS:
        if field not in finding:
            return False, f"missing required field: {field}"
        val = finding[field]
        if val is None or val == "" or val == [] or val == {}:
            return False, f"empty required field: {field}"
    # Severity must be a dict with Label or Normalized
    sev = finding.get("Severity")
    if not isinstance(sev, dict):
        return False, "Severity must be a dict"
    if "Label" not in sev and "Normalized" not in sev:
        return False, "Severity must carry Label or Normalized"
    # Types and Resources must be non-empty lists
    if not isinstance(finding.get("Types"), list) or not finding["Types"]:
        return False, "Types must be a non-empty list"
    if not isinstance(finding.get("Resources"), list) or not finding["Resources"]:
        return False, "Resources must be a non-empty list"
    return True, ""


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


def severity_to_id(severity: dict[str, Any] | None) -> int:
    """Map ASFF Severity (Label or Normalized) to OCSF severity_id.

    Label wins over Normalized (more stable). Normalized is the 0-100
    fallback.

    >>> severity_to_id({"Label": "CRITICAL"})
    5
    >>> severity_to_id({"Label": "HIGH"})
    4
    >>> severity_to_id({"Normalized": 85})
    4
    >>> severity_to_id({"Normalized": 0})
    1
    >>> severity_to_id(None)
    1
    """
    if not isinstance(severity, dict):
        return SEVERITY_INFORMATIONAL

    label = (severity.get("Label") or "").upper()
    label_map = {
        "CRITICAL": SEVERITY_CRITICAL,
        "HIGH": SEVERITY_HIGH,
        "MEDIUM": SEVERITY_MEDIUM,
        "LOW": SEVERITY_LOW,
        "INFORMATIONAL": SEVERITY_INFORMATIONAL,
    }
    if label in label_map:
        return label_map[label]

    # Fall back to Normalized 0-100 scale
    normalized = severity.get("Normalized")
    if normalized is None:
        return SEVERITY_INFORMATIONAL
    try:
        n = float(normalized)
    except (TypeError, ValueError):
        return SEVERITY_INFORMATIONAL
    if n >= 90:
        return SEVERITY_CRITICAL
    if n >= 70:
        return SEVERITY_HIGH
    if n >= 40:
        return SEVERITY_MEDIUM
    if n >= 1:
        return SEVERITY_LOW
    return SEVERITY_INFORMATIONAL


# ---------------------------------------------------------------------------
# MITRE extraction
# ---------------------------------------------------------------------------


def extract_attacks(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract MITRE ATT&CK annotations from ASFF Types[] and ProductFields.

    Returns an `attacks[]` list (may be empty) suitable for
    `finding_info.attacks`.
    """
    attacks: list[dict[str, Any]] = []
    seen_tactic_uids: set[str] = set()
    seen_technique_uids: set[str] = set()

    # 1. Walk Types[] taxonomy for TTPs/<Tactic Name>/<Classifier>
    for type_str in finding.get("Types") or []:
        if not isinstance(type_str, str):
            continue
        parts = [p.strip() for p in type_str.split("/")]
        if len(parts) < 2:
            continue
        if parts[0] != "TTPs":
            continue
        tactic_name = parts[1]
        tactic_uid = _TACTIC_NAME_TO_UID.get(tactic_name)
        if not tactic_uid or tactic_uid in seen_tactic_uids:
            continue
        seen_tactic_uids.add(tactic_uid)
        attacks.append(
            {
                "version": MITRE_VERSION,
                "tactic": {"name": tactic_name, "uid": tactic_uid},
                "technique": {"name": "Unknown", "uid": ""},
            }
        )

    # 2. Walk ProductFields for mitre-technique annotations
    product_fields = finding.get("ProductFields") or {}
    if isinstance(product_fields, dict):
        for key, val in product_fields.items():
            if not isinstance(key, str) or not isinstance(val, str):
                continue
            if "mitre-technique" not in key.lower():
                continue
            match = _TECHNIQUE_RE.search(val)
            if not match:
                continue
            tech_uid = match.group(1)
            if tech_uid in seen_technique_uids:
                continue
            seen_technique_uids.add(tech_uid)
            # Promote into the first attack (if any), else create a new entry
            if attacks:
                attacks[0]["technique"] = {"name": "Annotated", "uid": tech_uid}
            else:
                attacks.append(
                    {
                        "version": MITRE_VERSION,
                        "tactic": {"name": "Unknown", "uid": ""},
                        "technique": {"name": "Annotated", "uid": tech_uid},
                    }
                )

    return attacks


# ---------------------------------------------------------------------------
# Time parsing
# ---------------------------------------------------------------------------


def parse_ts_ms(ts: str | None) -> int:
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


def _build_resources(resources: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Project ASFF Resources[] into an OCSF resources[] array."""
    if not isinstance(resources, list):
        return []
    out: list[dict[str, Any]] = []
    for r in resources:
        if not isinstance(r, dict):
            continue
        entry: dict[str, Any] = {}
        if "Type" in r:
            entry["type"] = r["Type"]
        if "Id" in r:
            entry["uid"] = r["Id"]
            entry["name"] = r["Id"]
        if "Region" in r:
            entry["region"] = r["Region"]
        if entry:
            out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------


def _short(s: str) -> str:
    return hashlib.sha256((s or "").encode()).hexdigest()[:8]


def _build_canonical_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert one ASFF finding into the repo's canonical finding shape."""
    asff_id = raw["Id"]
    title = raw["Title"]
    desc = raw["Description"]
    types = list(raw["Types"])
    created = raw["CreatedAt"]
    updated = raw["UpdatedAt"]
    first_seen = raw.get("FirstObservedAt") or created
    last_seen = raw.get("LastObservedAt") or updated
    account_id = raw["AwsAccountId"]
    severity = raw["Severity"]

    label = (severity.get("Label") or "").upper() if isinstance(severity, dict) else ""
    normalized = severity.get("Normalized") if isinstance(severity, dict) else None

    attacks = extract_attacks(raw)
    resources_out = _build_resources(raw.get("Resources"))
    region = ""
    if resources_out and "region" in resources_out[0]:
        region = resources_out[0]["region"]

    finding_uid = f"det-shub-{_short(asff_id)}"

    # Compliance passthrough
    compliance = raw.get("Compliance") or {}
    compliance_status = compliance.get("Status", "") if isinstance(compliance, dict) else ""
    compliance_control = compliance.get("SecurityControlId", "") if isinstance(compliance, dict) else ""
    compliance_reasons_list = compliance.get("StatusReasons", []) if isinstance(compliance, dict) else []
    compliance_reasons = ";".join(str((r or {}).get("ReasonCode", "")) for r in compliance_reasons_list if isinstance(r, dict))

    return {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "event_uid": asff_id,
        "finding_uid": finding_uid,
        "provider": "AWS",
        "account_uid": account_id,
        "region": region,
        "time_ms": parse_ts_ms(updated),
        "severity_id": severity_to_id(severity),
        "status_id": STATUS_SUCCESS,
        "status": "success",
        "severity_label": label,
        "severity_normalized": normalized,
        "title": title,
        "description": desc,
        "finding_types": types,
        "first_seen_time_ms": parse_ts_ms(first_seen),
        "last_seen_time_ms": parse_ts_ms(last_seen),
        "attacks": attacks,
        "resources": resources_out,
        "cloud": {
            "provider": "AWS",
            "account": {"uid": account_id},
            "region": region,
        },
        "source": {
            "kind": "aws.security-hub",
            "finding_id": asff_id,
            "product_arn": raw.get("ProductArn", ""),
            "generator_id": raw.get("GeneratorId", ""),
        },
        "compliance": {
            "status": compliance_status,
            "control_id": compliance_control,
            "reason_codes": compliance_reasons,
        },
        "evidence": {
            "events_observed": 1,
            "first_seen_time": parse_ts_ms(first_seen),
            "last_seen_time": parse_ts_ms(last_seen),
            "raw_events": [
                {
                    "uid": asff_id,
                    "product_arn": raw.get("ProductArn", ""),
                    "product": "aws-security-hub",
                }
            ],
        },
    }


def _build_observables(canonical: dict[str, Any]) -> list[dict[str, Any]]:
    observables: list[dict[str, Any]] = [
        {"name": "shub.finding_id", "type": "Other", "value": canonical["source"]["finding_id"]},
        {"name": "shub.product_arn", "type": "Other", "value": canonical["source"]["product_arn"]},
        {"name": "shub.generator_id", "type": "Other", "value": canonical["source"]["generator_id"]},
        {"name": "shub.severity_label", "type": "Other", "value": canonical["severity_label"]},
        {
            "name": "shub.severity_normalized",
            "type": "Other",
            "value": str(canonical["severity_normalized"]) if canonical["severity_normalized"] is not None else "",
        },
        {"name": "shub.types", "type": "Other", "value": ",".join(canonical["finding_types"])},
        {"name": "aws.account", "type": "Other", "value": canonical["account_uid"]},
        {"name": "aws.region", "type": "Other", "value": canonical["region"]},
    ]
    compliance = canonical["compliance"]
    if compliance["status"]:
        observables.append({"name": "shub.compliance_status", "type": "Other", "value": compliance["status"]})
    if compliance["control_id"]:
        observables.append({"name": "shub.compliance_control", "type": "Other", "value": compliance["control_id"]})
    if compliance["reason_codes"]:
        observables.append({"name": "shub.compliance_reasons", "type": "Other", "value": compliance["reason_codes"]})
    return observables


def _render_ocsf_finding(canonical: dict[str, Any]) -> dict[str, Any]:
    """Render the canonical Security Hub finding as OCSF Detection Finding."""
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
            "labels": ["detection-engineering", "aws", "security-hub", "asff", "ingest", "passthrough"],
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
        "observables": _build_observables(canonical),
        "evidence": canonical["evidence"],
    }
    return finding


def _render_native_finding(canonical: dict[str, Any]) -> dict[str, Any]:
    """Render the canonical Security Hub finding as the repo's native enriched shape."""
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["source_skill"] = SKILL_NAME
    native["output_format"] = "native"
    return native


def convert_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert one ASFF finding into one OCSF Detection Finding event."""
    return _render_ocsf_finding(_build_canonical_finding(raw))


def convert_finding_native(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert one ASFF finding into the native enriched finding shape."""
    return _render_native_finding(_build_canonical_finding(raw))


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def iter_raw_findings(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    """Yield raw ASFF finding dicts from JSONL / Findings-wrapper / EventBridge."""
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
            # EventBridge envelope: {"detail-type": "Security Hub Findings - Imported",
            #                       "detail": {"findings": [...]}}
            if obj.get("detail-type") in (
                "Security Hub Findings - Imported",
                "Security Hub Findings - Custom Action",
            ):
                detail = obj.get("detail") or {}
                inner = detail.get("findings") if isinstance(detail, dict) else None
                if isinstance(inner, list):
                    for f in inner:
                        if isinstance(f, dict):
                            yield f
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
        valid, reason = validate_asff(raw)
        if not valid:
            print(
                f"[{SKILL_NAME}] skipping finding {raw.get('Id', '?')}: asff invalid: {reason}",
                file=sys.stderr,
            )
            continue
        try:
            canonical = _build_canonical_finding(raw)
            if output_format == "native":
                yield _render_native_finding(canonical)
            else:
                yield _render_ocsf_finding(canonical)
        except Exception as e:
            print(f"[{SKILL_NAME}] skipping finding: convert error: {e}", file=sys.stderr)
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert AWS Security Hub ASFF findings to OCSF 1.8 Detection Finding JSONL.")
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
