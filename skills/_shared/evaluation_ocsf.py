"""Shared helpers for evaluation skills that emit OCSF Compliance Findings."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from typing import Any

REPO_NAME = "cloud-ai-security-skills"
REPO_VENDOR = "msaad00/cloud-ai-security-skills"
OCSF_VERSION = "1.8.0"

FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_CLASS_UID = 2003
FINDING_CLASS_NAME = "Compliance Finding"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

STATUS_SUCCESS = 1
STATUS_FAILURE = 2

_SEVERITY_TO_ID = {
    "INFORMATIONAL": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def findings_to_native(findings: list[Any]) -> list[dict[str, Any]]:
    """Render evaluation findings into plain dicts."""
    rendered: list[dict[str, Any]] = []
    for finding in findings:
        if is_dataclass(finding) and not isinstance(finding, type):
            rendered.append(asdict(finding))
        elif isinstance(finding, dict):
            rendered.append(dict(finding))
        else:
            raise TypeError(f"Unsupported finding type: {type(finding)!r}")
    return rendered


def findings_to_ocsf(
    findings: list[Any],
    *,
    skill_name: str,
    benchmark_name: str,
    provider: str,
    frameworks: list[str],
) -> list[dict[str, Any]]:
    """Convert native evaluation findings into OCSF Compliance Findings."""
    native_findings = findings_to_native(findings)
    return [
        render_compliance_finding(
            native_finding,
            skill_name=skill_name,
            benchmark_name=benchmark_name,
            provider=provider,
            frameworks=frameworks,
        )
        for native_finding in native_findings
    ]


def render_compliance_finding(
    native_finding: dict[str, Any],
    *,
    skill_name: str,
    benchmark_name: str,
    provider: str,
    frameworks: list[str],
) -> dict[str, Any]:
    """Project a repo-native evaluation result into OCSF class 2003."""
    uid = _finding_uid(native_finding, skill_name=skill_name, provider=provider)
    resources = _resource_names(native_finding)
    now_ms = _now_ms()
    severity_name = str(native_finding.get("severity") or "LOW").upper()
    status_name = str(native_finding.get("status") or "UNKNOWN").upper()
    title = str(native_finding.get("title") or benchmark_name)
    detail = str(native_finding.get("detail") or "")
    section = str(native_finding.get("section") or "")
    rule_id = str(
        native_finding.get("control_id")
        or native_finding.get("check_id")
        or native_finding.get("rule_id")
        or title
    )

    remediation = str(native_finding.get("remediation") or "")
    desc_parts = [detail] if detail else []
    if remediation:
        desc_parts.append(f"Remediation: {remediation}")

    observables = [
        {"name": "resource", "type": "Other", "value": resource} for resource in resources
    ]

    evidence = {
        "frameworks": frameworks,
        "benchmark": benchmark_name,
        "provider": provider,
        "section": section,
        "native_finding": native_finding,
    }

    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "activity_name": "Create",
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": _severity_id(severity_name),
        "status_id": _status_id(status_name),
        "time": now_ms,
        "metadata": {
            "version": OCSF_VERSION,
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": skill_name},
            },
            "labels": ["evaluation", "compliance", provider.lower(), skill_name],
        },
        "finding_info": {
            "uid": uid,
            "title": title,
            "desc": " ".join(desc_parts).strip(),
            "types": [rule_id],
            "first_seen_time": now_ms,
            "last_seen_time": now_ms,
        },
        "compliance": {
            "status": status_name,
            "control": rule_id,
            "frameworks": frameworks,
            "requirements": [entry for entry in _framework_requirements(native_finding) if entry],
        },
        "cloud": {"provider": provider},
        "resources": [{"name": resource, "type": "Other"} for resource in resources],
        "observables": observables,
        "evidence": evidence,
    }


def _framework_requirements(native_finding: dict[str, Any]) -> list[str]:
    keys = (
        "cis_docker",
        "cis_control",
        "cis_k8s",
        "nist_csf",
        "nist_ai_rmf",
        "iso_27001",
        "mitre_attack",
        "mitre_atlas",
    )
    return [str(native_finding.get(key) or "") for key in keys]


def _resource_names(native_finding: dict[str, Any]) -> list[str]:
    resources = native_finding.get("resources") or []
    names: list[str] = []
    for resource in resources:
        if isinstance(resource, str) and resource:
            names.append(resource)
    return names


def _finding_uid(native_finding: dict[str, Any], *, skill_name: str, provider: str) -> str:
    identifier = str(
        native_finding.get("control_id")
        or native_finding.get("check_id")
        or native_finding.get("title")
        or "finding"
    )
    resources = "|".join(sorted(_resource_names(native_finding)))
    material = "|".join(
        [
            skill_name,
            provider.lower(),
            identifier,
            str(native_finding.get("status") or ""),
            str(native_finding.get("severity") or ""),
            resources,
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"eval-{skill_name}-{digest}"


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _severity_id(severity_name: str) -> int:
    return _SEVERITY_TO_ID.get(severity_name.upper(), 2)


def _status_id(status_name: str) -> int:
    return STATUS_SUCCESS if status_name == "PASS" else STATUS_FAILURE
