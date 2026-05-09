"""Convert OCSF 1.8 Detection Findings (class 2004) to SARIF 2.1.0.

Reads OCSF Detection Finding JSONL on stdin (one finding per line) and writes
a single SARIF 2.1.0 document on stdout. Designed to be the last step in a
detection-engineering pipeline so findings land in GitHub code scanning's
Security tab via `github/codeql-action/upload-sarif@v3`.

Contract: see ../OCSF_CONTRACT.md for the input shape; SARIF spec at
https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import INFORMATION_URI  # noqa: E402

SKILL_NAME = "convert-ocsf-to-sarif"
SKILL_VERSION = "0.1.0"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"

# OCSF Detection Finding (2004) class_uid we recognise
DETECTION_FINDING_CLASS_UID = 2004


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

# OCSF severity_id → SARIF level
# https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317648
_SEVERITY_TO_LEVEL = {
    0: "none",  # Unknown
    1: "note",  # Informational
    2: "note",  # Low
    3: "warning",  # Medium
    4: "error",  # High
    5: "error",  # Critical
    6: "error",  # Fatal
}


def severity_to_sarif_level(severity_id: int) -> str:
    """Map an OCSF severity_id (0-6) to a SARIF level string."""
    return _SEVERITY_TO_LEVEL.get(severity_id, "none")


# ---------------------------------------------------------------------------
# MITRE ATT&CK helpers
# ---------------------------------------------------------------------------


def _first_attack(finding_info: dict[str, Any]) -> dict[str, Any]:
    attacks = finding_info.get("attacks") or []
    return attacks[0] if attacks else {}


def _technique_uid(attack: dict[str, Any]) -> str:
    return ((attack.get("technique") or {}).get("uid")) or "no-mitre"


def _technique_name(attack: dict[str, Any]) -> str:
    return ((attack.get("technique") or {}).get("name")) or "Unknown technique"


def _tactic_uid(attack: dict[str, Any]) -> str:
    return ((attack.get("tactic") or {}).get("uid")) or ""


def _tactic_name(attack: dict[str, Any]) -> str:
    return ((attack.get("tactic") or {}).get("name")) or ""


def _mitre_tags(attack: dict[str, Any]) -> list[str]:
    """Build the MITRE tag list for SARIF result.tags / rule.tags."""
    tags: list[str] = []
    tactic_uid = _tactic_uid(attack)
    if tactic_uid:
        # Slug-style tactic name for grep-friendliness
        tactic_slug = _tactic_name(attack).lower().replace(" ", "-")
        tags.append(f"mitre/attack/{tactic_slug}/{tactic_uid}")
    technique_uid = _technique_uid(attack)
    if technique_uid and technique_uid != "no-mitre":
        tags.append(f"mitre/attack/technique/{technique_uid}")
    sub = (attack.get("sub_technique") or {}).get("uid")
    if sub:
        tags.append(f"mitre/attack/sub-technique/{sub}")
    return tags


# ---------------------------------------------------------------------------
# Rule and result builders
# ---------------------------------------------------------------------------


def _rule_for_attack(attack: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF rule object for one MITRE technique."""
    technique_uid = _technique_uid(attack)
    technique_name = _technique_name(attack)
    tactic_uid = _tactic_uid(attack)
    tactic_name = _tactic_name(attack)

    rule: dict[str, Any] = {
        "id": technique_uid,
        "name": technique_name,
        "shortDescription": {"text": technique_name},
    }

    desc_parts = []
    if tactic_uid and tactic_name:
        desc_parts.append(f"MITRE ATT&CK tactic: {tactic_name} ({tactic_uid})")
    if technique_uid != "no-mitre":
        desc_parts.append(f"Technique: {technique_name} ({technique_uid})")
        desc_parts.append(f"Reference: https://attack.mitre.org/techniques/{technique_uid.replace('.', '/')}/")
    if desc_parts:
        rule["fullDescription"] = {"text": " · ".join(desc_parts)}

    rule["properties"] = {
        "tags": _mitre_tags(attack),
        "precision": "high",
    }
    return rule


def _build_message(finding: dict[str, Any]) -> str:
    finding_info = finding.get("finding_info") or {}
    title = finding_info.get("title") or "Detection finding"
    desc = finding_info.get("desc") or ""
    if desc:
        return f"{title}\n\n{desc}"
    return title


def _build_locations(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """SARIF 2.1.0 requires locations[] to make a result clickable in code
    scanning. Detection findings don't always have a file:line — they live in
    cloud / runtime telemetry. We synthesise a logical location keyed by
    metadata.product.feature.name + finding uid so the SARIF UI groups
    related findings sensibly.
    """
    finding_info = finding.get("finding_info") or {}
    feature = ((finding.get("metadata") or {}).get("product") or {}).get("feature") or {}
    detector = feature.get("name") or "unknown-detector"
    uid = finding_info.get("uid") or "no-uid"
    return [
        {
            "logicalLocations": [
                {
                    "name": detector,
                    "fullyQualifiedName": f"{detector}/{uid}",
                    "kind": "module",
                }
            ]
        }
    ]


def _build_result(finding: dict[str, Any]) -> dict[str, Any]:
    finding_info = finding.get("finding_info") or {}
    attack = _first_attack(finding_info)
    severity_id = int(finding.get("severity_id", 0))

    result: dict[str, Any] = {
        "ruleId": _technique_uid(attack),
        "level": severity_to_sarif_level(severity_id),
        "message": {"text": _build_message(finding)},
        "locations": _build_locations(finding),
    }

    uid = finding_info.get("uid")
    if uid:
        result["guid"] = uid
        # SARIF partialFingerprints make code-scanning dedupe stable across runs
        result["partialFingerprints"] = {"primaryLocationLineHash": uid}

    properties: dict[str, Any] = {
        "detector": ((finding.get("metadata") or {}).get("product") or {}).get("feature", {}).get("name", ""),
        "detected_at_ms": finding.get("time"),
        "ocsf_class_uid": finding.get("class_uid"),
        "ocsf_severity_id": severity_id,
        "tags": _mitre_tags(attack),
    }

    observables = finding.get("observables")
    if observables:
        properties["observables"] = observables

    evidence = finding.get("evidence")
    if evidence:
        properties["evidence"] = evidence

    finding_types = finding_info.get("types")
    if finding_types:
        properties["finding_types"] = finding_types

    result["properties"] = properties
    return result


# ---------------------------------------------------------------------------
# Tool / driver builders
# ---------------------------------------------------------------------------


def _build_driver(detectors: set[str], rules: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Build the SARIF tool.driver object.

    name: cloud-ai-security-skills-detection-engineering (the product family — all
    detect-* skills emit findings that flow through this converter, so the
    Security tab groups them under one tool name)
    rules: deduplicated by MITRE technique uid
    """
    return {
        "name": "cloud-ai-security-skills-detection-engineering",
        "version": SKILL_VERSION,
        "informationUri": INFORMATION_URI,
        "rules": list(rules.values()),
        "properties": {
            "detectors": sorted(detectors),
        },
    }


# ---------------------------------------------------------------------------
# Top-level convert
# ---------------------------------------------------------------------------


def convert(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Convert an iterable of OCSF Detection Findings to a single SARIF document."""
    materialised = list(findings)

    # Filter to Detection Findings (2004) — emit a warning for anything else.
    detection_findings: list[dict[str, Any]] = []
    for f in materialised:
        cls = f.get("class_uid")
        if cls == DETECTION_FINDING_CLASS_UID:
            detection_findings.append(f)
        else:
            print(
                f"[{SKILL_NAME}] skipping event with class_uid={cls} — convert-ocsf-to-sarif only handles Detection Finding (2004)",
                file=sys.stderr,
            )

    # Build deduplicated rules keyed by technique uid
    rules: dict[str, dict[str, Any]] = {}
    detectors: set[str] = set()
    for f in detection_findings:
        attack = _first_attack(f.get("finding_info") or {})
        rule_id = _technique_uid(attack)
        if rule_id not in rules:
            rules[rule_id] = _rule_for_attack(attack)
        detector = ((f.get("metadata") or {}).get("product") or {}).get("feature", {}).get("name")
        if detector:
            detectors.add(detector)

    results = [_build_result(f) for f in detection_findings]

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": _build_driver(detectors, rules)},
                "results": results,
            }
        ],
    }
    return sarif_doc


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
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {e}", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert OCSF Detection Findings to SARIF 2.1.0.")
    parser.add_argument("input", nargs="?", help="OCSF JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="SARIF output file. Defaults to stdout.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        sarif = convert(load_jsonl(in_stream))
        json.dump(sarif, out_stream, indent=2, sort_keys=False)
        out_stream.write("\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
