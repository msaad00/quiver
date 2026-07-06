"""Tests for convert-ocsf-to-sarif."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from convert import (  # type: ignore[import-not-found]
    SARIF_SCHEMA,
    SARIF_VERSION,
    convert,
    load_jsonl,
    severity_to_sarif_level,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT_FIXTURE = GOLDEN / "k8s_priv_esc_findings.ocsf.jsonl"
EXPECTED = GOLDEN / "k8s_priv_esc_findings.sarif"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _detection_finding(
    *,
    uid: str = "det-test-1",
    technique_uid: str = "T1611",
    technique_name: str = "Escape to Host",
    tactic_uid: str = "TA0004",
    tactic_name: str = "Privilege Escalation",
    sub_uid: str | None = None,
    severity_id: int = 4,
    title: str = "Test finding",
    desc: str = "Test description",
    detector: str = "detect-test",
) -> dict:
    attack: dict = {
        "version": "v14",
        "tactic": {"name": tactic_name, "uid": tactic_uid},
        "technique": {"name": technique_name, "uid": technique_uid},
    }
    if sub_uid:
        attack["sub_technique"] = {"name": "Sub", "uid": sub_uid}
    return {
        "class_uid": 2004,
        "category_uid": 2,
        "type_uid": 200401,
        "severity_id": severity_id,
        "status_id": 1,
        "time": 1775797200000,
        "metadata": {
            "version": "1.8.0",
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": "msaad00/quiver",
                "feature": {"name": detector},
            },
        },
        "finding_info": {
            "uid": uid,
            "title": title,
            "desc": desc,
            "attacks": [attack],
        },
        "observables": [{"name": "actor.name", "type": "Other", "value": "test-actor"}],
        "evidence": {"events_observed": 1},
    }


# ── Severity mapping ─────────────────────────────────────────────────


class TestSeverityMapping:
    def test_unknown(self):
        assert severity_to_sarif_level(0) == "none"

    def test_informational(self):
        assert severity_to_sarif_level(1) == "note"

    def test_low(self):
        assert severity_to_sarif_level(2) == "note"

    def test_medium(self):
        assert severity_to_sarif_level(3) == "warning"

    def test_high(self):
        assert severity_to_sarif_level(4) == "error"

    def test_critical(self):
        assert severity_to_sarif_level(5) == "error"

    def test_fatal(self):
        assert severity_to_sarif_level(6) == "error"

    def test_unmapped_falls_to_none(self):
        assert severity_to_sarif_level(99) == "none"


# ── Document shape ───────────────────────────────────────────────────


class TestDocShape:
    def test_empty_input(self):
        doc = convert([])
        assert doc["$schema"] == SARIF_SCHEMA
        assert doc["version"] == SARIF_VERSION
        assert len(doc["runs"]) == 1
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []

    def test_single_finding(self):
        doc = convert([_detection_finding()])
        assert len(doc["runs"][0]["results"]) == 1
        result = doc["runs"][0]["results"][0]
        assert result["ruleId"] == "T1611"
        assert result["level"] == "error"
        assert "Test finding" in result["message"]["text"]
        assert "Test description" in result["message"]["text"]

    def test_tool_name_pinned(self):
        doc = convert([_detection_finding()])
        assert (
            doc["runs"][0]["tool"]["driver"]["name"]
            == "cloud-ai-security-skills-detection-engineering"
        )

    def test_skips_non_detection_finding(self, capsys):
        doc = convert(
            [
                _detection_finding(),
                {
                    "class_uid": 6003,
                    "metadata": {},
                    "finding_info": {},
                },  # API Activity, not a finding
            ]
        )
        assert len(doc["runs"][0]["results"]) == 1
        assert "skipping event with class_uid=6003" in capsys.readouterr().err


# ── Rule deduplication ───────────────────────────────────────────────


class TestRuleDedup:
    def test_two_findings_same_technique_one_rule(self):
        doc = convert(
            [
                _detection_finding(uid="a", technique_uid="T1611"),
                _detection_finding(uid="b", technique_uid="T1611"),
            ]
        )
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "T1611"
        # But two results
        assert len(doc["runs"][0]["results"]) == 2

    def test_three_findings_three_techniques_three_rules(self):
        doc = convert(
            [
                _detection_finding(uid="a", technique_uid="T1611"),
                _detection_finding(uid="b", technique_uid="T1098"),
                _detection_finding(uid="c", technique_uid="T1552"),
            ]
        )
        rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        assert rule_ids == {"T1611", "T1098", "T1552"}


# ── MITRE tags ───────────────────────────────────────────────────────


class TestMitreTags:
    def test_tags_include_technique_and_tactic(self):
        doc = convert(
            [
                _detection_finding(
                    technique_uid="T1611", tactic_uid="TA0004", tactic_name="Privilege Escalation"
                )
            ]
        )
        result = doc["runs"][0]["results"][0]
        tags = result["properties"]["tags"]
        assert "mitre/attack/technique/T1611" in tags
        assert "mitre/attack/privilege-escalation/TA0004" in tags

    def test_sub_technique_in_tags_when_present(self):
        doc = convert([_detection_finding(sub_uid="T1552.007")])
        tags = doc["runs"][0]["results"][0]["properties"]["tags"]
        assert "mitre/attack/sub-technique/T1552.007" in tags


# ── Properties carry observables + evidence ──────────────────────────


class TestProperties:
    def test_observables_passthrough(self):
        f = _detection_finding()
        f["observables"] = [
            {"name": "actor.name", "type": "Other", "value": "alice"},
            {"name": "tool.name", "type": "Other", "value": "query_db"},
        ]
        doc = convert([f])
        obs = doc["runs"][0]["results"][0]["properties"]["observables"]
        assert len(obs) == 2
        assert obs[0]["value"] == "alice"

    def test_evidence_passthrough(self):
        f = _detection_finding()
        f["evidence"] = {"events_observed": 5, "before_event_time": 1000, "after_event_time": 2000}
        doc = convert([f])
        ev = doc["runs"][0]["results"][0]["properties"]["evidence"]
        assert ev["events_observed"] == 5

    def test_detector_metadata(self):
        f = _detection_finding(detector="detect-mcp-tool-drift")
        doc = convert([f])
        assert doc["runs"][0]["results"][0]["properties"]["detector"] == "detect-mcp-tool-drift"


# ── Locations ───────────────────────────────────────────────────────


class TestLocations:
    def test_logical_location_present(self):
        doc = convert([_detection_finding(uid="abc", detector="detect-test")])
        loc = doc["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]
        assert loc["name"] == "detect-test"
        assert "abc" in loc["fullyQualifiedName"]
        assert loc["kind"] == "module"


# ── Fingerprints (dedup across runs) ─────────────────────────────────


class TestFingerprints:
    def test_partial_fingerprint_present_when_uid(self):
        doc = convert([_detection_finding(uid="det-abc")])
        result = doc["runs"][0]["results"][0]
        assert "partialFingerprints" in result
        assert "primaryLocationLineHash" in result["partialFingerprints"]

    def test_guid_matches_uid(self):
        doc = convert([_detection_finding(uid="det-abc-123")])
        assert doc["runs"][0]["results"][0]["guid"] == "det-abc-123"


# ── load_jsonl robustness ────────────────────────────────────────────


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 2004}']))
        assert out == [{"class_uid": 2004}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_skips_non_object(self, capsys):
        out = list(load_jsonl(["[1,2,3]", '{"class_uid": 2004}']))
        assert out == [{"class_uid": 2004}]


# ── Golden fixture parity ────────────────────────────────────────────


class TestGoldenFixture:
    def test_k8s_priv_esc_to_sarif_matches_frozen(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        produced = convert(findings)
        expected = json.loads(EXPECTED.read_text())
        assert produced == expected, (
            "SARIF golden drift — re-generate via:\n  python src/convert.py ../golden/k8s_priv_esc_findings.ocsf.jsonl > ../golden/k8s_priv_esc_findings.sarif"
        )

    def test_three_findings_three_rules(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        doc = convert(findings)
        assert len(doc["runs"][0]["results"]) == 3
        rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        assert rule_ids == {"T1552", "T1611", "T1098"}

    def test_all_results_are_error_level(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        doc = convert(findings)
        for r in doc["runs"][0]["results"]:
            assert r["level"] == "error"

    def test_sarif_validates_schema_url(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        doc = convert(findings)
        assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
        assert doc["version"] == "2.1.0"
