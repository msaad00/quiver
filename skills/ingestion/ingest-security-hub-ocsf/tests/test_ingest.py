"""Tests for ingest-security-hub-ocsf."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_security_hub", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INGEST)

ASFF_REQUIRED_FIELDS = _INGEST.ASFF_REQUIRED_FIELDS
CATEGORY_UID = _INGEST.CATEGORY_UID
CLASS_UID = _INGEST.CLASS_UID
OCSF_VERSION = _INGEST.OCSF_VERSION
SEVERITY_CRITICAL = _INGEST.SEVERITY_CRITICAL
SEVERITY_HIGH = _INGEST.SEVERITY_HIGH
SEVERITY_INFORMATIONAL = _INGEST.SEVERITY_INFORMATIONAL
SEVERITY_LOW = _INGEST.SEVERITY_LOW
SEVERITY_MEDIUM = _INGEST.SEVERITY_MEDIUM
SKILL_NAME = _INGEST.SKILL_NAME
TYPE_UID = _INGEST.TYPE_UID
convert_finding = _INGEST.convert_finding
convert_finding_native = _INGEST.convert_finding_native
extract_attacks = _INGEST.extract_attacks
ingest = _INGEST.ingest
iter_raw_findings = _INGEST.iter_raw_findings
severity_to_id = _INGEST.severity_to_id
validate_asff = _INGEST.validate_asff

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW = GOLDEN / "security_hub_raw_sample.json"
EXPECTED = GOLDEN / "security_hub_sample.ocsf.jsonl"


def _load_jsonl(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def _minimal_asff(
    *,
    asff_id: str = "arn:aws:securityhub:us-east-1:111122223333:subscription/aws-foundational/v/1.0.0/finding/abc",
    types: list[str] | None = None,
    severity_label: str = "HIGH",
    severity_normalized: int | None = 75,
    created: str = "2026-04-10T05:00:00.000Z",
    updated: str = "2026-04-10T05:05:00.000Z",
    product_fields: dict | None = None,
    compliance: dict | None = None,
    resources: list[dict] | None = None,
) -> dict:
    sev: dict = {}
    if severity_label:
        sev["Label"] = severity_label
    if severity_normalized is not None:
        sev["Normalized"] = severity_normalized
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": asff_id,
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
        "GeneratorId": "arn:aws:guardduty:us-east-1:111122223333:detector/abc",
        "AwsAccountId": "111122223333",
        "Types": types
        or [
            "TTPs/Initial Access/UnauthorizedAccess:IAMUser-InstanceCredentialExfiltration.OutsideAWS"
        ],
        "CreatedAt": created,
        "UpdatedAt": updated,
        "FirstObservedAt": created,
        "LastObservedAt": updated,
        "Severity": sev,
        "Title": "Unauthorized API call from outside AWS",
        "Description": "A principal used credentials outside AWS.",
        "Resources": resources
        or [
            {
                "Type": "AwsIamAccessKey",
                "Id": "AKIAUSERKEY",
                "Region": "us-east-1",
                "Partition": "aws",
            }
        ],
    }
    if product_fields is not None:
        finding["ProductFields"] = product_fields
    if compliance is not None:
        finding["Compliance"] = compliance
    return finding


# ── ASFF validation ─────────────────────────────────────────────


class TestValidateAsff:
    def test_valid_minimal(self):
        ok, reason = validate_asff(_minimal_asff())
        assert ok, reason

    def test_not_a_dict(self):
        ok, reason = validate_asff("string")  # type: ignore[arg-type]
        assert not ok
        assert "not a dict" in reason

    def test_missing_required_fields_each_caught(self):
        base = _minimal_asff()
        for field in ASFF_REQUIRED_FIELDS:
            broken = {k: v for k, v in base.items() if k != field}
            ok, reason = validate_asff(broken)
            assert not ok, field
            assert field in reason, field

    def test_empty_required_fields_caught(self):
        for field, empty_value in [
            ("Id", ""),
            ("Title", ""),
            ("Types", []),
            ("Resources", []),
            ("Severity", {}),
        ]:
            broken = _minimal_asff()
            broken[field] = empty_value
            ok, _ = validate_asff(broken)
            assert not ok, field

    def test_severity_must_have_label_or_normalized(self):
        broken = _minimal_asff()
        broken["Severity"] = {"SomethingElse": 42}
        ok, reason = validate_asff(broken)
        assert not ok
        assert "Label or Normalized" in reason

    def test_types_must_be_list(self):
        broken = _minimal_asff()
        broken["Types"] = "not-a-list"
        ok, _ = validate_asff(broken)
        assert not ok

    def test_resources_must_be_list(self):
        broken = _minimal_asff()
        broken["Resources"] = "not-a-list"
        ok, _ = validate_asff(broken)
        assert not ok


# ── Severity mapping ─────────────────────────────────────────────


class TestSeverityToId:
    def test_label_critical(self):
        assert severity_to_id({"Label": "CRITICAL"}) == SEVERITY_CRITICAL

    def test_label_high(self):
        assert severity_to_id({"Label": "HIGH"}) == SEVERITY_HIGH

    def test_label_medium(self):
        assert severity_to_id({"Label": "MEDIUM"}) == SEVERITY_MEDIUM

    def test_label_low(self):
        assert severity_to_id({"Label": "LOW"}) == SEVERITY_LOW

    def test_label_informational(self):
        assert severity_to_id({"Label": "INFORMATIONAL"}) == SEVERITY_INFORMATIONAL

    def test_label_case_insensitive(self):
        assert severity_to_id({"Label": "critical"}) == SEVERITY_CRITICAL

    def test_label_wins_over_normalized(self):
        # Label says LOW, Normalized says 99 — Label should win
        assert severity_to_id({"Label": "LOW", "Normalized": 99}) == SEVERITY_LOW

    def test_normalized_fallback_critical(self):
        assert severity_to_id({"Normalized": 95}) == SEVERITY_CRITICAL
        assert severity_to_id({"Normalized": 90}) == SEVERITY_CRITICAL

    def test_normalized_fallback_high(self):
        assert severity_to_id({"Normalized": 75}) == SEVERITY_HIGH
        assert severity_to_id({"Normalized": 70}) == SEVERITY_HIGH

    def test_normalized_fallback_medium(self):
        assert severity_to_id({"Normalized": 50}) == SEVERITY_MEDIUM
        assert severity_to_id({"Normalized": 40}) == SEVERITY_MEDIUM

    def test_normalized_fallback_low(self):
        assert severity_to_id({"Normalized": 20}) == SEVERITY_LOW
        assert severity_to_id({"Normalized": 1}) == SEVERITY_LOW

    def test_normalized_fallback_informational(self):
        assert severity_to_id({"Normalized": 0}) == SEVERITY_INFORMATIONAL

    def test_none(self):
        assert severity_to_id(None) == SEVERITY_INFORMATIONAL

    def test_garbage_normalized(self):
        assert severity_to_id({"Normalized": "nope"}) == SEVERITY_INFORMATIONAL


# ── MITRE extraction ────────────────────────────────────────────


class TestExtractAttacks:
    def test_ttps_taxonomy_walk(self):
        f = _minimal_asff(types=["TTPs/Initial Access/Some Technique"])
        attacks = extract_attacks(f)
        assert len(attacks) == 1
        assert attacks[0]["tactic"]["uid"] == "TA0001"
        assert attacks[0]["tactic"]["name"] == "Initial Access"

    def test_multiple_ttps_deduped(self):
        f = _minimal_asff(
            types=[
                "TTPs/Initial Access/One",
                "TTPs/Initial Access/Two",  # duplicate tactic
                "TTPs/Credential Access/Three",
            ]
        )
        attacks = extract_attacks(f)
        tactic_uids = {a["tactic"]["uid"] for a in attacks}
        assert tactic_uids == {"TA0001", "TA0006"}

    def test_product_fields_technique_id(self):
        f = _minimal_asff(
            types=["TTPs/Initial Access/Foo"],
            product_fields={"aws/securityhub/annotations/mitre-technique": "T1552.005"},
        )
        attacks = extract_attacks(f)
        assert attacks[0]["technique"]["uid"] == "T1552.005"

    def test_product_fields_technique_creates_attack_if_no_tactic(self):
        f = _minimal_asff(
            types=["SoftwareAndConfigurationChecks/Industry and Regulatory Standards/Foo"],
            product_fields={"mitre-technique-id": "T1078"},
        )
        attacks = extract_attacks(f)
        assert len(attacks) == 1
        assert attacks[0]["technique"]["uid"] == "T1078"

    def test_non_ttps_types_ignored(self):
        f = _minimal_asff(types=["Software and Configuration Checks/Vulnerabilities/CVE-2024-1234"])
        assert extract_attacks(f) == []

    def test_no_mitre_hints_empty(self):
        f = _minimal_asff(types=["Effects/Data Exposure/Foo"])
        assert extract_attacks(f) == []

    def test_malformed_product_fields(self):
        f = _minimal_asff(
            types=["TTPs/Initial Access/Foo"], product_fields={"mitre-technique": "garbage-no-id"}
        )
        attacks = extract_attacks(f)
        # Still emits the tactic from Types[], ProductFields match fails silently
        assert len(attacks) == 1


# ── Convert finding ──────────────────────────────────────────────


class TestConvertFinding:
    def test_pinned_ocsf_fields(self):
        ev = convert_finding(_minimal_asff())
        assert ev["class_uid"] == CLASS_UID == 2004
        assert ev["category_uid"] == CATEGORY_UID == 2
        assert ev["type_uid"] == TYPE_UID
        assert ev["activity_id"] == 1
        assert ev["metadata"]["version"] == OCSF_VERSION
        assert ev["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert ev["severity_id"] == SEVERITY_HIGH

    def test_attacks_inside_finding_info(self):
        ev = convert_finding(_minimal_asff())
        assert "attacks" not in ev
        assert "attacks" in ev["finding_info"]
        # Types[0] starts with "TTPs/Initial Access/..." so we should get TA0001
        assert ev["finding_info"]["attacks"][0]["tactic"]["uid"] == "TA0001"

    def test_deterministic_uid(self):
        a = convert_finding(_minimal_asff(asff_id="ID1"))["finding_info"]["uid"]
        b = convert_finding(_minimal_asff(asff_id="ID1"))["finding_info"]["uid"]
        assert a == b
        assert a.startswith("det-shub-")
        c = convert_finding(_minimal_asff(asff_id="ID2"))["finding_info"]["uid"]
        assert a != c

    def test_resources_projection_includes_region(self):
        ev = convert_finding(_minimal_asff())
        assert ev["resources"][0]["type"] == "AwsIamAccessKey"
        assert ev["resources"][0]["uid"] == "AKIAUSERKEY"
        assert ev["resources"][0]["region"] == "us-east-1"

    def test_cloud_region_lifted_from_first_resource(self):
        ev = convert_finding(_minimal_asff())
        assert ev["cloud"]["region"] == "us-east-1"

    def test_compliance_block_lifted_to_observables(self):
        f = _minimal_asff(
            compliance={
                "Status": "FAILED",
                "SecurityControlId": "IAM.1",
                "StatusReasons": [{"ReasonCode": "CONFIG_EVALUATIONS_EMPTY"}],
            }
        )
        ev = convert_finding(f)
        obs = {o["name"]: o["value"] for o in ev["observables"]}
        assert obs["shub.compliance_status"] == "FAILED"
        assert obs["shub.compliance_control"] == "IAM.1"
        assert obs["shub.compliance_reasons"] == "CONFIG_EVALUATIONS_EMPTY"

    def test_observables_include_severity_label_and_normalized(self):
        ev = convert_finding(_minimal_asff(severity_label="CRITICAL", severity_normalized=95))
        obs = {o["name"]: o["value"] for o in ev["observables"]}
        assert obs["shub.severity_label"] == "CRITICAL"
        assert obs["shub.severity_normalized"] == "95"
        assert ev["severity_id"] == SEVERITY_CRITICAL

    def test_first_observed_time(self):
        ev = convert_finding(
            _minimal_asff(created="2026-04-10T05:00:00.000Z", updated="2026-04-10T05:05:00.000Z")
        )
        assert ev["finding_info"]["first_seen_time"] == 1775797200000
        assert ev["finding_info"]["last_seen_time"] == 1775797500000

    def test_evidence_raw_event_pointer_only(self):
        ev = convert_finding(_minimal_asff(asff_id="ABC"))
        raw = ev["evidence"]["raw_events"][0]
        assert raw["uid"] == "ABC"
        assert raw["product"] == "aws-security-hub"
        assert "Resources" not in raw  # pointer only

    def test_native_output_has_no_ocsf_envelope(self):
        native = convert_finding_native(_minimal_asff())
        assert native["schema_mode"] == "native"
        assert native["record_type"] == "detection_finding"
        assert native["provider"] == "AWS"
        assert native["title"] == "Unauthorized API call from outside AWS"
        assert "class_uid" not in native
        assert "category_uid" not in native
        assert "metadata" not in native

    def test_native_and_ocsf_share_same_uid_basis(self):
        raw = _minimal_asff(asff_id="ID-SAME")
        native = convert_finding_native(raw)
        ocsf = convert_finding(raw)
        assert native["event_uid"] == ocsf["metadata"]["uid"] == "ID-SAME"
        assert native["finding_uid"] == ocsf["finding_info"]["uid"]


# ── Stream parsing ───────────────────────────────────────────────


class TestIterRawFindings:
    def test_single_finding(self):
        out = list(iter_raw_findings([json.dumps(_minimal_asff())]))
        assert len(out) == 1

    def test_findings_wrapper(self):
        payload = json.dumps({"Findings": [_minimal_asff(asff_id="A"), _minimal_asff(asff_id="B")]})
        out = list(iter_raw_findings([payload]))
        assert {x["Id"] for x in out} == {"A", "B"}

    def test_eventbridge_envelope(self):
        envelope = {
            "version": "0",
            "id": "ev-1",
            "detail-type": "Security Hub Findings - Imported",
            "source": "aws.securityhub",
            "account": "111122223333",
            "region": "us-east-1",
            "detail": {"findings": [_minimal_asff(asff_id="EB-1"), _minimal_asff(asff_id="EB-2")]},
        }
        out = list(iter_raw_findings([json.dumps(envelope)]))
        assert {x["Id"] for x in out} == {"EB-1", "EB-2"}

    def test_malformed_line_skipped(self, capsys):
        out = list(iter_raw_findings(['{"bad": ', json.dumps(_minimal_asff(asff_id="OK"))]))
        assert len(out) == 1
        assert out[0]["Id"] == "OK"
        assert "skipping line" in capsys.readouterr().err

    def test_empty_stream(self):
        assert list(iter_raw_findings([])) == []


# ── End-to-end ingest ────────────────────────────────────────────


class TestIngestEndToEnd:
    def test_invalid_findings_dropped_with_warning(self, capsys):
        payload = json.dumps(
            {
                "Findings": [
                    _minimal_asff(asff_id="GOOD"),
                    {"Id": "BAD", "SchemaVersion": "2018-10-08"},  # missing most required fields
                ]
            }
        )
        out = list(ingest([payload]))
        assert len(out) == 1
        assert out[0]["finding_info"]["uid"].startswith("det-shub-")
        assert "asff invalid" in capsys.readouterr().err

    def test_all_valid_findings_converted(self):
        payload = json.dumps({"Findings": [_minimal_asff(asff_id=f"F{i}") for i in range(5)]})
        out = list(ingest([payload]))
        assert len(out) == 5

    def test_native_output_mode_emits_enriched_findings(self):
        payload = json.dumps({"Findings": [_minimal_asff(asff_id=f"F{i}") for i in range(2)]})
        out = list(ingest([payload], output_format="native"))
        assert len(out) == 2
        first = out[0]
        assert first["schema_mode"] == "native"
        assert first["record_type"] == "detection_finding"
        assert first["provider"] == "AWS"
        assert "class_uid" not in first
        assert "metadata" not in first


# ── Golden fixture parity ────────────────────────────────────────


class TestGoldenFixture:
    def test_fixture_files_exist(self):
        assert RAW.exists()
        assert EXPECTED.exists()

    def test_deep_eq_against_frozen_golden(self):
        produced = list(ingest(RAW.read_text().splitlines(keepends=True)))
        expected = _load_jsonl(EXPECTED)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e
