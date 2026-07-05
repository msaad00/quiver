"""Tests for ingest-guardduty-ocsf."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ingest import (  # type: ignore[import-not-found]
    CATEGORY_UID,
    CLASS_UID,
    OCSF_VERSION,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SKILL_NAME,
    TYPE_UID,
    convert_finding,
    convert_finding_native,
    ingest,
    iter_raw_findings,
    map_type_to_attacks,
    parse_threat_purpose,
    severity_to_id,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW = GOLDEN / "guardduty_raw_sample.json"
EXPECTED = GOLDEN / "guardduty_sample.ocsf.jsonl"


def _load_jsonl(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def _minimal_finding(
    *,
    gd_id: str = "FID-001",
    finding_type: str = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    severity: float = 8.5,
    created: str = "2026-04-10T05:00:00.000Z",
    updated: str = "2026-04-10T05:05:00.000Z",
    first_seen: str = "2026-04-10T05:00:00.000Z",
    last_seen: str = "2026-04-10T05:05:00.000Z",
    account_id: str = "111122223333",
    region: str = "us-east-1",
    resource: dict | None = None,
) -> dict:
    return {
        "Id": gd_id,
        "Arn": f"arn:aws:guardduty:us-east-1:111122223333:detector/abc/finding/{gd_id}",
        "Type": finding_type,
        "Severity": severity,
        "Title": "Unauthorized API call from outside AWS",
        "Description": "A principal used credentials outside AWS.",
        "CreatedAt": created,
        "UpdatedAt": updated,
        "AccountId": account_id,
        "Region": region,
        "Resource": resource
        or {
            "ResourceType": "AccessKey",
            "AccessKeyDetails": {"AccessKeyId": "AKIAUSERKEY", "UserName": "alice"},
        },
        "Service": {
            "ServiceName": "guardduty",
            "Count": 3,
            "EventFirstSeen": first_seen,
            "EventLastSeen": last_seen,
        },
    }


# ── Threat purpose extraction ────────────────────────────────────


class TestParseThreatPurpose:
    def test_standard(self):
        assert parse_threat_purpose("UnauthorizedAccess:IAMUser/Foo") == "UnauthorizedAccess"

    def test_with_bang_artifact(self):
        assert parse_threat_purpose("Backdoor:EC2/C&CActivity.B!DNS") == "Backdoor"

    def test_empty(self):
        assert parse_threat_purpose("") == ""

    def test_no_colon(self):
        assert parse_threat_purpose("JustGarbage") == ""


# ── MITRE mapping ────────────────────────────────────────────────


class TestMapTypeToAttacks:
    def test_exact_match_with_sub_technique(self):
        attacks = map_type_to_attacks(
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
        )
        assert len(attacks) == 1
        a = attacks[0]
        assert a["version"] == "v14"
        assert a["tactic"]["uid"] == "TA0001"
        assert a["technique"]["uid"] == "T1552"
        assert a["sub_technique"]["uid"] == "T1552.005"

    def test_exact_match_without_sub_technique(self):
        attacks = map_type_to_attacks("UnauthorizedAccess:EC2/SSHBruteForce")
        a = attacks[0]
        assert a["technique"]["uid"] == "T1110"
        assert "sub_technique" not in a

    def test_tactic_only_fallback(self):
        # ThreatPurpose known, finding type not in curated table
        attacks = map_type_to_attacks("Exfiltration:IAMUser/SomeNewVariant.A")
        assert len(attacks) == 1
        assert attacks[0]["tactic"]["uid"] == "TA0010"
        assert attacks[0]["technique"]["uid"] == ""

    def test_unknown_threat_purpose_empty(self):
        assert map_type_to_attacks("FooBarBaz:IAMUser/Nothing") == []

    def test_empty_type(self):
        assert map_type_to_attacks("") == []

    def test_all_threat_purposes_have_valid_tactic_uid(self):
        # Every ThreatPurpose in the map should yield a TA#### tactic uid
        purposes = (
            "UnauthorizedAccess",
            "Backdoor",
            "CredentialAccess",
            "CryptoCurrency",
            "DefenseEvasion",
            "Discovery",
            "Execution",
            "Exfiltration",
            "Impact",
            "InitialAccess",
            "Persistence",
            "Policy",
            "PrivilegeEscalation",
            "Recon",
            "Stealth",
            "Trojan",
            "Behavior",
            "ResourceConsumption",
        )
        for p in purposes:
            attacks = map_type_to_attacks(f"{p}:IAMUser/Generic.A")
            assert attacks, p
            assert attacks[0]["tactic"]["uid"].startswith("TA"), p


# ── Severity mapping ─────────────────────────────────────────────


class TestSeverityToId:
    def test_critical(self):
        assert severity_to_id(8.0) == SEVERITY_CRITICAL
        assert severity_to_id(8.9) == SEVERITY_CRITICAL

    def test_high(self):
        assert severity_to_id(6.0) == SEVERITY_HIGH
        assert severity_to_id(7.9) == SEVERITY_HIGH

    def test_medium(self):
        assert severity_to_id(4.0) == SEVERITY_MEDIUM
        assert severity_to_id(5.9) == SEVERITY_MEDIUM

    def test_low(self):
        assert severity_to_id(2.0) == SEVERITY_LOW
        assert severity_to_id(3.9) == SEVERITY_LOW

    def test_informational(self):
        assert severity_to_id(0.0) == SEVERITY_INFORMATIONAL
        assert severity_to_id(1.9) == SEVERITY_INFORMATIONAL

    def test_none(self):
        assert severity_to_id(None) == SEVERITY_INFORMATIONAL

    def test_garbage(self):
        assert severity_to_id("not-a-number") == SEVERITY_INFORMATIONAL

    def test_int_input(self):
        assert severity_to_id(8) == SEVERITY_CRITICAL

    def test_string_number(self):
        assert severity_to_id("6.5") == SEVERITY_HIGH


# ── Convert finding ──────────────────────────────────────────────


class TestConvertFinding:
    def test_pinned_ocsf_fields(self):
        ev = convert_finding(_minimal_finding())
        assert ev["class_uid"] == CLASS_UID == 2004
        assert ev["category_uid"] == CATEGORY_UID == 2
        assert ev["type_uid"] == TYPE_UID
        assert ev["activity_id"] == 1
        assert ev["metadata"]["version"] == OCSF_VERSION == "1.8.0"
        assert ev["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert ev["severity_id"] == SEVERITY_CRITICAL

    def test_attacks_inside_finding_info_not_root(self):
        ev = convert_finding(_minimal_finding())
        assert "attacks" not in ev
        assert "attacks" in ev["finding_info"]
        assert ev["finding_info"]["attacks"][0]["technique"]["uid"] == "T1552"

    def test_deterministic_uid(self):
        a = convert_finding(_minimal_finding(gd_id="FID-ABC"))["finding_info"]["uid"]
        b = convert_finding(_minimal_finding(gd_id="FID-ABC"))["finding_info"]["uid"]
        assert a == b
        assert a.startswith("det-gd-")
        c = convert_finding(_minimal_finding(gd_id="FID-XYZ"))["finding_info"]["uid"]
        assert a != c

    def test_resource_projection_access_key(self):
        ev = convert_finding(_minimal_finding())
        assert ev["resources"] == [
            {"type": "AccessKey", "uid": "AKIAUSERKEY", "name": "AKIAUSERKEY"}
        ]

    def test_resource_projection_instance(self):
        f = _minimal_finding(
            resource={
                "ResourceType": "Instance",
                "InstanceDetails": {"InstanceId": "i-0web01"},
            }
        )
        ev = convert_finding(f)
        assert ev["resources"] == [{"type": "Instance", "uid": "i-0web01", "name": "i-0web01"}]

    def test_resource_projection_s3(self):
        f = _minimal_finding(
            resource={
                "ResourceType": "S3Bucket",
                "S3BucketDetails": [{"Name": "my-bucket", "Arn": "arn:aws:s3:::my-bucket"}],
            }
        )
        ev = convert_finding(f)
        assert ev["resources"][0]["type"] == "S3Bucket"
        assert ev["resources"][0]["uid"] == "my-bucket"

    def test_resource_projection_unknown(self):
        f = _minimal_finding(resource={"ResourceType": "Lambda"})
        ev = convert_finding(f)
        # Unknown type still emits the type tag; no uid/name
        assert ev["resources"] == [{"type": "Lambda"}]

    def test_resource_projection_empty(self):
        # Build a finding with an explicit empty Resource block (bypasses the
        # helper's `or {...}` default which treats {} as falsy).
        f = _minimal_finding()
        f["Resource"] = {}
        ev = convert_finding(f)
        assert ev["resources"] == []

    def test_cloud_block(self):
        ev = convert_finding(_minimal_finding())
        assert ev["cloud"]["provider"] == "AWS"
        assert ev["cloud"]["account"]["uid"] == "111122223333"
        assert ev["cloud"]["region"] == "us-east-1"

    def test_observables_present(self):
        ev = convert_finding(_minimal_finding())
        names = {o["name"] for o in ev["observables"]}
        assert names == {
            "gd.finding_id",
            "gd.type",
            "gd.severity",
            "resource.type",
            "aws.account",
            "aws.region",
        }

    def test_evidence_raw_event_pointer(self):
        ev = convert_finding(_minimal_finding(gd_id="FID-001"))
        raw = ev["evidence"]["raw_events"]
        assert len(raw) == 1
        assert raw[0]["uid"] == "FID-001"
        assert raw[0]["product"] == "aws-guardduty"
        # Pointer only — full body MUST NOT be embedded
        assert "Resource" not in raw[0]
        assert "Service" not in raw[0]

    def test_times_use_service_event_timestamps(self):
        ev = convert_finding(
            _minimal_finding(
                first_seen="2026-04-10T05:00:00.000Z",
                last_seen="2026-04-10T05:05:00.000Z",
            )
        )
        assert ev["finding_info"]["first_seen_time"] == 1775797200000
        assert ev["finding_info"]["last_seen_time"] == 1775797500000
        assert ev["evidence"]["first_seen_time"] == 1775797200000

    def test_missing_optional_fields_do_not_crash(self):
        minimal = {"Id": "F", "Type": "UnauthorizedAccess:IAMUser/Foo.A", "Severity": 5.0}
        ev = convert_finding(minimal)
        assert ev["severity_id"] == SEVERITY_MEDIUM
        assert ev["finding_info"]["uid"].startswith("det-gd-")

    def test_native_output_has_no_ocsf_envelope(self):
        native = convert_finding_native(_minimal_finding())
        assert native["schema_mode"] == "native"
        assert native["record_type"] == "detection_finding"
        assert native["provider"] == "AWS"
        assert native["title"] == "Unauthorized API call from outside AWS"
        assert "class_uid" not in native
        assert "category_uid" not in native
        assert "metadata" not in native

    def test_native_and_ocsf_share_same_uid_basis(self):
        raw = _minimal_finding(gd_id="FID-SAME")
        native = convert_finding_native(raw)
        ocsf = convert_finding(raw)
        assert native["event_uid"] == ocsf["metadata"]["uid"] == "FID-SAME"
        assert native["finding_uid"] == ocsf["finding_info"]["uid"]


# ── Stream parsing ───────────────────────────────────────────────


class TestIterRawFindings:
    def test_single_finding_dict(self):
        f = _minimal_finding()
        out = list(iter_raw_findings([json.dumps(f)]))
        assert len(out) == 1
        assert out[0]["Id"] == "FID-001"

    def test_findings_wrapper(self):
        payload = json.dumps(
            {"Findings": [_minimal_finding(gd_id="A"), _minimal_finding(gd_id="B")]}
        )
        out = list(iter_raw_findings([payload]))
        assert [x["Id"] for x in out] == ["A", "B"]

    def test_eventbridge_envelope(self):
        envelope = {
            "version": "0",
            "id": "ev-1",
            "detail-type": "GuardDuty Finding",
            "source": "aws.guardduty",
            "account": "111122223333",
            "region": "us-east-1",
            "detail": _minimal_finding(gd_id="EB-1"),
        }
        out = list(iter_raw_findings([json.dumps(envelope)]))
        assert len(out) == 1
        assert out[0]["Id"] == "EB-1"

    def test_ndjson_multiple_lines(self):
        # Line-by-line parse kicks in when the full blob isn't a single JSON value
        # (an empty line between two JSON objects triggers this).
        lines = [
            json.dumps(_minimal_finding(gd_id="N1")),
            "",
            json.dumps(_minimal_finding(gd_id="N2")),
        ]
        out = list(iter_raw_findings(lines))
        assert {x["Id"] for x in out} == {"N1", "N2"}

    def test_top_level_array(self):
        payload = json.dumps([_minimal_finding(gd_id="A1"), _minimal_finding(gd_id="A2")])
        out = list(iter_raw_findings([payload]))
        assert {x["Id"] for x in out} == {"A1", "A2"}

    def test_malformed_line_skipped(self, capsys):
        # Triggers the line-by-line fallback because the whole-document parse fails
        out = list(iter_raw_findings(['{"bad": ', json.dumps(_minimal_finding(gd_id="OK"))]))
        assert len(out) == 1
        assert out[0]["Id"] == "OK"
        assert "skipping line" in capsys.readouterr().err

    def test_empty_stream(self):
        assert list(iter_raw_findings([])) == []
        assert list(iter_raw_findings([""])) == []


# ── End-to-end ingest ────────────────────────────────────────────


class TestIngestEndToEnd:
    def test_emits_finding_per_input(self):
        lines = [
            json.dumps({"Findings": [_minimal_finding(gd_id="E1"), _minimal_finding(gd_id="E2")]}),
        ]
        out = list(ingest(lines))
        assert len(out) == 2
        assert {o["finding_info"]["uid"] for o in out} == {
            "det-gd-" + o["finding_info"]["uid"].removeprefix("det-gd-") for o in out
        }

    def test_native_output_mode_emits_enriched_findings(self):
        lines = [
            json.dumps({"Findings": [_minimal_finding(gd_id="E1"), _minimal_finding(gd_id="E2")]}),
        ]
        out = list(ingest(lines, output_format="native"))
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
