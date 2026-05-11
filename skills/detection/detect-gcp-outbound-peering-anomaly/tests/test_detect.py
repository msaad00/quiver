"""Tests for detect-gcp-outbound-peering-anomaly."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    ANCHOR_OPERATION,
    AUTHORIZED_PROJECTS_ENV,
    FINDING_CLASS_UID,
    OUTPUT_FORMATS,
    PRIMARY_TECHNIQUE_UID,
    SECONDARY_TECHNIQUE_UID,
    SEVERITY_HIGH,
    SKILL_NAME,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "gcp_outbound_peering_anomaly_input.ocsf.jsonl"
EXPECTED = GOLDEN / "gcp_outbound_peering_anomaly_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str = "evt-1",
    time_ms: int = 1_700_000_000_000,
    actor: str = "mallory@example.com",
    source_project: str = "prod-host",
    source_network: str = "core",
    peer_project: str = "attacker-tools",
    peer_network: str = "exfil",
    peering_name: str = "exfil-peer",
    operation: str = "compute.networks.addPeering",
    status_id: int = 1,
    producer: str = "ingest-gcp-audit-ocsf",
) -> dict:
    return {
        "class_uid": 6003,
        "status_id": status_id,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {"feature": {"name": producer}},
        },
        "actor": {"user": {"name": actor}},
        "api": {"operation": operation, "service": {"name": "compute.googleapis.com"}},
        "cloud": {"provider": "GCP", "account": {"uid": source_project}},
        "unmapped": {
            "gcp": {
                "network": f"projects/{source_project}/global/networks/{source_network}",
                "peer_network": f"projects/{peer_project}/global/networks/{peer_network}",
                "peering_name": peering_name,
            }
        },
    }


class TestCoreContract:
    def test_accepted_producer(self) -> None:
        assert ACCEPTED_PRODUCERS == frozenset({"ingest-gcp-audit-ocsf"})

    def test_anchor_operation(self) -> None:
        assert ANCHOR_OPERATION == "compute.networks.addPeering"

    def test_coverage_metadata(self) -> None:
        meta = coverage_metadata()
        assert meta["providers"] == ("gcp",)
        assert PRIMARY_TECHNIQUE_UID in meta["attack_coverage"]["gcp"]["techniques"]
        assert SECONDARY_TECHNIQUE_UID in meta["attack_coverage"]["gcp"]["techniques"]
        assert meta["thresholds"]["allowlist_mode"] == "fail-open"


class TestDetection:
    def test_cross_project_fires_in_fail_open(self) -> None:
        findings = list(detect([_event()]))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["evidence"]["allowlist_mode"] == "fail-open"
        assert finding["evidence"]["peer_project"] == "attacker-tools"
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == PRIMARY_TECHNIQUE_UID
        assert finding["finding_info"]["attacks"][1]["technique"]["uid"] == SECONDARY_TECHNIQUE_UID

    def test_cross_project_fires_when_peer_not_on_allowlist(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_PROJECTS_ENV, "shared-host-prod,partner-acme")
        findings = list(detect([_event()]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["allowlist_mode"] == "enforced"

    def test_same_project_does_not_fire(self) -> None:
        findings = list(detect([_event(peer_project="prod-host")]))
        assert findings == []

    def test_authorized_peer_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_PROJECTS_ENV, "attacker-tools,partner-acme")
        findings = list(detect([_event()]))
        assert findings == []

    def test_failed_call_does_not_fire(self) -> None:
        findings = list(detect([_event(status_id=2)]))
        assert findings == []

    def test_wrong_producer_ignored(self, capsys) -> None:
        findings = list(detect([_event(producer="ingest-cloudtrail-ocsf")]))
        assert findings == []
        assert "non-gcp-audit producer" in capsys.readouterr().err

    def test_missing_peer_network_skipped(self, capsys) -> None:
        evt = _event()
        evt["unmapped"]["gcp"]["peer_network"] = ""
        findings = list(detect([evt]))
        assert findings == []
        assert "missing source or peer network" in capsys.readouterr().err

    def test_malformed_uri_skipped(self, capsys) -> None:
        evt = _event()
        evt["unmapped"]["gcp"]["peer_network"] = "not-a-real-uri"
        findings = list(detect([evt]))
        assert findings == []
        assert "could not parse project" in capsys.readouterr().err

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        evt = _event()
        findings = list(detect([evt, evt]))
        assert len(findings) == 1

    def test_two_distinct_cross_project_peerings(self) -> None:
        findings = list(
            detect(
                [
                    _event(uid="evt-1", peer_project="attacker-a"),
                    _event(uid="evt-2", peer_project="attacker-b", time_ms=1_700_000_060_000),
                ]
            )
        )
        assert len(findings) == 2

    def test_native_output(self) -> None:
        findings = list(detect([_event()], output_format="native"))
        assert len(findings) == 1
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["source_skill"] == SKILL_NAME
        assert OUTPUT_FORMATS == frozenset({"ocsf", "native"})

    def test_rejects_unsupported_output_format(self) -> None:
        from skills._shared.errors import ContractError

        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected ContractError")

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
