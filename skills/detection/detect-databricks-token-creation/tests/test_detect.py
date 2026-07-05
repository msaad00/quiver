"""Tests for detect-databricks-token-creation."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    API_ACTIVITY_CLASS_UID,
    DATABRICKS_VENDOR_NAME,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    KNOWN_TOKEN_OPERATIONS,
    MITRE_SUBTECHNIQUE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPO_NAME,
    SEVERITY_HIGH,
    SKILL_NAME,
    TOKEN_CREATE_OPERATION,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "databricks_token_creation_input.ocsf.jsonl"
EXPECTED = GOLDEN / "databricks_token_creation_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "alice@example.com",
    actor_email: str = "alice@example.com",
    actor_name: str = "Alice Engineer",
    api_operation: str = TOKEN_CREATE_OPERATION,
    workspace_id: str = "1234567890123456",
    token_id: str = "tok-abc",
    comment: str = "automation token",
    lifetime_seconds: int | None = 0,
    producer: str = "ingest-databricks-audit-ocsf",
    vendor_name: str = DATABRICKS_VENDOR_NAME,
    status_id: int = 1,
) -> dict:
    databricks_block: dict = {
        "workspace_id": workspace_id,
        "token_id": token_id,
        "comment": comment,
    }
    if lifetime_seconds is not None:
        databricks_block["lifetime_seconds"] = lifetime_seconds
    return {
        "activity_id": 1,
        "category_uid": 6,
        "category_name": "Application Activity",
        "class_uid": API_ACTIVITY_CLASS_UID,
        "class_name": "API Activity",
        "type_uid": API_ACTIVITY_CLASS_UID * 100 + 1,
        "severity_id": 1,
        "status_id": status_id,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": vendor_name,
                "feature": {"name": producer},
            },
        },
        "actor": {
            "user": {
                "uid": actor_uid,
                "name": actor_name,
                "email_addr": actor_email,
                "type": "User",
            }
        },
        "api": {"operation": api_operation, "service": {"name": "databricks.token-management"}},
        "src_endpoint": {"ip": "203.0.113.42"},
        "unmapped": {"databricks": databricks_block},
    }


class TestDetection:
    def test_successful_token_create_fires_once(self) -> None:
        events = [_event(uid="ev-1", time_ms=1_000_000)]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["status_id"] == 1
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["metadata"]["uid"] == finding["finding_info"]["uid"]
        attack = finding["finding_info"]["attacks"][0]
        assert attack["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert attack["sub_technique"]["uid"] == MITRE_SUBTECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert "databricks-token-creation" in finding["finding_info"]["types"]
        assert finding["evidence"]["events_observed"] == 1
        assert finding["evidence"]["workspace_id"] == "1234567890123456"
        assert finding["evidence"]["token_id"] == "tok-abc"

    def test_read_only_tokens_list_does_not_fire(self) -> None:
        events = [_event(uid="ev-list-1", time_ms=1_000, api_operation="tokens/list")]
        assert list(detect(events)) == []

    def test_failed_token_create_does_not_fire(self) -> None:
        events = [_event(uid="ev-fail-1", time_ms=1_000, status_id=2)]
        assert list(detect(events)) == []

    def test_non_databricks_event_is_ignored(self) -> None:
        events = [
            _event(
                uid="ev-other",
                time_ms=1_000,
                producer="ingest-cloudtrail-ocsf",
                vendor_name="AWS",
            )
        ]
        assert list(detect(events)) == []

    def test_malformed_payload_is_skipped(self, capsys) -> None:
        # Malformed input via load_jsonl: parse error on first line, valid on second.
        out = list(load_jsonl(['{"bad":', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_multi_token_burst_fires_once_per_token(self) -> None:
        events = [
            _event(uid=f"ev-burst-{i}", time_ms=1_000 + i, token_id=f"tok-{i}") for i in range(4)
        ]
        findings = list(detect(events))
        assert len(findings) == 4
        # each finding is its own persistence anchor — uids must all differ
        uids = {f["metadata"]["uid"] for f in findings}
        assert len(uids) == 4

    def test_unmapped_token_operation_emits_telemetry(self, capsys, monkeypatch) -> None:
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        events = [_event(uid="ev-future-1", time_ms=1_000, api_operation="tokens/futureverb")]
        assert list(detect(events)) == []
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["event"] == "unmapped_event_type"
        assert payload["api_operation"] == "tokens/futureverb"
        assert payload["skill"] == SKILL_NAME

    def test_known_non_create_token_op_does_not_emit_unmapped(self, capsys) -> None:
        # tokens/list is in the known map — it should NOT produce
        # `unmapped_event_type` telemetry, and it should NOT fire.
        events = [_event(uid="ev-list-2", time_ms=1_000, api_operation="tokens/delete")]
        assert list(detect(events)) == []
        assert "unmapped_event_type" not in capsys.readouterr().err

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [
            _event(uid="ev-dup", time_ms=1_000),
            _event(uid="ev-dup", time_ms=1_000),
        ]
        assert len(list(detect(events))) == 1

    def test_native_output_format(self) -> None:
        events = [_event(uid="ev-native-1", time_ms=1_000)]
        findings = list(detect(events, output_format="native"))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "Databricks"
        assert "class_uid" not in finding

    def test_rejects_unsupported_output_format(self) -> None:
        from skills._shared.errors import ContractError

        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
            assert exc.error_class == "contract"
            assert exc.retryable is False
        else:
            raise AssertionError("expected unsupported output_format to raise")

    def test_missing_actor_is_skipped_with_telemetry(self, capsys, monkeypatch) -> None:
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        bad = _event(uid="ev-noactor", time_ms=1_000, actor_uid="", actor_email="")
        # Wipe actor block to also clear the `name` fallback
        bad["actor"] = {"user": {}}
        assert list(detect([bad])) == []
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["event"] == "missing_actor"

    def test_vendor_name_route_accepts_unknown_producer(self) -> None:
        # vendor_name == Databricks alone is enough even if the producer name
        # isn't in ACCEPTED_PRODUCERS — keeps the detector usable when an
        # operator wires up a custom Databricks ingester.
        events = [
            _event(
                uid="ev-custom-1",
                time_ms=1_000,
                producer="custom-databricks-tap",
                vendor_name=DATABRICKS_VENDOR_NAME,
            )
        ]
        assert len(list(detect(events))) == 1

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("databricks",)
        assert (
            TOKEN_CREATE_OPERATION in metadata["attack_coverage"]["databricks"]["anchor_operations"]
        )
        assert MITRE_TECHNIQUE_UID in metadata["attack_coverage"]["databricks"]["techniques"]
        assert MITRE_SUBTECHNIQUE_UID in metadata["attack_coverage"]["databricks"]["techniques"]
        assert "ingest-databricks-audit-ocsf" in ACCEPTED_PRODUCERS
        assert TOKEN_CREATE_OPERATION in KNOWN_TOKEN_OPERATIONS
        assert OUTPUT_FORMATS == ("ocsf", "native")


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_emits_json_stderr_telemetry_when_enabled(self, capsys, monkeypatch) -> None:
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        list(load_jsonl(['{"bad": ']))
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["skill"] == SKILL_NAME
        assert payload["level"] == "warning"
        assert payload["event"] == "json_parse_failed"
        assert payload["line"] == 1
