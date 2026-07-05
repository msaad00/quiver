"""Tests for detect-snowflake-bulk-data-egress."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    API_ACTIVITY_CLASS_UID,
    BYTE_THRESHOLD_DEFAULT,
    EGRESS_OPERATIONS,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MIN_STAGES_DEFAULT,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPO_NAME,
    REPO_VENDOR,
    ROW_THRESHOLD_DEFAULT,
    SEVERITY_HIGH,
    SKILL_NAME,
    WINDOW_MIN_DEFAULT,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "snowflake_bulk_egress_input.ocsf.jsonl"
EXPECTED = GOLDEN / "snowflake_bulk_egress_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "SVC_ETL",
    actor_name: str = "SVC_ETL",
    api_operation: str = "COPY_INTO_LOCATION",
    stage_name: str = "@s3_stage_alpha",
    bytes_scanned: int = 2_000_000_000,
    rows_unloaded: int = 200_000,
    producer: str = "ingest-snowflake-query-history-ocsf",
    status_id: int = 1,
) -> dict:
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
                "vendor_name": REPO_VENDOR,
                "feature": {"name": producer},
            },
        },
        "actor": {"user": {"uid": actor_uid, "name": actor_name, "type": "Service"}},
        "api": {"operation": api_operation, "service": {"name": "snowflake.warehouse"}},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {
            "snowflake": {
                "bytes_scanned": bytes_scanned,
                "rows_unloaded": rows_unloaded,
                "stage_name": stage_name,
                "query_id": uid,
            }
        },
    }


class TestDetection:
    def test_three_stages_over_byte_threshold_fires_once(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, stage_name="@s3_alpha", bytes_scanned=2_500_000_000),
            _event(uid="q-2", time_ms=2_000, stage_name="@s3_beta", bytes_scanned=2_500_000_000),
            _event(uid="q-3", time_ms=3_000, stage_name="@s3_gamma", bytes_scanned=2_500_000_000),
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["metadata"]["uid"] == finding["finding_info"]["uid"]
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["events_observed"] == 3
        assert sorted(finding["evidence"]["stage_names"]) == ["@s3_alpha", "@s3_beta", "@s3_gamma"]
        assert finding["evidence"]["bytes_scanned"] == 7_500_000_000

    def test_three_stages_over_row_threshold_fires_when_bytes_low(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                stage_name="@s3_a",
                bytes_scanned=10,
                rows_unloaded=400_000,
            ),
            _event(
                uid="q-2",
                time_ms=2_000,
                stage_name="@s3_b",
                bytes_scanned=10,
                rows_unloaded=400_000,
            ),
            _event(
                uid="q-3",
                time_ms=3_000,
                stage_name="@s3_c",
                bytes_scanned=10,
                rows_unloaded=400_000,
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["rows_unloaded"] == 1_200_000
        assert findings[0]["evidence"]["bytes_scanned"] == 30

    def test_single_stage_burst_does_not_fire(self) -> None:
        # Legit batch ETL pattern: one stage, large volume. No fan-out, no fire.
        events = [
            _event(
                uid=f"q-{i}",
                time_ms=1_000 + i,
                stage_name="@etl_stage",
                bytes_scanned=3_000_000_000,
            )
            for i in range(5)
        ]
        assert list(detect(events)) == []

    def test_single_event_does_not_fire(self) -> None:
        # Single event physically cannot hit >=3 distinct stages.
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                bytes_scanned=BYTE_THRESHOLD_DEFAULT * 2,
                rows_unloaded=ROW_THRESHOLD_DEFAULT * 2,
                stage_name="@solo",
            ),
        ]
        assert list(detect(events)) == []

    def test_non_snowflake_producer_is_ignored(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, stage_name="@s3_a", producer="ingest-cloudtrail-ocsf"),
            _event(uid="q-2", time_ms=2_000, stage_name="@s3_b", producer="ingest-cloudtrail-ocsf"),
            _event(uid="q-3", time_ms=3_000, stage_name="@s3_c", producer="ingest-cloudtrail-ocsf"),
        ]
        assert list(detect(events)) == []

    def test_failed_query_is_ignored(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, stage_name="@s3_a", status_id=2),
            _event(uid="q-2", time_ms=2_000, stage_name="@s3_b", status_id=2),
            _event(uid="q-3", time_ms=3_000, stage_name="@s3_c", status_id=2),
        ]
        assert list(detect(events)) == []

    def test_out_of_order_events_still_fire_once(self) -> None:
        events = [
            _event(uid="q-3", time_ms=3_000, stage_name="@s3_gamma", bytes_scanned=2_500_000_000),
            _event(uid="q-1", time_ms=1_000, stage_name="@s3_alpha", bytes_scanned=2_500_000_000),
            _event(uid="q-2", time_ms=2_000, stage_name="@s3_beta", bytes_scanned=2_500_000_000),
        ]
        assert len(list(detect(events))) == 1

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, stage_name="@s3_a", bytes_scanned=2_500_000_000),
            _event(uid="q-1", time_ms=1_000, stage_name="@s3_a", bytes_scanned=2_500_000_000),
            _event(uid="q-2", time_ms=2_000, stage_name="@s3_b", bytes_scanned=2_500_000_000),
        ]
        assert list(detect(events)) == []

    def test_two_principals_each_fire_separately(self) -> None:
        events = [
            _event(
                uid="a-1",
                time_ms=1_000,
                actor_uid="ALICE",
                stage_name="@a_alpha",
                bytes_scanned=2_500_000_000,
            ),
            _event(
                uid="a-2",
                time_ms=2_000,
                actor_uid="ALICE",
                stage_name="@a_beta",
                bytes_scanned=2_500_000_000,
            ),
            _event(
                uid="b-1",
                time_ms=2_500,
                actor_uid="BOB",
                stage_name="@b_alpha",
                bytes_scanned=2_500_000_000,
            ),
            _event(
                uid="b-2",
                time_ms=2_700,
                actor_uid="BOB",
                stage_name="@b_beta",
                bytes_scanned=2_500_000_000,
            ),
            _event(
                uid="a-3",
                time_ms=3_000,
                actor_uid="ALICE",
                stage_name="@a_gamma",
                bytes_scanned=2_500_000_000,
            ),
            _event(
                uid="b-3",
                time_ms=3_500,
                actor_uid="BOB",
                stage_name="@b_gamma",
                bytes_scanned=2_500_000_000,
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 2
        principals = {finding["observables"][0]["value"] for finding in findings}
        assert principals == {"ALICE", "BOB"}

    def test_native_output_format(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, stage_name="@s3_a", bytes_scanned=2_500_000_000),
            _event(uid="q-2", time_ms=2_000, stage_name="@s3_b", bytes_scanned=2_500_000_000),
            _event(uid="q-3", time_ms=3_000, stage_name="@s3_c", bytes_scanned=2_500_000_000),
        ]
        findings = list(detect(events, output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "Snowflake"
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

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestThresholdOverrides:
    def test_min_stages_env_override_raises_threshold(self, monkeypatch) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, stage_name="@s3_a", bytes_scanned=2_500_000_000),
            _event(uid="q-2", time_ms=2_000, stage_name="@s3_b", bytes_scanned=2_500_000_000),
            _event(uid="q-3", time_ms=3_000, stage_name="@s3_c", bytes_scanned=2_500_000_000),
        ]
        assert len(list(detect(events))) == 1

        monkeypatch.setenv("SNOWFLAKE_EGRESS_MIN_STAGES", "5")
        assert list(detect(events)) == []

    def test_byte_threshold_env_override(self, monkeypatch) -> None:
        events = [
            _event(
                uid="q-1", time_ms=1_000, stage_name="@s3_a", bytes_scanned=10, rows_unloaded=10
            ),
            _event(
                uid="q-2", time_ms=2_000, stage_name="@s3_b", bytes_scanned=10, rows_unloaded=10
            ),
            _event(
                uid="q-3", time_ms=3_000, stage_name="@s3_c", bytes_scanned=10, rows_unloaded=10
            ),
        ]
        # default thresholds: not enough volume → no fire
        assert list(detect(events)) == []

        # lower the byte threshold so the burst above crosses it
        monkeypatch.setenv("SNOWFLAKE_EGRESS_BYTE_THRESHOLD", "20")
        assert len(list(detect(events))) == 1


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("snowflake",)
        assert metadata["thresholds"]["window_minutes"] == WINDOW_MIN_DEFAULT
        assert metadata["thresholds"]["byte_threshold"] == BYTE_THRESHOLD_DEFAULT
        assert metadata["thresholds"]["row_threshold"] == ROW_THRESHOLD_DEFAULT
        assert metadata["thresholds"]["min_stages"] == MIN_STAGES_DEFAULT
        assert "ingest-snowflake-query-history-ocsf" in ACCEPTED_PRODUCERS
        assert "COPY_INTO_LOCATION" in EGRESS_OPERATIONS


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
