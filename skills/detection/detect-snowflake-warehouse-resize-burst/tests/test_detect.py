"""Tests for detect-snowflake-warehouse-resize-burst."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    ANCHOR_OPERATION,
    API_ACTIVITY_CLASS_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPO_NAME,
    REPO_VENDOR,
    SEVERITY_MEDIUM,
    SIZE_JUMP_DEFAULT,
    SKILL_NAME,
    WINDOW_MIN_DEFAULT,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "snowflake_resize_burst_input.ocsf.jsonl"
EXPECTED = GOLDEN / "snowflake_resize_burst_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "SVC_LOADER",
    actor_name: str = "SVC_LOADER",
    api_operation: str = "ALTER_WAREHOUSE",
    warehouse_name: str = "ANALYTICS_WH",
    size_from: str = "XSMALL",
    size_to: str = "LARGE",
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
                "warehouse_name": warehouse_name,
                "warehouse_size_from": size_from,
                "warehouse_size_to": size_to,
                "query_id": uid,
            }
        },
    }


class TestDetection:
    def test_three_size_jump_fires_once(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="LARGE")]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_MEDIUM
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["size_jump"] == 3
        assert finding["evidence"]["min_size"] == "XSMALL"
        assert finding["evidence"]["max_size"] == "LARGE"

    def test_incremental_steps_sum_to_threshold(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="SMALL"),
            _event(uid="q-2", time_ms=2_000, size_from="SMALL", size_to="MEDIUM"),
            _event(uid="q-3", time_ms=3_000, size_from="MEDIUM", size_to="LARGE"),
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["size_jump"] == 3
        assert findings[0]["evidence"]["events_observed"] == 3

    def test_two_size_jump_does_not_fire(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="MEDIUM")]
        assert list(detect(events)) == []

    def test_failed_alter_does_not_fire(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="LARGE", status_id=2),
        ]
        assert list(detect(events)) == []

    def test_non_snowflake_producer_is_ignored(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="LARGE", producer="ingest-cloudtrail-ocsf"),
        ]
        assert list(detect(events)) == []

    def test_unknown_size_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, size_from="WEIRD", size_to="LARGE")]
        assert list(detect(events)) == []

    def test_out_of_order_events_still_fire_once(self) -> None:
        events = [
            _event(uid="q-3", time_ms=3_000, size_from="MEDIUM", size_to="LARGE"),
            _event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="SMALL"),
            _event(uid="q-2", time_ms=2_000, size_from="SMALL", size_to="MEDIUM"),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="LARGE"),
            _event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="LARGE"),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_two_warehouses_each_fire_separately(self) -> None:
        events = [
            _event(uid="a-1", time_ms=1_000, warehouse_name="WH_A", size_from="XSMALL", size_to="LARGE"),
            _event(uid="b-1", time_ms=1_500, warehouse_name="WH_B", size_from="XSMALL", size_to="LARGE"),
        ]
        findings = list(detect(events))
        assert len(findings) == 2

    def test_native_output_format(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="LARGE")]
        findings = list(detect(events, output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["provider"] == "Snowflake"

    def test_rejects_unsupported_output_format(self) -> None:
        from skills._shared.errors import ContractError

        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
        else:
            raise AssertionError("expected unsupported output_format to raise")

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestThresholdOverrides:
    def test_size_jump_env_override(self, monkeypatch) -> None:
        events = [_event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="MEDIUM")]
        # default jump=3, MEDIUM is jump=2 → no fire
        assert list(detect(events)) == []
        monkeypatch.setenv("SNOWFLAKE_RESIZE_MIN_SIZE_JUMP", "2")
        assert len(list(detect(events))) == 1

    def test_window_env_override(self, monkeypatch) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, size_from="XSMALL", size_to="SMALL"),
            # 2 hours later
            _event(uid="q-2", time_ms=1_000 + 2 * 60 * 60_000, size_from="SMALL", size_to="MEDIUM"),
            _event(uid="q-3", time_ms=1_000 + 2 * 60 * 60_000 + 5_000, size_from="MEDIUM", size_to="LARGE"),
        ]
        # default 60-min window: events too spread out → no fire
        assert list(detect(events)) == []
        monkeypatch.setenv("SNOWFLAKE_RESIZE_WINDOW_MIN", "240")
        # 4-hour window swallows all 3 → fire
        assert len(list(detect(events))) == 1


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("snowflake",)
        assert metadata["thresholds"]["window_minutes"] == WINDOW_MIN_DEFAULT
        assert metadata["thresholds"]["min_size_jump"] == SIZE_JUMP_DEFAULT
        assert ANCHOR_OPERATION in metadata["attack_coverage"]["snowflake"]["anchor_operations"]
        assert "ingest-snowflake-query-history-ocsf" in ACCEPTED_PRODUCERS


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
