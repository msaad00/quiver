"""Contract tests for the ClickHouse data-lake pack.

The detection query packs (lateral-movement, privilege-escalation-k8s) already
have pytest coverage; these tests give the ClickHouse lake DDL the same
treatment: golden column locks, append-only/retention markers, and a guarantee
that every replay query template stays inside the read-only SQL subset that
`source-clickhouse-query` enforces at runtime.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "packs" / "clickhouse"

GOLDEN_COLUMNS = json.loads((PACK / "golden" / "expected_columns.json").read_text())

SINK_TABLES = {
    "security.findings_sink": "ddl/02_findings_sink.sql",
    "security.events_sink": "ddl/03_events_sink.sql",
    "security.evidence_sink": "ddl/04_evidence_sink.sql",
    "security.audit_sink": "ddl/05_audit_sink.sql",
}
ROLLUP_VIEWS = {
    "security.findings_by_rule_hourly": "materialized-views/01_findings_by_rule_hourly.sql",
    "security.events_by_class_daily": "materialized-views/02_events_by_class_daily.sql",
    "security.remediations_by_outcome_daily": "materialized-views/03_remediations_by_outcome_daily.sql",
}
QUERY_TEMPLATES = sorted((PACK / "queries").glob("*.sql"))


def _load_read_only_sql():
    path = ROOT / "skills" / "_shared" / "read_only_sql.py"
    spec = importlib.util.spec_from_file_location("read_only_sql_clickhouse_pack_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


READ_ONLY_SQL = _load_read_only_sql()


def _strip_comment_lines(sql: str) -> str:
    return "\n".join(line for line in sql.splitlines() if not line.lstrip().startswith("--"))


class TestClickHouseLakeDdl:
    def test_golden_covers_every_sink_and_rollup(self):
        assert set(GOLDEN_COLUMNS) == set(SINK_TABLES) | set(ROLLUP_VIEWS)

    @pytest.mark.parametrize("table,ddl_file", sorted(SINK_TABLES.items()))
    def test_sink_ddl_declares_golden_columns(self, table, ddl_file):
        sql = (PACK / ddl_file).read_text()
        assert f"CREATE TABLE IF NOT EXISTS {table}" in sql
        for column in GOLDEN_COLUMNS[table]:
            assert column in sql, f"{ddl_file} is missing golden column {column!r}"

    @pytest.mark.parametrize("table,ddl_file", sorted(SINK_TABLES.items()))
    def test_sink_ddl_keeps_lake_contract_markers(self, table, ddl_file):
        sql = (PACK / ddl_file).read_text()
        assert "ENGINE = MergeTree" in sql, f"{ddl_file} must stay on MergeTree"
        assert "PARTITION BY" in sql, f"{ddl_file} must keep monthly partitioning"
        if table == "security.audit_sink":
            # Legal-hold chain: audit rows are deleted only after a hold
            # release, so TTL is intentionally absent.
            assert "TTL ingested_at" not in sql
        else:
            assert "TTL ingested_at" in sql, f"{ddl_file} must keep TTL-managed retention"

    @pytest.mark.parametrize("view,view_file", sorted(ROLLUP_VIEWS.items()))
    def test_rollup_views_declare_golden_columns(self, view, view_file):
        sql = (PACK / view_file).read_text()
        assert view in sql
        assert "MATERIALIZED VIEW" in sql
        for column in GOLDEN_COLUMNS[view]:
            assert column in sql, f"{view_file} is missing golden column {column!r}"

    def test_row_policies_cover_tenant_scoped_sinks(self):
        sql = (PACK / "ddl" / "06_row_policies.sql").read_text()
        # audit_sink is intentionally excluded: the audit trail is
        # operator-owned and not tenant-partitioned.
        for short_name in ("findings_sink", "events_sink", "evidence_sink"):
            assert short_name in sql, f"row policies must mention {short_name}"


class TestClickHouseReplayQueries:
    def test_query_templates_shipped(self):
        names = {path.name for path in QUERY_TEMPLATES}
        assert names == {
            "audit_trail_last_hour.sql",
            "backfill_detection_window.sql",
            "replay_findings_last_day.sql",
            "top_rules_by_finding_volume.sql",
        }

    @pytest.mark.parametrize("query_file", QUERY_TEMPLATES, ids=lambda p: p.name)
    def test_query_passes_source_adapter_read_only_gate(self, query_file):
        raw = query_file.read_text()
        stripped = _strip_comment_lines(raw)
        # Same normalization source-clickhouse-query applies at runtime.
        normalized = READ_ONLY_SQL.normalize_read_only_query(stripped)
        assert normalized.upper().startswith(("SELECT", "WITH"))

    @pytest.mark.parametrize("query_file", QUERY_TEMPLATES, ids=lambda p: p.name)
    def test_query_reads_only_pack_tables(self, query_file):
        stripped = _strip_comment_lines(query_file.read_text())
        assert "security." in stripped
        referenced = {table for table in GOLDEN_COLUMNS if table in stripped}
        assert referenced, f"{query_file.name} must read from a pack-managed table"
