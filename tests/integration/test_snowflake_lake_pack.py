"""Contract tests for the Snowflake data-lake pack.

Mirrors the ClickHouse lake-pack tests: golden column locks on the DDL and
dynamic-table rollups, retention/governance markers, and read-only enforcement
for the replay query templates that `source-snowflake-query` executes.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "packs" / "snowflake"

GOLDEN_COLUMNS = json.loads((PACK / "golden" / "expected_columns.json").read_text())

SINK_TABLES = {
    "security_db.ops.findings_sink": "ddl/02_findings_sink.sql",
    "security_db.ops.events_sink": "ddl/03_events_sink.sql",
    "security_db.ops.evidence_sink": "ddl/04_evidence_sink.sql",
    "security_db.ops.audit_sink": "ddl/05_audit_sink.sql",
}
ROLLUP_TABLES = {
    "security_db.ops.findings_by_rule_hourly": "dynamic-tables/01_findings_by_rule_hourly.sql",
    "security_db.ops.events_by_class_daily": "dynamic-tables/02_events_by_class_daily.sql",
    "security_db.ops.remediations_by_outcome_daily": "dynamic-tables/03_remediations_by_outcome_daily.sql",
}
QUERY_TEMPLATES = sorted((PACK / "queries").glob("*.sql"))


def _load_read_only_sql():
    path = ROOT / "skills" / "_shared" / "read_only_sql.py"
    spec = importlib.util.spec_from_file_location("read_only_sql_snowflake_pack_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


READ_ONLY_SQL = _load_read_only_sql()


def _strip_comment_lines(sql: str) -> str:
    return "\n".join(line for line in sql.splitlines() if not line.lstrip().startswith("--"))


class TestSnowflakeLakeDdl:
    def test_golden_covers_every_sink_and_rollup(self):
        assert set(GOLDEN_COLUMNS) == set(SINK_TABLES) | set(ROLLUP_TABLES)

    @pytest.mark.parametrize("table,ddl_file", sorted(SINK_TABLES.items()))
    def test_sink_ddl_declares_golden_columns(self, table, ddl_file):
        sql = (PACK / ddl_file).read_text()
        assert f"CREATE TABLE IF NOT EXISTS {table}" in sql
        for column in GOLDEN_COLUMNS[table]:
            assert column in sql, f"{ddl_file} is missing golden column {column!r}"

    @pytest.mark.parametrize("table,ddl_file", sorted(SINK_TABLES.items()))
    def test_sink_ddl_keeps_lake_contract_markers(self, table, ddl_file):
        sql = (PACK / ddl_file).read_text()
        assert "CLUSTER BY" in sql, f"{ddl_file} must keep its clustering key"
        assert "DATA_RETENTION_TIME_IN_DAYS" in sql, f"{ddl_file} must keep Time Travel retention"

    @pytest.mark.parametrize("table,table_file", sorted(ROLLUP_TABLES.items()))
    def test_rollup_dynamic_tables_declare_golden_columns(self, table, table_file):
        sql = (PACK / table_file).read_text()
        assert table in sql
        assert "DYNAMIC TABLE" in sql
        for column in GOLDEN_COLUMNS[table]:
            assert column in sql, f"{table_file} is missing golden column {column!r}"

    def test_row_access_policies_cover_tenant_scoped_sinks(self):
        sql = (PACK / "ddl" / "06_row_policies.sql").read_text()
        # audit_sink is intentionally excluded: the audit trail is
        # operator-owned and not tenant-partitioned.
        for short_name in ("findings_sink", "events_sink", "evidence_sink"):
            assert short_name in sql, f"row access policies must mention {short_name}"

    def test_iceberg_variant_stays_optional(self):
        sql = (PACK / "ddl" / "07_iceberg_open_format.sql").read_text()
        assert "ICEBERG" in sql.upper()


class TestSnowflakeReplayQueries:
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
        # Same normalization source-snowflake-query applies at runtime.
        normalized = READ_ONLY_SQL.normalize_read_only_query(stripped)
        assert normalized.upper().startswith(("SELECT", "WITH"))

    @pytest.mark.parametrize("query_file", QUERY_TEMPLATES, ids=lambda p: p.name)
    def test_query_reads_only_pack_tables(self, query_file):
        stripped = _strip_comment_lines(query_file.read_text())
        assert "security_db.ops." in stripped
        referenced = {table for table in GOLDEN_COLUMNS if table in stripped}
        assert referenced, f"{query_file.name} must read from a pack-managed table"
