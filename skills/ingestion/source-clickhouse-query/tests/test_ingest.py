"""Tests for source-clickhouse-query."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("source_clickhouse_query", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INGEST)

_normalize_query = _INGEST._normalize_query
_read_query = _INGEST._read_query
fetch_rows = _INGEST.fetch_rows


class _FakeResult:
    def __init__(self, column_names, result_rows):
        self.column_names = column_names
        self.result_rows = result_rows


class _FakeClient:
    def __init__(self, column_names, rows):
        self._result = _FakeResult(column_names, rows)
        self.queries: list[str] = []
        self.closed = False

    def query(self, statement):
        self.queries.append(statement)
        return self._result

    def close(self):
        self.closed = True


class TestNormalizeQuery:
    def test_allows_select(self):
        assert _normalize_query("SELECT * FROM foo") == "SELECT * FROM foo"

    def test_allows_with(self):
        assert (
            _normalize_query("WITH t AS (SELECT 1) SELECT * FROM t")
            == "WITH t AS (SELECT 1) SELECT * FROM t"
        )

    def test_allows_describe(self):
        assert (
            _normalize_query("DESCRIBE TABLE security.findings_sink")
            == "DESCRIBE TABLE security.findings_sink"
        )

    def test_rejects_multiple_statements(self):
        try:
            _normalize_query("SELECT 1; SELECT 2")
        except ValueError as exc:
            assert "multiple SQL statements" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_write_statement(self):
        try:
            _normalize_query("INSERT INTO foo VALUES (1)")
        except ValueError as exc:
            assert "only SELECT, WITH, SHOW, and DESCRIBE" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_drop_statement(self):
        try:
            _normalize_query("DROP TABLE foo")
        except ValueError as exc:
            assert "only SELECT, WITH, SHOW, and DESCRIBE" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_optimize_statement(self):
        try:
            _normalize_query("OPTIMIZE TABLE security.findings_sink")
        except ValueError as exc:
            assert "only SELECT, WITH, SHOW, and DESCRIBE" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_sql_comments(self):
        try:
            _normalize_query("SELECT * FROM foo -- drop everything")
        except ValueError as exc:
            assert "comments, session controls, or write-oriented keywords" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_block_comments(self):
        try:
            _normalize_query("SELECT 1 /* note */")
        except ValueError as exc:
            assert "comments, session controls, or write-oriented keywords" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_session_set(self):
        try:
            _normalize_query("SET max_threads = 4")
        except ValueError as exc:
            assert "only SELECT, WITH, SHOW, and DESCRIBE" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_allows_keyword_inside_string_literal(self):
        assert (
            _normalize_query("SELECT 'drop table foo' AS sample")
            == "SELECT 'drop table foo' AS sample"
        )

    def test_rejects_unbalanced_parentheses(self):
        try:
            _normalize_query("SELECT (1")
        except ValueError as exc:
            assert "unbalanced parentheses" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestReadQuery:
    def test_prefers_cli_query(self):
        assert _read_query("SELECT 1", ["SELECT 2"]) == "SELECT 1"

    def test_falls_back_to_stdin(self):
        assert _read_query(None, ["SELECT ", "1"]) == "SELECT 1"

    def test_empty_inputs_raise(self):
        try:
            _read_query(None, [])
        except ValueError as exc:
            assert "read-only SQL query" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestFetchRows:
    def test_fetches_rows_zipped_with_columns(self, monkeypatch):
        fake = _FakeClient(
            column_names=["event_uid", "schema_mode", "payload"],
            rows=[
                ("evt-1", "ocsf", '{"class_uid":6003}'),
                ("evt-2", "ocsf", '{"class_uid":4001}'),
            ],
        )
        monkeypatch.setattr(_INGEST, "_connect", lambda: fake)

        rows = fetch_rows("SELECT event_uid, schema_mode, payload FROM security.events_sink")

        assert rows == [
            {"event_uid": "evt-1", "schema_mode": "ocsf", "payload": '{"class_uid":6003}'},
            {"event_uid": "evt-2", "schema_mode": "ocsf", "payload": '{"class_uid":4001}'},
        ]
        assert fake.queries == ["SELECT event_uid, schema_mode, payload FROM security.events_sink"]
        assert fake.closed is True

    def test_returns_empty_list_for_empty_resultset(self, monkeypatch):
        fake = _FakeClient(column_names=["payload"], rows=[])
        monkeypatch.setattr(_INGEST, "_connect", lambda: fake)

        rows = fetch_rows("SELECT payload FROM security.findings_sink")

        assert rows == []
        assert fake.closed is True
