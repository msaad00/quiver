"""Tests for source-snowflake-query."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("source_snowflake_query", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INGEST)

_normalize_query = _INGEST._normalize_query
_read_query = _INGEST._read_query
fetch_rows = _INGEST.fetch_rows


class _FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executed = None
        self.closed = False

    def execute(self, query):
        self.executed = query

    def fetchall(self):
        return self.rows

    def close(self):
        self.closed = True


class _FakeConnection:
    def __init__(self, rows):
        self.rows = rows
        self.closed = False
        self.cursor_instance = None

    def cursor(self, _cursor_cls):
        self.cursor_instance = _FakeCursor(self.rows)
        return self.cursor_instance

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

    def test_rejects_multiple_statements(self):
        try:
            _normalize_query("SELECT 1; SELECT 2")
        except ValueError as exc:
            assert "multiple SQL statements" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_write_statement(self):
        try:
            _normalize_query("DELETE FROM foo")
        except ValueError as exc:
            assert "only SELECT, WITH, SHOW, and DESCRIBE" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_sql_comments(self):
        try:
            _normalize_query("SELECT * FROM foo -- nope")
        except ValueError as exc:
            assert "comments, session controls, or write-oriented keywords" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_disallowed_control_keyword(self):
        try:
            _normalize_query("SELECT SYSTEM$ABORT_SESSION('x')")
        except ValueError as exc:
            assert "comments, session controls, or write-oriented keywords" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_allows_keyword_inside_string_literal(self):
        assert (
            _normalize_query("SELECT 'delete from foo' AS sample")
            == "SELECT 'delete from foo' AS sample"
        )

    def test_rejects_session_mutation_keyword(self):
        try:
            _normalize_query("SELECT * FROM foo SET x = 1")
        except ValueError as exc:
            assert "comments, session controls, or write-oriented keywords" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_optimizer_control_keyword(self):
        try:
            _normalize_query("OPTIMIZE foo")
        except ValueError as exc:
            assert "only SELECT, WITH, SHOW, and DESCRIBE" in str(exc)
        else:
            raise AssertionError("expected ValueError")

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


class TestFetchRows:
    def test_fetches_dict_rows(self, monkeypatch):
        fake = _FakeConnection([{"EVENT_TIME": "2026-04-15T00:00:00Z", "ACTION": "AssumeRole"}])
        monkeypatch.setattr(_INGEST, "_connect", lambda: fake)
        monkeypatch.setattr(_INGEST, "_dict_cursor_class", lambda: object)

        rows = fetch_rows("SELECT * FROM sec.cloudtrail_ocsf")

        assert rows == [{"EVENT_TIME": "2026-04-15T00:00:00Z", "ACTION": "AssumeRole"}]
        assert fake.cursor_instance is not None
        assert fake.cursor_instance.executed == "SELECT * FROM sec.cloudtrail_ocsf"
        assert fake.cursor_instance.closed is True
        assert fake.closed is True

    def test_wraps_non_dict_rows(self, monkeypatch):
        fake = _FakeConnection([("value",)])
        monkeypatch.setattr(_INGEST, "_connect", lambda: fake)
        monkeypatch.setattr(_INGEST, "_dict_cursor_class", lambda: object)

        rows = fetch_rows("SHOW TABLES")

        assert rows == [{"value": ("value",)}]
