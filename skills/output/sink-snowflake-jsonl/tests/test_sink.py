"""Tests for sink-snowflake-jsonl."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "sink.py"
_SPEC = importlib.util.spec_from_file_location("sink_snowflake_jsonl", _SRC)
assert _SPEC and _SPEC.loader
_SINK = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SINK
_SPEC.loader.exec_module(_SINK)

_normalize_table_name = _SINK._normalize_table_name
_prepare_rows = _SINK._prepare_rows
_summary = _SINK._summary
main = _SINK.main


class _FakeCursor:
    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.raise_message = "insert failed"
        self.executemany_sql = ""
        self.executemany_params = []
        self.closed = False

    def executemany(self, sql, params) -> None:
        self.executemany_sql = sql
        self.executemany_params = list(params)
        if self.should_fail:
            raise RuntimeError(self.raise_message)

    def close(self) -> None:
        self.closed = True


class _FakeConnection:
    def __init__(self, *, should_fail: bool = False) -> None:
        self.cursor_instance = _FakeCursor(should_fail=should_fail)
        self.closed = False
        self.autocommit_calls = []
        self.commit_called = False
        self.rollback_called = False

    def autocommit(self, value) -> None:
        self.autocommit_calls.append(value)

    def cursor(self):
        return self.cursor_instance

    def commit(self) -> None:
        self.commit_called = True

    def rollback(self) -> None:
        self.rollback_called = True

    def close(self) -> None:
        self.closed = True


class TestNormalizeTableName:
    def test_accepts_database_schema_table(self):
        assert (
            _normalize_table_name("security_db.ops.findings_sink")
            == '"security_db"."ops"."findings_sink"'
        )

    def test_rejects_invalid_identifier(self):
        try:
            _normalize_table_name("security_db.ops.findings;drop")
        except ValueError as exc:
            assert "invalid Snowflake identifier" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestPrepareRows:
    def test_extracts_metadata_from_native_and_ocsf(self):
        rows = _prepare_rows(
            [
                '{"schema_mode":"native","event_uid":"evt-1","finding_uid":"f-1"}\n',
                '{"metadata":{"uid":"evt-2"},"finding_info":{"uid":"f-2"}}\n',
            ]
        )

        assert rows[0].schema_mode == "native"
        assert rows[0].event_uid == "evt-1"
        assert rows[0].finding_uid == "f-1"
        assert rows[1].schema_mode == "ocsf"
        assert rows[1].event_uid == "evt-2"
        assert rows[1].finding_uid == "f-2"

    def test_rejects_non_object_json(self):
        try:
            _prepare_rows(['["not","an","object"]\n'])
        except ValueError as exc:
            assert "expected a JSON object" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestInsertAndMain:
    def test_apply_uses_parameterized_insert(self, monkeypatch):
        fake = _FakeConnection()
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)

        inserted = _SINK._insert_rows(
            '"security_db"."ops"."findings_sink"',
            _prepare_rows(['{"schema_mode":"native","event_uid":"evt-1","finding_uid":"f-1"}\n']),
        )

        assert inserted == 1
        assert "PARSE_JSON(%s)" in fake.cursor_instance.executemany_sql
        assert "INSERT INTO" in fake.cursor_instance.executemany_sql
        assert fake.cursor_instance.executemany_params == [
            (
                '{"event_uid":"evt-1","finding_uid":"f-1","schema_mode":"native"}',
                "native",
                "evt-1",
                "f-1",
            )
        ]
        assert fake.commit_called is True
        assert fake.rollback_called is False
        assert fake.cursor_instance.closed is True
        assert fake.closed is True

    def test_insert_rolls_back_when_executemany_fails(self, monkeypatch):
        fake = _FakeConnection(should_fail=True)
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)

        try:
            _SINK._insert_rows(
                '"security_db"."ops"."findings_sink"',
                _prepare_rows(
                    ['{"schema_mode":"native","event_uid":"evt-1","finding_uid":"f-1"}\n']
                ),
            )
        except RuntimeError as exc:
            assert "insert failed" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")

        assert fake.commit_called is False
        assert fake.rollback_called is True
        assert fake.cursor_instance.closed is True
        assert fake.closed is True

    def test_summary_reports_dry_run(self):
        rows = _prepare_rows(['{"schema_mode":"native","event_uid":"evt-1"}\n'])
        result = _summary('"security_db"."ops"."findings_sink"', rows, True, 0)

        assert result["record_type"] == "sink_result"
        assert result["dry_run"] is True
        assert result["would_insert_records"] == 1
        assert result["inserted_records"] == 0

    def test_main_defaults_to_dry_run(self, monkeypatch, capsys):
        monkeypatch.setattr(
            _SINK.sys, "stdin", io.StringIO('{"schema_mode":"native","event_uid":"evt-1"}\n')
        )

        exit_code = main(["--table", "security_db.ops.findings_sink"])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is True
        assert payload["would_insert_records"] == 1

    def test_main_apply_executes_insert(self, monkeypatch, capsys):
        fake = _FakeConnection()
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO('{"metadata":{"uid":"evt-2"}}\n'))

        exit_code = main(["--table", "security_db.ops.findings_sink", "--apply"])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is False
        assert payload["inserted_records"] == 1
        assert fake.cursor_instance.executemany_params

    def test_main_apply_returns_error_when_insert_fails(self, monkeypatch, capsys):
        fake = _FakeConnection(should_fail=True)
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO('{"metadata":{"uid":"evt-2"}}\n'))

        exit_code = main(["--table", "security_db.ops.findings_sink", "--apply"])

        assert exit_code == 1
        assert "insert failed" in capsys.readouterr().err
        assert fake.commit_called is False
        assert fake.rollback_called is True

    def test_main_requires_records(self, monkeypatch, capsys):
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO(""))

        exit_code = main(["--table", "security_db.ops.findings_sink"])

        assert exit_code == 1
        assert "stdin did not contain any JSONL records" in capsys.readouterr().err
