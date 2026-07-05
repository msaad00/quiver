"""Tests for sink-clickhouse-jsonl."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "sink.py"
_SPEC = importlib.util.spec_from_file_location("sink_clickhouse_jsonl", _SRC)
assert _SPEC and _SPEC.loader
_SINK = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SINK
_SPEC.loader.exec_module(_SINK)

_normalize_table_name = _SINK._normalize_table_name
_prepare_rows = _SINK._prepare_rows
_summary = _SINK._summary
main = _SINK.main


class _FakeClient:
    def __init__(self, *, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.calls = []
        self.closed = False

    def insert(self, *, table, data, column_names) -> None:
        if self.should_fail:
            raise RuntimeError("insert failed")
        self.calls.append(
            {
                "table": table,
                "data": data,
                "column_names": column_names,
            }
        )

    def close(self) -> None:
        self.closed = True


class TestNormalizeTableName:
    def test_accepts_database_table(self):
        assert _normalize_table_name("security.findings_sink") == "security.findings_sink"

    def test_rejects_invalid_identifier(self):
        try:
            _normalize_table_name("security.findings-sink")
        except ValueError as exc:
            assert "invalid ClickHouse identifier" in str(exc)
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
        assert rows[1].schema_mode == "ocsf"
        assert rows[1].event_uid == "evt-2"
        assert rows[1].finding_uid == "f-2"


class TestInsertAndMain:
    def test_apply_uses_client_insert(self, monkeypatch):
        fake = _FakeClient()
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)

        inserted = _SINK._insert_rows(
            "security.findings_sink",
            _prepare_rows(['{"schema_mode":"native","event_uid":"evt-1","finding_uid":"f-1"}\n']),
        )

        assert inserted == 1
        assert fake.calls == [
            {
                "table": "security.findings_sink",
                "data": [
                    [
                        '{"event_uid":"evt-1","finding_uid":"f-1","schema_mode":"native"}',
                        "native",
                        "evt-1",
                        "f-1",
                    ]
                ],
                "column_names": ["payload", "schema_mode", "event_uid", "finding_uid"],
            }
        ]
        assert fake.closed is True

    def test_insert_closes_client_when_insert_fails(self, monkeypatch):
        fake = _FakeClient(should_fail=True)
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)

        try:
            _SINK._insert_rows(
                "security.findings_sink",
                _prepare_rows(
                    ['{"schema_mode":"native","event_uid":"evt-1","finding_uid":"f-1"}\n']
                ),
            )
        except RuntimeError as exc:
            assert "insert failed" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")

        assert fake.closed is True

    def test_summary_reports_dry_run(self):
        rows = _prepare_rows(['{"schema_mode":"native","event_uid":"evt-1"}\n'])
        result = _summary("security.findings_sink", rows, True, 0)

        assert result["record_type"] == "sink_result"
        assert result["sink"] == "clickhouse"
        assert result["would_insert_records"] == 1

    def test_main_defaults_to_dry_run(self, monkeypatch, capsys):
        monkeypatch.setattr(
            _SINK.sys, "stdin", io.StringIO('{"schema_mode":"native","event_uid":"evt-1"}\n')
        )

        exit_code = main(["--table", "security.findings_sink"])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is True
        assert payload["would_insert_records"] == 1

    def test_main_apply_executes_insert(self, monkeypatch, capsys):
        fake = _FakeClient()
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO('{"metadata":{"uid":"evt-2"}}\n'))

        exit_code = main(["--table", "security.findings_sink", "--apply"])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is False
        assert payload["inserted_records"] == 1
        assert fake.calls

    def test_main_apply_returns_error_when_insert_fails(self, monkeypatch, capsys):
        fake = _FakeClient(should_fail=True)
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO('{"metadata":{"uid":"evt-2"}}\n'))

        exit_code = main(["--table", "security.findings_sink", "--apply"])

        assert exit_code == 1
        assert "insert failed" in capsys.readouterr().err
        assert fake.closed is True

    def test_main_requires_records(self, monkeypatch, capsys):
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO(""))

        exit_code = main(["--table", "security.findings_sink"])

        assert exit_code == 1
        assert "stdin did not contain any JSONL records" in capsys.readouterr().err
