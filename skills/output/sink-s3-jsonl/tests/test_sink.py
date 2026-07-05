"""Tests for sink-s3-jsonl."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "sink.py"
_SPEC = importlib.util.spec_from_file_location("sink_s3_jsonl", _SRC)
assert _SPEC and _SPEC.loader
_SINK = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SINK
_SPEC.loader.exec_module(_SINK)

_normalize_bucket = _SINK._normalize_bucket
_normalize_prefix = _SINK._normalize_prefix
_object_key = _SINK._object_key
_prepare_rows = _SINK._prepare_rows
_summary = _SINK._summary
main = _SINK.main


class _FakeClient:
    def __init__(self, *, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.calls = []

    def put_object(self, **kwargs) -> None:
        if self.should_fail:
            raise RuntimeError("write failed")
        self.calls.append(kwargs)


class TestNormalizeNames:
    def test_accepts_bucket_and_prefix(self):
        assert _normalize_bucket("my-sec-lake") == "my-sec-lake"
        assert _normalize_prefix("/findings/lateral-movement/") == "findings/lateral-movement"

    def test_rejects_invalid_bucket(self):
        try:
            _normalize_bucket("BadBucket")
        except ValueError as exc:
            assert "invalid S3 bucket name" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_invalid_prefix(self):
        try:
            _normalize_prefix("findings/*")
        except ValueError as exc:
            assert "invalid S3 prefix segment" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestPrepareRowsAndKey:
    def test_extracts_metadata_and_builds_deterministic_key(self):
        rows = _prepare_rows(
            [
                '{"schema_mode":"native","event_uid":"evt-1","finding_uid":"f-1"}\n',
                '{"metadata":{"uid":"evt-2"},"finding_info":{"uid":"f-2"}}\n',
            ]
        )

        assert rows[0].schema_mode == "native"
        assert rows[1].schema_mode == "ocsf"
        key = _object_key("findings/lm", rows, datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC))
        assert key.startswith("findings/lm/2026/04/15/20260415T120000Z-")
        assert key.endswith(".jsonl")

    def test_rejects_non_object_json(self):
        try:
            _prepare_rows(['["not","an","object"]\n'])
        except ValueError as exc:
            assert "expected a JSON object" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestWriteAndMain:
    def test_apply_writes_one_object(self, monkeypatch):
        fake = _FakeClient()
        monkeypatch.setattr(_SINK, "_client", lambda: fake)

        written = _SINK._write_object(
            "my-sec-lake",
            "findings/lm/2026/04/15/object.jsonl",
            _prepare_rows(['{"schema_mode":"native","event_uid":"evt-1","finding_uid":"f-1"}\n']),
        )

        assert written == 1
        assert len(fake.calls) == 1
        call = fake.calls[0]
        assert call["Bucket"] == "my-sec-lake"
        assert call["Key"] == "findings/lm/2026/04/15/object.jsonl"
        assert call["ContentType"] == "application/x-ndjson"
        assert call["Body"].endswith(b"\n")

    def test_summary_reports_dry_run(self):
        rows = _prepare_rows(['{"schema_mode":"native","event_uid":"evt-1"}\n'])
        result = _summary(
            bucket="my-sec-lake",
            prefix="findings/lm",
            object_key="findings/lm/2026/04/15/object.jsonl",
            rows=rows,
            dry_run=True,
            written_records=0,
        )

        assert result["record_type"] == "sink_result"
        assert result["sink"] == "s3"
        assert result["would_write_objects"] == 1
        assert result["would_write_records"] == 1

    def test_main_defaults_to_dry_run(self, monkeypatch, capsys):
        monkeypatch.setattr(
            _SINK.sys, "stdin", io.StringIO('{"schema_mode":"native","event_uid":"evt-1"}\n')
        )
        monkeypatch.setattr(
            _SINK,
            "_object_key",
            lambda prefix, rows: "findings/lm/2026/04/15/object.jsonl",
        )

        exit_code = main(["--bucket", "my-sec-lake", "--prefix", "findings/lm"])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is True
        assert payload["would_write_objects"] == 1
        assert payload["object_key"] == "findings/lm/2026/04/15/object.jsonl"

    def test_main_apply_writes_object(self, monkeypatch, capsys):
        fake = _FakeClient()
        monkeypatch.setattr(_SINK, "_client", lambda: fake)
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO('{"metadata":{"uid":"evt-2"}}\n'))
        monkeypatch.setattr(
            _SINK,
            "_object_key",
            lambda prefix, rows: "evidence/ctrl/2026/04/15/object.jsonl",
        )

        exit_code = main(["--bucket", "my-sec-lake", "--prefix", "evidence/ctrl", "--apply"])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is False
        assert payload["written_objects"] == 1
        assert payload["written_records"] == 1
        assert fake.calls

    def test_main_apply_returns_error_when_write_fails(self, monkeypatch, capsys):
        fake = _FakeClient(should_fail=True)
        monkeypatch.setattr(_SINK, "_client", lambda: fake)
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO('{"metadata":{"uid":"evt-2"}}\n'))
        monkeypatch.setattr(
            _SINK,
            "_object_key",
            lambda prefix, rows: "evidence/ctrl/2026/04/15/object.jsonl",
        )

        exit_code = main(["--bucket", "my-sec-lake", "--prefix", "evidence/ctrl", "--apply"])

        assert exit_code == 1
        assert "write failed" in capsys.readouterr().err

    def test_main_requires_records(self, monkeypatch, capsys):
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO(""))

        exit_code = main(["--bucket", "my-sec-lake", "--prefix", "findings/lm"])

        assert exit_code == 1
        assert "stdin did not contain any JSONL records" in capsys.readouterr().err
