"""Tests for source-s3-select."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("source_s3_select", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INGEST)

_input_serialization = _INGEST._input_serialization
_normalize_expression = _INGEST._normalize_expression
_read_expression = _INGEST._read_expression
fetch_rows = _INGEST.fetch_rows


class _FakeS3Client:
    def __init__(self, payload):
        self.payload = payload
        self.kwargs = None

    def select_object_content(self, **kwargs):
        self.kwargs = kwargs
        return {"Payload": self.payload}


class TestNormalizeExpression:
    def test_allows_select(self):
        assert _normalize_expression("SELECT * FROM S3Object s") == "SELECT * FROM S3Object s"

    def test_rejects_multiple_statements(self):
        try:
            _normalize_expression("SELECT * FROM S3Object s; SELECT 2")
        except ValueError as exc:
            assert "multiple SQL statements" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_rejects_write_statement(self):
        try:
            _normalize_expression("DELETE FROM S3Object s")
        except ValueError as exc:
            assert "only SELECT statements" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestReadExpression:
    def test_prefers_cli_expression(self):
        assert (
            _read_expression("SELECT * FROM S3Object s", ["SELECT 2"]) == "SELECT * FROM S3Object s"
        )

    def test_falls_back_to_stdin(self):
        assert (
            _read_expression(None, ["SELECT * ", "FROM S3Object s"]) == "SELECT * FROM S3Object s"
        )


class TestInputSerialization:
    def test_builds_lines_serialization(self):
        assert _input_serialization("lines", "none") == {"JSON": {"Type": "LINES"}}

    def test_builds_document_serialization_with_compression(self):
        assert _input_serialization("document", "gzip") == {
            "JSON": {"Type": "DOCUMENT"},
            "CompressionType": "GZIP",
        }


class TestFetchRows:
    def test_fetches_json_objects(self, monkeypatch):
        fake = _FakeS3Client(
            [
                {"Records": {"Payload": b'{"event":"a"}\n{"event":"b"}\n'}},
                {"End": {}},
            ]
        )
        monkeypatch.setattr(_INGEST, "_client", lambda: fake)

        rows = fetch_rows(
            bucket="sec-lake",
            key="events.jsonl",
            expression="SELECT * FROM S3Object s",
            input_serialization="lines",
            compression_type="none",
        )

        assert rows == [{"event": "a"}, {"event": "b"}]
        assert fake.kwargs is not None
        assert fake.kwargs["Bucket"] == "sec-lake"
        assert fake.kwargs["Key"] == "events.jsonl"
        assert fake.kwargs["Expression"] == "SELECT * FROM S3Object s"
        assert fake.kwargs["InputSerialization"] == {"JSON": {"Type": "LINES"}}

    def test_wraps_non_dict_rows(self, monkeypatch):
        fake = _FakeS3Client(
            [
                {"Records": {"Payload": b'"value"\n'}},
            ]
        )
        monkeypatch.setattr(_INGEST, "_client", lambda: fake)

        rows = fetch_rows(
            bucket="sec-lake",
            key="values.jsonl",
            expression="SELECT _1 FROM S3Object s",
            input_serialization="lines",
            compression_type="none",
        )

        assert rows == [{"value": "value"}]

    def test_stitches_partial_record_chunks(self, monkeypatch):
        fake = _FakeS3Client(
            [
                {"Records": {"Payload": b'{"event":"a"'}},
                {"Records": {"Payload": b"}\n"}},
            ]
        )
        monkeypatch.setattr(_INGEST, "_client", lambda: fake)

        rows = fetch_rows(
            bucket="sec-lake",
            key="events.jsonl",
            expression="SELECT * FROM S3Object s",
            input_serialization="lines",
            compression_type="none",
        )

        assert rows == [{"event": "a"}]
