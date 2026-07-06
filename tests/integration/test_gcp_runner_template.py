from __future__ import annotations

import base64
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

_PASSTHROUGH_CMD = f'{sys.executable} -c "import sys; sys.stdout.write(sys.stdin.read())"'
_FAILING_CMD = f"{sys.executable} -c \"import sys; sys.stderr.write('boom'); sys.exit(3)\""


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


INGEST = _load_module(
    "cloud_security_gcp_runner_ingest_handler_test",
    ROOT / "runners" / "gcp-gcs-pubsub-detect" / "src" / "ingest_handler.py",
)
DETECT = _load_module(
    "cloud_security_gcp_runner_detect_handler_test",
    ROOT / "runners" / "gcp-gcs-pubsub-detect" / "src" / "detect_handler.py",
)


class TestGcpGcsPubsubDetectRunner:
    def test_publish_findings_waits_for_pubsub_results(self):
        seen: list[str] = []

        class _FakeFuture:
            def __init__(self, line: str):
                self.line = line

            def result(self):
                seen.append(self.line)
                return "message-id"

        class _FakePublisher:
            def publish(self, topic: str, payload: bytes):
                assert topic == "projects/test/topics/findings"
                return _FakeFuture(payload.decode("utf-8"))

        DETECT._publish_findings(
            _FakePublisher(),
            "projects/test/topics/findings",
            [("line-1", "uid-1"), ("line-2", "uid-2")],
        )

        assert seen == ["line-1", "line-2"]

    def test_ingest_skill_command_requires_env(self, monkeypatch):
        monkeypatch.delenv("INGEST_SKILL_CMD", raising=False)
        try:
            INGEST._skill_command()
        except ValueError as exc:
            assert "INGEST_SKILL_CMD" in str(exc)
        else:
            raise AssertionError("expected INGEST_SKILL_CMD validation failure")

    def test_ingest_detect_topic_requires_env(self, monkeypatch):
        monkeypatch.delenv("DETECT_TOPIC", raising=False)
        try:
            INGEST._detect_topic()
        except ValueError as exc:
            assert "DETECT_TOPIC" in str(exc)
        else:
            raise AssertionError("expected DETECT_TOPIC validation failure")

    def test_detect_extracts_uid_from_finding_info(self):
        record = {"finding_info": {"uid": "det-123"}, "metadata": {"uid": "meta-123"}}
        assert DETECT._extract_uid(record) == "det-123"

    def test_detect_falls_back_to_metadata_uid(self):
        record = {"metadata": {"uid": "meta-123"}}
        assert DETECT._extract_uid(record) == "meta-123"

    def test_detect_falls_back_to_event_uid(self):
        record = {"event_uid": "evt-123"}
        assert DETECT._extract_uid(record) == "evt-123"

    def test_decode_pubsub_event(self):
        payload = "line-1\nline-2\n".encode("utf-8")
        event = {"data": base64.b64encode(payload).decode("ascii")}
        assert DETECT._decode_pubsub_event(event) == ["line-1", "line-2"]

    def test_detect_ttl_days_default_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("DEDUPE_TTL_DAYS", raising=False)
        assert DETECT._dedupe_ttl_days() == 30

    def test_detect_ttl_days_respects_env(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "14")
        assert DETECT._dedupe_ttl_days() == 14

    def test_detect_ttl_days_rejects_non_integer(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "fast")
        try:
            DETECT._dedupe_ttl_days()
        except ValueError as exc:
            assert "DEDUPE_TTL_DAYS" in str(exc)
        else:
            raise AssertionError("expected ValueError on non-integer DEDUPE_TTL_DAYS")

    def test_detect_ttl_days_rejects_out_of_range(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "0")
        try:
            DETECT._dedupe_ttl_days()
        except ValueError as exc:
            assert "between 1 and 365" in str(exc)
        else:
            raise AssertionError("expected ValueError on out-of-range DEDUPE_TTL_DAYS")

    def test_detect_expires_at_adds_configured_ttl(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "10")
        base = datetime(2026, 4, 17, tzinfo=UTC)
        assert DETECT._expires_at(now=base) == datetime(2026, 4, 27, tzinfo=UTC)

    def test_decode_pubsub_event_without_data_returns_empty(self):
        assert DETECT._decode_pubsub_event({}) == []
        assert DETECT._decode_pubsub_event({"data": ""}) == []

    def test_ingest_run_skill_surfaces_skill_stderr(self, monkeypatch):
        monkeypatch.setenv("INGEST_SKILL_CMD", _FAILING_CMD)
        with pytest.raises(RuntimeError, match="boom"):
            INGEST._run_skill("line-1\n")

    def test_ingest_gcs_event_end_to_end(self, monkeypatch):
        monkeypatch.setenv("INGEST_SKILL_CMD", _PASSTHROUGH_CMD)
        monkeypatch.setenv("DETECT_TOPIC", "projects/test/topics/detect")

        monkeypatch.setattr(
            INGEST, "_read_object", lambda bucket, name: f"{bucket}/{name}:line-1\nline-2\n"
        )
        published: list[tuple[str, bytes]] = []

        class _FakePublisher:
            def publish(self, topic, payload):
                published.append((topic, payload))

        monkeypatch.setattr(INGEST, "_publisher_client", lambda: _FakePublisher())

        result = INGEST.handle_gcs_event({"bucket": "raw-bucket", "name": "audit/day1.jsonl"}, None)

        assert result == {"objects_processed": 1, "messages_enqueued": 2}
        assert published == [
            ("projects/test/topics/detect", b"raw-bucket/audit/day1.jsonl:line-1"),
            ("projects/test/topics/detect", b"line-2"),
        ]

    def test_detect_pubsub_event_end_to_end_dedupes(self, monkeypatch):
        monkeypatch.setenv("DETECT_SKILL_CMD", _PASSTHROUGH_CMD)
        monkeypatch.setenv("FINDINGS_TOPIC", "projects/test/topics/findings")

        dedupe_results = iter([True, False])
        monkeypatch.setattr(DETECT, "_put_if_new", lambda uid, payload: next(dedupe_results))
        monkeypatch.setattr(DETECT, "_publisher_client", lambda: object())
        published: list[tuple[str, str]] = []
        monkeypatch.setattr(
            DETECT,
            "_publish_findings",
            lambda publisher, topic, records: published.extend(records),
        )

        finding_new = json.dumps({"finding_info": {"uid": "finding-new"}})
        finding_dup = json.dumps({"event_uid": "event-dup"})
        payload = f"{finding_new}\n{finding_dup}\n".encode("utf-8")
        event = {"data": base64.b64encode(payload).decode("ascii")}

        result = DETECT.handle_pubsub_event(event, None)

        assert result == {"messages_processed": 2, "published": 1, "duplicates": 1}
        assert published == [(finding_new, "finding-new")]

    def test_detect_put_if_new_returns_false_on_conflict(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_COLLECTION", "dedupe")
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "30")

        class _FakeDocument:
            def __init__(self, existing: set[str], uid: str):
                self.existing = existing
                self.uid = uid

            def create(self, item):
                if self.uid in self.existing:
                    raise DETECT.Conflict("already exists")
                self.existing.add(self.uid)

        class _FakeCollection:
            def __init__(self, existing: set[str]):
                self.existing = existing

            def document(self, uid):
                return _FakeDocument(self.existing, uid)

        class _FakeFirestore:
            def __init__(self):
                self.existing: set[str] = set()

            def collection(self, name):
                assert name == "dedupe"
                return _FakeCollection(self.existing)

        client = _FakeFirestore()
        monkeypatch.setattr(DETECT, "_firestore_client", lambda: client)

        assert DETECT._put_if_new("uid-1", "payload") is True
        assert DETECT._put_if_new("uid-1", "payload") is False
