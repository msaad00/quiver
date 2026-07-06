from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# stdin -> stdout passthrough, used as a stand-in skill so handler tests
# exercise the real subprocess path without needing a cloud fixture.
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
    "cloud_security_runner_ingest_handler_test",
    ROOT / "runners" / "aws-s3-sqs-detect" / "src" / "ingest_handler.py",
)
DETECT = _load_module(
    "cloud_security_runner_detect_handler_test",
    ROOT / "runners" / "aws-s3-sqs-detect" / "src" / "detect_handler.py",
)


class TestAwsS3SqsDetectRunner:
    def test_ingest_skill_command_requires_env(self, monkeypatch):
        monkeypatch.delenv("INGEST_SKILL_CMD", raising=False)
        try:
            INGEST._skill_command()
        except ValueError as exc:
            assert "INGEST_SKILL_CMD" in str(exc)
        else:
            raise AssertionError("expected INGEST_SKILL_CMD validation failure")

    def test_ingest_batches_lines_for_sqs_limits(self):
        batches = list(INGEST._batched([str(i) for i in range(23)], size=10))
        assert [len(batch) for batch in batches] == [10, 10, 3]

    def test_detect_extracts_uid_from_finding_info(self):
        record = {"finding_info": {"uid": "det-123"}, "metadata": {"uid": "meta-123"}}
        assert DETECT._extract_uid(record) == "det-123"

    def test_detect_falls_back_to_metadata_uid(self):
        record = {"metadata": {"uid": "meta-123"}}
        assert DETECT._extract_uid(record) == "meta-123"

    def test_detect_falls_back_to_event_uid(self):
        record = {"event_uid": "evt-123"}
        assert DETECT._extract_uid(record) == "evt-123"

    def test_detect_ttl_days_default_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("DEDUPE_TTL_DAYS", raising=False)
        assert DETECT._dedupe_ttl_days() == 30

    def test_detect_ttl_days_respects_env(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "7")
        assert DETECT._dedupe_ttl_days() == 7

    def test_detect_ttl_days_rejects_non_integer(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "twelve")
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
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "30")
        base = 1_700_000_000
        assert DETECT._expires_at(now=base) == base + 30 * 86_400

    def test_detect_expires_at_uses_default_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("DEDUPE_TTL_DAYS", raising=False)
        base = 1_700_000_000
        assert DETECT._expires_at(now=base) == base + 30 * 86_400

    def test_detect_publish_findings_uses_sns_batches(self, monkeypatch):
        seen_batches: list[list[dict[str, str]]] = []

        class _FakeClient:
            def publish_batch(self, **kwargs):
                seen_batches.append(kwargs["PublishBatchRequestEntries"])
                return {"Failed": []}

        monkeypatch.setattr(DETECT, "_sns_client", lambda: _FakeClient())
        monkeypatch.setattr(DETECT, "_sns_topic", lambda: "arn:aws:sns:us-east-1:123:topic")

        records = [(f"line-{idx}", f"uid-{idx}") for idx in range(12)]
        DETECT._publish_findings(records)

        assert [len(batch) for batch in seen_batches] == [10, 2]
        assert seen_batches[0][0]["Subject"] == "skill-finding:uid-0"

    def test_detect_publish_findings_raises_on_partial_failure(self, monkeypatch):
        class _FakeClient:
            def publish_batch(self, **kwargs):
                return {"Failed": [{"Id": "0-0"}]}

        monkeypatch.setattr(DETECT, "_sns_client", lambda: _FakeClient())
        monkeypatch.setattr(DETECT, "_sns_topic", lambda: "arn:aws:sns:us-east-1:123:topic")

        with pytest.raises(RuntimeError, match="publish_batch failed"):
            DETECT._publish_findings([("line-0", "uid-0")])

    def test_ingest_run_skill_passes_payload_through(self, monkeypatch):
        monkeypatch.setenv("INGEST_SKILL_CMD", _PASSTHROUGH_CMD)
        assert INGEST._run_skill("line-1\n\nline-2\n") == ["line-1", "line-2"]

    def test_ingest_run_skill_surfaces_skill_stderr(self, monkeypatch):
        monkeypatch.setenv("INGEST_SKILL_CMD", _FAILING_CMD)
        with pytest.raises(RuntimeError, match="boom"):
            INGEST._run_skill("line-1\n")

    def test_detect_run_skill_joins_lines_for_stdin(self, monkeypatch):
        monkeypatch.setenv("DETECT_SKILL_CMD", _PASSTHROUGH_CMD)
        assert DETECT._run_skill(["line-1", "line-2"]) == ["line-1", "line-2"]

    def test_detect_extract_uid_rejects_record_without_identity(self):
        with pytest.raises(ValueError, match="finding_info.uid"):
            DETECT._extract_uid({"metadata": {"uid": ""}})

    def test_ingest_lambda_handler_end_to_end(self, monkeypatch):
        monkeypatch.setenv("INGEST_SKILL_CMD", _PASSTHROUGH_CMD)
        monkeypatch.setenv("DETECT_QUEUE_URL", "https://sqs.test/queue")

        class _FakeBody:
            def read(self):
                return b"line-1\nline-2\n"

        class _FakeS3:
            def get_object(self, Bucket, Key):
                assert (Bucket, Key) == ("raw-bucket", "audit/day1.jsonl")
                return {"Body": _FakeBody()}

        sent: list[tuple[str, str]] = []

        class _FakeSqs:
            def send_message(self, QueueUrl, MessageBody):
                sent.append((QueueUrl, MessageBody))

        monkeypatch.setattr(INGEST, "_s3_client", lambda: _FakeS3())
        monkeypatch.setattr(INGEST, "_sqs_client", lambda: _FakeSqs())

        event = {
            "Records": [
                {"s3": {"bucket": {"name": "raw-bucket"}, "object": {"key": "audit/day1.jsonl"}}}
            ]
        }
        result = INGEST.lambda_handler(event, None)

        assert result == {"objects_processed": 1, "messages_enqueued": 2}
        assert sent == [
            ("https://sqs.test/queue", "line-1"),
            ("https://sqs.test/queue", "line-2"),
        ]

    def test_detect_lambda_handler_dedupes_and_publishes(self, monkeypatch):
        monkeypatch.setenv("DETECT_SKILL_CMD", _PASSTHROUGH_CMD)

        dedupe_results = iter([True, False])
        monkeypatch.setattr(DETECT, "_put_if_new", lambda uid, payload: next(dedupe_results))
        published: list[tuple[str, str]] = []
        monkeypatch.setattr(DETECT, "_publish_findings", lambda records: published.extend(records))

        finding_new = json.dumps({"finding_info": {"uid": "finding-new"}})
        finding_dup = json.dumps({"event_uid": "event-dup"})
        event = {"Records": [{"body": finding_new}, {"body": finding_dup}]}

        result = DETECT.lambda_handler(event, None)

        assert result == {"messages_processed": 2, "published": 1, "duplicates": 1}
        assert published == [(finding_new, "finding-new")]

    def test_detect_put_if_new_true_then_false_for_same_uid(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "30")

        class _FakeTable:
            def __init__(self):
                self.items: dict[str, dict] = {}

            def put_item(self, Item, ConditionExpression):
                assert ConditionExpression == "attribute_not_exists(pk)"
                if Item["pk"] in self.items:
                    raise DETECT.ClientError(
                        {"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem"
                    )
                self.items[Item["pk"]] = Item

        table = _FakeTable()
        monkeypatch.setattr(DETECT, "_dedupe_table", lambda: table)

        assert DETECT._put_if_new("uid-1", "payload") is True
        assert DETECT._put_if_new("uid-1", "payload") is False
        assert set(table.items) == {"uid-1"}
