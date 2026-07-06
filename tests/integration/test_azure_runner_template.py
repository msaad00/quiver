from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

_PASSTHROUGH_CMD = f'{sys.executable} -c "import sys; sys.stdout.write(sys.stdin.read())"'
_FAILING_CMD = f"{sys.executable} -c \"import sys; sys.stderr.write('boom'); sys.exit(3)\""


def _azure_exceptions(monkeypatch) -> tuple[type[Exception], type[Exception]]:
    """Return the exception classes _put_if_new imports lazily.

    Uses the real azure-core classes when the SDK is installed; otherwise
    installs a minimal stand-in module so the handler path still runs in
    SDK-free CI lanes.
    """
    try:
        from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

        return ResourceExistsError, ResourceNotFoundError
    except ImportError:
        pass

    class _ResourceExistsError(Exception):
        pass

    class _ResourceNotFoundError(Exception):
        pass

    exceptions_module = types.ModuleType("azure.core.exceptions")
    setattr(exceptions_module, "ResourceExistsError", _ResourceExistsError)
    setattr(exceptions_module, "ResourceNotFoundError", _ResourceNotFoundError)
    core_module = types.ModuleType("azure.core")
    setattr(core_module, "exceptions", exceptions_module)
    azure_module = types.ModuleType("azure")
    setattr(azure_module, "core", core_module)
    monkeypatch.setitem(sys.modules, "azure", azure_module)
    monkeypatch.setitem(sys.modules, "azure.core", core_module)
    monkeypatch.setitem(sys.modules, "azure.core.exceptions", exceptions_module)
    return _ResourceExistsError, _ResourceNotFoundError


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


INGEST = _load_module(
    "cloud_security_azure_runner_ingest_handler_test",
    ROOT / "runners" / "azure-blob-eventgrid-detect" / "src" / "ingest_handler.py",
)
DETECT = _load_module(
    "cloud_security_azure_runner_detect_handler_test",
    ROOT / "runners" / "azure-blob-eventgrid-detect" / "src" / "detect_handler.py",
)


class TestAzureBlobEventGridDetectRunner:
    def test_ingest_skill_command_requires_env(self, monkeypatch):
        monkeypatch.delenv("INGEST_SKILL_CMD", raising=False)
        with pytest.raises(ValueError, match="INGEST_SKILL_CMD"):
            INGEST._skill_command()

    def test_ingest_service_bus_fqdn_requires_env(self, monkeypatch):
        monkeypatch.delenv("SERVICE_BUS_FQDN", raising=False)
        with pytest.raises(ValueError, match="SERVICE_BUS_FQDN"):
            INGEST._service_bus_fqdn()

    def test_ingest_queue_name_requires_env(self, monkeypatch):
        monkeypatch.delenv("DETECT_QUEUE_NAME", raising=False)
        with pytest.raises(ValueError, match="DETECT_QUEUE_NAME"):
            INGEST._ingest_queue_name()

    def test_ingest_handles_blob_event_and_enqueues_lines(self, monkeypatch):
        monkeypatch.setattr(INGEST, "_download_blob_text", lambda url: f"blob:{url}")
        monkeypatch.setattr(
            INGEST, "_run_skill", lambda payload: [f"{payload}:line1", f"{payload}:line2"]
        )
        seen_lines: list[str] = []
        monkeypatch.setattr(
            INGEST,
            "_enqueue_detect_lines",
            lambda lines: seen_lines.extend(lines) or len(lines),
        )

        result = INGEST.handle_ingest_message(
            json.dumps(
                {"data": {"url": "https://account.blob.core.windows.net/container/blob.jsonl"}}
            )
        )

        assert result == {
            "blob_events_processed": 1,
            "blobs_processed": 1,
            "messages_enqueued": 2,
        }
        assert seen_lines == [
            "blob:https://account.blob.core.windows.net/container/blob.jsonl:line1",
            "blob:https://account.blob.core.windows.net/container/blob.jsonl:line2",
        ]

    def test_detect_skill_command_requires_env(self, monkeypatch):
        monkeypatch.delenv("DETECT_SKILL_CMD", raising=False)
        with pytest.raises(ValueError, match="DETECT_SKILL_CMD"):
            DETECT._skill_command()

    def test_detect_service_bus_fqdn_requires_env(self, monkeypatch):
        monkeypatch.delenv("SERVICE_BUS_FQDN", raising=False)
        with pytest.raises(ValueError, match="SERVICE_BUS_FQDN"):
            DETECT._service_bus_fqdn()

    def test_detect_alert_topic_name_requires_env(self, monkeypatch):
        monkeypatch.delenv("ALERT_TOPIC_NAME", raising=False)
        with pytest.raises(ValueError, match="ALERT_TOPIC_NAME"):
            DETECT._alert_topic_name()

    def test_detect_dedupe_table_name_requires_env(self, monkeypatch):
        monkeypatch.delenv("DEDUPE_TABLE_NAME", raising=False)
        with pytest.raises(ValueError, match="DEDUPE_TABLE_NAME"):
            DETECT._dedupe_table_name()

    def test_detect_table_account_url_requires_env(self, monkeypatch):
        monkeypatch.delenv("TABLE_ACCOUNT_URL", raising=False)
        with pytest.raises(ValueError, match="TABLE_ACCOUNT_URL"):
            DETECT._table_account_url()

    def test_detect_extracts_uid_from_finding_info_then_metadata_then_event_uid(self):
        assert DETECT._extract_uid({"finding_info": {"uid": "finding-1"}}) == "finding-1"
        assert DETECT._extract_uid({"metadata": {"uid": "meta-1"}}) == "meta-1"
        assert DETECT._extract_uid({"event_uid": "event-1"}) == "event-1"

    def test_detect_ttl_days_default_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("DEDUPE_TTL_DAYS", raising=False)
        assert DETECT._dedupe_ttl_days() == 30

    def test_detect_ttl_days_respects_env(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "21")
        assert DETECT._dedupe_ttl_days() == 21

    def test_detect_ttl_days_rejects_non_integer(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "long")
        with pytest.raises(ValueError, match="DEDUPE_TTL_DAYS"):
            DETECT._dedupe_ttl_days()

    def test_detect_ttl_days_rejects_out_of_range(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "366")
        with pytest.raises(ValueError, match="between 1 and 365"):
            DETECT._dedupe_ttl_days()

    def test_detect_expires_at_adds_configured_ttl(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "30")
        base = 1_700_000_000
        assert DETECT._expires_at(now=base) == base + 30 * 86_400

    def test_detect_entity_is_expired(self):
        assert DETECT._entity_is_expired({"expires_at": 10}, now=11) is True
        assert DETECT._entity_is_expired({"expires_at": 12}, now=11) is False
        assert DETECT._entity_is_expired({}, now=11) is False

    def test_detect_batches_service_bus_messages(self):
        batches = DETECT._batched([(f"line-{idx}", f"uid-{idx}") for idx in range(205)], size=100)
        assert [len(batch) for batch in batches] == [100, 100, 5]

    def test_detect_handles_findings_and_dedupes(self, monkeypatch):
        lines = [
            json.dumps(
                {
                    "finding_info": {"uid": "finding-1"},
                    "metadata": {"uid": "meta-1"},
                    "event_uid": "event-1",
                }
            ),
            json.dumps({"event_uid": "event-2"}),
        ]
        published: list[tuple[str, str]] = []
        dedupe_results = iter([True, False])
        monkeypatch.setattr(DETECT, "_run_skill", lambda messages: lines)
        monkeypatch.setattr(DETECT, "_put_if_new", lambda uid, payload: next(dedupe_results))
        monkeypatch.setattr(
            DETECT,
            "_publish_findings",
            lambda records: published.extend(records),
        )
        monkeypatch.setattr(
            DETECT,
            "_batched",
            DETECT._batched,
        )

        result = DETECT.handle_detect_messages(["raw message"])

        assert result == {
            "messages_processed": 1,
            "published": 1,
            "duplicates": 1,
        }
        assert published == [(lines[0], "finding-1")]

    def test_ingest_event_payloads_accepts_object_and_array(self):
        single = INGEST._event_payloads(json.dumps({"data": {"url": "https://a/b"}}))
        assert single == [{"data": {"url": "https://a/b"}}]

        batch = INGEST._event_payloads(json.dumps([{"data": {}}, "not-an-event", {"id": "2"}]))
        assert batch == [{"data": {}}, {"id": "2"}]

        with pytest.raises(ValueError, match="JSON object or array"):
            INGEST._event_payloads(json.dumps("just a string"))

    def test_ingest_blob_url_prefers_url_then_blob_url(self):
        assert (
            INGEST._blob_url({"data": {"url": " https://a/blob.jsonl "}}) == "https://a/blob.jsonl"
        )
        assert (
            INGEST._blob_url({"data": {"blobUrl": "https://a/alt.jsonl"}}) == "https://a/alt.jsonl"
        )
        with pytest.raises(ValueError, match="data.url"):
            INGEST._blob_url({"data": {}})

    def test_ingest_run_skill_surfaces_skill_stderr(self, monkeypatch):
        monkeypatch.setenv("INGEST_SKILL_CMD", _FAILING_CMD)
        with pytest.raises(RuntimeError, match="boom"):
            INGEST._run_skill("line-1\n")

    def test_ingest_handles_message_batch_and_aggregates_counts(self, monkeypatch):
        monkeypatch.setattr(INGEST, "_download_blob_text", lambda url: "payload")
        monkeypatch.setattr(INGEST, "_run_skill", lambda payload: ["line-1", "line-2"])
        monkeypatch.setattr(INGEST, "_enqueue_detect_lines", lambda lines: len(list(lines)))

        body = json.dumps({"data": {"url": "https://account.blob.core.windows.net/c/b.jsonl"}})
        result = INGEST.handle_ingest_messages([body, body])

        assert result == {
            "queue_messages_processed": 2,
            "blob_events_processed": 2,
            "blobs_processed": 2,
            "messages_enqueued": 4,
        }

    def test_detect_run_skill_passes_lines_through(self, monkeypatch):
        monkeypatch.setenv("DETECT_SKILL_CMD", _PASSTHROUGH_CMD)
        assert DETECT._run_skill(["line-1", "line-2"]) == ["line-1", "line-2"]

    def test_detect_put_if_new_dedupes_and_replaces_expired_rows(self, monkeypatch):
        resource_exists, resource_not_found = _azure_exceptions(monkeypatch)
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "30")

        class _FakeTable:
            def __init__(self):
                self.entities: dict[str, dict] = {}

            def create_entity(self, entity):
                if entity["RowKey"] in self.entities:
                    raise resource_exists("conflict")
                self.entities[entity["RowKey"]] = entity

            def get_entity(self, partition_key, row_key):
                assert partition_key == "finding"
                if row_key not in self.entities:
                    raise resource_not_found("missing")
                return self.entities[row_key]

            def delete_entity(self, partition_key, row_key):
                del self.entities[row_key]

        table = _FakeTable()
        monkeypatch.setattr(DETECT, "_dedupe_table", lambda: table)

        assert DETECT._put_if_new("uid-1", "payload") is True
        assert DETECT._put_if_new("uid-1", "payload") is False

        # An expired row is replaced instead of counted as a duplicate.
        table.entities["uid-1"]["expires_at"] = 1
        assert DETECT._put_if_new("uid-1", "payload") is True

    def test_template_contains_azure_components(self):
        template = (ROOT / "runners" / "azure-blob-eventgrid-detect" / "template.bicep").read_text()
        assert "Microsoft.EventGrid/systemTopics" in template
        assert "Microsoft.ServiceBus/namespaces" in template
        assert "Microsoft.ServiceBus/namespaces/queues" in template
        assert "ServiceBusQueue" in template
        assert "Microsoft.Storage.BlobCreated" in template
