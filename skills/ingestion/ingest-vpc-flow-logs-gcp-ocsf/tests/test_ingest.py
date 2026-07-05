"""Tests for ingest-vpc-flow-logs-gcp-ocsf."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_gcp_vpc_flow_logs", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INGEST)

ACTIVITY_DENIED = _INGEST.ACTIVITY_DENIED
ACTIVITY_TRAFFIC = _INGEST.ACTIVITY_TRAFFIC
CATEGORY_UID = _INGEST.CATEGORY_UID
CLASS_UID = _INGEST.CLASS_UID
OCSF_VERSION = _INGEST.OCSF_VERSION
SKILL_NAME = _INGEST.SKILL_NAME
activity_id_for_disposition = _INGEST.activity_id_for_disposition
convert_entry = _INGEST.convert_entry
convert_entry_native = _INGEST.convert_entry_native
ingest = _INGEST.ingest
iter_raw_entries = _INGEST.iter_raw_entries
parse_ts_ms = _INGEST.parse_ts_ms
protocol_name = _INGEST.protocol_name

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "gcp_vpc_flow_logs_raw_sample.jsonl"
OCSF_FIXTURE = GOLDEN / "gcp_vpc_flow_logs_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _entry(**payload_overrides) -> dict:
    payload = {
        "connection": {
            "src_ip": "10.128.0.5",
            "dest_ip": "10.128.0.8",
            "src_port": 49821,
            "dest_port": 3306,
            "protocol": 6,
        },
        "reporter": "SRC",
        "disposition": "ACCEPT",
        "bytes_sent": "4200",
        "bytes_received": "1800",
        "packets_sent": "12",
        "packets_received": "8",
        "start_time": "2026-04-10T05:00:00.000000Z",
        "end_time": "2026-04-10T05:01:00.000000Z",
        "src_instance": {"vm_name": "gke-node-1", "region": "us-central1", "zone": "us-central1-a"},
        "dest_instance": {"vm_name": "mysql-1", "region": "us-central1", "zone": "us-central1-b"},
        "src_vpc": {
            "project_id": "prod-project",
            "vpc_name": "prod-vpc",
            "subnetwork_name": "apps-subnet",
        },
        "dest_vpc": {
            "project_id": "prod-project",
            "vpc_name": "prod-vpc",
            "subnetwork_name": "db-subnet",
        },
    }
    payload.update(payload_overrides)
    return {"timestamp": "2026-04-10T05:01:00.000000Z", "jsonPayload": payload}


class TestHelpers:
    def test_protocol_name(self):
        assert protocol_name(6) == "TCP"
        assert protocol_name(17) == "UDP"

    def test_disposition_to_activity(self):
        assert activity_id_for_disposition("ACCEPT") == ACTIVITY_TRAFFIC
        assert activity_id_for_disposition("DENIED") == ACTIVITY_DENIED
        assert activity_id_for_disposition(None) == ACTIVITY_TRAFFIC

    def test_parse_ts(self):
        assert parse_ts_ms("2026-04-10T05:01:00.000000Z") == 1775797260000


class TestConvertEntry:
    def test_class_pinning(self):
        event = convert_entry(_entry())
        assert event["class_uid"] == CLASS_UID == 4001
        assert event["category_uid"] == CATEGORY_UID == 4
        assert event["metadata"]["version"] == OCSF_VERSION
        assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_network_fields(self):
        event = convert_entry(_entry())
        assert event["src_endpoint"]["ip"] == "10.128.0.5"
        assert event["src_endpoint"]["instance_uid"] == "gke-node-1"
        assert event["dst_endpoint"]["ip"] == "10.128.0.8"
        assert event["dst_endpoint"]["instance_uid"] == "mysql-1"
        assert event["traffic"]["bytes"] == 6000
        assert event["traffic"]["packets"] == 20
        assert event["connection_info"]["direction"] == "egress"
        assert event["connection_info"]["boundary"] == "prod-vpc"
        assert event["cloud"]["provider"] == "GCP"
        assert event["cloud"]["account"]["uid"] == "prod-project"

    def test_denied_flow(self):
        event = convert_entry(_entry(disposition="DENIED"))
        assert event["activity_id"] == ACTIVITY_DENIED

    def test_skips_non_flow_record(self):
        assert convert_entry({"jsonPayload": {"foo": "bar"}}) is None

    def test_native_output_keeps_canonical_fields_without_ocsf_envelope(self):
        event = convert_entry_native(_entry())
        assert event["schema_mode"] == "native"
        assert event["record_type"] == "network_activity"
        assert event["provider"] == "GCP"
        assert event["event_uid"]
        assert event["connection"]["boundary"] == "prod-vpc"
        assert "class_uid" not in event
        assert "metadata" not in event


class TestStream:
    def test_iter_jsonl(self):
        entries = list(iter_raw_entries(RAW_FIXTURE.read_text().splitlines(True)))
        assert len(entries) == 1

    def test_ingest_fixture(self):
        produced = list(ingest(RAW_FIXTURE.read_text().splitlines(True)))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert produced == expected

    def test_native_output_mode(self):
        produced = list(ingest(RAW_FIXTURE.read_text().splitlines(True), output_format="native"))
        assert len(produced) == 1
        event = produced[0]
        assert event["schema_mode"] == "native"
        assert event["record_type"] == "network_activity"
        assert event["provider"] == "GCP"
        assert "class_uid" not in event
        assert "metadata" not in event
