"""Tests for ingest-nsg-flow-logs-azure-ocsf."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_azure_nsg_flow_logs", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INGEST)

ACTIVITY_DENIED = _INGEST.ACTIVITY_DENIED
ACTIVITY_TRAFFIC = _INGEST.ACTIVITY_TRAFFIC
CATEGORY_UID = _INGEST.CATEGORY_UID
CLASS_UID = _INGEST.CLASS_UID
OCSF_VERSION = _INGEST.OCSF_VERSION
SKILL_NAME = _INGEST.SKILL_NAME
_extract_subscription_id = _INGEST._extract_subscription_id
activity_id_for_decision = _INGEST.activity_id_for_decision
convert_tuple = _INGEST.convert_tuple
convert_tuple_native = _INGEST.convert_tuple_native
ingest = _INGEST.ingest
iter_raw_records = _INGEST.iter_raw_records
parse_flow_tuple = _INGEST.parse_flow_tuple
protocol_name = _INGEST.protocol_name

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "azure_nsg_flow_logs_raw_sample.json"
OCSF_FIXTURE = GOLDEN / "azure_nsg_flow_logs_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class TestHelpers:
    def test_protocol_name(self):
        assert protocol_name("T") == "TCP"
        assert protocol_name("U") == "UDP"

    def test_activity(self):
        assert activity_id_for_decision("A") == ACTIVITY_TRAFFIC
        assert activity_id_for_decision("D") == ACTIVITY_DENIED

    def test_subscription(self):
        rid = "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/rg/providers/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/web-nsg"
        assert _extract_subscription_id(rid) == "00000000-0000-0000-0000-000000000000"

    def test_parse_tuple_v2(self):
        parsed = parse_flow_tuple(
            "1775797320000,10.0.1.4,10.0.2.7,49812,3306,T,O,A,B,12,4500,10,3200", 2
        )
        assert parsed["src_ip"] == "10.0.1.4"
        assert parsed["bytes_out"] == "4500"


class TestConvert:
    def test_convert_tuple(self):
        event = convert_tuple(
            parse_flow_tuple(
                "1775797320000,10.0.1.4,10.0.2.7,49812,3306,T,O,A,B,12,4500,10,3200", 2
            ),
            resource_id="/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/rg/providers/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/web-nsg",
            rule="AllowDb",
            mac="000D3A1B2C3D",
            location="eastus",
        )
        assert event["class_uid"] == CLASS_UID == 4001
        assert event["category_uid"] == CATEGORY_UID == 4
        assert event["metadata"]["version"] == OCSF_VERSION
        assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert event["traffic"]["bytes"] == 7700
        assert event["traffic"]["packets"] == 22
        assert event["cloud"]["provider"] == "Azure"
        assert event["cloud"]["region"] == "eastus"

    def test_native_output_keeps_canonical_fields_without_ocsf_envelope(self):
        event = convert_tuple_native(
            parse_flow_tuple(
                "1775797320000,10.0.1.4,10.0.2.7,49812,3306,T,O,A,B,12,4500,10,3200", 2
            ),
            resource_id="/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/rg/providers/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/web-nsg",
            rule="AllowDb",
            mac="000D3A1B2C3D",
            location="eastus",
        )
        assert event["schema_mode"] == "native"
        assert event["record_type"] == "network_activity"
        assert event["provider"] == "Azure"
        assert event["event_uid"]
        assert event["connection"]["boundary"].endswith("/web-nsg")
        assert "class_uid" not in event
        assert "metadata" not in event


class TestStream:
    def test_iter_records(self):
        records = list(iter_raw_records([RAW_FIXTURE.read_text()]))
        assert len(records) == 1

    def test_golden_fixture(self):
        produced = list(ingest([RAW_FIXTURE.read_text()]))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert produced == expected

    def test_native_output_mode(self):
        produced = list(ingest([RAW_FIXTURE.read_text()], output_format="native"))
        assert len(produced) == 1
        event = produced[0]
        assert event["schema_mode"] == "native"
        assert event["record_type"] == "network_activity"
        assert event["provider"] == "Azure"
        assert "class_uid" not in event
        assert "metadata" not in event
