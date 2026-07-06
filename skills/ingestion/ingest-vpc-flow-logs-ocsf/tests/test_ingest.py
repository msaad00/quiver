"""Tests for ingest-vpc-flow-logs-ocsf."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_vpc_flow_logs", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INGEST)

ACTIVITY_DENIED = _INGEST.ACTIVITY_DENIED
ACTIVITY_TRAFFIC = _INGEST.ACTIVITY_TRAFFIC
ACTIVITY_UNKNOWN = _INGEST.ACTIVITY_UNKNOWN
CATEGORY_UID = _INGEST.CATEGORY_UID
CLASS_UID = _INGEST.CLASS_UID
OCSF_VERSION = _INGEST.OCSF_VERSION
SKILL_NAME = _INGEST.SKILL_NAME
activity_id_for_action = _INGEST.activity_id_for_action
convert_record = _INGEST.convert_record
convert_record_native = _INGEST.convert_record_native
decode_tcp_flags = _INGEST.decode_tcp_flags
ingest = _INGEST.ingest
parse_header = _INGEST.parse_header
parse_record = _INGEST.parse_record
protocol_name = _INGEST.protocol_name
sec_to_ms = _INGEST.sec_to_ms

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW = GOLDEN / "vpc_flow_logs_raw_sample.log"
OCSF = GOLDEN / "vpc_flow_logs_sample.ocsf.jsonl"


def _load_jsonl(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


# ── Protocol name map ────────────────────────────────────────────


class TestProtocolName:
    def test_common(self):
        assert protocol_name(6) == "TCP"
        assert protocol_name("17") == "UDP"
        assert protocol_name(1) == "ICMP"
        assert protocol_name(58) == "ICMPv6"

    def test_unknown(self):
        assert protocol_name(250) == ""

    def test_garbage(self):
        assert protocol_name("foo") == ""
        assert protocol_name(None) == ""  # type: ignore[arg-type]


# ── TCP flags decoder ────────────────────────────────────────────


class TestTcpFlags:
    def test_zero(self):
        assert decode_tcp_flags(0) == ""

    def test_syn(self):
        assert decode_tcp_flags(2) == "SYN"

    def test_syn_ack(self):
        assert decode_tcp_flags(18) == "SYN,ACK"

    def test_fin_ack(self):
        assert decode_tcp_flags(17) == "FIN,ACK"

    def test_all_flags(self):
        assert decode_tcp_flags(63) == "FIN,SYN,RST,PSH,ACK,URG"

    def test_dash(self):
        assert decode_tcp_flags("-") == ""

    def test_none(self):
        assert decode_tcp_flags(None) == ""

    def test_string_number(self):
        assert decode_tcp_flags("18") == "SYN,ACK"

    def test_garbage(self):
        assert decode_tcp_flags("garbage") == ""


# ── Action → activity_id ─────────────────────────────────────────


class TestActivityId:
    def test_accept(self):
        assert activity_id_for_action("ACCEPT") == ACTIVITY_TRAFFIC

    def test_accept_lowercase(self):
        assert activity_id_for_action("accept") == ACTIVITY_TRAFFIC

    def test_reject(self):
        assert activity_id_for_action("REJECT") == ACTIVITY_DENIED

    def test_dash(self):
        assert activity_id_for_action("-") == ACTIVITY_UNKNOWN

    def test_empty(self):
        assert activity_id_for_action("") == ACTIVITY_UNKNOWN

    def test_unknown(self):
        assert activity_id_for_action("BLOCK") == ACTIVITY_UNKNOWN


# ── Time conversion ──────────────────────────────────────────────


class TestSecToMs:
    def test_numeric_string(self):
        assert sec_to_ms("1775797200") == 1775797200000

    def test_int(self):
        assert sec_to_ms(1775797200) == 1775797200000

    def test_dash(self):
        assert sec_to_ms("-") is None

    def test_empty(self):
        assert sec_to_ms("") is None

    def test_none(self):
        assert sec_to_ms(None) is None

    def test_garbage(self):
        assert sec_to_ms("foo") is None


# ── Header parser ────────────────────────────────────────────────


class TestParseHeader:
    def test_canonical_v5(self):
        header_line = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
        out = parse_header(header_line)
        assert out is not None
        assert out[0] == "version"
        assert "srcaddr" in out
        assert "action" in out

    def test_extended_v5(self):
        header_line = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status vpc-id subnet-id instance-id tcp-flags flow-direction region"
        out = parse_header(header_line)
        assert out is not None
        assert "vpc-id" in out
        assert "tcp-flags" in out

    def test_non_header_line(self):
        # A real flow record starts with a version number, not the word "version"
        assert (
            parse_header("5 111122223333 eni-abc 10.0.0.1 10.0.0.2 80 443 6 5 320 1 2 ACCEPT OK")
            is None
        )

    def test_empty(self):
        assert parse_header("") is None


# ── Record parser ────────────────────────────────────────────────


class TestParseRecord:
    def test_default_v5(self):
        line = "5 111122223333 eni-abc 10.0.0.1 10.0.0.2 80 443 6 5 320 1775797200 1775797260 ACCEPT OK"
        rec = parse_record(line, _INGEST._DEFAULT_V5_FIELDS)
        assert rec is not None
        assert rec["srcaddr"] == "10.0.0.1"
        assert rec["dstaddr"] == "10.0.0.2"
        assert rec["action"] == "ACCEPT"

    def test_too_few_tokens(self):
        assert parse_record("5 111122223333", _INGEST._DEFAULT_V5_FIELDS) is None


# ── convert_record ───────────────────────────────────────────────


class TestConvertRecord:
    def _base(self, **overrides) -> dict[str, str]:
        r = {
            "version": "5",
            "account-id": "111122223333",
            "interface-id": "eni-abc",
            "srcaddr": "10.0.0.1",
            "dstaddr": "10.0.0.2",
            "srcport": "48123",
            "dstport": "22",
            "protocol": "6",
            "packets": "12",
            "bytes": "1680",
            "start": "1775797200",
            "end": "1775797260",
            "action": "ACCEPT",
            "log-status": "OK",
            "vpc-id": "vpc-0abcdef",
            "subnet-id": "subnet-priv-1a",
            "instance-id": "i-0web01",
            "tcp-flags": "18",
            "flow-direction": "egress",
            "region": "us-east-1",
        }
        r.update(overrides)
        return r

    def test_class_pinning(self):
        e = convert_record(self._base())
        assert e["class_uid"] == CLASS_UID == 4001
        assert e["category_uid"] == CATEGORY_UID == 4
        assert e["type_uid"] == CLASS_UID * 100 + ACTIVITY_TRAFFIC
        assert e["metadata"]["version"] == OCSF_VERSION
        assert e["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_accept_is_activity_6(self):
        e = convert_record(self._base(action="ACCEPT"))
        assert e["activity_id"] == ACTIVITY_TRAFFIC

    def test_reject_is_activity_7(self):
        e = convert_record(self._base(action="REJECT"))
        assert e["activity_id"] == ACTIVITY_DENIED

    def test_nodata_returns_none(self):
        assert convert_record(self._base(**{"log-status": "NODATA"})) is None

    def test_skipdata_returns_none(self):
        assert convert_record(self._base(**{"log-status": "SKIPDATA"})) is None

    def test_src_endpoint(self):
        e = convert_record(self._base())
        src = e["src_endpoint"]
        assert src["ip"] == "10.0.0.1"
        assert src["port"] == 48123
        assert src["interface_uid"] == "eni-abc"
        assert src["instance_uid"] == "i-0web01"
        assert src["subnet_uid"] == "subnet-priv-1a"

    def test_dst_endpoint(self):
        e = convert_record(self._base())
        dst = e["dst_endpoint"]
        assert dst["ip"] == "10.0.0.2"
        assert dst["port"] == 22

    def test_traffic_counters(self):
        e = convert_record(self._base(packets="50", bytes="8200"))
        assert e["traffic"]["packets"] == 50
        assert e["traffic"]["bytes"] == 8200

    def test_connection_info_tcp(self):
        e = convert_record(self._base(protocol="6", **{"tcp-flags": "18"}))
        ci = e["connection_info"]
        assert ci["protocol_num"] == 6
        assert ci["protocol_name"] == "TCP"
        assert ci["tcp_flags"] == "SYN,ACK"
        assert ci["direction"] == "egress"
        assert ci["boundary"] == "vpc-0abcdef"

    def test_connection_info_udp_no_flags(self):
        e = convert_record(self._base(protocol="17", **{"tcp-flags": "-"}))
        assert e["connection_info"]["protocol_name"] == "UDP"
        assert "tcp_flags" not in e["connection_info"]

    def test_cloud(self):
        e = convert_record(self._base())
        assert e["cloud"]["provider"] == "AWS"
        assert e["cloud"]["account"]["uid"] == "111122223333"
        assert e["cloud"]["region"] == "us-east-1"

    def test_time_is_end_time(self):
        e = convert_record(self._base(start="1775797200", end="1775797260"))
        assert e["time"] == 1775797260000
        assert e["start_time"] == 1775797200000
        assert e["end_time"] == 1775797260000

    def test_native_output_keeps_enriched_flow_fields_without_ocsf_envelope(self):
        e = convert_record_native(self._base())
        assert e is not None
        assert e["schema_mode"] == "native"
        assert e["record_type"] == "network_activity"
        assert e["provider"] == "AWS"
        assert e["event_uid"]
        assert e["src"]["ip"] == "10.0.0.1"
        assert e["dst"]["ip"] == "10.0.0.2"
        assert "class_uid" not in e
        assert "metadata" not in e


# ── Stream ingestion w/ header ───────────────────────────────────


class TestIngestStream:
    def test_default_field_order_no_header(self):
        lines = [
            "5 111122223333 eni-abc 10.0.0.1 10.0.0.2 48123 22 6 12 1680 1775797200 1775797260 ACCEPT OK"
        ]
        out = list(ingest(lines))
        assert len(out) == 1
        assert out[0]["src_endpoint"]["ip"] == "10.0.0.1"

    def test_header_driven_field_order(self):
        # Header with extended fields, then one record
        lines = [
            "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status vpc-id subnet-id",
            "5 111122223333 eni-xyz 172.16.0.1 172.16.0.2 48123 22 6 12 1680 1775797200 1775797260 ACCEPT OK vpc-test subnet-test",
        ]
        out = list(ingest(lines))
        assert len(out) == 1
        assert out[0]["connection_info"]["boundary"] == "vpc-test"

    def test_nodata_skipped(self):
        lines = ["5 111122223333 eni-abc - - - - - - - 1775797200 1775797260 - NODATA"]
        assert list(ingest(lines)) == []

    def test_blank_lines_skipped(self):
        assert list(ingest(["", "  ", "\n"])) == []

    def test_too_few_tokens_warns(self, capsys):
        lines = [
            "5 111122223333",  # truncated record
            "5 111122223333 eni-abc 10.0.0.1 10.0.0.2 48123 22 6 12 1680 1775797200 1775797260 ACCEPT OK",
        ]
        out = list(ingest(lines))
        assert len(out) == 1
        assert "skipping line 1" in capsys.readouterr().err

    def test_native_output_mode_emits_enriched_flows(self):
        lines = [
            "5 111122223333 eni-abc 10.0.0.1 10.0.0.2 48123 22 6 12 1680 1775797200 1775797260 ACCEPT OK"
        ]
        out = list(ingest(lines, output_format="native"))
        assert len(out) == 1
        assert out[0]["schema_mode"] == "native"
        assert out[0]["record_type"] == "network_activity"
        assert out[0]["provider"] == "AWS"
        assert "class_uid" not in out[0]


# ── Golden fixture parity ────────────────────────────────────────


class TestGoldenFixture:
    def test_event_count(self):
        produced = list(ingest(RAW.read_text().splitlines()))
        expected = _load_jsonl(OCSF)
        # 6 raw records + 1 header = 7 lines; NODATA dropped → 5 OCSF events
        assert len(produced) == len(expected) == 5

    def test_deep_equality(self):
        produced = list(ingest(RAW.read_text().splitlines()))
        expected = _load_jsonl(OCSF)
        for p, e in zip(produced, expected):
            assert p == e, (
                f"drift:\n  produced: {json.dumps(p, sort_keys=True)}\n  expected: {json.dumps(e, sort_keys=True)}"
            )

    def test_fixture_has_one_reject(self):
        events = _load_jsonl(OCSF)
        denied = [e for e in events if e["activity_id"] == ACTIVITY_DENIED]
        assert len(denied) == 1
        assert denied[0]["dst_endpoint"]["ip"] == "192.168.1.10"

    def test_fixture_has_tcp_and_udp(self):
        events = _load_jsonl(OCSF)
        protos = {e["connection_info"]["protocol_name"] for e in events}
        assert "TCP" in protos
        assert "UDP" in protos

    def test_fixture_syn_ack_decoded(self):
        events = _load_jsonl(OCSF)
        with_flags = [e for e in events if e["connection_info"].get("tcp_flags") == "SYN,ACK"]
        assert len(with_flags) >= 1

    def test_native_golden_mode_keeps_expected_count(self):
        produced = list(ingest(RAW.read_text().splitlines(), output_format="native"))
        assert len(produced) == 5
        assert all(event["schema_mode"] == "native" for event in produced)
