"""Tests for ingest-aws-config-ocsf."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from skills._shared.ocsf_validator import validate_event

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_aws_config", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INGEST)

API_CLASS_UID = _INGEST.API_CLASS_UID
COMPLIANCE_CLASS_UID = _INGEST.COMPLIANCE_CLASS_UID
OUTPUT_FORMATS = _INGEST.OUTPUT_FORMATS
convert_message = _INGEST.convert_message
ingest = _INGEST.ingest
iter_raw_messages = _INGEST.iter_raw_messages
parse_ts_ms = _INGEST.parse_ts_ms

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW = GOLDEN / "aws_config_raw_sample.json"
EXPECTED = GOLDEN / "aws_config_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _raw_fixture() -> list[dict]:
    return json.loads(RAW.read_text())


def test_golden_fixture_parity():
    actual = list(ingest([RAW.read_text()]))
    assert actual == _load_jsonl(EXPECTED)


def test_golden_output_validates_against_repo_ocsf_contract():
    events = list(ingest([RAW.read_text()]))
    assert [event["class_uid"] for event in events] == [API_CLASS_UID, COMPLIANCE_CLASS_UID]
    for event in events:
        assert validate_event(event) == []


def test_sns_message_json_string_is_unwrapped():
    raw = _raw_fixture()[0]
    messages = list(iter_raw_messages([json.dumps(raw)]))
    assert len(messages) == 1
    assert messages[0]["messageType"] == "ConfigurationItemChangeNotification"
    assert messages[0]["configurationItem"]["resourceId"] == "prod-logs-bucket"


def test_configuration_item_snapshot_without_message_type_maps_to_api_activity():
    item = json.loads(_raw_fixture()[0]["Message"])["configurationItem"]
    event = convert_message(item)[0]
    assert event["class_uid"] == API_CLASS_UID
    assert event["activity_name"] == "Read"
    assert event["resources"][0]["type"] == "AWS::S3::Bucket"
    assert event["unmapped"]["aws_config"]["configuration_item_status"] == "OK"


def test_compliance_non_compliant_maps_to_compliance_finding_failure():
    message = _raw_fixture()[1]
    event = convert_message(message)[0]
    assert event["class_uid"] == COMPLIANCE_CLASS_UID
    assert event["status_id"] == 2
    assert event["severity_id"] == 4
    assert event["compliance"]["status"] == "FAIL"
    assert event["finding_info"]["types"] == ["s3-bucket-server-side-encryption-enabled"]


def test_compliant_maps_to_success_and_informational():
    message = _raw_fixture()[1]
    message = json.loads(json.dumps(message))
    message["newEvaluationResult"]["complianceType"] = "COMPLIANT"
    event = convert_message(message)[0]
    assert event["status_id"] == 1
    assert event["severity_id"] == 1
    assert event["compliance"]["status"] == "PASS"


def test_native_output_has_no_ocsf_envelope():
    native = list(ingest([RAW.read_text()], output_format="native"))
    assert OUTPUT_FORMATS == ("ocsf", "native")
    assert len(native) == 2
    assert native[0]["schema_mode"] == "native"
    assert native[0]["record_type"] == "aws_config_configuration_item"
    assert native[0]["source_skill"] == "ingest-aws-config-ocsf"
    assert "class_uid" not in native[0]
    assert native[1]["record_type"] == "aws_config_compliance_finding"


def test_eventbridge_detail_is_unwrapped():
    detail = _raw_fixture()[1]
    wrapped = {
        "source": "aws.config",
        "detail-type": "Config Rules Compliance Change",
        "detail": detail,
    }
    events = list(ingest([json.dumps(wrapped)]))
    assert len(events) == 1
    assert events[0]["class_uid"] == COMPLIANCE_CLASS_UID


def test_parse_ts_ms_handles_epoch_seconds_and_milliseconds():
    assert parse_ts_ms(1776572760) == 1776572760000
    assert parse_ts_ms(1776572760000) == 1776572760000
