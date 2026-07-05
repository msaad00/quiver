"""Tests for detect-aws-cloudtrail-event-selector-tampering."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError  # noqa: E402

THIS = Path(__file__).resolve().parent
SRC = THIS.parent / "src" / "detect.py"
SPEC = importlib.util.spec_from_file_location(
    "detect_aws_cloudtrail_event_selector_tampering_under_test", SRC
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCEPTED_PRODUCERS = MODULE.ACCEPTED_PRODUCERS
ANCHOR_OPERATIONS = MODULE.ANCHOR_OPERATIONS
FINDING_CLASS_UID = MODULE.FINDING_CLASS_UID
OUTPUT_FORMATS = MODULE.OUTPUT_FORMATS
SIGNAL_DATA_RESOURCES = MODULE.SIGNAL_DATA_RESOURCES
SIGNAL_EMPTY = MODULE.SIGNAL_EMPTY
SIGNAL_MGMT_DISABLED = MODULE.SIGNAL_MGMT_DISABLED
SIGNAL_MULTI_REGION = MODULE.SIGNAL_MULTI_REGION
SIGNAL_RW_NONE = MODULE.SIGNAL_RW_NONE
SEVERITY_HIGH = MODULE.SEVERITY_HIGH
SKILL_NAME = MODULE.SKILL_NAME
STRUCTURAL_SIGNALS = MODULE.STRUCTURAL_SIGNALS
TECHNIQUE_UID = MODULE.TECHNIQUE_UID
coverage_metadata = MODULE.coverage_metadata
detect = MODULE.detect
load_jsonl = MODULE.load_jsonl

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "aws_cloudtrail_event_selector_tampering_input.ocsf.jsonl"
EXPECTED = GOLDEN / "aws_cloudtrail_event_selector_tampering_findings.ocsf.jsonl"

ACCOUNT = "111122223333"
REGION = "us-east-1"
TRAIL_NAME = "prod-trail"
TRAIL_ARN = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/{TRAIL_NAME}"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str = "evt-1",
    time_ms: int = 1_700_000_000_000,
    actor: str = "mallory",
    operation: str = "PutEventSelectors",
    status_id: int = 1,
    producer: str = "ingest-cloudtrail-ocsf",
    request_parameters: dict | None = None,
    event_selector_change: dict | None = None,
) -> dict:
    if request_parameters is None:
        request_parameters = {
            "trailName": TRAIL_NAME,
            "eventSelectors": [],
        }
    unmapped_cloudtrail: dict = {"request_parameters": request_parameters}
    if event_selector_change is not None:
        unmapped_cloudtrail["event_selector_change"] = event_selector_change
    return {
        "class_uid": 6003,
        "status_id": status_id,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {"feature": {"name": producer}},
        },
        "actor": {"user": {"name": actor}},
        "api": {"operation": operation, "service": {"name": "cloudtrail.amazonaws.com"}},
        "cloud": {"provider": "AWS", "account": {"uid": ACCOUNT}, "region": REGION},
        "resources": [{"name": TRAIL_ARN, "type": "trail"}],
        "unmapped": {"cloudtrail": unmapped_cloudtrail},
    }


class TestCoreContract:
    def test_accepted_producer_is_cloudtrail(self) -> None:
        assert ACCEPTED_PRODUCERS == frozenset({"ingest-cloudtrail-ocsf"})

    def test_anchor_operations(self) -> None:
        assert ANCHOR_OPERATIONS == frozenset({"PutEventSelectors", "UpdateTrail"})

    def test_coverage_metadata(self) -> None:
        meta = coverage_metadata()
        assert meta["providers"] == ("aws",)
        assert TECHNIQUE_UID in meta["attack_coverage"]["aws"]["techniques"]
        assert set(meta["thresholds"]["structural_signals"]) == STRUCTURAL_SIGNALS
        assert meta["thresholds"]["diff_context_signals"] == [SIGNAL_DATA_RESOURCES]


class TestStructuralSignals:
    def test_empty_event_selectors_fires(self) -> None:
        findings = list(detect([_event()]))
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID == 2004
        assert f["severity_id"] == SEVERITY_HIGH
        assert f["evidence"]["signal_kind"] == SIGNAL_EMPTY
        assert f["evidence"]["signal_provenance"] == "structural"
        assert f["finding_info"]["attacks"][0]["technique"]["uid"] == TECHNIQUE_UID

    def test_management_events_disabled_fires(self) -> None:
        params = {
            "trailName": TRAIL_NAME,
            "eventSelectors": [{"IncludeManagementEvents": False, "ReadWriteType": "All"}],
        }
        findings = list(detect([_event(request_parameters=params)]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["signal_kind"] == SIGNAL_MGMT_DISABLED

    def test_read_write_type_none_fires(self) -> None:
        params = {
            "trailName": TRAIL_NAME,
            "eventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "None"}],
        }
        findings = list(detect([_event(request_parameters=params)]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["signal_kind"] == SIGNAL_RW_NONE

    def test_multi_region_collapsed_fires_on_update_trail(self) -> None:
        params = {
            "name": TRAIL_NAME,
            "isMultiRegionTrail": False,
            "previousIsMultiRegionTrail": True,
        }
        findings = list(detect([_event(operation="UpdateTrail", request_parameters=params)]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["signal_kind"] == SIGNAL_MULTI_REGION

    def test_multi_region_flag_alone_without_previous_does_not_fire(self) -> None:
        # Without `previousIsMultiRegionTrail` we cannot prove the trail was
        # multi-region before, so the detector deliberately stays silent.
        params = {"name": TRAIL_NAME, "isMultiRegionTrail": False}
        findings = list(detect([_event(operation="UpdateTrail", request_parameters=params)]))
        assert findings == []

    def test_normal_selectors_do_not_fire(self) -> None:
        params = {
            "trailName": TRAIL_NAME,
            "eventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "All"}],
        }
        findings = list(detect([_event(request_parameters=params)]))
        assert findings == []

    def test_multiple_structural_signals_in_one_event(self) -> None:
        # One PutEventSelectors call carries TWO selectors — one disables
        # management events, the other pins ReadWriteType to None. Both
        # structural signals should fire and produce two findings on the
        # same trail.
        params = {
            "trailName": TRAIL_NAME,
            "eventSelectors": [
                {"IncludeManagementEvents": False, "ReadWriteType": "All"},
                {"IncludeManagementEvents": True, "ReadWriteType": "None"},
            ],
        }
        findings = list(detect([_event(request_parameters=params)]))
        assert len(findings) == 2
        kinds = {f["evidence"]["signal_kind"] for f in findings}
        assert kinds == {SIGNAL_MGMT_DISABLED, SIGNAL_RW_NONE}


class TestProducerAndStatusGuards:
    def test_failed_call_does_not_fire(self) -> None:
        findings = list(detect([_event(status_id=2)]))
        assert findings == []

    def test_wrong_operation_does_not_fire(self) -> None:
        findings = list(detect([_event(operation="StartLogging")]))
        assert findings == []

    def test_non_cloudtrail_producer_ignored(self, capsys) -> None:
        findings = list(detect([_event(producer="ingest-gcp-audit-ocsf")]))
        assert findings == []
        assert "non-cloudtrail producer" in capsys.readouterr().err

    def test_missing_request_parameters_skipped(self, capsys) -> None:
        evt = _event()
        evt["unmapped"]["cloudtrail"] = {}
        findings = list(detect([evt]))
        assert findings == []
        assert "no `unmapped.cloudtrail.request_parameters`" in capsys.readouterr().err

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        evt = _event()
        findings = list(detect([evt, evt]))
        assert len(findings) == 1


class TestDiffContext:
    def test_removed_data_resources_fires_diff_context(self) -> None:
        # PutEventSelectors with otherwise normal selectors but the upstream
        # ingester surfaces a diff under `event_selector_change`.
        params = {
            "trailName": TRAIL_NAME,
            "eventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "All"}],
        }
        change = {
            "removed_data_resources": [
                {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::sensitive-bucket/"]}
            ]
        }
        findings = list(detect([_event(request_parameters=params, event_selector_change=change)]))
        assert len(findings) == 1
        f = findings[0]
        assert f["evidence"]["signal_kind"] == SIGNAL_DATA_RESOURCES
        assert f["evidence"]["signal_provenance"] == "diff_context"
        assert (
            f["evidence"]["signal_evidence"]["removed_data_resources"][0]["Type"]
            == "AWS::S3::Object"
        )


class TestSchemaModeDiscriminator:
    def test_native_output(self) -> None:
        findings = list(detect([_event()], output_format="native"))
        assert len(findings) == 1
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["source_skill"] == SKILL_NAME
        assert findings[0]["signal_provenance"] == "structural"
        assert OUTPUT_FORMATS == frozenset({"ocsf", "native"})

    def test_rejects_unsupported_output_format(self) -> None:
        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected ContractError")


class TestGolden:
    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
