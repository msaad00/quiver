"""Tests for detect-aws-enumeration-burst."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError  # noqa: E402

THIS = Path(__file__).resolve().parent
SRC = THIS.parent / "src" / "detect.py"
SPEC = importlib.util.spec_from_file_location("detect_aws_enumeration_burst_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCEPTED_PRODUCERS = MODULE.ACCEPTED_PRODUCERS
DISCOVERY_CALLS = MODULE.DISCOVERY_CALLS
MIN_DISTINCT_CALLS = MODULE.MIN_DISTINCT_CALLS
MIN_TOTAL_EVENTS = MODULE.MIN_TOTAL_EVENTS
TECHNIQUE_UID = MODULE.TECHNIQUE_UID
detect = MODULE.detect


def _ct_event(
    *,
    service: str = "ec2.amazonaws.com",
    operation: str = "DescribeInstances",
    success: bool = True,
    actor: str = "alice",
    session_uid: str = "ASIAXAMPLE123",
    account_uid: str = "111122223333",
    region: str = "us-east-1",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-cloudtrail-ocsf",
    time_ms: int = 1700000000000,
    event_uid: str = "evt-1",
) -> dict:
    return {
        "class_uid": 6003,
        "status_id": 1 if success else 2,
        "time": time_ms,
        "metadata": {"uid": event_uid, "product": {"feature": {"name": producer}}},
        "actor": {"user": {"name": actor}, "session": {"uid": session_uid} if session_uid else {}},
        "src_endpoint": {"ip": src_ip},
        "api": {"operation": operation, "service": {"name": service}},
        "cloud": {"provider": "AWS", "account": {"uid": account_uid}, "region": region},
    }


def test_accepted_producer_is_cloudtrail():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-cloudtrail-ocsf"})


def test_threshold_constants_are_expected():
    assert MIN_TOTAL_EVENTS == 6
    assert MIN_DISTINCT_CALLS == 5


def test_detection_set_contains_high_signal_discovery_calls():
    assert ("ec2.amazonaws.com", "DescribeInstances") in DISCOVERY_CALLS
    assert ("iam.amazonaws.com", "GetAccountAuthorizationDetails") in DISCOVERY_CALLS
    assert ("s3.amazonaws.com", "ListBuckets") in DISCOVERY_CALLS


def test_fires_on_short_window_enumeration_burst():
    events = [
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListUsers",
            event_uid="evt-1",
            time_ms=1700000000000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListRoles",
            event_uid="evt-2",
            time_ms=1700000010000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="GetAccountAuthorizationDetails",
            event_uid="evt-3",
            time_ms=1700000020000,
        ),
        _ct_event(
            service="ec2.amazonaws.com",
            operation="DescribeInstances",
            event_uid="evt-4",
            time_ms=1700000030000,
        ),
        _ct_event(
            service="s3.amazonaws.com",
            operation="ListBuckets",
            event_uid="evt-5",
            time_ms=1700000040000,
        ),
        _ct_event(
            service="organizations.amazonaws.com",
            operation="ListAccounts",
            event_uid="evt-6",
            time_ms=1700000050000,
        ),
    ]
    findings = list(detect(events))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["class_uid"] == 2004
    assert finding["finding_info"]["title"] == "AWS discovery API burst"
    assert finding["finding_info"]["attacks"][0]["technique_uid"] == TECHNIQUE_UID
    assert any(
        obs["name"] == "calls.distinct" and obs["value"] == "6" for obs in finding["observables"]
    )


def test_native_output_contains_counts_and_calls():
    events = [
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListUsers",
            event_uid="evt-1",
            time_ms=1700000000000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListRoles",
            event_uid="evt-2",
            time_ms=1700000010000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="GetAccountAuthorizationDetails",
            event_uid="evt-3",
            time_ms=1700000020000,
        ),
        _ct_event(
            service="ec2.amazonaws.com",
            operation="DescribeInstances",
            event_uid="evt-4",
            time_ms=1700000030000,
        ),
        _ct_event(
            service="s3.amazonaws.com",
            operation="ListBuckets",
            event_uid="evt-5",
            time_ms=1700000040000,
        ),
        _ct_event(
            service="organizations.amazonaws.com",
            operation="ListAccounts",
            event_uid="evt-6",
            time_ms=1700000050000,
        ),
    ]
    findings = list(detect(events, output_format="native"))
    finding = findings[0]
    assert finding["schema_mode"] == "native"
    assert finding["total_events"] == 6
    assert finding["distinct_calls"] == 6
    assert "ec2.amazonaws.com:DescribeInstances" in finding["observed_calls"]


def test_skips_below_total_event_threshold():
    events = [
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListUsers",
            event_uid="evt-1",
            time_ms=1700000000000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListRoles",
            event_uid="evt-2",
            time_ms=1700000010000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="GetAccountAuthorizationDetails",
            event_uid="evt-3",
            time_ms=1700000020000,
        ),
        _ct_event(
            service="ec2.amazonaws.com",
            operation="DescribeInstances",
            event_uid="evt-4",
            time_ms=1700000030000,
        ),
        _ct_event(
            service="s3.amazonaws.com",
            operation="ListBuckets",
            event_uid="evt-5",
            time_ms=1700000040000,
        ),
    ]
    assert list(detect(events)) == []


def test_skips_below_distinct_call_threshold():
    events = [
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListUsers",
            event_uid="evt-1",
            time_ms=1700000000000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListUsers",
            event_uid="evt-2",
            time_ms=1700000010000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListRoles",
            event_uid="evt-3",
            time_ms=1700000020000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListRoles",
            event_uid="evt-4",
            time_ms=1700000030000,
        ),
        _ct_event(
            service="ec2.amazonaws.com",
            operation="DescribeInstances",
            event_uid="evt-5",
            time_ms=1700000040000,
        ),
        _ct_event(
            service="s3.amazonaws.com",
            operation="ListBuckets",
            event_uid="evt-6",
            time_ms=1700000050000,
        ),
    ]
    assert list(detect(events)) == []


def test_skips_failed_event():
    events = [
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListUsers",
            event_uid="evt-1",
            time_ms=1700000000000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListRoles",
            event_uid="evt-2",
            time_ms=1700000010000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="GetAccountAuthorizationDetails",
            event_uid="evt-3",
            time_ms=1700000020000,
        ),
        _ct_event(
            service="ec2.amazonaws.com",
            operation="DescribeInstances",
            event_uid="evt-4",
            time_ms=1700000030000,
        ),
        _ct_event(
            service="s3.amazonaws.com",
            operation="ListBuckets",
            event_uid="evt-5",
            time_ms=1700000040000,
        ),
        _ct_event(
            service="organizations.amazonaws.com",
            operation="ListAccounts",
            event_uid="evt-6",
            time_ms=1700000050000,
            success=False,
        ),
    ]
    assert list(detect(events)) == []


def test_skips_unrelated_operation():
    events = [
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListUsers",
            event_uid="evt-1",
            time_ms=1700000000000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListRoles",
            event_uid="evt-2",
            time_ms=1700000010000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="GetAccountAuthorizationDetails",
            event_uid="evt-3",
            time_ms=1700000020000,
        ),
        _ct_event(
            service="ec2.amazonaws.com",
            operation="DescribeInstances",
            event_uid="evt-4",
            time_ms=1700000030000,
        ),
        _ct_event(
            service="ec2.amazonaws.com",
            operation="ModifyInstanceAttribute",
            event_uid="evt-5",
            time_ms=1700000040000,
        ),
        _ct_event(
            service="ec2.amazonaws.com",
            operation="CreateTags",
            event_uid="evt-6",
            time_ms=1700000050000,
        ),
        _ct_event(
            service="s3.amazonaws.com",
            operation="ListBuckets",
            event_uid="evt-7",
            time_ms=1700000060000,
        ),
    ]
    assert list(detect(events)) == []


def test_skips_wrong_producer(capsys):
    findings = list(detect([_ct_event(producer="ingest-okta-system-log-ocsf")]))
    assert findings == []
    assert "non-cloudtrail producer" in capsys.readouterr().err


def test_skips_missing_actor(capsys):
    events = [
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListUsers",
            event_uid="evt-1",
            time_ms=1700000000000,
            actor="",
            session_uid="",
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListRoles",
            event_uid="evt-2",
            time_ms=1700000010000,
            actor="",
            session_uid="",
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="GetAccountAuthorizationDetails",
            event_uid="evt-3",
            time_ms=1700000020000,
            actor="",
            session_uid="",
        ),
        _ct_event(
            service="ec2.amazonaws.com",
            operation="DescribeInstances",
            event_uid="evt-4",
            time_ms=1700000030000,
            actor="",
            session_uid="",
        ),
        _ct_event(
            service="s3.amazonaws.com",
            operation="ListBuckets",
            event_uid="evt-5",
            time_ms=1700000040000,
            actor="",
            session_uid="",
        ),
        _ct_event(
            service="organizations.amazonaws.com",
            operation="ListAccounts",
            event_uid="evt-6",
            time_ms=1700000050000,
            actor="",
            session_uid="",
        ),
    ]
    findings = list(detect(events))
    assert findings == []
    assert "no actor or session identifier" in capsys.readouterr().err


def test_finding_uid_is_deterministic():
    events = [
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListUsers",
            event_uid="evt-1",
            time_ms=1700000000000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="ListRoles",
            event_uid="evt-2",
            time_ms=1700000010000,
        ),
        _ct_event(
            service="iam.amazonaws.com",
            operation="GetAccountAuthorizationDetails",
            event_uid="evt-3",
            time_ms=1700000020000,
        ),
        _ct_event(
            service="ec2.amazonaws.com",
            operation="DescribeInstances",
            event_uid="evt-4",
            time_ms=1700000030000,
        ),
        _ct_event(
            service="s3.amazonaws.com",
            operation="ListBuckets",
            event_uid="evt-5",
            time_ms=1700000040000,
        ),
        _ct_event(
            service="organizations.amazonaws.com",
            operation="ListAccounts",
            event_uid="evt-6",
            time_ms=1700000050000,
        ),
    ]
    first = list(detect(events))[0]["finding_info"]["uid"]
    second = list(detect(events))[0]["finding_info"]["uid"]
    assert first == second
    assert first.startswith("aeb-")


def test_rejects_unknown_output_format():
    with pytest.raises(ContractError, match="unsupported output_format") as excinfo:
        list(detect([_ct_event()], output_format="weird"))
    assert excinfo.value.error_class == "contract"
    assert excinfo.value.retryable is False
    assert excinfo.value.hint
    assert "ocsf" in excinfo.value.hint or "native" in excinfo.value.hint
