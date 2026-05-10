"""Tests for detect-cloudtrail-disabled."""

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
SPEC = importlib.util.spec_from_file_location("detect_cloudtrail_disabled_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCEPTED_PRODUCERS = MODULE.ACCEPTED_PRODUCERS
DISABLING_OPERATIONS = MODULE.DISABLING_OPERATIONS
TECHNIQUE_UID = MODULE.TECHNIQUE_UID
detect = MODULE.detect


def _ct_event(
    *,
    operation: str = "StopLogging",
    success: bool = True,
    trail_name: str = "org-trail",
    trail_arn: str = "",
    actor: str = "alice",
    account_uid: str = "111122223333",
    region: str = "us-east-1",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-cloudtrail-ocsf",
) -> dict:
    params: dict[str, str] = {}
    if trail_name:
        params["name"] = trail_name
    if trail_arn:
        params["trailARN"] = trail_arn
    return {
        "class_uid": 6003,
        "status_id": 1 if success else 2,
        "time": 1700000000000,
        "metadata": {
            "uid": "evt-1",
            "product": {"feature": {"name": producer}},
        },
        "actor": {"user": {"name": actor}},
        "src_endpoint": {"ip": src_ip},
        "api": {"operation": operation},
        "cloud": {"provider": "AWS", "account": {"uid": account_uid}, "region": region},
        "unmapped": {"cloudtrail": {"request_parameters": params}},
        "resources": [{"name": trail_name, "type": "name"}] if trail_name else [],
    }


def test_accepted_producer_is_cloudtrail():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-cloudtrail-ocsf"})


def test_disabling_operations_are_stop_and_delete():
    assert DISABLING_OPERATIONS == frozenset({"StopLogging", "DeleteTrail"})


def test_fires_on_stop_logging():
    findings = list(detect([_ct_event(operation="StopLogging")]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["class_uid"] == 2004
    assert finding["finding_info"]["attacks"][0]["technique_uid"] == TECHNIQUE_UID
    assert finding["finding_info"]["title"] == "CloudTrail disabled via StopLogging"
    assert any(obs["name"] == "target.name" and obs["value"] == "org-trail" for obs in finding["observables"])


def test_fires_on_delete_trail():
    findings = list(detect([_ct_event(operation="DeleteTrail")]))
    assert len(findings) == 1
    assert any(obs["name"] == "api.operation" and obs["value"] == "DeleteTrail" for obs in findings[0]["observables"])


def test_native_output_contains_trail_identity():
    findings = list(
        detect(
            [_ct_event(operation="StopLogging", trail_name="org-trail", trail_arn="arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail")],
            output_format="native",
        )
    )
    finding = findings[0]
    assert finding["schema_mode"] == "native"
    assert finding["trail_name"] == "org-trail"
    assert finding["trail_arn"].endswith(":trail/org-trail")


def test_skips_failed_event():
    assert list(detect([_ct_event(success=False)])) == []


def test_skips_unrelated_operation():
    assert list(detect([_ct_event(operation="DescribeTrails")])) == []


def test_skips_wrong_producer(capsys):
    findings = list(detect([_ct_event(producer="ingest-okta-system-log-ocsf")]))
    assert findings == []
    assert "non-cloudtrail producer" in capsys.readouterr().err


def test_skips_missing_trail_identifier(capsys):
    findings = list(detect([_ct_event(trail_name="", trail_arn="")]))
    assert findings == []
    assert "missing trail identifier" in capsys.readouterr().err


def test_rejects_unknown_output_format():
    with pytest.raises(ContractError, match="unsupported output_format") as excinfo:
        list(detect([_ct_event()], output_format="weird"))
    assert excinfo.value.error_class == "contract"
    assert excinfo.value.retryable is False
    assert excinfo.value.hint
    assert "ocsf" in excinfo.value.hint or "native" in excinfo.value.hint


def test_finding_uid_is_deterministic():
    event = _ct_event()
    first = list(detect([event]))[0]["finding_info"]["uid"]
    second = list(detect([event]))[0]["finding_info"]["uid"]
    assert first == second
    assert first.startswith("ctd-")
