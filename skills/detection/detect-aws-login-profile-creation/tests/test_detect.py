"""Tests for detect-aws-login-profile-creation."""

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
SPEC = importlib.util.spec_from_file_location("detect_aws_login_profile_creation_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCEPTED_PRODUCERS = MODULE.ACCEPTED_PRODUCERS
LOGIN_PROFILE_CREATE_OPERATION = MODULE.LOGIN_PROFILE_CREATE_OPERATION
SUBTECHNIQUE_UID = MODULE.SUBTECHNIQUE_UID
detect = MODULE.detect


def _ct_event(
    *,
    operation: str = "CreateLoginProfile",
    success: bool = True,
    target_user: str = "bob",
    actor: str = "AROAEXAMPLEID:alice",
    account_uid: str = "111122223333",
    region: str = "us-east-1",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-cloudtrail-ocsf",
    resource_type: str = "userName",
) -> dict:
    resources = []
    if target_user:
        resources.append({"name": target_user, "type": resource_type})
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
        "resources": resources,
    }


def test_accepted_producer_is_cloudtrail():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-cloudtrail-ocsf"})


def test_operation_is_create_login_profile_only():
    assert LOGIN_PROFILE_CREATE_OPERATION == "CreateLoginProfile"


def test_fires_on_create_login_profile():
    findings = list(detect([_ct_event()]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["class_uid"] == 2004
    attack = finding["finding_info"]["attacks"][0]
    assert attack["sub_technique_uid"] == SUBTECHNIQUE_UID
    assert finding["finding_info"]["title"] == "AWS IAM login profile created"
    assert any(
        obs["name"] == "target.name" and obs["value"] == "bob" for obs in finding["observables"]
    )


def test_native_output_contains_target_user():
    findings = list(detect([_ct_event(target_user="carol")], output_format="native"))
    finding = findings[0]
    assert finding["schema_mode"] == "native"
    assert finding["target_user_name"] == "carol"
    assert finding["rule"] == "aws-login-profile-creation"


def test_skips_failed_event():
    assert list(detect([_ct_event(success=False)])) == []


def test_skips_unrelated_operation():
    assert list(detect([_ct_event(operation="ListUsers")])) == []


def test_skips_wrong_producer(capsys):
    findings = list(detect([_ct_event(producer="ingest-okta-system-log-ocsf")]))
    assert findings == []
    assert "non-cloudtrail producer" in capsys.readouterr().err


def test_skips_missing_target_user(capsys):
    findings = list(detect([_ct_event(target_user="")]))
    assert findings == []
    assert "no target IAM username" in capsys.readouterr().err


def test_accepts_resource_type_user():
    findings = list(detect([_ct_event(resource_type="user")]))
    assert len(findings) == 1


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
    assert first.startswith("alpc-")
