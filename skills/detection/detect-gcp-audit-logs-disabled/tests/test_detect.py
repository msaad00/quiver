"""Tests for detect-gcp-audit-logs-disabled."""

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
SPEC = importlib.util.spec_from_file_location("detect_gcp_audit_logs_disabled_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCEPTED_PRODUCERS = MODULE.ACCEPTED_PRODUCERS
DISABLING_OPERATIONS = MODULE.DISABLING_OPERATIONS
TECHNIQUE_UID = MODULE.TECHNIQUE_UID
detect = MODULE.detect


def _gcp_event(
    *,
    operation: str = "google.logging.v2.ConfigServiceV2.DeleteSink",
    success: bool = True,
    target_name: str = "audit-export",
    actor: str = "alice@example.com",
    account_uid: str = "p-1",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-gcp-audit-ocsf",
) -> dict:
    resource_path = (
        f"projects/{account_uid}/sinks/{target_name}"
        if operation.endswith("DeleteSink")
        else f"projects/{account_uid}/logs/{target_name}"
    )
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
        "api": {"operation": operation, "service": {"name": "logging.googleapis.com"}},
        "cloud": {"provider": "GCP", "account": {"uid": account_uid}, "region": "global"},
        "resources": [{"name": resource_path, "type": "logging_resource"}] if target_name else [],
    }


def test_accepted_producer_is_gcp_audit():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-gcp-audit-ocsf"})


def test_disabling_operations_are_delete_sink_and_delete_log():
    assert DISABLING_OPERATIONS == frozenset(
        {
            "google.logging.v2.ConfigServiceV2.DeleteSink",
            "google.logging.v2.LoggingServiceV2.DeleteLog",
        }
    )


def test_fires_on_delete_sink():
    findings = list(detect([_gcp_event(operation="google.logging.v2.ConfigServiceV2.DeleteSink")]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["class_uid"] == 2004
    assert finding["finding_info"]["attacks"][0]["technique_uid"] == TECHNIQUE_UID
    assert any(obs["name"] == "target.name" and obs["value"] == "audit-export" for obs in finding["observables"])


def test_fires_on_delete_log():
    findings = list(detect([_gcp_event(operation="google.logging.v2.LoggingServiceV2.DeleteLog", target_name="cloudaudit.googleapis.com%2Factivity")]))
    assert len(findings) == 1
    assert any(obs["name"] == "api.operation" and obs["value"] == "google.logging.v2.LoggingServiceV2.DeleteLog" for obs in findings[0]["observables"])


def test_native_output_contains_target_identity():
    findings = list(
        detect(
            [_gcp_event(operation="google.logging.v2.ConfigServiceV2.DeleteSink", target_name="audit-export")],
            output_format="native",
        )
    )
    finding = findings[0]
    assert finding["schema_mode"] == "native"
    assert finding["target_name"] == "audit-export"
    assert finding["target_type"] == "log_sink"


def test_skips_failed_event():
    assert list(detect([_gcp_event(success=False)])) == []


def test_skips_unrelated_operation():
    assert list(detect([_gcp_event(operation="google.logging.v2.ConfigServiceV2.CreateSink")])) == []


def test_skips_wrong_producer(capsys):
    findings = list(detect([_gcp_event(producer="ingest-cloudtrail-ocsf")]))
    assert findings == []
    assert "non-gcp-audit producer" in capsys.readouterr().err


def test_skips_missing_target(capsys):
    findings = list(detect([_gcp_event(target_name="")]))
    assert findings == []
    assert "missing logging target" in capsys.readouterr().err


def test_rejects_unknown_output_format():
    with pytest.raises(ContractError, match="unsupported output_format") as excinfo:
        list(detect([_gcp_event()], output_format="weird"))
    assert excinfo.value.error_class == "contract"
    assert excinfo.value.retryable is False
    assert excinfo.value.hint
    assert "ocsf" in excinfo.value.hint or "native" in excinfo.value.hint


def test_finding_uid_is_deterministic():
    event = _gcp_event()
    first = list(detect([event]))[0]["finding_info"]["uid"]
    second = list(detect([event]))[0]["finding_info"]["uid"]
    assert first == second
    assert first.startswith("gald-")
