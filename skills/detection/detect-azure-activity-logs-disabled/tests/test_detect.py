"""Tests for detect-azure-activity-logs-disabled."""

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
SPEC = importlib.util.spec_from_file_location("detect_azure_activity_logs_disabled_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCEPTED_PRODUCERS = MODULE.ACCEPTED_PRODUCERS
DIAGNOSTIC_DELETE_OPERATION = MODULE.DIAGNOSTIC_DELETE_OPERATION
TECHNIQUE_UID = MODULE.TECHNIQUE_UID
detect = MODULE.detect


def _az_event(
    *,
    operation: str = "Microsoft.Insights/diagnosticSettings/delete",
    success: bool = True,
    resource_id: str = (
        "/subscriptions/00000000-0000-0000-0000-000000000001/"
        "resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web/"
        "providers/Microsoft.Insights/diagnosticSettings/activity-export"
    ),
    actor: str = "alice@example.com",
    account_uid: str = "00000000-0000-0000-0000-000000000001",
    region: str = "eastus",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-azure-activity-ocsf",
) -> dict:
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
        "resources": [{"name": resource_id, "type": "diagnosticsettings"}] if resource_id else [],
        "cloud": {"provider": "Azure", "account": {"uid": account_uid}, "region": region},
    }


def test_accepted_producer_is_azure_activity():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-azure-activity-ocsf"})


def test_delete_operation_constant():
    assert DIAGNOSTIC_DELETE_OPERATION == "microsoft.insights/diagnosticsettings/delete"


def test_fires_on_diagnostic_settings_delete():
    findings = list(detect([_az_event()]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["class_uid"] == 2004
    assert finding["finding_info"]["attacks"][0]["technique_uid"] == TECHNIQUE_UID
    assert any(
        obs["name"] == "target.name" and obs["value"] == "activity-export"
        for obs in finding["observables"]
    )


def test_operation_match_is_case_insensitive():
    findings = list(detect([_az_event(operation="MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE")]))
    assert len(findings) == 1


def test_native_output_contains_target_identity():
    findings = list(detect([_az_event()], output_format="native"))
    finding = findings[0]
    assert finding["schema_mode"] == "native"
    assert finding["setting_name"] == "activity-export"
    assert finding["resource_id"].endswith("/diagnosticSettings/activity-export")


def test_skips_failed_event():
    assert list(detect([_az_event(success=False)])) == []


def test_skips_unrelated_operation():
    assert list(detect([_az_event(operation="Microsoft.Insights/diagnosticSettings/write")])) == []


def test_skips_wrong_producer(capsys):
    findings = list(detect([_az_event(producer="ingest-cloudtrail-ocsf")]))
    assert findings == []
    assert "non-azure-activity producer" in capsys.readouterr().err


def test_skips_missing_resource_id(capsys):
    findings = list(detect([_az_event(resource_id="")]))
    assert findings == []
    assert "missing resource id" in capsys.readouterr().err


def test_rejects_unknown_output_format():
    with pytest.raises(ContractError, match="unsupported output_format") as excinfo:
        list(detect([_az_event()], output_format="weird"))
    assert excinfo.value.error_class == "contract"
    assert excinfo.value.retryable is False
    assert excinfo.value.hint
    assert "ocsf" in excinfo.value.hint or "native" in excinfo.value.hint


def test_finding_uid_is_deterministic():
    event = _az_event()
    first = list(detect([event]))[0]["finding_info"]["uid"]
    second = list(detect([event]))[0]["finding_info"]["uid"]
    assert first == second
    assert first.startswith("aad-")
