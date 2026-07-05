"""Tests for detect-gcp-service-account-token-minting."""

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
SPEC = importlib.util.spec_from_file_location(
    "detect_gcp_service_account_token_minting_under_test", SRC
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

detect = MODULE.detect
GENERATE_ACCESS_TOKEN_OPERATION = "google.iam.credentials.v1.GenerateAccessToken"
GENERATE_ID_TOKEN_OPERATION = "google.iam.credentials.v1.GenerateIdToken"


def _event(
    *,
    operation: str = GENERATE_ACCESS_TOKEN_OPERATION,
    service: str = "iamcredentials.googleapis.com",
    success: bool = True,
    target_service_account: str = "sa-deploy@my-project.iam.gserviceaccount.com",
    actor_name: str = "alice@example.com",
    project_uid: str = "my-project",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-gcp-audit-ocsf",
    resource_type: str = "service_account",
) -> dict:
    resources = []
    if target_service_account:
        resources.append(
            {
                "name": f"projects/-/serviceAccounts/{target_service_account}",
                "type": resource_type,
            }
        )
    return {
        "class_uid": 6003,
        "status_id": 1 if success else 2,
        "time": 1775797200000,
        "metadata": {"uid": "evt-1", "product": {"feature": {"name": producer}}},
        "actor": {"user": {"name": actor_name}},
        "src_endpoint": {"ip": src_ip},
        "api": {"operation": operation, "service": {"name": service}},
        "cloud": {"provider": "GCP", "account": {"uid": project_uid}},
        "resources": resources,
    }


def test_accepted_producer_is_gcp_audit():
    assert MODULE.ACCEPTED_PRODUCERS == frozenset({"ingest-gcp-audit-ocsf"})


def test_fires_on_generate_access_token():
    findings = list(detect([_event()]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["class_uid"] == 2004
    assert finding["finding_info"]["title"] == "GCP service account token minted"
    assert finding["evidence"]["token_type"] == "access_token"
    attack = finding["finding_info"]["attacks"][0]
    assert attack["sub_technique_uid"] == "T1098.001"


def test_fires_on_generate_id_token():
    findings = list(detect([_event(operation=GENERATE_ID_TOKEN_OPERATION)]))
    assert len(findings) == 1
    assert findings[0]["evidence"]["token_type"] == "id_token"
    assert any(
        obs["name"] == "token.type" and obs["value"] == "id_token"
        for obs in findings[0]["observables"]
    )


def test_native_output_contains_target_service_account_and_token_type():
    findings = list(
        detect(
            [_event(target_service_account="sa-ci@my-project.iam.gserviceaccount.com")],
            output_format="native",
        )
    )
    finding = findings[0]
    assert finding["schema_mode"] == "native"
    assert finding["target_service_account"] == "sa-ci@my-project.iam.gserviceaccount.com"
    assert finding["token_type"] == "access_token"
    assert finding["rule"] == "gcp-service-account-token-minting"


def test_skips_failed_event():
    assert list(detect([_event(success=False)])) == []


def test_skips_unrelated_operation():
    assert list(detect([_event(operation="google.iam.credentials.v1.SignJwt")])) == []


def test_skips_wrong_service():
    assert list(detect([_event(service="iam.googleapis.com")])) == []


def test_skips_wrong_producer(capsys):
    findings = list(detect([_event(producer="ingest-cloudtrail-ocsf")]))
    assert findings == []
    assert "non-gcp-audit producer" in capsys.readouterr().err


def test_skips_missing_target_service_account(capsys):
    findings = list(detect([_event(target_service_account="")]))
    assert findings == []
    assert "no target service account" in capsys.readouterr().err


def test_accepts_raw_service_account_resource_name_without_prefix():
    findings = list(
        detect(
            [
                {
                    **_event(),
                    "resources": [
                        {
                            "name": "sa-deploy@my-project.iam.gserviceaccount.com",
                            "type": "service_account",
                        }
                    ],
                }
            ]
        )
    )
    assert len(findings) == 1


def test_rejects_unknown_output_format():
    with pytest.raises(ContractError, match="unsupported output_format") as excinfo:
        list(detect([_event()], output_format="weird"))
    assert excinfo.value.error_class == "contract"
    assert excinfo.value.retryable is False
    assert excinfo.value.hint
    assert "ocsf" in excinfo.value.hint or "native" in excinfo.value.hint


def test_finding_uid_is_deterministic():
    event = _event()
    first = list(detect([event]))[0]["finding_info"]["uid"]
    second = list(detect([event]))[0]["finding_info"]["uid"]
    assert first == second
    assert first.startswith("gsatm-")
