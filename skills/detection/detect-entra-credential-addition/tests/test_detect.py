"""Tests for detect-entra-credential-addition."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detect import (  # type: ignore[import-not-found]  # noqa: E402
    CANONICAL_VERSION,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    INGEST_SKILL,
    OUTPUT_FORMATS,
    REPO_NAME,
    REPO_VENDOR,
    SKILL_NAME,
    SUBTECHNIQUE_UID,
    TECHNIQUE_UID,
    coverage_metadata,
    detect,
    load_jsonl,
)

from skills._shared.errors import ContractError  # noqa: E402

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT = GOLDEN / "entra_directory_audit_sample.ocsf.jsonl"
EXPECTED = GOLDEN / "entra_credential_addition_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _ocsf_event(
    *,
    uid: str,
    operation: str,
    time_ms: int,
    status_id: int = 1,
    actor_name: str = "Terraform Runner",
    actor_uid: str = "spn-111",
    target_name: str = "payments-api",
    target_uid: str = "spn-target-1",
    target_type: str = "ServicePrincipal",
    correlation_uid: str = "corr-entra-1",
    src_ip: str | None = None,
    additional_details: list[dict] | None = None,
) -> dict:
    event = {
        "activity_id": 1,
        "category_uid": 6,
        "category_name": "Application Activity",
        "class_uid": 6003,
        "class_name": "API Activity",
        "type_uid": 600301,
        "severity_id": 1,
        "status_id": status_id,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": INGEST_SKILL},
            },
        },
        "actor": {"user": {"name": actor_name, "uid": actor_uid, "type": "ServicePrincipal"}},
        "api": {
            "operation": operation,
            "service": {"name": "Core Directory"},
            "request": {"uid": correlation_uid},
        },
        "cloud": {"provider": "Azure"},
        "resources": [{"name": target_name, "uid": target_uid, "type": target_type}],
        "unmapped": {"entra": {"additional_details": additional_details or []}},
    }
    if src_ip:
        event["src_endpoint"] = {"ip": src_ip}
    return event


def _native_event(
    *,
    uid: str,
    operation: str,
    time_ms: int,
    status_id: int = 1,
    actor_name: str = "Terraform Runner",
    actor_uid: str = "spn-111",
    target_name: str = "payments-api",
    target_uid: str = "spn-target-1",
    target_type: str = "ServicePrincipal",
    correlation_uid: str = "corr-entra-1",
    src_ip: str | None = None,
    additional_details: list[dict] | None = None,
) -> dict:
    event = {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "api_activity",
        "source_skill": INGEST_SKILL,
        "event_uid": uid,
        "provider": "Azure",
        "time_ms": time_ms,
        "status": "success" if status_id == 1 else "failure",
        "status_id": status_id,
        "activity_id": 1,
        "operation": operation,
        "service_name": "Core Directory",
        "correlation_uid": correlation_uid,
        "actor": {"user": {"name": actor_name, "uid": actor_uid, "type": "ServicePrincipal"}},
        "resources": [{"name": target_name, "uid": target_uid, "type": target_type}],
        "unmapped": {"entra": {"additional_details": additional_details or []}},
    }
    if src_ip:
        event["src_endpoint"] = {"ip": src_ip}
    return event


class TestDetection:
    def test_credential_addition_fires_for_ocsf(self):
        findings = list(
            detect(
                [
                    _ocsf_event(
                        uid="evt-1",
                        operation="Add service principal credentials",
                        time_ms=1776052800000,
                        additional_details=[{"key": "KeyId", "value": "cred-123"}],
                    )
                ]
            )
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        attacks = finding["finding_info"]["attacks"]
        assert attacks[0]["technique"]["uid"] == TECHNIQUE_UID
        assert attacks[0]["sub_technique"]["uid"] == SUBTECHNIQUE_UID

    def test_native_input_can_emit_native_finding(self):
        findings = list(
            detect(
                [
                    _native_event(
                        uid="evt-1",
                        operation="Create federated identity credential",
                        time_ms=1776052800000,
                        actor_name="alice@example.com",
                        actor_uid="user-123",
                        target_name="payments-api",
                        target_uid="app-target-1",
                        target_type="Application",
                        src_ip="203.0.113.20",
                        additional_details=[{"key": "Issuer", "value": "https://token.actions.githubusercontent.com"}],
                    )
                ],
                output_format="native",
            )
        )
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "Azure"
        assert finding["finding_types"] == ["entra-federated-credential-addition"]
        assert "class_uid" not in finding

    def test_failed_event_is_skipped(self):
        findings = list(
            detect(
                [
                    _ocsf_event(
                        uid="evt-2",
                        operation="Create federated identity credential",
                        time_ms=1776053100000,
                        status_id=2,
                    )
                ]
            )
        )
        assert findings == []

    def test_duplicate_event_uid_does_not_double_count(self):
        event = _ocsf_event(uid="evt-1", operation="Add service principal credentials", time_ms=1776052800000)
        findings = list(detect([event, event]))
        assert len(findings) == 1

    def test_golden_fixture_matches(self):
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)

    def test_rejects_unsupported_output_format(self):
        try:
            list(detect([], output_format="bridge"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
            assert exc.error_class == "contract"
            assert exc.retryable is False
            assert exc.hint
            assert "ocsf" in exc.hint or "native" in exc.hint
        else:
            raise AssertionError("expected unsupported output_format to raise")


class TestMetadata:
    def test_coverage_metadata(self):
        metadata = coverage_metadata()
        assert metadata["providers"] == ("azure", "entra", "microsoft-graph")
        assert metadata["attack_coverage"]["azure"]["techniques"] == [SUBTECHNIQUE_UID]


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        out = list(load_jsonl(['{"bad": ', '{"record_type": "api_activity"}']))
        assert out == [{"record_type": "api_activity"}]
        assert "skipping line 1" in capsys.readouterr().err
