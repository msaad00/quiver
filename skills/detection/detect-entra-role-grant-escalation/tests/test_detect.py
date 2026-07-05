"""Tests for detect-entra-role-grant-escalation."""

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
    API_ACTIVITY_CLASS_UID,
    CANONICAL_VERSION,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
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
INPUT = GOLDEN / "entra_role_grant_input.ocsf.jsonl"
EXPECTED = GOLDEN / "entra_role_grant_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    status_id: int = 1,
    source_skill: str = "ingest-entra-directory-audit-ocsf",
    operation: str = "Add app role assignment to service principal",
) -> dict:
    return {
        "activity_id": 3,
        "category_uid": 6,
        "category_name": "Application Activity",
        "class_uid": API_ACTIVITY_CLASS_UID,
        "class_name": "API Activity",
        "type_uid": 600303,
        "severity_id": 1,
        "status_id": status_id,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": source_skill},
            },
        },
        "cloud": {"provider": "Azure"},
        "api": {
            "operation": operation,
            "service": {"name": "Core Directory"},
            "request": {"uid": f"corr-{uid}"},
        },
        "actor": {
            "user": {
                "uid": "user-123",
                "name": "alice@example.com",
                "email_addr": "alice@example.com",
            }
        },
        "src_endpoint": {"ip": "203.0.113.44"},
        "resources": [{"uid": "spn-target-1", "name": "payments-api", "type": "ServicePrincipal"}],
        "unmapped": {
            "entra": {
                "additional_details": [
                    {"key": "AppRoleId", "value": "role-123"},
                    {"key": "ResourceDisplayName", "value": "Microsoft Graph"},
                ]
            }
        },
    }


def _native_event(
    *,
    uid: str,
    time_ms: int,
    status_id: int = 1,
    source_skill: str = "ingest-entra-directory-audit-ocsf",
    operation: str = "Add app role assignment to service principal",
) -> dict:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "api_activity",
        "source_skill": source_skill,
        "event_uid": uid,
        "provider": "Azure",
        "time_ms": time_ms,
        "status_id": status_id,
        "operation": operation,
        "service_name": "Core Directory",
        "correlation_uid": f"corr-{uid}",
        "actor": {
            "user": {
                "uid": "user-123",
                "name": "alice@example.com",
                "email_addr": "alice@example.com",
            }
        },
        "src_endpoint": {"ip": "203.0.113.44"},
        "resources": [{"uid": "spn-target-1", "name": "payments-api", "type": "ServicePrincipal"}],
        "unmapped": {
            "entra": {
                "additional_details": [
                    {"key": "AppRoleId", "value": "role-123"},
                    {"key": "ResourceDisplayName", "value": "Microsoft Graph"},
                ]
            }
        },
    }


class TestDetection:
    def test_successful_role_grant_fires(self):
        findings = list(detect([_event(uid="evt-1", time_ms=1000)]))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["metadata"]["product"]["name"] == REPO_NAME
        assert finding["metadata"]["product"]["vendor_name"] == REPO_VENDOR
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        attacks = finding["finding_info"]["attacks"]
        assert attacks[0]["technique"]["uid"] == TECHNIQUE_UID
        assert attacks[0]["sub_technique"]["uid"] == SUBTECHNIQUE_UID

    def test_failed_role_grant_is_skipped(self):
        assert list(detect([_event(uid="evt-1", time_ms=1000, status_id=2)])) == []

    def test_wrong_source_skill_is_skipped(self):
        assert (
            list(detect([_event(uid="evt-1", time_ms=1000, source_skill="ingest-cloudtrail-ocsf")]))
            == []
        )

    def test_duplicate_event_uid_is_suppressed(self):
        findings = list(
            detect([_event(uid="evt-1", time_ms=1000), _event(uid="evt-1", time_ms=1000)])
        )
        assert len(findings) == 1

    def test_golden_fixture_matches(self):
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)

    def test_native_input_can_emit_native_finding(self):
        findings = list(detect([_native_event(uid="evt-1", time_ms=1000)], output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "Azure"
        assert "class_uid" not in finding

    def test_native_input_can_emit_ocsf_finding(self):
        findings = list(detect([_native_event(uid="evt-1", time_ms=1000)], output_format="ocsf"))
        assert len(findings) == 1
        assert findings[0]["class_uid"] == FINDING_CLASS_UID

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
        assert "app-role-assignments" in metadata["asset_classes"]


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
