"""Tests for detect-databricks-unity-catalog-cross-workspace-share."""

from __future__ import annotations

import json
from pathlib import Path

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    ANCHOR_OPERATIONS,
    API_ACTIVITY_CLASS_UID,
    AUTHORIZED_RECIPIENTS_ENV,
    DATABRICKS_VENDOR_NAME,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPO_NAME,
    SEVERITY_HIGH,
    SKILL_NAME,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "databricks_unity_catalog_cross_workspace_share_input.ocsf.jsonl"
EXPECTED = GOLDEN / "databricks_unity_catalog_cross_workspace_share_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "alice@example.com",
    actor_name: str = "Alice Engineer",
    api_operation: str = "unityCatalog.CreateRecipient",
    workspace_id: str = "1234567890123456",
    recipient_id: str = "ext-recipient-1",
    recipient_type: str = "EXTERNAL",
    share_name: str = "",
    share_recipients: list[str] | None = None,
    producer: str = "ingest-databricks-audit-ocsf",
    vendor_name: str = DATABRICKS_VENDOR_NAME,
    status_id: int = 1,
) -> dict:
    databricks_block: dict = {"workspace_id": workspace_id}
    if recipient_id or recipient_type:
        databricks_block["recipient"] = {"id": recipient_id, "type": recipient_type}
    if share_name or share_recipients:
        databricks_block["share"] = {
            "name": share_name,
            "recipients": share_recipients or [],
        }
    return {
        "activity_id": 1,
        "category_uid": 6,
        "category_name": "Application Activity",
        "class_uid": API_ACTIVITY_CLASS_UID,
        "class_name": "API Activity",
        "type_uid": API_ACTIVITY_CLASS_UID * 100 + 1,
        "severity_id": 1,
        "status_id": status_id,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": vendor_name,
                "feature": {"name": producer},
            },
        },
        "actor": {
            "user": {
                "uid": actor_uid,
                "name": actor_name,
                "email_addr": actor_uid,
                "type": "User",
            }
        },
        "api": {"operation": api_operation, "service": {"name": "databricks.unity-catalog"}},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {"databricks": databricks_block},
    }


class TestDetection:
    def test_external_recipient_fires(self) -> None:
        events = [_event(uid="ev-1", time_ms=1_000_000)]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        attack = finding["finding_info"]["attacks"][0]
        assert attack["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert "databricks-uc-cross-workspace-share" in finding["finding_info"]["types"]
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["recipient_id"] == "ext-recipient-1"
        assert finding["evidence"]["recipient_type"] == "EXTERNAL"
        assert finding["evidence"]["allowlist_mode"] == "fail-open"

    def test_share_create_with_off_allowlist_recipient_fires(self) -> None:
        events = [
            _event(
                uid="ev-share-1",
                time_ms=1_001_000,
                api_operation="unityCatalog.CreateShare",
                recipient_id="",
                recipient_type="",
                share_name="customer-pii-share",
                share_recipients=["ext-recipient-2"],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["share_name"] == "customer-pii-share"
        assert findings[0]["evidence"]["share_recipients"] == ["ext-recipient-2"]

    def test_authorized_recipient_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_RECIPIENTS_ENV, "ext-recipient-1,ext-recipient-2")
        events = [_event(uid="ev-auth-1", time_ms=1_000)]
        assert list(detect(events)) == []

    def test_internal_recipient_does_not_fire(self) -> None:
        events = [
            _event(
                uid="ev-internal-1",
                time_ms=1_000,
                recipient_type="DATABRICKS",
            )
        ]
        assert list(detect(events)) == []

    def test_failed_event_does_not_fire(self) -> None:
        events = [_event(uid="ev-fail-1", time_ms=1_000, status_id=2)]
        assert list(detect(events)) == []

    def test_fail_open_emits_telemetry(self, capsys, monkeypatch) -> None:
        monkeypatch.delenv(AUTHORIZED_RECIPIENTS_ENV, raising=False)
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        events = [_event(uid="ev-fo-1", time_ms=1_000)]
        list(detect(events))
        err = capsys.readouterr().err
        # The first stderr record is the allowlist_fail_open warning.
        first = json.loads(err.strip().splitlines()[0])
        assert first["event"] == "allowlist_fail_open"
        assert first["skill"] == SKILL_NAME

    def test_non_databricks_event_is_ignored(self) -> None:
        events = [
            _event(
                uid="ev-other-1",
                time_ms=1_000,
                producer="ingest-cloudtrail-ocsf",
                vendor_name="AWS",
            )
        ]
        assert list(detect(events)) == []

    def test_malformed_payload_is_skipped(self, capsys) -> None:
        out = list(load_jsonl(['{"bad":', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_share_with_partial_allowlist_fires_when_any_unauthorized(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_RECIPIENTS_ENV, "ext-recipient-2")
        events = [
            _event(
                uid="ev-share-mixed",
                time_ms=1_002_000,
                api_operation="unityCatalog.UpdateShare",
                recipient_id="",
                recipient_type="",
                share_name="mixed-share",
                share_recipients=["ext-recipient-2", "ext-recipient-3"],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["share_recipients"] == ["ext-recipient-2", "ext-recipient-3"]

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [
            _event(uid="ev-dup", time_ms=1_000),
            _event(uid="ev-dup", time_ms=1_000),
        ]
        assert len(list(detect(events))) == 1

    def test_native_output_format(self) -> None:
        findings = list(detect([_event(uid="ev-native", time_ms=1_000)], output_format="native"))
        assert len(findings) == 1
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["provider"] == "Databricks"
        assert "class_uid" not in findings[0]

    def test_rejects_unsupported_output_format(self) -> None:
        from skills._shared.errors import ContractError

        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
        else:
            raise AssertionError("expected unsupported output_format to raise")

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("databricks",)
        assert MITRE_TECHNIQUE_UID in metadata["attack_coverage"]["databricks"]["techniques"]
        assert (
            "unityCatalog.CreateRecipient"
            in metadata["attack_coverage"]["databricks"]["anchor_operations"]
        )
        assert (
            "unityCatalog.CreateShare"
            in metadata["attack_coverage"]["databricks"]["anchor_operations"]
        )
        assert "ingest-databricks-audit-ocsf" in ACCEPTED_PRODUCERS
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert "unityCatalog.UpdateRecipient" in ANCHOR_OPERATIONS
