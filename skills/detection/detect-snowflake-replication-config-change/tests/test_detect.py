"""Tests for detect-snowflake-replication-config-change."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    API_ACTIVITY_CLASS_UID,
    AUTHORIZED_TARGETS_ENV,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPLICATION_OPERATIONS,
    REPO_NAME,
    REPO_VENDOR,
    SEVERITY_HIGH,
    SKILL_NAME,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "snowflake_replication_config_change_input.ocsf.jsonl"
EXPECTED = GOLDEN / "snowflake_replication_config_change_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "ACCOUNTADMIN",
    actor_name: str = "alice@example.com",
    api_operation: str = "ALTER_DATABASE_ENABLE_REPLICATION",
    database_name: str = "PROD_ANALYTICS",
    target_accounts: list[str] | None = None,
    operation_kind: str = "",
    producer: str = "ingest-snowflake-query-history-ocsf",
    status_id: int = 1,
) -> dict:
    snowflake_block: dict[str, object] = {
        "database_name": database_name,
        "operation_kind": operation_kind or api_operation.lower(),
        "query_id": uid,
    }
    if target_accounts is not None:
        snowflake_block["target_accounts"] = target_accounts
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
                "vendor_name": REPO_VENDOR,
                "feature": {"name": producer},
            },
        },
        "actor": {"user": {"uid": actor_uid, "name": actor_name, "type": "User"}},
        "api": {"operation": api_operation, "service": {"name": "snowflake.warehouse"}},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {"snowflake": snowflake_block},
    }


class TestDetection:
    def test_unauthorized_target_fires(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_TARGETS_ENV, "PARTNER_PROD_AB123")
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                target_accounts=["ATTACKER_ACCOUNT_XY789"],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["unauthorized_accounts"] == ["ATTACKER_ACCOUNT_XY789"]
        assert finding["evidence"]["allowlist_empty"] is False

    def test_failover_to_unauthorized_account_fires(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_TARGETS_ENV, "PARTNER_PROD_AB123")
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                api_operation="ALTER_DATABASE_ENABLE_FAILOVER",
                target_accounts=["ATTACKER_ACCOUNT_XY789"],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["operation"] == "ALTER_DATABASE_ENABLE_FAILOVER"

    def test_allowlist_match_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_TARGETS_ENV, "PARTNER_PROD_AB123,PARTNER_DR_XY789")
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                target_accounts=["PARTNER_PROD_AB123"],
            )
        ]
        assert list(detect(events)) == []

    def test_allowlist_is_case_insensitive(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_TARGETS_ENV, "partner_prod_ab123")
        events = [_event(uid="q-1", time_ms=1_000, target_accounts=["PARTNER_PROD_AB123"])]
        assert list(detect(events)) == []

    def test_empty_allowlist_fails_open_with_stderr_warning(self, monkeypatch, capsys) -> None:
        monkeypatch.delenv(AUTHORIZED_TARGETS_ENV, raising=False)
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                target_accounts=["ANY_ACCOUNT"],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["allowlist_empty"] is True
        err = capsys.readouterr().err
        assert "allowlist_empty" in err

    def test_account_replication_enable_with_empty_allowlist_fires(self, monkeypatch) -> None:
        monkeypatch.delenv(AUTHORIZED_TARGETS_ENV, raising=False)
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                api_operation="ALTER_ACCOUNT_SET_REPLICATION",
                database_name="",
                target_accounts=[],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["allowlist_empty"] is True

    def test_non_replication_operation_is_ignored(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_TARGETS_ENV, "PARTNER_PROD_AB123")
        events = [_event(uid="q-1", time_ms=1_000, api_operation="SELECT")]
        assert list(detect(events)) == []

    def test_non_snowflake_producer_is_ignored(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_TARGETS_ENV, "PARTNER_PROD_AB123")
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                target_accounts=["ATTACKER_XY"],
                producer="ingest-cloudtrail-ocsf",
            )
        ]
        assert list(detect(events)) == []

    def test_failed_event_is_ignored(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_TARGETS_ENV, "PARTNER_PROD_AB123")
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                target_accounts=["ATTACKER_XY"],
                status_id=2,
            )
        ]
        assert list(detect(events)) == []

    def test_duplicate_metadata_uid_does_not_inflate(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_TARGETS_ENV, "PARTNER_PROD_AB123")
        events = [
            _event(uid="q-1", time_ms=1_000, target_accounts=["ATTACKER_XY"]),
            _event(uid="q-1", time_ms=1_000, target_accounts=["ATTACKER_XY"]),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_native_output_format(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_TARGETS_ENV, "PARTNER_PROD_AB123")
        events = [_event(uid="q-1", time_ms=1_000, target_accounts=["ATTACKER_XY"])]
        findings = list(detect(events, output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "Snowflake"
        assert "class_uid" not in finding

    def test_rejects_unsupported_output_format(self) -> None:
        from skills._shared.errors import ContractError

        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
            assert exc.error_class == "contract"
            assert exc.retryable is False
        else:
            raise AssertionError("expected unsupported output_format to raise")

    def test_golden_fixture_matches(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_TARGETS_ENV, "PARTNER_PROD_AB123,PARTNER_DR_XY789")
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("snowflake",)
        assert "ALTER_DATABASE_ENABLE_REPLICATION" in REPLICATION_OPERATIONS
        assert "ingest-snowflake-query-history-ocsf" in ACCEPTED_PRODUCERS
        assert metadata["allowlist_env"] == AUTHORIZED_TARGETS_ENV


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
