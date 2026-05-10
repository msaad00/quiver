"""Tests for detect-snowflake-share-creation."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    API_ACTIVITY_CLASS_UID,
    DEFAULT_SHARE_OPERATIONS,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
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
INPUT = GOLDEN / "snowflake_share_creation_input.ocsf.jsonl"
EXPECTED = GOLDEN / "snowflake_share_creation_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "ACCOUNTADMIN",
    actor_name: str = "ACCOUNTADMIN",
    api_operation: str = "CREATE_SHARE",
    share_name: str = "DATA_SHARE_ALPHA",
    target_accounts: list[str] | None = None,
    producer: str = "ingest-snowflake-query-history-ocsf",
    status_id: int = 1,
) -> dict:
    snowflake_block = {
        "share_name": share_name,
        "operation_kind": api_operation.lower(),
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
    def test_create_share_fires_once(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, api_operation="CREATE_SHARE")]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["metadata"]["uid"] == finding["finding_info"]["uid"]
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["operation"] == "CREATE_SHARE"
        assert finding["evidence"]["share_name"] == "DATA_SHARE_ALPHA"

    def test_alter_share_add_accounts_fires_with_new_account(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=2_000,
                api_operation="ALTER_SHARE_ADD_ACCOUNTS",
                target_accounts=["ATTACKER_ACCOUNT_AB123"],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["operation"] == "ALTER_SHARE_ADD_ACCOUNTS"
        assert findings[0]["evidence"]["target_accounts"] == ["ATTACKER_ACCOUNT_AB123"]

    def test_alter_share_add_accounts_without_targets_is_ignored(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=2_000,
                api_operation="ALTER_SHARE_ADD_ACCOUNTS",
                target_accounts=[],
            )
        ]
        assert list(detect(events)) == []

    def test_failed_share_creation_does_not_fire(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, status_id=2)]
        assert list(detect(events)) == []

    def test_non_share_operation_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, api_operation="SELECT")]
        assert list(detect(events)) == []

    def test_non_snowflake_producer_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, producer="ingest-cloudtrail-ocsf")]
        assert list(detect(events)) == []

    def test_missing_share_name_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, share_name="")]
        assert list(detect(events)) == []

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000),
            _event(uid="q-1", time_ms=1_000),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_multi_event_aggregation_two_shares_two_findings(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, share_name="SHARE_A"),
            _event(uid="q-2", time_ms=2_000, share_name="SHARE_B"),
            _event(
                uid="q-3",
                time_ms=3_000,
                api_operation="ALTER_SHARE_ADD_ACCOUNTS",
                share_name="SHARE_A",
                target_accounts=["EXT_1"],
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 3

    def test_native_output_format(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000)]
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

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestOperationOverride:
    def test_env_override_restricts_operations(self, monkeypatch) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, api_operation="CREATE_SHARE"),
            _event(
                uid="q-2",
                time_ms=2_000,
                api_operation="ALTER_SHARE_ADD_ACCOUNTS",
                target_accounts=["EXT_1"],
            ),
        ]
        # default: both fire
        assert len(list(detect(events))) == 2

        monkeypatch.setenv("SNOWFLAKE_SHARE_OPERATIONS", "CREATE_SHARE")
        # only create_share fires now
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["operation"] == "CREATE_SHARE"


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("snowflake",)
        assert "CREATE_SHARE" in metadata["attack_coverage"]["snowflake"]["anchor_operations"]
        assert "ingest-snowflake-query-history-ocsf" in ACCEPTED_PRODUCERS
        assert DEFAULT_SHARE_OPERATIONS == ("CREATE_SHARE", "ALTER_SHARE_ADD_ACCOUNTS")


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
