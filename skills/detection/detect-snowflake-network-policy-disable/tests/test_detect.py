"""Tests for detect-snowflake-network-policy-disable."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    API_ACTIVITY_CLASS_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TECHNIQUE_UID,
    NETWORK_POLICY_OPERATIONS,
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
INPUT = GOLDEN / "snowflake_network_policy_disable_input.ocsf.jsonl"
EXPECTED = GOLDEN / "snowflake_network_policy_disable_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "ACCOUNTADMIN",
    actor_name: str = "alice@example.com",
    api_operation: str = "ALTER_NETWORK_POLICY",
    policy_name: str = "PROD_NETWORK_POLICY",
    allowed_ip_list: list[str] | None = None,
    blocked_ip_list: list[str] | None = None,
    operation_kind: str = "",
    producer: str = "ingest-snowflake-query-history-ocsf",
    status_id: int = 1,
) -> dict:
    snowflake_block: dict[str, object] = {
        "policy_name": policy_name,
        "operation_kind": operation_kind or api_operation.lower(),
        "query_id": uid,
    }
    if allowed_ip_list is not None:
        snowflake_block["allowed_ip_list"] = allowed_ip_list
    if blocked_ip_list is not None:
        snowflake_block["blocked_ip_list"] = blocked_ip_list
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
    def test_account_network_policy_unset_fires(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                api_operation="ALTER_ACCOUNT",
                operation_kind="account_network_policy_unset",
                policy_name="",
                allowed_ip_list=[],
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
        assert finding["evidence"]["opened_wide"] == "account_network_policy_unset"

    def test_allowed_ip_list_wildcard_ipv4_fires(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, allowed_ip_list=["0.0.0.0/0"])]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["opened_wide"] == "allowed_ip_list_wildcard"
        assert "0.0.0.0/0" in findings[0]["evidence"]["allowed_ip_list"]

    def test_allowed_ip_list_wildcard_ipv6_fires(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, allowed_ip_list=["::/0"])]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["opened_wide"] == "allowed_ip_list_wildcard"

    def test_restrictive_allowlist_does_not_fire(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, allowed_ip_list=["198.51.100.0/24", "203.0.113.10"])
        ]
        assert list(detect(events)) == []

    def test_non_network_operation_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, api_operation="SELECT")]
        assert list(detect(events)) == []

    def test_non_snowflake_producer_is_ignored(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                allowed_ip_list=["0.0.0.0/0"],
                producer="ingest-cloudtrail-ocsf",
            )
        ]
        assert list(detect(events)) == []

    def test_failed_event_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, allowed_ip_list=["0.0.0.0/0"], status_id=2)]
        assert list(detect(events)) == []

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, allowed_ip_list=["0.0.0.0/0"]),
            _event(uid="q-1", time_ms=1_000, allowed_ip_list=["0.0.0.0/0"]),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_create_network_policy_open_fires(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                api_operation="CREATE_NETWORK_POLICY",
                allowed_ip_list=["0.0.0.0/0"],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["operation"] == "CREATE_NETWORK_POLICY"

    def test_native_output_format(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, allowed_ip_list=["0.0.0.0/0"])]
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


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("snowflake",)
        assert "ALTER_NETWORK_POLICY" in NETWORK_POLICY_OPERATIONS
        assert "ingest-snowflake-query-history-ocsf" in ACCEPTED_PRODUCERS


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
