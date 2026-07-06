"""Tests for detect-snowflake-unauthorized-grant."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    ANCHOR_OPERATION,
    API_ACTIVITY_CLASS_UID,
    DEFAULT_PRIVILEGED_ROLES,
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
INPUT = GOLDEN / "snowflake_unauthorized_grant_input.ocsf.jsonl"
EXPECTED = GOLDEN / "snowflake_unauthorized_grant_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "MALLORY",
    actor_name: str = "mallory@example.com",
    api_operation: str = "GRANT_ROLE",
    granted_role: str = "ACCOUNTADMIN",
    grantee_user: str = "ATTACKER_USER",
    grantee_role: str = "",
    producer: str = "ingest-snowflake-query-history-ocsf",
    status_id: int = 1,
) -> dict:
    snowflake_block: dict = {"granted_role": granted_role, "query_id": uid}
    if grantee_user:
        snowflake_block["grantee_user"] = grantee_user
    if grantee_role:
        snowflake_block["grantee_role"] = grantee_role
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
    def test_unauthorized_granter_fires_when_allowlist_enforced(self, monkeypatch) -> None:
        monkeypatch.setenv("SNOWFLAKE_AUTHORIZED_GRANTERS", "BREAK_GLASS_USER,SECURITYADMIN_BOT")
        events = [_event(uid="q-1", time_ms=1_000, actor_uid="MALLORY")]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["allowlist_mode"] == "enforced"
        assert finding["evidence"]["granted_role"] == "ACCOUNTADMIN"

    def test_fail_open_when_allowlist_empty(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, actor_uid="SECURITYADMIN_BOT")]
        findings = list(detect(events))
        # fail-open: fires even for what would be an allowed identity
        assert len(findings) == 1
        assert findings[0]["evidence"]["allowlist_mode"] == "fail-open"

    def test_authorized_granter_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv("SNOWFLAKE_AUTHORIZED_GRANTERS", "BREAK_GLASS_USER,SECURITYADMIN_BOT")
        events = [_event(uid="q-1", time_ms=1_000, actor_uid="BREAK_GLASS_USER")]
        assert list(detect(events)) == []

    def test_non_privileged_role_grant_does_not_fire(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, granted_role="ANALYST")]
        assert list(detect(events)) == []

    def test_failed_grant_does_not_fire(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, status_id=2)]
        assert list(detect(events)) == []

    def test_non_snowflake_producer_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, producer="ingest-cloudtrail-ocsf")]
        assert list(detect(events)) == []

    def test_missing_grantee_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, grantee_user="", grantee_role="")]
        assert list(detect(events)) == []

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000),
            _event(uid="q-1", time_ms=1_000),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_multi_event_two_unauthorized_grants_two_findings(self, monkeypatch) -> None:
        monkeypatch.setenv("SNOWFLAKE_AUTHORIZED_GRANTERS", "BREAK_GLASS_USER")
        events = [
            _event(uid="q-1", time_ms=1_000, actor_uid="MALLORY", granted_role="ACCOUNTADMIN"),
            _event(
                uid="q-2",
                time_ms=2_000,
                actor_uid="EVE",
                granted_role="SECURITYADMIN",
                grantee_user="ANOTHER_USER",
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 2

    def test_grantee_role_pathway(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, grantee_user="", grantee_role="SOME_ROLE")]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["grantee_role"] == "SOME_ROLE"

    def test_native_output_format(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000)]
        findings = list(detect(events, output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["provider"] == "Snowflake"

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


class TestPolicyOverrides:
    def test_privileged_roles_env_override(self, monkeypatch) -> None:
        # Add a custom role to the privileged list
        monkeypatch.setenv("SNOWFLAKE_PRIVILEGED_ROLES", "CUSTOM_ROOT")
        events = [_event(uid="q-1", time_ms=1_000, granted_role="ACCOUNTADMIN")]
        # ACCOUNTADMIN no longer in the new list → no fire
        assert list(detect(events)) == []
        events = [_event(uid="q-1", time_ms=1_000, granted_role="CUSTOM_ROOT")]
        assert len(list(detect(events))) == 1


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("snowflake",)
        assert ANCHOR_OPERATION in metadata["attack_coverage"]["snowflake"]["anchor_operations"]
        assert "ingest-snowflake-query-history-ocsf" in ACCEPTED_PRODUCERS
        assert DEFAULT_PRIVILEGED_ROLES == ("ACCOUNTADMIN", "SECURITYADMIN", "ORGADMIN")
        # default mode is fail-open with no env var
        assert metadata["thresholds"]["allowlist_mode"] == "fail-open"


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
