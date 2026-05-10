"""Tests for detect-snowflake-account-key-creation."""

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
    DEFAULT_KEY_STATEMENT_HINTS,
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
INPUT = GOLDEN / "snowflake_account_key_input.ocsf.jsonl"
EXPECTED = GOLDEN / "snowflake_account_key_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "SECURITYADMIN",
    actor_name: str = "SECURITYADMIN",
    api_operation: str = "ALTER_USER",
    target_user: str = "ANALYST_BOB",
    statement_kind: str = "ALTER_USER_SET_RSA_PUBLIC_KEY",
    rsa_public_key_set: bool = True,
    producer: str = "ingest-snowflake-query-history-ocsf",
    status_id: int = 1,
) -> dict:
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
        "unmapped": {
            "snowflake": {
                "target_user": target_user,
                "statement_kind": statement_kind,
                "rsa_public_key_set": rsa_public_key_set,
                "query_id": uid,
            }
        },
    }


class TestDetection:
    def test_rsa_public_key_set_fires_once(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000)]
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
        assert finding["evidence"]["target_user"] == "ANALYST_BOB"
        assert finding["evidence"]["key_slot"] == "RSA_PUBLIC_KEY"

    def test_rsa_public_key_2_slot_also_fires(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                statement_kind="ALTER_USER_SET_RSA_PUBLIC_KEY_2",
                rsa_public_key_set=False,
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["key_slot"] == "RSA_PUBLIC_KEY_2"

    def test_non_key_alter_user_is_ignored(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                statement_kind="ALTER_USER_SET_DEFAULT_ROLE",
                rsa_public_key_set=False,
            )
        ]
        assert list(detect(events)) == []

    def test_failed_key_set_does_not_fire(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, status_id=2)]
        assert list(detect(events)) == []

    def test_non_snowflake_producer_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, producer="ingest-cloudtrail-ocsf")]
        assert list(detect(events)) == []

    def test_missing_target_user_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, target_user="")]
        assert list(detect(events)) == []

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000),
            _event(uid="q-1", time_ms=1_000),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_multi_event_aggregation_two_users_two_findings(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000, target_user="ANALYST_BOB"),
            _event(uid="q-2", time_ms=2_000, target_user="ANALYST_CAROL"),
        ]
        findings = list(detect(events))
        assert len(findings) == 2

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
            assert exc.error_class == "contract"
        else:
            raise AssertionError("expected unsupported output_format to raise")

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestHintOverride:
    def test_env_override_restricts_hints(self, monkeypatch) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                statement_kind="ALTER_USER_SET_RSA_PUBLIC_KEY_2",
                rsa_public_key_set=False,
            )
        ]
        # default: fires
        assert len(list(detect(events))) == 1
        # restrict to RSA_PUBLIC_KEY only: no fire
        monkeypatch.setenv("SNOWFLAKE_KEY_STATEMENT_HINTS", "RSA_PUBLIC_KEY")
        assert list(detect(events)) == []


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("snowflake",)
        assert ANCHOR_OPERATION in metadata["attack_coverage"]["snowflake"]["anchor_operations"]
        assert "ingest-snowflake-query-history-ocsf" in ACCEPTED_PRODUCERS
        assert DEFAULT_KEY_STATEMENT_HINTS == ("RSA_PUBLIC_KEY", "RSA_PUBLIC_KEY_2")


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
