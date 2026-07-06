"""Tests for detect-databricks-workspace-admin-grant."""

from __future__ import annotations

import json
from pathlib import Path

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    ACCOUNT_SET_ADMIN_OPERATION,
    ADD_USER_TO_GROUP_OPERATION,
    ADMIN_GROUP_NAMES,
    ANCHOR_OPERATIONS,
    API_ACTIVITY_CLASS_UID,
    AUTHORIZED_GRANTERS_ENV,
    DATABRICKS_VENDOR_NAME,
    DEFAULT_GRANT_WINDOW,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    GRANT_WINDOW_ENV,
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
INPUT = GOLDEN / "databricks_workspace_admin_grant_input.ocsf.jsonl"
EXPECTED = GOLDEN / "databricks_workspace_admin_grant_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "mallory@example.com",
    actor_name: str = "Mallory Granter",
    api_operation: str = ACCOUNT_SET_ADMIN_OPERATION,
    workspace_id: str = "1234567890123456",
    grantee: str = "newadmin@example.com",
    group_name: str = "",
    producer: str = "ingest-databricks-audit-ocsf",
    vendor_name: str = DATABRICKS_VENDOR_NAME,
    status_id: int = 1,
) -> dict:
    databricks_block: dict = {
        "workspace_id": workspace_id,
        "grantee": {"uid": grantee, "email_addr": grantee},
    }
    if group_name:
        databricks_block["group_name"] = group_name
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
        "api": {"operation": api_operation, "service": {"name": "databricks.iam"}},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {"databricks": databricks_block},
    }


# 2026-04-15T10:00:00Z — inside the default 08-18 UTC window.
TIME_IN_WINDOW_MS = 1744711200000
# 2026-04-15T03:00:00Z — outside the default window.
TIME_OUTSIDE_WINDOW_MS = 1744686000000


class TestDetection:
    def test_unauthorized_granter_fires(self) -> None:
        events = [_event(uid="ev-1", time_ms=TIME_IN_WINDOW_MS)]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        attack = finding["finding_info"]["attacks"][0]
        assert attack["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["allowlist_mode"] == "fail-open"

    def test_add_to_admins_outside_window_fires(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_GRANTERS_ENV, "mallory@example.com")
        events = [
            _event(
                uid="ev-window-1",
                time_ms=TIME_OUTSIDE_WINDOW_MS,
                api_operation=ADD_USER_TO_GROUP_OPERATION,
                group_name="admins",
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["within_change_window"] is False

    def test_authorized_granter_in_window_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_GRANTERS_ENV, "mallory@example.com")
        events = [_event(uid="ev-clean-1", time_ms=TIME_IN_WINDOW_MS)]
        assert list(detect(events)) == []

    def test_failed_grant_does_not_fire(self) -> None:
        events = [_event(uid="ev-fail-1", time_ms=TIME_IN_WINDOW_MS, status_id=2)]
        assert list(detect(events)) == []

    def test_add_to_non_admin_group_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_GRANTERS_ENV, "mallory@example.com")
        events = [
            _event(
                uid="ev-other-group",
                time_ms=TIME_IN_WINDOW_MS,
                api_operation=ADD_USER_TO_GROUP_OPERATION,
                group_name="data-scientists",
            )
        ]
        assert list(detect(events)) == []

    def test_fail_open_emits_telemetry(self, capsys, monkeypatch) -> None:
        monkeypatch.delenv(AUTHORIZED_GRANTERS_ENV, raising=False)
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        events = [_event(uid="ev-fo-1", time_ms=TIME_IN_WINDOW_MS)]
        list(detect(events))
        err = capsys.readouterr().err
        first = json.loads(err.strip().splitlines()[0])
        assert first["event"] == "allowlist_fail_open"
        assert first["skill"] == SKILL_NAME

    def test_invalid_window_falls_back(self, monkeypatch, capsys) -> None:
        monkeypatch.setenv(GRANT_WINDOW_ENV, "garbage")
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        events = [_event(uid="ev-bad-window-1", time_ms=TIME_IN_WINDOW_MS)]
        findings = list(detect(events))
        # Fires anyway because fail-open allowlist.
        assert len(findings) == 1
        payloads = [
            json.loads(line)
            for line in capsys.readouterr().err.strip().splitlines()
            if line.strip()
        ]
        assert any(p.get("event") == "invalid_grant_window" for p in payloads)

    def test_non_databricks_event_is_ignored(self) -> None:
        events = [
            _event(
                uid="ev-other-1",
                time_ms=TIME_IN_WINDOW_MS,
                producer="ingest-cloudtrail-ocsf",
                vendor_name="AWS",
            )
        ]
        assert list(detect(events)) == []

    def test_malformed_payload_is_skipped(self, capsys) -> None:
        out = list(load_jsonl(['{"bad":', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_account_admins_group_grant_fires(self) -> None:
        events = [
            _event(
                uid="ev-acct-admins",
                time_ms=TIME_OUTSIDE_WINDOW_MS,
                api_operation=ADD_USER_TO_GROUP_OPERATION,
                group_name="account_admins",
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["group_name"] == "account_admins"

    def test_native_output_format(self) -> None:
        findings = list(
            detect([_event(uid="ev-native", time_ms=TIME_IN_WINDOW_MS)], output_format="native")
        )
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
            ACCOUNT_SET_ADMIN_OPERATION
            in metadata["attack_coverage"]["databricks"]["anchor_operations"]
        )
        assert (
            ADD_USER_TO_GROUP_OPERATION
            in metadata["attack_coverage"]["databricks"]["anchor_operations"]
        )
        assert "ingest-databricks-audit-ocsf" in ACCEPTED_PRODUCERS
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert "admins" in ADMIN_GROUP_NAMES
        assert "account_admins" in ADMIN_GROUP_NAMES
        assert ACCOUNT_SET_ADMIN_OPERATION in ANCHOR_OPERATIONS
        assert DEFAULT_GRANT_WINDOW == "08-18"
