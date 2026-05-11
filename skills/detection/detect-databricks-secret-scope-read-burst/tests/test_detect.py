"""Tests for detect-databricks-secret-scope-read-burst."""

from __future__ import annotations

import json
from pathlib import Path

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    ANCHOR_OPERATION,
    API_ACTIVITY_CLASS_UID,
    DATABRICKS_VENDOR_NAME,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPO_NAME,
    SEVERITY_HIGH,
    THRESHOLD_DEFAULT,
    THRESHOLD_ENV,
    WINDOW_MIN_DEFAULT,
    WINDOW_MIN_ENV,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "databricks_secret_scope_read_burst_input.ocsf.jsonl"
EXPECTED = GOLDEN / "databricks_secret_scope_read_burst_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "alice@example.com",
    actor_name: str = "Alice Engineer",
    api_operation: str = ANCHOR_OPERATION,
    workspace_id: str = "1234567890123456",
    secret_scope: str = "prod-vault",
    secret_key: str = "api-key-1",
    producer: str = "ingest-databricks-audit-ocsf",
    vendor_name: str = DATABRICKS_VENDOR_NAME,
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
        "api": {"operation": api_operation, "service": {"name": "databricks.secrets"}},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {
            "databricks": {
                "workspace_id": workspace_id,
                "secret_scope": secret_scope,
                "secret_key": secret_key,
            }
        },
    }


class TestDetection:
    def test_distinct_keys_burst_fires(self, monkeypatch) -> None:
        monkeypatch.setenv(THRESHOLD_ENV, "5")
        monkeypatch.setenv(WINDOW_MIN_ENV, "10")
        events = [
            _event(uid=f"ev-{i}", time_ms=1_000_000 + i * 1_000, secret_key=f"key-{i}")
            for i in range(5)
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        attack = finding["finding_info"]["attacks"][0]
        assert attack["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["distinct_keys_read"] == 5

    def test_same_key_read_repeatedly_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv(THRESHOLD_ENV, "5")
        events = [
            _event(uid=f"ev-{i}", time_ms=1_000_000 + i * 1_000, secret_key="poll-me")
            for i in range(50)
        ]
        assert list(detect(events)) == []

    def test_distinct_keys_across_two_scopes_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv(THRESHOLD_ENV, "5")
        events = []
        for i in range(3):
            events.append(_event(uid=f"ev-a-{i}", time_ms=1_000 + i, secret_scope="scope-a", secret_key=f"k-{i}"))
            events.append(_event(uid=f"ev-b-{i}", time_ms=2_000 + i, secret_scope="scope-b", secret_key=f"k-{i}"))
        # Each scope only has 3 distinct keys per actor, below threshold of 5.
        assert list(detect(events)) == []

    def test_failed_reads_do_not_count(self, monkeypatch) -> None:
        monkeypatch.setenv(THRESHOLD_ENV, "5")
        events = [
            _event(
                uid=f"ev-{i}",
                time_ms=1_000_000 + i * 1_000,
                secret_key=f"key-{i}",
                status_id=2,
            )
            for i in range(5)
        ]
        assert list(detect(events)) == []

    def test_cooldown_prevents_re_fire(self, monkeypatch) -> None:
        monkeypatch.setenv(THRESHOLD_ENV, "3")
        monkeypatch.setenv(WINDOW_MIN_ENV, "10")
        # Two bursts of 3 distinct keys back-to-back inside one window — should fire once.
        events = []
        for i in range(3):
            events.append(_event(uid=f"ev-a-{i}", time_ms=1_000 + i, secret_key=f"k-a-{i}"))
        for i in range(3):
            events.append(_event(uid=f"ev-b-{i}", time_ms=2_000 + i, secret_key=f"k-b-{i}"))
        findings = list(detect(events))
        assert len(findings) == 1

    def test_separate_actors_fire_separately(self, monkeypatch) -> None:
        monkeypatch.setenv(THRESHOLD_ENV, "3")
        events = []
        for i in range(3):
            events.append(_event(uid=f"a-{i}", time_ms=1_000 + i, actor_uid="alice@example.com", secret_key=f"k-{i}"))
        for i in range(3):
            events.append(_event(uid=f"b-{i}", time_ms=1_000 + i, actor_uid="bob@example.com", secret_key=f"k-{i}"))
        findings = list(detect(events))
        assert len(findings) == 2

    def test_malformed_payload_is_skipped(self, capsys) -> None:
        out = list(load_jsonl(['{"bad":', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_non_databricks_event_is_ignored(self, monkeypatch) -> None:
        monkeypatch.setenv(THRESHOLD_ENV, "3")
        events = [
            _event(
                uid=f"ev-{i}",
                time_ms=1_000 + i,
                producer="ingest-cloudtrail-ocsf",
                vendor_name="AWS",
                secret_key=f"k-{i}",
            )
            for i in range(5)
        ]
        assert list(detect(events)) == []

    def test_custom_threshold_via_env(self, monkeypatch) -> None:
        monkeypatch.setenv(THRESHOLD_ENV, "2")
        events = [
            _event(uid="ev-1", time_ms=1_000, secret_key="k-1"),
            _event(uid="ev-2", time_ms=1_001, secret_key="k-2"),
        ]
        assert len(list(detect(events))) == 1

    def test_native_output_format(self, monkeypatch) -> None:
        monkeypatch.setenv(THRESHOLD_ENV, "2")
        events = [
            _event(uid="ev-n-1", time_ms=1_000, secret_key="k-1"),
            _event(uid="ev-n-2", time_ms=1_001, secret_key="k-2"),
        ]
        findings = list(detect(events, output_format="native"))
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
        assert ANCHOR_OPERATION in metadata["attack_coverage"]["databricks"]["anchor_operations"]
        assert "ingest-databricks-audit-ocsf" in ACCEPTED_PRODUCERS
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert THRESHOLD_DEFAULT == 30
        assert WINDOW_MIN_DEFAULT == 10
