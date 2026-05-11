"""Tests for detect-databricks-mlflow-model-exfil."""

from __future__ import annotations

import json
from pathlib import Path

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    ANCHOR_OPERATIONS,
    API_ACTIVITY_CLASS_UID,
    ATLAS_TECHNIQUE_UID,
    DATABRICKS_VENDOR_NAME,
    DEDUPE_WINDOW_MIN_ENV,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPO_NAME,
    SEVERITY_HIGH,
    TRANSITION_OPERATION,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "databricks_mlflow_model_exfil_input.ocsf.jsonl"
EXPECTED = GOLDEN / "databricks_mlflow_model_exfil_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_email: str = "alice@example.com",
    actor_name: str = "Alice Engineer",
    api_operation: str = "mlflow.downloadArtifact",
    workspace_id: str = "1234567890123456",
    target_workspace_id: str = "",
    model_name: str = "fraud-classifier",
    model_version: str = "5",
    target_stage: str = "",
    producer: str = "ingest-databricks-audit-ocsf",
    vendor_name: str = DATABRICKS_VENDOR_NAME,
    status_id: int = 1,
) -> dict:
    databricks_block: dict = {
        "workspace_id": workspace_id,
        "model_name": model_name,
        "model_version": model_version,
    }
    if target_workspace_id:
        databricks_block["target_workspace_id"] = target_workspace_id
    if target_stage:
        databricks_block["target_stage"] = target_stage
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
                "uid": actor_email,
                "name": actor_name,
                "email_addr": actor_email,
                "type": "User",
            }
        },
        "api": {"operation": api_operation, "service": {"name": "databricks.mlflow"}},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {"databricks": databricks_block},
    }


class TestDetection:
    def test_download_artifact_fires(self) -> None:
        events = [_event(uid="ev-1", time_ms=1_000_000)]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        attack_uids = {a["technique"]["uid"] for a in finding["finding_info"]["attacks"]}
        assert MITRE_TECHNIQUE_UID in attack_uids
        assert ATLAS_TECHNIQUE_UID in attack_uids
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["model_name"] == "fraud-classifier"

    def test_cross_workspace_transition_fires(self) -> None:
        events = [
            _event(
                uid="ev-trans-1",
                time_ms=1_001_000,
                api_operation=TRANSITION_OPERATION,
                target_workspace_id="9999999999999999",
                target_stage="Production",
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["target_workspace_id"] == "9999999999999999"

    def test_same_workspace_transition_does_not_fire(self) -> None:
        events = [
            _event(
                uid="ev-trans-same",
                time_ms=1_000,
                api_operation=TRANSITION_OPERATION,
                target_workspace_id="1234567890123456",  # same as workspace_id
                target_stage="Staging",
            )
        ]
        assert list(detect(events)) == []

    def test_transition_without_target_workspace_does_not_fire(self) -> None:
        events = [
            _event(
                uid="ev-trans-no-target",
                time_ms=1_000,
                api_operation=TRANSITION_OPERATION,
                target_stage="Production",
            )
        ]
        assert list(detect(events)) == []

    def test_failed_download_does_not_fire(self) -> None:
        events = [_event(uid="ev-fail-1", time_ms=1_000, status_id=2)]
        assert list(detect(events)) == []

    def test_burst_collapses_to_one_finding_per_pair(self) -> None:
        events = [
            _event(uid=f"ev-burst-{i}", time_ms=1_000_000 + i * 1_000) for i in range(5)
        ]
        findings = list(detect(events))
        # All 5 are same (model, actor) within 24h => one finding.
        assert len(findings) == 1

    def test_distinct_actors_fire_separately(self) -> None:
        events = [
            _event(uid="ev-a-1", time_ms=1_000_000, actor_email="alice@example.com"),
            _event(uid="ev-b-1", time_ms=1_000_010, actor_email="bob@example.com"),
        ]
        findings = list(detect(events))
        assert len(findings) == 2

    def test_short_window_re_fires(self, monkeypatch) -> None:
        # 1-minute dedupe window; two events 5 minutes apart should fire twice.
        monkeypatch.setenv(DEDUPE_WINDOW_MIN_ENV, "1")
        events = [
            _event(uid="ev-w-1", time_ms=1_000_000),
            _event(uid="ev-w-2", time_ms=1_000_000 + 5 * 60_000),
        ]
        findings = list(detect(events))
        assert len(findings) == 2

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
        assert ATLAS_TECHNIQUE_UID in metadata["attack_coverage"]["databricks"]["techniques"]
        assert "mlflow.downloadArtifact" in metadata["attack_coverage"]["databricks"]["anchor_operations"]
        assert "ingest-databricks-audit-ocsf" in ACCEPTED_PRODUCERS
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert "mlflow.getModelVersionDownloadUri" in ANCHOR_OPERATIONS
