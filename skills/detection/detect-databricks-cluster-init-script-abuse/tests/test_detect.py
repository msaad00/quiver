"""Tests for detect-databricks-cluster-init-script-abuse."""

from __future__ import annotations

import json
from pathlib import Path

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    ALLOWED_PATHS_ENV,
    ANCHOR_OPERATIONS,
    API_ACTIVITY_CLASS_UID,
    DATABRICKS_VENDOR_NAME,
    DEFAULT_ALLOWED_PATHS,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_PERSISTENCE_TECHNIQUE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPO_NAME,
    SEVERITY_HIGH,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "databricks_cluster_init_script_abuse_input.ocsf.jsonl"
EXPECTED = GOLDEN / "databricks_cluster_init_script_abuse_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "alice@example.com",
    actor_name: str = "Alice Engineer",
    api_operation: str = "clusters.create",
    workspace_id: str = "1234567890123456",
    cluster_id: str = "cluster-abc",
    cluster_name: str = "etl-cluster",
    init_scripts: list[dict] | None = None,
    producer: str = "ingest-databricks-audit-ocsf",
    vendor_name: str = DATABRICKS_VENDOR_NAME,
    status_id: int = 1,
) -> dict:
    if init_scripts is None:
        init_scripts = [{"destination": "s3://attacker-bucket/init.sh"}]
    databricks_block = {
        "workspace_id": workspace_id,
        "cluster_config": {
            "cluster_id": cluster_id,
            "cluster_name": cluster_name,
            "init_scripts": init_scripts,
        },
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
        "api": {"operation": api_operation, "service": {"name": "databricks.clusters"}},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {"databricks": databricks_block},
    }


class TestDetection:
    def test_external_s3_destination_fires(self) -> None:
        events = [_event(uid="ev-1", time_ms=1_000_000)]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        attack_uids = {a["technique"]["uid"] for a in finding["finding_info"]["attacks"]}
        assert MITRE_TECHNIQUE_UID in attack_uids
        assert MITRE_PERSISTENCE_TECHNIQUE_UID in attack_uids
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert "s3://attacker-bucket/init.sh" in finding["evidence"]["init_script_destination"]

    def test_curl_in_destination_fires(self) -> None:
        events = [
            _event(
                uid="ev-curl-1",
                time_ms=1_001_000,
                api_operation="clusters.edit",
                init_scripts=[{"destination": "dbfs:/databricks/init/curl-exec.sh"}],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert "unsafe shell-command pattern" in " ".join(findings[0]["evidence"]["violations"])

    def test_dbfs_internal_does_not_fire(self) -> None:
        events = [
            _event(
                uid="ev-clean-1",
                time_ms=1_000,
                init_scripts=[{"destination": "dbfs:/databricks/init/safe.sh"}],
            )
        ]
        assert list(detect(events)) == []

    def test_failed_event_does_not_fire(self) -> None:
        events = [_event(uid="ev-fail-1", time_ms=1_000, status_id=2)]
        assert list(detect(events)) == []

    def test_multiple_destinations_fire_per_pair(self) -> None:
        events = [
            _event(
                uid="ev-multi-1",
                time_ms=1_000,
                init_scripts=[
                    {"destination": "s3://attacker-1/init.sh"},
                    {"destination": "https://attacker-2.example.com/install.sh"},
                ],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 2
        destinations = {f["evidence"]["init_script_destination"] for f in findings}
        assert destinations == {
            "s3://attacker-1/init.sh",
            "https://attacker-2.example.com/install.sh",
        }

    def test_malformed_payload_is_skipped(self, capsys) -> None:
        out = list(load_jsonl(['{"bad":', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err

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

    def test_nested_dbfs_destination_extracted(self) -> None:
        events = [
            _event(
                uid="ev-nested-1",
                time_ms=1_000,
                init_scripts=[{"dbfs": {"destination": "dbfs:/elsewhere/script.sh"}}],
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["init_script_destination"] == "dbfs:/elsewhere/script.sh"

    def test_invalid_regex_falls_back_with_warning(self, monkeypatch, capsys) -> None:
        monkeypatch.setenv(ALLOWED_PATHS_ENV, "[")
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        events = [_event(uid="ev-regex-1", time_ms=1_000)]
        findings = list(detect(events))
        # Still fires (s3://attacker-bucket/init.sh is outside the default).
        assert len(findings) == 1
        err_lines = [line for line in capsys.readouterr().err.strip().splitlines() if line.strip()]
        payloads = [json.loads(line) for line in err_lines]
        assert any(p.get("event") == "invalid_allowed_paths_regex" for p in payloads)

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
            MITRE_PERSISTENCE_TECHNIQUE_UID
            in metadata["attack_coverage"]["databricks"]["techniques"]
        )
        assert "clusters.create" in metadata["attack_coverage"]["databricks"]["anchor_operations"]
        assert "clusters.edit" in metadata["attack_coverage"]["databricks"]["anchor_operations"]
        assert "ingest-databricks-audit-ocsf" in ACCEPTED_PRODUCERS
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert "clusters.create" in ANCHOR_OPERATIONS
        assert DEFAULT_ALLOWED_PATHS.startswith("^(dbfs")
