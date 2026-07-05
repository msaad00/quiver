"""Tests for detect-azure-private-endpoint-to-external-sub."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError  # noqa: E402

THIS = Path(__file__).resolve().parent
SRC = THIS.parent / "src" / "detect.py"
SPEC = importlib.util.spec_from_file_location(
    "detect_azure_private_endpoint_to_external_sub_under_test", SRC
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCEPTED_PRODUCERS = MODULE.ACCEPTED_PRODUCERS
ANCHOR_OPERATION = MODULE.ANCHOR_OPERATION
AUTHORIZED_SUBS_ENV = MODULE.AUTHORIZED_SUBS_ENV
FINDING_CLASS_UID = MODULE.FINDING_CLASS_UID
OUTPUT_FORMATS = MODULE.OUTPUT_FORMATS
PRIMARY_TECHNIQUE_UID = MODULE.PRIMARY_TECHNIQUE_UID
SECONDARY_TECHNIQUE_UID = MODULE.SECONDARY_TECHNIQUE_UID
SEVERITY_HIGH = MODULE.SEVERITY_HIGH
SKILL_NAME = MODULE.SKILL_NAME
coverage_metadata = MODULE.coverage_metadata
detect = MODULE.detect
load_jsonl = MODULE.load_jsonl

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "azure_private_endpoint_external_sub_input.ocsf.jsonl"
EXPECTED = GOLDEN / "azure_private_endpoint_external_sub_findings.ocsf.jsonl"

SOURCE_SUB = "11111111-1111-1111-1111-111111111111"
TARGET_SUB = "99999999-9999-9999-9999-999999999999"
SECOND_TARGET_SUB = "55555555-5555-5555-5555-555555555555"
AUTHORIZED_SUB = "22222222-2222-2222-2222-222222222222"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _link_service_id(subscription: str, service: str = "mySqlServer") -> str:
    return (
        f"/subscriptions/{subscription}/resourceGroups/rg-shared/"
        f"providers/Microsoft.Sql/servers/{service}"
    )


def _event(
    *,
    uid: str = "evt-1",
    time_ms: int = 1_700_000_000_000,
    actor: str = "mallory",
    resource_uid: str | None = None,
    source_subscription: str = SOURCE_SUB,
    source_region: str = "eastus",
    operation: str = "Microsoft.Network/privateEndpoints/write",
    status_id: int = 1,
    producer: str = "ingest-azure-activity-ocsf",
    connections: list[dict] | None = None,
) -> dict:
    if resource_uid is None:
        resource_uid = (
            f"/subscriptions/{source_subscription}/resourceGroups/rg-prod/"
            f"providers/Microsoft.Network/privateEndpoints/pe-prod-1"
        )
    if connections is None:
        connections = [
            {
                "name": "to-external-sql",
                "privateLinkServiceId": _link_service_id(TARGET_SUB),
            }
        ]
    return {
        "class_uid": 6003,
        "status_id": status_id,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {"feature": {"name": producer}},
        },
        "actor": {"user": {"name": actor}},
        "api": {"operation": operation, "service": {"name": "Microsoft.Network"}},
        "cloud": {
            "provider": "Azure",
            "account": {"uid": source_subscription},
            "region": source_region,
        },
        "resources": [{"name": resource_uid, "type": "privateendpoints"}],
        "unmapped": {"azure": {"privateLinkServiceConnections": connections}},
    }


class TestCoreContract:
    def test_accepted_producer_is_azure_activity(self) -> None:
        assert ACCEPTED_PRODUCERS == frozenset({"ingest-azure-activity-ocsf"})

    def test_anchor_operation_normalized_lower(self) -> None:
        assert ANCHOR_OPERATION == "microsoft.network/privateendpoints/write"

    def test_coverage_metadata(self) -> None:
        meta = coverage_metadata()
        assert meta["providers"] == ("azure",)
        techniques = meta["attack_coverage"]["azure"]["techniques"]
        assert PRIMARY_TECHNIQUE_UID in techniques
        assert SECONDARY_TECHNIQUE_UID in techniques
        assert meta["thresholds"]["allowlist_mode"] == "fail-open"


class TestDetection:
    def test_cross_subscription_fires_in_fail_open(self) -> None:
        findings = list(detect([_event()]))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["evidence"]["boundary"] == "cross-subscription"
        assert finding["evidence"]["allowlist_mode"] == "fail-open"
        assert finding["evidence"]["target_subscription"] == TARGET_SUB
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == PRIMARY_TECHNIQUE_UID
        assert finding["finding_info"]["attacks"][1]["technique"]["uid"] == SECONDARY_TECHNIQUE_UID

    def test_authorized_sub_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_SUBS_ENV, AUTHORIZED_SUB + "," + TARGET_SUB)
        findings = list(detect([_event()]))
        assert findings == []

    def test_enforced_with_unauthorized_target_fires(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_SUBS_ENV, AUTHORIZED_SUB)
        findings = list(detect([_event()]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["allowlist_mode"] == "enforced"

    def test_same_subscription_does_not_fire(self) -> None:
        connections = [
            {
                "name": "internal",
                "privateLinkServiceId": _link_service_id(SOURCE_SUB),
            }
        ]
        findings = list(detect([_event(connections=connections)]))
        assert findings == []

    def test_failed_call_does_not_fire(self) -> None:
        findings = list(detect([_event(status_id=2)]))
        assert findings == []

    def test_wrong_operation_does_not_fire(self) -> None:
        findings = list(detect([_event(operation="Microsoft.Network/virtualNetworks/write")]))
        assert findings == []

    def test_non_azure_producer_ignored(self, capsys) -> None:
        findings = list(detect([_event(producer="ingest-cloudtrail-ocsf")]))
        assert findings == []
        err = capsys.readouterr().err
        assert "non-azure-activity producer" in err

    def test_missing_connections_skipped(self, capsys) -> None:
        evt = _event()
        evt["unmapped"]["azure"]["privateLinkServiceConnections"] = []
        findings = list(detect([evt]))
        assert findings == []
        assert "carries no" in capsys.readouterr().err

    def test_multi_target_endpoint_emits_one_per_target(self) -> None:
        # One privateEndpoint with two link-service connections, each in a
        # different external subscription. We expect TWO findings, one per
        # (resource_uid, target_subscription) tuple.
        connections = [
            {
                "name": "to-external-sql",
                "privateLinkServiceId": _link_service_id(TARGET_SUB, "primary-sql"),
            },
            {
                "name": "to-external-storage",
                "privateLinkServiceId": _link_service_id(SECOND_TARGET_SUB, "secondary-storage"),
            },
        ]
        findings = list(detect([_event(connections=connections)]))
        assert len(findings) == 2
        targets = {f["evidence"]["target_subscription"] for f in findings}
        assert targets == {TARGET_SUB, SECOND_TARGET_SUB}

    def test_duplicate_target_within_same_event_only_fires_once(self) -> None:
        connections = [
            {"name": "a", "privateLinkServiceId": _link_service_id(TARGET_SUB, "x")},
            {"name": "b", "privateLinkServiceId": _link_service_id(TARGET_SUB, "y")},
        ]
        findings = list(detect([_event(connections=connections)]))
        assert len(findings) == 1

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        evt = _event()
        findings = list(detect([evt, evt]))
        assert len(findings) == 1

    def test_native_output(self) -> None:
        findings = list(detect([_event()], output_format="native"))
        assert len(findings) == 1
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["source_skill"] == SKILL_NAME
        assert OUTPUT_FORMATS == frozenset({"ocsf", "native"})

    def test_rejects_unsupported_output_format(self) -> None:
        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected ContractError")

    def test_subscription_extraction_case_insensitive(self) -> None:
        # Azure REST sometimes upper-cases path segments; the resource id
        # still needs to map to the lower-case GUID for set comparison.
        upper_link = (
            f"/SUBSCRIPTIONS/{TARGET_SUB.upper()}/RESOURCEGROUPS/RG/"
            f"PROVIDERS/Microsoft.Sql/servers/x"
        )
        findings = list(
            detect([_event(connections=[{"name": "c", "privateLinkServiceId": upper_link}])])
        )
        assert len(findings) == 1
        assert findings[0]["evidence"]["target_subscription"] == TARGET_SUB

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
