"""Tests for discover-control-evidence."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "discover.py"
_SPEC = importlib.util.spec_from_file_location("discover_control_evidence", _SRC)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

build_evidence = _MODULE.build_evidence
normalize_source = _MODULE.normalize_source
to_ocsf_live_evidence = _MODULE.to_ocsf_live_evidence


def _bom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "serialNumber": "urn:uuid:ai-bom-123",
        "metadata": {"timestamp": "2026-04-12T00:00:00Z"},
        "components": [
            {
                "bom-ref": "aws:sagemaker:model:model:fraud-v5",
                "name": "fraud-model",
                "type": "machine-learning-model",
                "properties": [
                    {"name": "cloud-security:provider", "value": "aws"},
                    {"name": "cloud-security:service", "value": "sagemaker"},
                    {"name": "cloud-security:kind", "value": "model"},
                ],
            }
        ],
        "services": [
            {
                "bom-ref": "aws:sagemaker:endpoint:endpoint:fraud-prod",
                "name": "fraud-endpoint",
                "endpoints": ["https://fraud.example.internal/invoke"],
                "properties": [
                    {"name": "cloud-security:provider", "value": "aws"},
                    {"name": "cloud-security:service", "value": "sagemaker"},
                    {"name": "cloud-security:kind", "value": "endpoint"},
                    {"name": "cloud-security:token", "value": "drop-me"},
                ],
            }
        ],
        "dependencies": [
            {
                "ref": "aws:sagemaker:endpoint:endpoint:fraud-prod",
                "dependsOn": ["aws:sagemaker:model:model:fraud-v5"],
            }
        ],
    }


def _graph() -> dict:
    return {
        "scan_id": "graph-001",
        "discovered_at": "2026-04-12T01:00:00Z",
        "nodes": [
            {
                "id": "aws:iam_user:alice",
                "entity_type": "user",
                "label": "alice",
                "dimensions": {"cloud_provider": "aws", "service": "iam"},
                "attributes": {
                    "arn": "arn:aws:iam::123456789012:user/alice",
                    "password": "drop-me",
                },
            },
            {
                "id": "aws:lambda:score",
                "entity_type": "service",
                "label": "score",
                "dimensions": {"cloud_provider": "aws", "service": "lambda"},
            },
        ],
        "edges": [
            {"source": "aws:iam_user:alice", "target": "aws:lambda:score", "relationship": "uses"}
        ],
    }


class TestNormalizeSource:
    def test_accepts_cyclonedx_bom(self):
        normalized = normalize_source(_bom())
        assert normalized["source_kind"] == "cyclonedx-ai-bom"
        assert len(normalized["assets"]) == 2

    def test_accepts_environment_graph(self):
        normalized = normalize_source(_graph())
        assert normalized["source_kind"] == "environment-graph"
        assert len(normalized["assets"]) == 2


class TestBuildEvidence:
    def test_builds_pci_and_soc2_controls(self):
        evidence = build_evidence(_bom())
        assert evidence["artifact_type"] == "technical-control-evidence"
        assert evidence["frameworks"] == ["PCI DSS 4.0", "SOC 2 Security"]
        assert len(evidence["controls"]) == 4
        statuses = {control["status"] for control in evidence["controls"]}
        assert "evidence-ready" in statuses

    def test_drops_secret_like_properties(self):
        normalized = normalize_source(_bom())
        service_asset = next(asset for asset in normalized["assets"] if asset["kind"] == "endpoint")
        assert "token" not in service_asset

    def test_framework_filter(self):
        evidence = build_evidence(_graph(), ["soc2"])
        assert evidence["frameworks"] == ["SOC 2 Security"]
        assert {control["framework"] for control in evidence["controls"]} == {"SOC 2 Security"}

    def test_deterministic_output(self):
        left = build_evidence(_bom())
        right = build_evidence(_bom())
        assert left == right

    def test_graph_without_external_services_is_partial_for_pci_surface(self):
        evidence = build_evidence(_graph(), ["pci"])
        pci_surface = next(
            control
            for control in evidence["controls"]
            if control["control_id"] == "inventory.external-services"
        )
        assert pci_surface["status"] == "missing"

    def test_invalid_input_raises(self):
        try:
            build_evidence({"unexpected": True})
        except ValueError as exc:
            assert "CycloneDX AI BOM" in str(exc)
        else:  # pragma: no cover - defensive
            raise AssertionError("expected ValueError")

    def test_can_emit_ocsf_live_evidence_bridge(self):
        event = to_ocsf_live_evidence(build_evidence(_bom(), ["soc2"]))
        assert event["category_uid"] == 5
        assert event["class_uid"] == 5040
        assert event["class_name"] == "Live Evidence Info"
        assert event["metadata"]["version"] == "1.8.0"
        assert event["unmapped"]["cloud_security_technical_evidence"]["frameworks"] == [
            "SOC 2 Security"
        ]
