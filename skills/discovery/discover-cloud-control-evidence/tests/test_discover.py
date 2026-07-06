"""Tests for discover-cloud-control-evidence."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "discover.py"
_SPEC = importlib.util.spec_from_file_location("discover_cloud_control_evidence", _SRC)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

build_evidence = _MODULE.build_evidence
normalize_inventory = _MODULE.normalize_inventory
to_ocsf_live_evidence = _MODULE.to_ocsf_live_evidence


def _aws_snapshot() -> dict:
    return {
        "inventory_id": "aws-snap-1",
        "collected_at": "2026-04-12T02:00:00Z",
        "aws": {
            "iam": {
                "users": [{"UserName": "alice", "MFAEnabled": True}],
                "roles": [{"RoleName": "ml-runtime-role"}],
            },
            "s3": {
                "buckets": [
                    {
                        "Name": "ml-artifacts",
                        "encrypted": True,
                        "public": False,
                        "logging_enabled": True,
                        "token": "drop-me",
                    }
                ]
            },
            "kms": {"keys": [{"KeyId": "key-1", "RotationEnabled": True}]},
            "cloudtrail": {
                "trails": [{"Name": "org-trail", "IsLogging": True, "KmsKeyId": "arn:kms"}]
            },
            "ec2": {
                "instances": [{"InstanceId": "i-123", "PublicIpAddress": "1.2.3.4"}],
                "security_groups": [
                    {
                        "GroupId": "sg-1",
                        "GroupName": "public-sg",
                        "ingress": [{"cidr": "0.0.0.0/0"}],
                    }
                ],
            },
        },
    }


def _multi_cloud_snapshot() -> dict:
    return {
        "snapshot_id": "multi-1",
        "captured_at": "2026-04-12T03:00:00Z",
        "aws": {
            "bedrock": {
                "custom_models": [
                    {"modelArn": "arn:aws:bedrock:model/guard", "modelName": "guard-model"}
                ],
                "guardrails": [{"id": "gr-1", "name": "bedrock-guard"}],
                "knowledge_bases": [
                    {"knowledgeBaseId": "kb-1", "name": "kb-prod", "encrypted": True}
                ],
            },
            "sagemaker": {
                "endpoints": [
                    {
                        "EndpointArn": "arn:aws:sagemaker:endpoint/fraud",
                        "EndpointName": "fraud",
                        "public": False,
                    }
                ],
                "training_jobs": [
                    {
                        "TrainingJobArn": "arn:aws:sagemaker:training-job/fraud",
                        "TrainingJobName": "fraud-train",
                    }
                ],
            },
        },
        "gcp": {
            "iam": {"service_accounts": [{"email": "svc@example.iam.gserviceaccount.com"}]},
            "logging": {"sinks": [{"name": "org-sink"}]},
            "compute": {
                "instances": [
                    {"id": "gce-1", "name": "gce-1", "networkInterfaces": [{"accessConfigs": [{}]}]}
                ]
            },
            "vertex_ai": {
                "models": [
                    {"name": "projects/p/locations/us/models/1", "displayName": "fraud-model"}
                ],
                "endpoints": [
                    {
                        "name": "projects/p/locations/us/endpoints/1",
                        "displayName": "fraud-endpoint",
                        "public": True,
                    }
                ],
                "datasets": [
                    {"name": "projects/p/locations/us/datasets/1", "displayName": "fraud-dataset"}
                ],
                "indexes": [
                    {"name": "projects/p/locations/us/indexes/1", "displayName": "fraud-index"}
                ],
            },
        },
        "azure": {
            "entra": {"managed_identities": [{"id": "mi-1", "name": "mi-prod"}]},
            "storage": {"accounts": [{"id": "st-1", "name": "stprod", "encrypted": True}]},
            "monitor": {"diagnostic_settings": [{"id": "diag-1", "name": "diag-prod"}]},
            "ai_foundry": {
                "deployments": [
                    {"id": "dep-1", "name": "chat-prod", "public": True, "logging_enabled": True}
                ],
                "projects": [{"id": "proj-1", "name": "ai-project"}],
            },
            "azure_ml": {
                "models": [{"id": "/models/fraud", "name": "fraud-model"}],
                "data_assets": [{"id": "/data/fraud", "name": "fraud-data"}],
                "online_endpoints": [
                    {"id": "/endpoints/fraud", "name": "fraud", "public_network_access": False}
                ],
            },
        },
    }


class TestNormalizeInventory:
    def test_accepts_aws_snapshot(self):
        normalized = normalize_inventory(_aws_snapshot())
        assert normalized["source_kind"] == "cloud-inventory-snapshot"
        assert normalized["providers"] == ["aws"]
        assert len(normalized["assets"]) >= 6

    def test_accepts_multi_cloud_snapshot(self):
        normalized = normalize_inventory(_multi_cloud_snapshot())
        assert normalized["providers"] == ["aws", "azure", "gcp"]
        assert any(asset["provider"] == "azure" for asset in normalized["assets"])
        assert any(asset["provider"] == "gcp" for asset in normalized["assets"])
        assert any(asset["service"] == "vertex-ai" for asset in normalized["assets"])
        assert any(asset["kind"] == "ai-guardrail" for asset in normalized["assets"])


class TestBuildEvidence:
    def test_builds_pci_and_soc2_controls(self):
        evidence = build_evidence(_aws_snapshot())
        assert evidence["artifact_type"] == "technical-control-evidence"
        assert evidence["frameworks"] == ["PCI DSS 4.0", "SOC 2 Security"]
        assert len(evidence["controls"]) == 12

    def test_drops_secret_like_properties(self):
        normalized = normalize_inventory(_aws_snapshot())
        bucket = next(asset for asset in normalized["assets"] if asset["kind"] == "bucket")
        assert "token" not in bucket

    def test_framework_filter(self):
        evidence = build_evidence(_multi_cloud_snapshot(), ["soc2"])
        assert evidence["frameworks"] == ["SOC 2 Security"]
        assert {control["framework"] for control in evidence["controls"]} == {"SOC 2 Security"}
        assert any(
            control["control_id"] == "cc6.ai-service-surface" for control in evidence["controls"]
        )

    def test_ai_rmf_filter(self):
        evidence = build_evidence(_multi_cloud_snapshot(), ["ai-rmf"])
        assert evidence["frameworks"] == ["NIST AI RMF 1.0"]
        assert {control["framework"] for control in evidence["controls"]} == {"NIST AI RMF 1.0"}
        assert any(
            control["control_id"] == "ai-rmf.map.ai-system-inventory"
            for control in evidence["controls"]
        )
        assert any(
            control["framework_mappings"]["nist_ai_rmf"] == "GOVERN"
            for control in evidence["controls"]
        )

    def test_inventory_summary_includes_ai_surface_counts(self):
        evidence = build_evidence(_multi_cloud_snapshot())
        counts = evidence["inventory_summary"]["control_surface_counts"]
        assert counts["ai_assets"] >= 1
        assert counts["ai_endpoint_assets"] >= 1
        assert counts["ai_governance_assets"] >= 1

    def test_inventory_summary_includes_provider_surface_depth(self):
        evidence = build_evidence(_multi_cloud_snapshot())
        provider_counts = evidence["inventory_summary"]["provider_control_surface_counts"]

        assert provider_counts["aws"]["encrypted_assets"] >= 1
        assert provider_counts["gcp"]["logging_assets"] >= 1
        assert provider_counts["azure"]["logging_assets"] >= 1

    def test_inventory_summary_tracks_segmentation_assets_by_provider(self):
        evidence = build_evidence(
            {
                "aws": {
                    "ec2": {
                        "security_groups": [
                            {
                                "GroupId": "sg-1",
                                "GroupName": "app",
                                "ingress": [{"cidr": "10.0.0.0/8"}],
                            }
                        ]
                    }
                },
                "gcp": {
                    "compute": {
                        "firewalls": [{"name": "internal-only", "sourceRanges": ["10.0.0.0/8"]}]
                    }
                },
                "azure": {
                    "network": {
                        "nsgs": [
                            {
                                "id": "nsg-1",
                                "name": "internal-only",
                                "securityRules": [
                                    {
                                        "access": "Allow",
                                        "direction": "Inbound",
                                        "sourceAddressPrefix": "10.0.0.0/8",
                                    }
                                ],
                            }
                        ]
                    }
                },
            },
            ["pci"],
        )
        provider_counts = evidence["inventory_summary"]["provider_control_surface_counts"]

        assert provider_counts["aws"]["segmentation_assets"] == 1
        assert provider_counts["gcp"]["segmentation_assets"] == 1
        assert provider_counts["azure"]["segmentation_assets"] == 1

    def test_deterministic_output(self):
        assert build_evidence(_multi_cloud_snapshot()) == build_evidence(_multi_cloud_snapshot())

    def test_reports_missing_logging_when_absent(self):
        evidence = build_evidence({"aws": {"iam": {"users": [{"UserName": "alice"}]}}}, ["pci"])
        logging_control = next(
            control
            for control in evidence["controls"]
            if control["control_id"] == "inventory.audit-logging"
        )
        assert logging_control["status"] == "missing"

    def test_invalid_input_raises(self):
        try:
            build_evidence({"unexpected": True})
        except ValueError as exc:
            assert "supported provider inventory" in str(exc)
        else:  # pragma: no cover - defensive
            raise AssertionError("expected ValueError")

    def test_can_emit_ocsf_live_evidence_bridge(self):
        event = to_ocsf_live_evidence(build_evidence(_multi_cloud_snapshot(), ["pci"]))
        assert event["category_uid"] == 5
        assert event["class_uid"] == 5040
        assert event["class_name"] == "Live Evidence Info"
        assert event["metadata"]["version"] == "1.8.0"
        assert event["unmapped"]["cloud_security_technical_evidence"]["frameworks"] == [
            "PCI DSS 4.0"
        ]

    def test_ai_rmf_bridge_preserves_framework(self):
        event = to_ocsf_live_evidence(build_evidence(_multi_cloud_snapshot(), ["ai-rmf"]))
        assert event["unmapped"]["cloud_security_technical_evidence"]["frameworks"] == [
            "NIST AI RMF 1.0"
        ]
