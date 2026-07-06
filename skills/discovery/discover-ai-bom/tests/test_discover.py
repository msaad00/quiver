"""Tests for discover-ai-bom."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "discover.py"
_SPEC = importlib.util.spec_from_file_location("discover_ai_bom", _SRC)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules["discover_ai_bom"] = _MODULE
_SPEC.loader.exec_module(_MODULE)

build_bom = _MODULE.build_bom
build_policy_findings = _MODULE.build_policy_findings
_normalize_assets = _MODULE._normalize_assets


def _normalized_doc() -> dict:
    return {
        "inventory_id": "ai-estate-prod-2026-04-12",
        "collected_at": "2026-04-12T00:00:00Z",
        "assets": [
            {
                "provider": "aws",
                "service": "sagemaker",
                "kind": "model",
                "id": "model:fraud-v5",
                "name": "fraud-model",
                "version": "5",
                "framework": "xgboost",
                "region": "us-east-1",
                "sensitivity": "restricted",
                "properties": {"owner": "fraud-platform", "api_key": "should-drop"},
            },
            {
                "provider": "aws",
                "service": "sagemaker",
                "kind": "endpoint",
                "id": "endpoint:fraud-prod",
                "name": "fraud-endpoint",
                "endpoint_url": "https://example.internal/invoke",
                "dependencies": ["aws:sagemaker:model:model:fraud-v5"],
            },
        ],
    }


def _policy_doc() -> dict:
    return {
        "inventory_id": "ai-estate-prod-2026-04-21",
        "collected_at": "2026-04-21T00:00:00Z",
        "assets": [
            {
                "provider": "aws",
                "service": "bedrock",
                "kind": "model",
                "id": "model:chat-prod",
                "name": "chat-prod",
                "version": "latest",
                "registry": "registry.evil.example/redteam/chat-prod:latest",
                "license": "research-only",
            },
            {
                "provider": "gcp",
                "service": "vertex-ai",
                "kind": "model",
                "id": "projects/p/locations/us/models/2",
                "name": "fraud-v2",
                "version": "2.1.0",
                "registry": "ghcr.io/acme/fraud-v2:2.1.0",
                "sigstore_verified": True,
                "license": "Apache-2.0",
            },
        ],
    }


class TestNormalizedInventory:
    def test_builds_components_services_and_dependencies(self):
        bom = build_bom(_normalized_doc())
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.7"
        assert bom["serialNumber"].startswith("urn:uuid:")
        assert len(bom["components"]) == 1
        assert len(bom["services"]) == 1
        assert bom["dependencies"] == [
            {
                "ref": "aws:sagemaker:endpoint:endpoint:fraud-prod",
                "dependsOn": ["aws:sagemaker:model:model:fraud-v5"],
            }
        ]

    def test_secret_like_properties_are_dropped(self):
        bom = build_bom(_normalized_doc())
        properties = bom["components"][0]["properties"]
        assert {"name": "cloud-security:properties.owner", "value": "fraud-platform"} in properties
        assert not any(prop["name"].endswith("api_key") for prop in properties)

    def test_output_is_order_independent(self):
        base = _normalized_doc()
        reversed_doc = {
            **base,
            "assets": list(reversed(base["assets"])),
        }
        assert build_bom(base) == build_bom(reversed_doc)


class TestPolicyFindings:
    def test_native_policy_findings_cover_expected_rules(self):
        findings = build_policy_findings(_policy_doc(), output_format="native")
        assert {finding["check_id"] for finding in findings} == {
            "AI-BOM-1",
            "AI-BOM-2",
            "AI-BOM-3",
            "AI-BOM-4",
        }
        assert all(finding["status"] == "FAIL" for finding in findings)

    def test_policy_findings_can_render_as_ocsf_compliance_findings(self):
        findings = build_policy_findings(_policy_doc(), output_format="ocsf")
        assert len(findings) == 4
        assert all(finding["class_uid"] == 2003 for finding in findings)
        assert all(
            finding["metadata"]["product"]["feature"]["name"] == "discover-ai-bom"
            for finding in findings
        )
        assert {finding["compliance"]["control"] for finding in findings} == {
            "AI-BOM-1",
            "AI-BOM-2",
            "AI-BOM-3",
            "AI-BOM-4",
        }

    def test_clean_inventory_has_no_policy_findings(self):
        clean = {
            "inventory_id": "ai-estate-clean",
            "collected_at": "2026-04-21T00:00:00Z",
            "assets": [
                {
                    "provider": "aws",
                    "service": "bedrock",
                    "kind": "model",
                    "id": "model:fraud-v5",
                    "name": "fraud-v5",
                    "version": "5.0.1",
                    "registry": "ghcr.io/acme/fraud-v5:5.0.1",
                    "sigstore_verified": True,
                    "license": "Apache-2.0",
                }
            ],
        }
        assert build_policy_findings(clean, output_format="native") == []


class TestProviderSnapshots:
    def test_aws_snapshot_normalization(self):
        assets = _normalize_assets(
            {
                "provider": "aws",
                "sagemaker": {
                    "model_packages": [
                        {
                            "ModelPackageArn": "arn:aws:sagemaker:us-east-1:123:model-package/fraud/5",
                            "ModelPackageName": "fraud",
                            "ModelPackageVersion": 5,
                        }
                    ],
                    "endpoints": [
                        {
                            "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/fraud",
                            "EndpointName": "fraud",
                            "ModelPackageArn": "arn:aws:sagemaker:us-east-1:123:model-package/fraud/5",
                        }
                    ],
                    "training_jobs": [
                        {
                            "TrainingJobArn": "arn:aws:sagemaker:us-east-1:123:training-job/fraud-train",
                            "TrainingJobName": "fraud-train",
                            "TrainingJobStatus": "Completed",
                        }
                    ],
                    "datasets": [
                        {
                            "DatasetArn": "arn:aws:sagemaker:us-east-1:123:dataset/fraud",
                            "DatasetName": "fraud-dataset",
                        }
                    ],
                },
                "bedrock": {
                    "custom_models": [
                        {
                            "modelArn": "arn:aws:bedrock:us-east-1:123:custom-model/fraud",
                            "modelName": "fraud-custom",
                            "foundationModelArn": "arn:aws:bedrock:::foundation-model/anthropic.claude",
                        }
                    ],
                    "knowledge_bases": [
                        {
                            "knowledgeBaseId": "kb-1",
                            "name": "fraud-kb",
                            "status": "ACTIVE",
                            "storageConfiguration": {"type": "OPENSEARCH_SERVERLESS"},
                        }
                    ],
                },
            }
        )
        assert [asset["kind"] for asset in assets] == [
            "model",
            "vector-store",
            "dataset",
            "endpoint",
            "model-package",
            "training-job",
        ]

    def test_gcp_snapshot_normalization(self):
        assets = _normalize_assets(
            {
                "provider": "gcp",
                "vertex_ai": {
                    "models": [
                        {"name": "projects/p/locations/us/models/1", "displayName": "fraud-model"}
                    ],
                    "endpoints": [
                        {
                            "name": "projects/p/locations/us/endpoints/99",
                            "displayName": "fraud-endpoint",
                            "deployedModels": [{"model": "projects/p/locations/us/models/1"}],
                        }
                    ],
                    "datasets": [
                        {
                            "name": "projects/p/locations/us/datasets/1",
                            "displayName": "fraud-dataset",
                        }
                    ],
                    "training_pipelines": [
                        {
                            "name": "projects/p/locations/us/trainingPipelines/1",
                            "displayName": "fraud-train",
                        }
                    ],
                    "indexes": [
                        {"name": "projects/p/locations/us/indexes/1", "displayName": "fraud-index"}
                    ],
                    "index_endpoints": [
                        {
                            "name": "projects/p/locations/us/indexEndpoints/1",
                            "displayName": "fraud-index-endpoint",
                            "deployedIndexes": [{"index": "projects/p/locations/us/indexes/1"}],
                        }
                    ],
                },
            }
        )
        assert [asset["kind"] for asset in assets] == [
            "dataset",
            "endpoint",
            "endpoint",
            "model",
            "training-job",
            "vector-index",
        ]

    def test_azure_snapshot_normalization(self):
        assets = _normalize_assets(
            {
                "provider": "azure",
                "azure_ml": {
                    "models": [{"id": "/models/fraud", "name": "fraud-model", "version": "3"}],
                    "deployments": [
                        {
                            "id": "/deployments/fraud-blue",
                            "name": "fraud-blue",
                            "model": "/models/fraud",
                        }
                    ],
                    "online_endpoints": [
                        {
                            "name": "fraud-endpoint",
                            "deployments": [{"id": "/deployments/fraud-blue"}],
                        }
                    ],
                    "data_assets": [{"id": "/data/fraud", "name": "fraud-data", "version": "1"}],
                    "compute_clusters": [
                        {"id": "/compute/gpu", "name": "gpu", "vmSize": "Standard_NC6s_v3"}
                    ],
                },
                "ai_foundry": {
                    "deployments": [
                        {
                            "id": "/foundry/deployments/chat",
                            "name": "chat-prod",
                            "model": "/models/fraud",
                        }
                    ],
                    "projects": [{"id": "/foundry/projects/ai-sec", "name": "ai-sec"}],
                },
            }
        )
        assert [asset["kind"] for asset in assets] == [
            "endpoint",
            "runtime",
            "dataset",
            "deployment",
            "endpoint",
            "model",
            "runtime",
        ]


class TestErrors:
    def test_requires_assets_or_supported_provider_snapshot(self):
        try:
            build_bom({"inventory_id": "empty"})
        except ValueError as exc:
            assert "supported provider snapshot" in str(exc)
        else:  # pragma: no cover - defensive
            raise AssertionError("expected ValueError for empty inventory")

    def test_requires_asset_identity(self):
        try:
            _normalize_assets(
                {"assets": [{"provider": "aws", "service": "bedrock", "kind": "model"}]}
            )
        except ValueError as exc:
            assert "at least one of `id` or `name`" in str(exc)
        else:  # pragma: no cover - defensive
            raise AssertionError("expected ValueError for missing asset identity")
