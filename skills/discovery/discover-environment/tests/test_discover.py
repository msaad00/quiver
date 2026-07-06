"""Tests for cloud environment discovery — graph output and MITRE mapping."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from discover import (
    MITRE_ATLAS_MAP,
    MITRE_ATTACK_MAP,
    EnvironmentGraph,
    GraphEdge,
    GraphNode,
    discover_from_config,
    get_attack_techniques,
    to_ocsf_cloud_resources_inventory,
)


class TestGraphModel:
    def test_graph_has_scan_id(self):
        g = EnvironmentGraph(provider="aws")
        assert g.scan_id
        assert g.provider == "aws"

    def test_add_node(self):
        g = EnvironmentGraph()
        g.add_node(GraphNode(id="test:1", entity_type="cloud_resource", label="Test"))
        assert len(g.nodes) == 1
        assert g.nodes[0].id == "test:1"

    def test_add_edge(self):
        g = EnvironmentGraph()
        g.add_edge(GraphEdge(source="a", target="b", relationship="contains"))
        assert len(g.edges) == 1

    def test_to_dict(self):
        g = EnvironmentGraph(provider="aws", region="us-east-1")
        g.add_node(GraphNode(id="n1", entity_type="user", label="admin"))
        g.add_edge(GraphEdge(source="n1", target="n2", relationship="owns"))
        d = g.to_dict()
        assert d["provider"] == "aws"
        assert d["stats"]["total_nodes"] == 1
        assert d["stats"]["total_edges"] == 1
        assert "user" in d["stats"]["node_types"]

    def test_to_dict_is_json_serializable(self):
        g = EnvironmentGraph()
        g.add_node(GraphNode(id="n1", entity_type="user", label="admin"))
        result = json.dumps(g.to_dict())
        assert '"user"' in result


class TestMITREMapping:
    def test_iam_user_has_attack_techniques(self):
        techniques = get_attack_techniques("iam_user")
        ids = [t["technique"] for t in techniques]
        assert "T1078.004" in ids

    def test_s3_bucket_has_techniques(self):
        techniques = get_attack_techniques("s3_bucket")
        ids = [t["technique"] for t in techniques]
        assert "T1530" in ids

    def test_lambda_has_techniques(self):
        techniques = get_attack_techniques("lambda_function")
        ids = [t["technique"] for t in techniques]
        assert "T1648" in ids

    def test_model_endpoint_has_atlas(self):
        techniques = get_attack_techniques("model_endpoint")
        ids = [t["technique"] for t in techniques]
        assert "AML.T0024" in ids

    def test_unknown_type_returns_empty(self):
        techniques = get_attack_techniques("nonexistent")
        assert techniques == []

    def test_all_techniques_have_required_fields(self):
        for entity_type, techniques in {**MITRE_ATTACK_MAP, **MITRE_ATLAS_MAP}.items():
            for t in techniques:
                assert "technique" in t, f"{entity_type} missing technique"
                assert "name" in t, f"{entity_type} missing name"
                assert "tactic" in t, f"{entity_type} missing tactic"


class TestStaticConfigDiscovery:
    def test_discover_from_config(self, tmp_path):
        config = {
            "provider": "static",
            "resources": [
                {
                    "id": "res:1",
                    "type": "cloud_resource",
                    "name": "My VPC",
                    "dimensions": {"cloud_provider": "aws"},
                },
                {"id": "res:2", "type": "user", "name": "admin"},
            ],
            "relationships": [
                {"source": "res:1", "target": "res:2", "type": "contains"},
            ],
        }
        config_path = tmp_path / "env.json"
        config_path.write_text(json.dumps(config))

        graph = discover_from_config(str(config_path))
        assert graph.provider == "static"
        # 2 resources + MITRE technique nodes
        assert len(graph.nodes) >= 2
        # 1 relationship + MITRE edges
        assert len(graph.edges) >= 1

    def test_mitre_edges_added(self, tmp_path):
        config = {
            "resources": [
                {"id": "res:1", "type": "iam_user", "name": "admin"},
            ],
            "relationships": [],
        }
        config_path = tmp_path / "env.json"
        config_path.write_text(json.dumps(config))

        graph = discover_from_config(str(config_path))
        # Should have MITRE technique nodes + edges for iam_user
        mitre_nodes = [n for n in graph.nodes if n.id.startswith("mitre:")]
        mitre_edges = [e for e in graph.edges if e.relationship == "exploitable_via"]
        assert len(mitre_nodes) >= 1
        assert len(mitre_edges) >= 1

    def test_empty_config(self, tmp_path):
        config = {"resources": [], "relationships": []}
        config_path = tmp_path / "empty.json"
        config_path.write_text(json.dumps(config))

        graph = discover_from_config(str(config_path))
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0


class TestGraphStats:
    def test_stats_count_types(self):
        g = EnvironmentGraph()
        g.add_node(GraphNode(id="u1", entity_type="user", label="u1"))
        g.add_node(GraphNode(id="u2", entity_type="user", label="u2"))
        g.add_node(GraphNode(id="s1", entity_type="server", label="s1"))
        g.add_edge(GraphEdge(source="u1", target="s1", relationship="uses"))
        g.add_edge(GraphEdge(source="u2", target="s1", relationship="uses"))

        stats = g.to_dict()["stats"]
        assert stats["total_nodes"] == 3
        assert stats["total_edges"] == 2
        assert stats["node_types"]["user"] == 2
        assert stats["node_types"]["server"] == 1
        assert stats["relationship_types"]["uses"] == 2


class TestOcsfCloudInventoryBridge:
    def test_can_emit_ocsf_cloud_resources_inventory(self):
        graph = EnvironmentGraph(
            provider="aws",
            region="us-east-1",
            discovered_at="2026-04-13T12:00:00+00:00",
        )
        graph.add_node(
            GraphNode(
                id="aws:account:123456789012",
                entity_type="cloud_resource",
                label="AWS Account 123456789012",
                attributes={"account_id": "123456789012", "arn": "arn:aws:iam::123456789012:root"},
                dimensions={"cloud_provider": "aws", "surface": "account"},
            )
        )
        graph.add_node(
            GraphNode(
                id="aws:s3:prod-bucket",
                entity_type="cloud_resource",
                label="s3://prod-bucket",
                attributes={"created": "2026-04-13T11:00:00+00:00"},
                compliance_tags=["MITRE-T1530"],
                dimensions={"cloud_provider": "aws", "surface": "storage"},
            )
        )
        graph.add_node(
            GraphNode(
                id="mitre:T1530",
                entity_type="vulnerability",
                label="T1530: Data from Cloud Storage",
            )
        )
        graph.add_edge(
            GraphEdge(
                source="mitre:T1530",
                target="aws:s3:prod-bucket",
                relationship="exploitable_via",
                evidence={"technique": "T1530"},
            )
        )

        event = to_ocsf_cloud_resources_inventory(graph)

        assert event["class_uid"] == 5023
        assert event["category_uid"] == 5
        assert event["activity_id"] == 99
        assert len(event["metadata"]["uid"]) == 64
        assert event["metadata"]["product"]["feature"]["name"] == "discover-environment"
        assert event["cloud"]["provider"] == "aws"
        assert event["cloud"]["account"]["uid"] == "123456789012"
        assert event["count"] == 2
        assert len(event["resources"]) == 2
        assert all(resource["uid"] != "mitre:T1530" for resource in event["resources"])
        assert event["resources"][1]["labels"] == ["MITRE-T1530"]
        assert event["unmapped"]["bridge_format"] == "cloud-security.environment-graph.v1"
        assert event["unmapped"]["environment_graph"]["stats"]["total_nodes"] == 3

    def test_static_graph_can_emit_bridge_without_cloud_object(self):
        graph = EnvironmentGraph(provider="static", discovered_at="2026-04-13T12:00:00+00:00")
        graph.add_node(GraphNode(id="res:1", entity_type="cloud_resource", label="Static Resource"))

        event = to_ocsf_cloud_resources_inventory(graph)

        assert event["class_uid"] == 5023
        assert "cloud" not in event
        assert event["count"] == 1

    def test_ocsf_bridge_metadata_uid_is_deterministic(self):
        graph = EnvironmentGraph(
            provider="aws", region="us-east-1", discovered_at="2026-04-13T12:00:00+00:00"
        )
        graph.add_node(
            GraphNode(id="aws:account:123456789012", entity_type="cloud_resource", label="acct")
        )
        graph.add_node(
            GraphNode(id="aws:s3:prod-bucket", entity_type="cloud_resource", label="bucket")
        )

        a = to_ocsf_cloud_resources_inventory(graph)["metadata"]["uid"]
        b = to_ocsf_cloud_resources_inventory(graph)["metadata"]["uid"]
        assert a == b
