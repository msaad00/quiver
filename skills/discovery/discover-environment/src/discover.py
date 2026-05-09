"""Cloud Environment Discovery — map infrastructure to a security graph.

Discovers cloud resources, IAM roles, services, network paths, and
security posture across AWS, GCP, and Azure. Outputs a graph JSON
compatible with any graph visualization tool.

Each node has:
  - id, entity_type, label, attributes, compliance_tags, dimensions
Each edge has:
  - source, target, relationship, direction, weight, evidence

Read-only — uses only viewer/audit permissions. No write access.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SUPPORTED_OUTPUT_FORMATS = ("native", "ocsf-cloud-resources-inventory")

# ═══════════════════════════════════════════════════════════════════════════
# Graph data model (standalone — no agent-bom dependency)
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class GraphNode:
    id: str
    entity_type: str
    label: str
    attributes: dict[str, Any] = field(default_factory=dict)
    compliance_tags: list[str] = field(default_factory=list)
    dimensions: dict[str, str] = field(default_factory=dict)
    severity: str = ""
    risk_score: float = 0.0
    status: str = "active"


@dataclass
class GraphEdge:
    source: str
    target: str
    relationship: str
    direction: str = "directed"
    weight: float = 1.0
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnvironmentGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    scan_id: str = ""
    provider: str = ""
    region: str = ""
    discovered_at: str = ""

    def __post_init__(self) -> None:
        if not self.scan_id:
            self.scan_id = str(uuid4())
        if not self.discovered_at:
            self.discovered_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def add_node(self, node: GraphNode) -> None:
        self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "provider": self.provider,
            "region": self.region,
            "discovered_at": self.discovered_at,
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "node_types": _count_by(self.nodes, "entity_type"),
                "relationship_types": _count_by_attr(self.edges, "relationship"),
            },
        }


def _count_by(items: list, attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        val = getattr(item, attr, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts


def _count_by_attr(items: list, attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        val = getattr(item, attr, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts


def _time_to_epoch_ms(value: str) -> int:
    normalized = value.replace("Z", "+00:00")
    return int(datetime.fromisoformat(normalized).timestamp() * 1000)


# ═══════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK technique mapping
# ═══════════════════════════════════════════════════════════════════════════

# Resource type → potential attack techniques
MITRE_ATTACK_MAP: dict[str, list[dict[str, str]]] = {
    "iam_user": [
        {"technique": "T1078.004", "name": "Valid Accounts: Cloud", "tactic": "Initial Access"},
        {"technique": "T1098.001", "name": "Additional Cloud Credentials", "tactic": "Persistence"},
    ],
    "iam_role": [
        {"technique": "T1078.004", "name": "Valid Accounts: Cloud", "tactic": "Initial Access"},
        {"technique": "T1548.005", "name": "Abuse Elevation Control: Temp Elevated Access", "tactic": "Privilege Escalation"},
    ],
    "s3_bucket": [
        {"technique": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection"},
        {"technique": "T1537", "name": "Transfer Data to Cloud Account", "tactic": "Exfiltration"},
    ],
    "lambda_function": [
        {"technique": "T1648", "name": "Serverless Execution", "tactic": "Execution"},
        {"technique": "T1195.002", "name": "Supply Chain: Software Supply Chain", "tactic": "Initial Access"},
    ],
    "ec2_instance": [
        {"technique": "T1078.004", "name": "Valid Accounts: Cloud", "tactic": "Initial Access"},
        {"technique": "T1610", "name": "Deploy Container", "tactic": "Defense Evasion"},
    ],
    "security_group": [
        {"technique": "T1562.007", "name": "Impair Defenses: Disable or Modify Cloud Firewall", "tactic": "Defense Evasion"},
    ],
    "vpc": [
        {"technique": "T1599", "name": "Network Boundary Bridging", "tactic": "Defense Evasion"},
    ],
    "kms_key": [
        {"technique": "T1552.004", "name": "Unsecured Credentials: Cloud Instance Metadata", "tactic": "Credential Access"},
    ],
}

# MITRE ATLAS for AI/ML resources
MITRE_ATLAS_MAP: dict[str, list[dict[str, str]]] = {
    "model_endpoint": [
        {"technique": "AML.T0024", "name": "Inference API Access", "tactic": "ML Attack"},
        {"technique": "AML.T0042", "name": "Denial of ML Service", "tactic": "ML Attack"},
    ],
    "training_job": [
        {"technique": "AML.T0020", "name": "Poison Training Data", "tactic": "ML Attack"},
        {"technique": "AML.T0010", "name": "ML Supply Chain Compromise", "tactic": "ML Attack"},
    ],
    "model_artifact": [
        {"technique": "AML.T0010", "name": "ML Supply Chain Compromise", "tactic": "ML Attack"},
        {"technique": "AML.T0025", "name": "Exfiltrate Training Data", "tactic": "ML Attack"},
    ],
}


def get_attack_techniques(entity_type: str) -> list[dict[str, str]]:
    """Get MITRE ATT&CK and ATLAS techniques for a resource type."""
    techniques = list(MITRE_ATTACK_MAP.get(entity_type, []))
    techniques.extend(MITRE_ATLAS_MAP.get(entity_type, []))
    return techniques


# ═══════════════════════════════════════════════════════════════════════════
# AWS Discovery
# ═══════════════════════════════════════════════════════════════════════════


def discover_aws(region: str = "us-east-1", profile: str | None = None) -> EnvironmentGraph:
    """Discover AWS environment resources and relationships.

    Requires: boto3, AWS credentials with SecurityAudit or ViewOnlyAccess.
    """
    try:
        import boto3
    except ImportError:
        print("Error: boto3 required. Install with: pip install boto3", file=sys.stderr)
        sys.exit(1)

    session = boto3.Session(region_name=region, profile_name=profile)
    graph = EnvironmentGraph(provider="aws", region=region)

    # Account identity
    sts = session.client("sts")
    try:
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        graph.add_node(
            GraphNode(
                id=f"aws:account:{account_id}",
                entity_type="cloud_resource",
                label=f"AWS Account {account_id}",
                attributes={"account_id": account_id, "arn": identity["Arn"]},
                dimensions={"cloud_provider": "aws", "surface": "account"},
            )
        )
    except Exception as e:
        print(f"Warning: Could not get account identity: {e}", file=sys.stderr)
        account_id = "unknown"

    # IAM Users
    iam = session.client("iam")
    try:
        users = iam.list_users().get("Users", [])
        for user in users:
            username = user["UserName"]
            node_id = f"aws:iam_user:{username}"
            tags = _get_mitre_tags("iam_user")
            graph.add_node(
                GraphNode(
                    id=node_id,
                    entity_type="user",
                    label=username,
                    attributes={
                        "arn": user["Arn"],
                        "created": user["CreateDate"].isoformat(),
                        "password_last_used": user.get("PasswordLastUsed", "never"),
                    },
                    compliance_tags=tags,
                    dimensions={"cloud_provider": "aws"},
                )
            )
            graph.add_edge(
                GraphEdge(
                    source=f"aws:account:{account_id}",
                    target=node_id,
                    relationship="contains",
                )
            )

            # User's access keys
            try:
                keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                for key in keys:
                    key_id = key["AccessKeyId"]
                    graph.add_node(
                        GraphNode(
                            id=f"aws:access_key:{key_id}",
                            entity_type="credential",
                            label=f"Access Key {key_id[:8]}...",
                            attributes={
                                "status": key["Status"],
                                "created": key["CreateDate"].isoformat(),
                            },
                            dimensions={"cloud_provider": "aws"},
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source=node_id,
                            target=f"aws:access_key:{key_id}",
                            relationship="owns",
                        )
                    )
            except Exception:
                pass

    except Exception as e:
        print(f"Warning: IAM user discovery failed: {e}", file=sys.stderr)

    # IAM Roles
    try:
        roles = iam.list_roles().get("Roles", [])
        for role in roles:
            role_name = role["RoleName"]
            if role_name.startswith("aws-service-role/"):
                continue  # Skip AWS service-linked roles
            node_id = f"aws:iam_role:{role_name}"
            tags = _get_mitre_tags("iam_role")
            graph.add_node(
                GraphNode(
                    id=node_id,
                    entity_type="service_account",
                    label=role_name,
                    attributes={
                        "arn": role["Arn"],
                        "created": role["CreateDate"].isoformat(),
                        "trust_policy": json.dumps(role.get("AssumeRolePolicyDocument", {})),
                    },
                    compliance_tags=tags,
                    dimensions={"cloud_provider": "aws"},
                )
            )
            graph.add_edge(
                GraphEdge(
                    source=f"aws:account:{account_id}",
                    target=node_id,
                    relationship="contains",
                )
            )
    except Exception as e:
        print(f"Warning: IAM role discovery failed: {e}", file=sys.stderr)

    # S3 Buckets
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            bucket_name = bucket["Name"]
            node_id = f"aws:s3:{bucket_name}"
            tags = _get_mitre_tags("s3_bucket")
            graph.add_node(
                GraphNode(
                    id=node_id,
                    entity_type="cloud_resource",
                    label=f"s3://{bucket_name}",
                    attributes={
                        "created": bucket["CreationDate"].isoformat(),
                    },
                    compliance_tags=tags,
                    dimensions={"cloud_provider": "aws", "surface": "storage"},
                )
            )
            graph.add_edge(
                GraphEdge(
                    source=f"aws:account:{account_id}",
                    target=node_id,
                    relationship="contains",
                )
            )
    except Exception as e:
        print(f"Warning: S3 discovery failed: {e}", file=sys.stderr)

    # Lambda Functions
    lam = session.client("lambda")
    try:
        functions = lam.list_functions().get("Functions", [])
        for fn in functions:
            fn_name = fn["FunctionName"]
            node_id = f"aws:lambda:{fn_name}"
            runtime = fn.get("Runtime", "unknown")
            tags = _get_mitre_tags("lambda_function")
            graph.add_node(
                GraphNode(
                    id=node_id,
                    entity_type="server",
                    label=fn_name,
                    attributes={
                        "arn": fn["FunctionArn"],
                        "runtime": runtime,
                        "memory": fn.get("MemorySize", 0),
                        "timeout": fn.get("Timeout", 0),
                        "handler": fn.get("Handler", ""),
                        "last_modified": fn.get("LastModified", ""),
                    },
                    compliance_tags=tags,
                    dimensions={"cloud_provider": "aws", "surface": "compute", "ecosystem": _runtime_to_ecosystem(runtime)},
                )
            )
            # Lambda → IAM Role edge
            role_arn = fn.get("Role", "")
            if role_arn:
                role_name = role_arn.split("/")[-1]
                graph.add_edge(
                    GraphEdge(
                        source=node_id,
                        target=f"aws:iam_role:{role_name}",
                        relationship="uses",
                        evidence={"role_arn": role_arn},
                    )
                )
            graph.add_edge(
                GraphEdge(
                    source=f"aws:account:{account_id}",
                    target=node_id,
                    relationship="contains",
                )
            )
    except Exception as e:
        print(f"Warning: Lambda discovery failed: {e}", file=sys.stderr)

    # VPCs
    ec2 = session.client("ec2")
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            tags = _get_mitre_tags("vpc")
            name = _get_tag(vpc.get("Tags", []), "Name") or vpc_id
            graph.add_node(
                GraphNode(
                    id=f"aws:vpc:{vpc_id}",
                    entity_type="cloud_resource",
                    label=name,
                    attributes={
                        "vpc_id": vpc_id,
                        "cidr": vpc.get("CidrBlock", ""),
                        "is_default": vpc.get("IsDefault", False),
                    },
                    compliance_tags=tags,
                    dimensions={"cloud_provider": "aws", "surface": "network"},
                )
            )

        # Security Groups
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in sgs:
            sg_id = sg["GroupId"]
            tags = _get_mitre_tags("security_group")
            open_ingress = []
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = rule.get("FromPort", "all")
                        open_ingress.append(f"0.0.0.0/0:{port}")

            graph.add_node(
                GraphNode(
                    id=f"aws:sg:{sg_id}",
                    entity_type="cloud_resource",
                    label=sg.get("GroupName", sg_id),
                    attributes={
                        "sg_id": sg_id,
                        "vpc_id": sg.get("VpcId", ""),
                        "description": sg.get("Description", ""),
                        "open_ingress": open_ingress,
                    },
                    severity="high" if open_ingress else "",
                    compliance_tags=tags,
                    dimensions={"cloud_provider": "aws", "surface": "network"},
                )
            )
            vpc_id = sg.get("VpcId", "")
            if vpc_id:
                graph.add_edge(
                    GraphEdge(
                        source=f"aws:vpc:{vpc_id}",
                        target=f"aws:sg:{sg_id}",
                        relationship="contains",
                    )
                )
    except Exception as e:
        print(f"Warning: VPC/SG discovery failed: {e}", file=sys.stderr)

    # Add MITRE ATT&CK technique edges
    _add_mitre_edges(graph)

    return graph


# ═══════════════════════════════════════════════════════════════════════════
# GCP Discovery (requires google-cloud-resource-manager, google-cloud-iam,
# google-cloud-storage)
# ═══════════════════════════════════════════════════════════════════════════


def discover_gcp(project: str) -> EnvironmentGraph:
    """Discover GCP project resources. Requires google-cloud SDKs."""
    try:
        from google.cloud import resourcemanager_v3  # noqa: F401
    except ImportError:
        print("Error: google-cloud-resource-manager required. Install with: pip install google-cloud-resource-manager", file=sys.stderr)
        sys.exit(1)

    graph = EnvironmentGraph(provider="gcp", region=project)

    graph.add_node(
        GraphNode(
            id=f"gcp:project:{project}",
            entity_type="cloud_resource",
            label=f"GCP Project {project}",
            dimensions={"cloud_provider": "gcp", "surface": "project"},
        )
    )

    # Service Accounts
    try:
        iam_v1 = importlib.import_module("google.cloud.iam_v1")

        iam_client = iam_v1.IAMClient()
        request = iam_v1.ListServiceAccountsRequest(name=f"projects/{project}")
        for sa in iam_client.list_service_accounts(request=request):
            sa_email = sa.email
            tags = _get_mitre_tags("iam_role")
            graph.add_node(
                GraphNode(
                    id=f"gcp:sa:{sa_email}",
                    entity_type="service_account",
                    label=sa_email,
                    attributes={"display_name": sa.display_name, "disabled": sa.disabled},
                    compliance_tags=tags,
                    dimensions={"cloud_provider": "gcp"},
                )
            )
            graph.add_edge(
                GraphEdge(
                    source=f"gcp:project:{project}",
                    target=f"gcp:sa:{sa_email}",
                    relationship="contains",
                )
            )
    except Exception as e:
        print(f"Warning: GCP SA discovery failed: {e}", file=sys.stderr)

    # Cloud Storage Buckets
    try:
        storage = importlib.import_module("google.cloud.storage")

        storage_client = storage.Client(project=project)
        for bucket in storage_client.list_buckets():
            tags = _get_mitre_tags("s3_bucket")
            graph.add_node(
                GraphNode(
                    id=f"gcp:bucket:{bucket.name}",
                    entity_type="cloud_resource",
                    label=f"gs://{bucket.name}",
                    attributes={"location": bucket.location, "storage_class": bucket.storage_class},
                    compliance_tags=tags,
                    dimensions={"cloud_provider": "gcp", "surface": "storage"},
                )
            )
            graph.add_edge(
                GraphEdge(
                    source=f"gcp:project:{project}",
                    target=f"gcp:bucket:{bucket.name}",
                    relationship="contains",
                )
            )
    except Exception as e:
        print(f"Warning: GCS discovery failed: {e}", file=sys.stderr)

    _add_mitre_edges(graph)
    return graph


# ═══════════════════════════════════════════════════════════════════════════
# Azure Discovery (requires azure-identity, azure-mgmt-resource)
# ═══════════════════════════════════════════════════════════════════════════


def discover_azure(subscription_id: str) -> EnvironmentGraph:
    """Discover Azure subscription resources. Requires azure SDKs."""
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        print("Error: azure-identity required. Install with: pip install azure-identity azure-mgmt-resource", file=sys.stderr)
        sys.exit(1)

    graph = EnvironmentGraph(provider="azure", region=subscription_id)
    credential = DefaultAzureCredential()

    graph.add_node(
        GraphNode(
            id=f"azure:subscription:{subscription_id}",
            entity_type="cloud_resource",
            label=f"Azure Subscription {subscription_id[:8]}...",
            dimensions={"cloud_provider": "azure", "surface": "subscription"},
        )
    )

    # Resource Groups and Resources
    try:
        from azure.mgmt.resource import ResourceManagementClient

        client = ResourceManagementClient(credential, subscription_id)
        for rg in client.resource_groups.list():
            rg_name = rg.name
            if not rg_name:
                continue
            rg_id = f"azure:rg:{rg_name}"
            graph.add_node(
                GraphNode(
                    id=rg_id,
                    entity_type="cloud_resource",
                    label=rg_name,
                    attributes={"location": rg.location},
                    dimensions={"cloud_provider": "azure", "surface": "resource_group"},
                )
            )
            graph.add_edge(
                GraphEdge(
                    source=f"azure:subscription:{subscription_id}",
                    target=rg_id,
                    relationship="contains",
                )
            )

            # Resources in group
            for resource in client.resources.list_by_resource_group(rg_name):
                resource_name = resource.name
                if not resource_name:
                    continue
                res_id = f"azure:resource:{resource_name}"
                res_type = resource.type.split("/")[-1] if resource.type else "unknown"
                graph.add_node(
                    GraphNode(
                        id=res_id,
                        entity_type="cloud_resource",
                        label=resource_name,
                        attributes={"type": resource.type, "location": resource.location, "kind": resource.kind or ""},
                        dimensions={"cloud_provider": "azure", "surface": res_type},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source=rg_id,
                        target=res_id,
                        relationship="contains",
                    )
                )
    except Exception as e:
        print(f"Warning: Azure resource discovery failed: {e}", file=sys.stderr)

    _add_mitre_edges(graph)
    return graph


# ═══════════════════════════════════════════════════════════════════════════
# Static config discovery (no SDK needed)
# ═══════════════════════════════════════════════════════════════════════════


def discover_from_config(config_path: str) -> EnvironmentGraph:
    """Build environment graph from a static config file (JSON/YAML).

    Use when cloud SDK access is not available — manual inventory.
    """
    p = Path(config_path)
    if not p.exists():
        print(f"Error: Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    content = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml

            config = yaml.safe_load(content) or {}
        except ImportError:
            print("Error: PyYAML required for YAML. Install: pip install pyyaml", file=sys.stderr)
            sys.exit(1)
    else:
        config = json.loads(content)

    graph = EnvironmentGraph(provider=config.get("provider", "static"))

    for resource in config.get("resources", []):
        graph.add_node(
            GraphNode(
                id=resource.get("id", str(uuid4())),
                entity_type=resource.get("type", "cloud_resource"),
                label=resource.get("name", resource.get("id", "unknown")),
                attributes=resource.get("attributes", {}),
                compliance_tags=resource.get("compliance_tags", []),
                dimensions=resource.get("dimensions", {}),
                severity=resource.get("severity", ""),
            )
        )

    for rel in config.get("relationships", []):
        graph.add_edge(
            GraphEdge(
                source=rel["source"],
                target=rel["target"],
                relationship=rel.get("type", "related_to"),
                direction=rel.get("direction", "directed"),
                evidence=rel.get("evidence", {}),
            )
        )

    _add_mitre_edges(graph)
    return graph


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _get_tag(tags: list[dict], key: str) -> str:
    for tag in tags:
        if tag.get("Key") == key:
            return tag.get("Value", "")
    return ""


def _runtime_to_ecosystem(runtime: str) -> str:
    if "python" in runtime.lower():
        return "pypi"
    if "node" in runtime.lower():
        return "npm"
    if "java" in runtime.lower():
        return "maven"
    if "go" in runtime.lower():
        return "go"
    if "dotnet" in runtime.lower() or "csharp" in runtime.lower():
        return "nuget"
    if "ruby" in runtime.lower():
        return "rubygems"
    return ""


def _get_mitre_tags(entity_type: str) -> list[str]:
    techniques = get_attack_techniques(entity_type)
    return [f"MITRE-{t['technique']}" for t in techniques]


def _add_mitre_edges(graph: EnvironmentGraph) -> None:
    """Add MITRE ATT&CK/ATLAS technique edges to relevant nodes."""
    for node in graph.nodes:
        techniques = MITRE_ATTACK_MAP.get(node.entity_type, []) + MITRE_ATLAS_MAP.get(node.entity_type, [])
        for tech in techniques:
            tech_id = f"mitre:{tech['technique']}"
            # Add technique node if not present
            existing_ids = {n.id for n in graph.nodes}
            if tech_id not in existing_ids:
                graph.add_node(
                    GraphNode(
                        id=tech_id,
                        entity_type="vulnerability",
                        label=f"{tech['technique']}: {tech['name']}",
                        attributes={"tactic": tech["tactic"], "framework": "ATT&CK" if tech["technique"].startswith("T") else "ATLAS"},
                        compliance_tags=[f"MITRE-{tech['technique']}"],
                    )
                )
            graph.add_edge(
                GraphEdge(
                    source=tech_id,
                    target=node.id,
                    relationship="exploitable_via",
                    evidence={"technique": tech["technique"], "tactic": tech["tactic"]},
                )
            )


def _build_cloud_object(graph: EnvironmentGraph) -> dict[str, Any] | None:
    if graph.provider == "static":
        return None

    cloud: dict[str, Any] = {"provider": graph.provider}
    if graph.provider == "aws":
        account_node = next((node for node in graph.nodes if node.id.startswith("aws:account:")), None)
        if account_node:
            account_id = account_node.attributes.get("account_id")
            if account_id:
                cloud["account"] = {"uid": str(account_id), "name": f"AWS Account {account_id}"}
    elif graph.provider == "gcp":
        project_node = next((node for node in graph.nodes if node.id.startswith("gcp:project:")), None)
        if project_node:
            project_uid = project_node.id.split(":", 2)[-1]
            cloud["project_uid"] = project_uid
            cloud["account"] = {"uid": project_uid, "name": project_node.label}
    elif graph.provider == "azure":
        subscription_node = next((node for node in graph.nodes if node.id.startswith("azure:subscription:")), None)
        if subscription_node:
            subscription_uid = subscription_node.id.split(":", 2)[-1]
            cloud["account"] = {"uid": subscription_uid, "name": subscription_node.label}

    if graph.region:
        cloud["region"] = graph.region
    return cloud


def _node_to_ocsf_resource(node: GraphNode, region: str) -> dict[str, Any]:
    resource = {
        "uid": node.id,
        "name": node.label,
        "type": node.entity_type,
        "region": region or node.attributes.get("region") or node.dimensions.get("region"),
        "labels": sorted(set(node.compliance_tags)),
        "data": {
            "attributes": node.attributes,
            "dimensions": node.dimensions,
            "severity": node.severity,
            "risk_score": node.risk_score,
            "status": node.status,
        },
    }
    if not resource["region"]:
        resource.pop("region")
    if not resource["labels"]:
        resource.pop("labels")
    return resource


def _metadata_uid(graph: EnvironmentGraph, inventory_nodes: list[GraphNode]) -> str:
    canonical = json.dumps(
        {
            "provider": graph.provider,
            "region": graph.region,
            "discovered_at": graph.discovered_at,
            "nodes": sorted(node.id for node in inventory_nodes),
            "edges": sorted(
                f"{edge.source}->{edge.relationship}->{edge.target}"
                for edge in graph.edges
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def to_ocsf_cloud_resources_inventory(graph: EnvironmentGraph) -> dict[str, Any]:
    inventory_nodes = [node for node in graph.nodes if not node.id.startswith("mitre:")]
    message = f"{graph.provider} cloud resource inventory snapshot"
    event: dict[str, Any] = {
        "activity_id": 99,
        "activity_name": "inventory_snapshot",
        "category_uid": 5,
        "category_name": "Discovery",
        "class_uid": 5023,
        "class_name": "Cloud Resources Inventory Info",
        "type_uid": 502399,
        "type_name": "Cloud Resources Inventory Info: Other",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "time": _time_to_epoch_ms(graph.discovered_at),
        "message": message,
        "metadata": {
            "version": "1.8.0",
            "uid": _metadata_uid(graph, inventory_nodes),
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": "discover-environment"},
            },
        },
        "count": len(inventory_nodes),
        "resources": [_node_to_ocsf_resource(node, graph.region) for node in inventory_nodes],
        "unmapped": {
            "environment_graph": graph.to_dict(),
            "bridge_format": "cloud-security.environment-graph.v1",
        },
    }
    if cloud := _build_cloud_object(graph):
        event["cloud"] = cloud
    if inventory_nodes:
        event["start_time"] = _time_to_epoch_ms(graph.discovered_at)
        event["end_time"] = _time_to_epoch_ms(graph.discovered_at)
    return event


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    parser = argparse.ArgumentParser(description="Cloud Environment Discovery — map infrastructure to security graph")
    parser.add_argument("provider", choices=["aws", "gcp", "azure", "config"], help="Cloud provider or 'config' for static file")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--project", help="GCP project ID")
    parser.add_argument("--subscription-id", help="Azure subscription ID")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--config", help="Path to static config file (for 'config' provider)")
    parser.add_argument(
        "--output-format",
        choices=SUPPORTED_OUTPUT_FORMATS,
        default="native",
        help="Output format: native graph JSON or OCSF Cloud Resources Inventory bridge",
    )
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    args = parser.parse_args()

    if args.provider == "aws":
        graph = discover_aws(region=args.region, profile=args.profile)
    elif args.provider == "gcp":
        if not args.project:
            parser.error("--project required for GCP")
        graph = discover_gcp(project=args.project)
    elif args.provider == "azure":
        if not args.subscription_id:
            parser.error("--subscription-id required for Azure")
        graph = discover_azure(subscription_id=args.subscription_id)
    elif args.provider == "config":
        if not args.config:
            parser.error("--config required for static config discovery")
        graph = discover_from_config(config_path=args.config)
    else:
        parser.error(f"Unknown provider: {args.provider}")

    payload: dict[str, Any]
    if args.output_format == "ocsf-cloud-resources-inventory":
        payload = to_ocsf_cloud_resources_inventory(graph)
    else:
        payload = graph.to_dict()

    result = json.dumps(payload, indent=2, default=str)

    if args.output:
        Path(args.output).write_text(result)
        print(f"Graph written to {args.output} ({len(graph.nodes)} nodes, {len(graph.edges)} edges)", file=sys.stderr)
    else:
        print(result)


if __name__ == "__main__":
    main()
