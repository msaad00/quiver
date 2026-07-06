"""Provider-level discovery tests for discover-environment.

Covers the AWS, GCP, Azure, and CLI code paths that were previously
exercised only through the `discover_from_config` entrypoint.

Uses moto for AWS (real boto3 flow), and stand-in ``google.cloud.*`` /
``azure.*`` modules for GCP and Azure. The module reassigns module
globals at import-time, so we inject fake modules into ``sys.modules``
before the functions run their lazy imports.
"""

from __future__ import annotations

import io
import json
import sys
import types
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock

import boto3
import pytest

moto = pytest.importorskip("moto")
mock_aws = moto.mock_aws

_SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

import discover  # noqa: E402,I001


# ---------------------------------------------------------------------------
# AWS discovery
# ---------------------------------------------------------------------------


@mock_aws
def test_discover_aws_builds_full_graph():
    region = "us-east-1"
    iam = boto3.client("iam", region_name=region)
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    iam.create_role(
        RoleName="MyRole",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )

    s3 = boto3.client("s3", region_name=region)
    s3.create_bucket(Bucket="my-bucket")

    lam = boto3.client("lambda", region_name=region)
    lam.create_function(
        FunctionName="fn",
        Runtime="python3.11",
        Role="arn:aws:iam::123456789012:role/MyRole",
        Handler="app.handler",
        Code={"ZipFile": b"def handler(e, c): pass"},
    )

    ec2 = boto3.client("ec2", region_name=region)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(GroupName="open", Description="open", VpcId=vpc["VpcId"])
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    graph = discover.discover_aws(region=region)

    node_ids = {n.id for n in graph.nodes}
    assert any(nid.startswith("aws:account:") for nid in node_ids)
    assert "aws:iam_user:alice" in node_ids
    assert "aws:iam_role:MyRole" in node_ids
    assert "aws:s3:my-bucket" in node_ids
    assert "aws:lambda:fn" in node_ids
    assert any(nid.startswith("aws:vpc:") for nid in node_ids)
    assert any(nid.startswith("aws:sg:") for nid in node_ids)
    # At least one SG should be flagged high severity (the open-SSH one).
    open_sgs = [n for n in graph.nodes if n.id.startswith("aws:sg:") and n.severity == "high"]
    assert open_sgs, "expected at least one open SG flagged as high severity"
    # Lambda → role edge
    assert any(
        e.source == "aws:lambda:fn"
        and e.target == "aws:iam_role:MyRole"
        and e.relationship == "uses"
        for e in graph.edges
    )
    # Compliance tags from MITRE mapping propagate onto the discovered nodes.
    tagged = [n for n in graph.nodes if any(t.startswith("MITRE-") for t in n.compliance_tags)]
    assert tagged


def test_discover_aws_handles_sts_failure(monkeypatch):
    """If STS fails we still produce a graph without the account node."""
    import boto3 as _boto3

    class _Session:
        def __init__(self, **_):
            pass

        def client(self, name):
            c = MagicMock()
            if name == "sts":
                c.get_caller_identity.side_effect = RuntimeError("denied")
            else:
                c.list_users.return_value = {"Users": []}
                c.list_roles.return_value = {"Roles": []}
                c.list_buckets.return_value = {"Buckets": []}
                c.list_functions.return_value = {"Functions": []}
                c.describe_vpcs.return_value = {"Vpcs": []}
                c.describe_security_groups.return_value = {"SecurityGroups": []}
            return c

    monkeypatch.setattr(_boto3, "Session", _Session)
    buf = io.StringIO()
    with redirect_stderr(buf):
        graph = discover.discover_aws(region="us-east-1")
    assert graph.provider == "aws"
    assert "Could not get account identity" in buf.getvalue()


def test_discover_aws_logs_warnings_on_service_errors(monkeypatch):
    import boto3 as _boto3

    class _Session:
        def __init__(self, **_):
            pass

        def client(self, name):
            c = MagicMock()
            if name == "sts":
                c.get_caller_identity.return_value = {
                    "Account": "111",
                    "Arn": "arn:aws:iam::111:root",
                }
                return c
            err = RuntimeError(f"{name} broken")
            if name == "iam":
                c.list_users.side_effect = err
                c.list_roles.side_effect = err
                return c
            if name == "s3":
                c.list_buckets.side_effect = err
                return c
            if name == "lambda":
                c.list_functions.side_effect = err
                return c
            if name == "ec2":
                c.describe_vpcs.side_effect = err
                return c
            return c

    monkeypatch.setattr(_boto3, "Session", _Session)
    buf = io.StringIO()
    with redirect_stderr(buf):
        graph = discover.discover_aws(region="us-east-1")
    stderr = buf.getvalue()
    assert "IAM user discovery failed" in stderr
    assert "IAM role discovery failed" in stderr
    assert "S3 discovery failed" in stderr
    assert "Lambda discovery failed" in stderr
    assert "VPC/SG discovery failed" in stderr
    # Only account node + MITRE remains
    assert any(n.id.startswith("aws:account:") for n in graph.nodes)


def test_discover_aws_missing_boto3_exits(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError("no boto3")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # Ensure already-cached boto3 is treated as missing
    monkeypatch.delitem(sys.modules, "boto3", raising=False)
    with pytest.raises(SystemExit) as exc:
        discover.discover_aws()
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# GCP discovery
# ---------------------------------------------------------------------------


def _install_fake_gcp(
    monkeypatch, sa_items=None, bucket_items=None, sa_raises=False, gcs_raises=False
):
    google = types.ModuleType("google")
    cloud = types.ModuleType("google.cloud")

    # resourcemanager_v3 — just needs to import
    rm = types.ModuleType("google.cloud.resourcemanager_v3")
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud)
    monkeypatch.setitem(sys.modules, "google.cloud.resourcemanager_v3", rm)

    # iam_v1 with ListServiceAccountsRequest + IAMClient
    iam_v1 = types.ModuleType("google.cloud.iam_v1")

    class _ListReq:
        def __init__(self, name):
            self.name = name

    class _IAMClient:
        def list_service_accounts(self, request):
            if sa_raises:
                raise RuntimeError("sa boom")
            return list(sa_items or [])

    iam_v1.ListServiceAccountsRequest = _ListReq
    iam_v1.IAMClient = _IAMClient
    monkeypatch.setitem(sys.modules, "google.cloud.iam_v1", iam_v1)

    # storage
    storage_mod = types.ModuleType("google.cloud.storage")

    class _Client:
        def __init__(self, project):
            self.project = project

        def list_buckets(self):
            if gcs_raises:
                raise RuntimeError("gcs boom")
            return list(bucket_items or [])

    storage_mod.Client = _Client
    monkeypatch.setitem(sys.modules, "google.cloud.storage", storage_mod)


def test_discover_gcp_discovers_sas_and_buckets(monkeypatch):
    sa = MagicMock()
    sa.email = "sa@p.iam.gserviceaccount.com"
    sa.display_name = "SA"
    sa.disabled = False

    bucket = MagicMock()
    bucket.name = "my-bucket"
    bucket.location = "US"
    bucket.storage_class = "STANDARD"

    _install_fake_gcp(monkeypatch, sa_items=[sa], bucket_items=[bucket])
    graph = discover.discover_gcp(project="proj-1")
    ids = {n.id for n in graph.nodes}
    assert "gcp:project:proj-1" in ids
    assert "gcp:sa:sa@p.iam.gserviceaccount.com" in ids
    assert "gcp:bucket:my-bucket" in ids


def test_discover_gcp_handles_sa_and_storage_errors(monkeypatch):
    _install_fake_gcp(monkeypatch, sa_raises=True, gcs_raises=True)
    buf = io.StringIO()
    with redirect_stderr(buf):
        graph = discover.discover_gcp(project="proj-x")
    stderr = buf.getvalue()
    assert "GCP SA discovery failed" in stderr
    assert "GCS discovery failed" in stderr
    assert any(n.id.startswith("gcp:project:") for n in graph.nodes)


def test_discover_gcp_missing_sdk_exits(monkeypatch):
    import builtins

    for key in [k for k in sys.modules if k.startswith("google")]:
        monkeypatch.delitem(sys.modules, key, raising=False)
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("google.cloud"):
            raise ImportError("no sdk")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SystemExit) as exc:
        discover.discover_gcp(project="p")
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# Azure discovery
# ---------------------------------------------------------------------------


def _install_fake_azure(monkeypatch, resource_raises=False, rgs=None, resources_by_rg=None):
    azure = types.ModuleType("azure")
    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = MagicMock()
    monkeypatch.setitem(sys.modules, "azure", azure)
    monkeypatch.setitem(sys.modules, "azure.identity", identity)

    mgmt = types.ModuleType("azure.mgmt")
    resource_pkg = types.ModuleType("azure.mgmt.resource")

    class _Client:
        def __init__(self, credential, subscription_id):
            self.resource_groups = MagicMock()
            self.resources = MagicMock()
            if resource_raises:
                self.resource_groups.list.side_effect = RuntimeError("boom")
            else:
                self.resource_groups.list.return_value = rgs or []
                self.resources.list_by_resource_group.side_effect = lambda name: (
                    resources_by_rg or {}
                ).get(name, [])

    resource_pkg.ResourceManagementClient = _Client
    monkeypatch.setitem(sys.modules, "azure.mgmt", mgmt)
    monkeypatch.setitem(sys.modules, "azure.mgmt.resource", resource_pkg)


def test_discover_azure_discovers_rgs_and_resources(monkeypatch):
    rg = MagicMock()
    rg.name = "prod-rg"
    rg.location = "westus"

    res = MagicMock()
    res.name = "vm1"
    res.type = "Microsoft.Compute/virtualMachines"
    res.location = "westus"
    res.kind = None

    _install_fake_azure(monkeypatch, rgs=[rg], resources_by_rg={"prod-rg": [res]})
    graph = discover.discover_azure(subscription_id="sub-123")
    ids = {n.id for n in graph.nodes}
    assert "azure:subscription:sub-123" in ids
    assert "azure:rg:prod-rg" in ids
    assert "azure:resource:vm1" in ids
    # contains edge from rg → resource
    assert any(
        e.source == "azure:rg:prod-rg"
        and e.target == "azure:resource:vm1"
        and e.relationship == "contains"
        for e in graph.edges
    )


def test_discover_azure_handles_errors(monkeypatch):
    _install_fake_azure(monkeypatch, resource_raises=True)
    buf = io.StringIO()
    with redirect_stderr(buf):
        graph = discover.discover_azure(subscription_id="sub-err")
    assert "Azure resource discovery failed" in buf.getvalue()
    assert any(n.id.startswith("azure:subscription:") for n in graph.nodes)


def test_discover_azure_missing_sdk_exits(monkeypatch):
    import builtins

    for key in [k for k in sys.modules if k.startswith("azure")]:
        monkeypatch.delitem(sys.modules, key, raising=False)
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("azure"):
            raise ImportError("no sdk")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SystemExit) as exc:
        discover.discover_azure(subscription_id="s")
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# Static config discovery — missing path + YAML
# ---------------------------------------------------------------------------


def test_discover_from_config_missing_file_exits(tmp_path):
    missing = tmp_path / "nope.json"
    with pytest.raises(SystemExit) as exc:
        discover.discover_from_config(str(missing))
    assert exc.value.code == 1


def test_discover_from_config_yaml_path(tmp_path, monkeypatch):
    # Provide a minimal yaml module shim so the test doesn't require PyYAML.
    yaml_mod = types.ModuleType("yaml")

    def _safe_load(text):
        return {
            "provider": "static",
            "resources": [{"id": "res:y", "type": "cloud_resource", "name": "y"}],
            "relationships": [],
        }

    yaml_mod.safe_load = _safe_load
    monkeypatch.setitem(sys.modules, "yaml", yaml_mod)

    p = tmp_path / "env.yaml"
    p.write_text("doesnt-matter")
    graph = discover.discover_from_config(str(p))
    assert any(n.id == "res:y" for n in graph.nodes)


def test_discover_from_config_yaml_missing_dep_exits(tmp_path, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("no yaml")
        return real_import(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "yaml", raising=False)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    p = tmp_path / "env.yml"
    p.write_text("x: 1")
    with pytest.raises(SystemExit) as exc:
        discover.discover_from_config(str(p))
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# Helpers + OCSF projection edge cases
# ---------------------------------------------------------------------------


def test_get_tag_returns_value_or_empty():
    tags = [{"Key": "Name", "Value": "prod"}, {"Key": "Env", "Value": "prod"}]
    assert discover._get_tag(tags, "Name") == "prod"
    assert discover._get_tag(tags, "Missing") == ""


def test_runtime_to_ecosystem_covers_runtimes():
    for runtime, expected in [
        ("python3.11", "pypi"),
        ("nodejs20.x", "npm"),
        ("java17", "maven"),
        ("go1.x", "go"),
        ("dotnet6", "nuget"),
        ("ruby3.2", "rubygems"),
        ("custom", ""),
    ]:
        assert discover._runtime_to_ecosystem(runtime) == expected


def test_ocsf_bridge_for_gcp_populates_project_uid():
    graph = discover.EnvironmentGraph(
        provider="gcp", region="proj-1", discovered_at="2026-04-13T12:00:00+00:00"
    )
    graph.add_node(
        discover.GraphNode(
            id="gcp:project:proj-1",
            entity_type="cloud_resource",
            label="GCP Project proj-1",
        )
    )
    event = discover.to_ocsf_cloud_resources_inventory(graph)
    assert event["cloud"]["project_uid"] == "proj-1"
    assert event["cloud"]["account"]["uid"] == "proj-1"


def test_ocsf_bridge_for_azure_populates_subscription():
    graph = discover.EnvironmentGraph(
        provider="azure",
        region="sub-abc",
        discovered_at="2026-04-13T12:00:00+00:00",
    )
    graph.add_node(
        discover.GraphNode(
            id="azure:subscription:sub-abc",
            entity_type="cloud_resource",
            label="Azure Subscription sub-abc",
        )
    )
    event = discover.to_ocsf_cloud_resources_inventory(graph)
    assert event["cloud"]["account"]["uid"] == "sub-abc"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _run_cli(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["discover.py", *argv])
    buf_out = io.StringIO()
    buf_err = io.StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        try:
            discover.main()
            code = 0
        except SystemExit as e:
            code = e.code
    return code, buf_out.getvalue(), buf_err.getvalue()


def test_cli_config_output_native(tmp_path, monkeypatch):
    config = {
        "provider": "static",
        "resources": [{"id": "res:1", "type": "cloud_resource", "name": "r"}],
        "relationships": [],
    }
    cfg = tmp_path / "e.json"
    cfg.write_text(json.dumps(config))
    code, out, _ = _run_cli(monkeypatch, ["config", "--config", str(cfg)])
    assert code == 0
    payload = json.loads(out)
    assert payload["provider"] == "static"


def test_cli_config_output_ocsf_to_file(tmp_path, monkeypatch):
    config = {"resources": [{"id": "res:1", "type": "cloud_resource", "name": "r"}]}
    cfg = tmp_path / "e.json"
    cfg.write_text(json.dumps(config))
    out_file = tmp_path / "out.json"
    code, _, err = _run_cli(
        monkeypatch,
        [
            "config",
            "--config",
            str(cfg),
            "--output-format",
            "ocsf-cloud-resources-inventory",
            "--output",
            str(out_file),
        ],
    )
    assert code == 0
    assert out_file.exists()
    written = json.loads(out_file.read_text())
    assert written["class_uid"] == 5023
    assert "Graph written to" in err


def test_cli_config_without_config_flag_errors(monkeypatch):
    code, _, err = _run_cli(monkeypatch, ["config"])
    assert code != 0


def test_cli_gcp_without_project_errors(monkeypatch):
    code, _, err = _run_cli(monkeypatch, ["gcp"])
    assert code != 0


def test_cli_azure_without_subscription_errors(monkeypatch):
    code, _, err = _run_cli(monkeypatch, ["azure"])
    assert code != 0


def test_cli_gcp_with_stubbed_sdk(monkeypatch):
    _install_fake_gcp(monkeypatch)
    code, out, _ = _run_cli(monkeypatch, ["gcp", "--project", "p1"])
    assert code == 0
    payload = json.loads(out)
    assert payload["provider"] == "gcp"


def test_cli_azure_with_stubbed_sdk(monkeypatch):
    _install_fake_azure(monkeypatch, rgs=[])
    code, out, _ = _run_cli(monkeypatch, ["azure", "--subscription-id", "sub-cli"])
    assert code == 0
    payload = json.loads(out)
    assert payload["provider"] == "azure"
