"""Generate technical control evidence from raw AWS, GCP, and Azure inventory snapshots."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "discover-cloud-control-evidence"
SUPPORTED_FRAMEWORKS = ("pci", "soc2", "ai-rmf")
SUPPORTED_OUTPUT_FORMATS = ("native", "ocsf-live-evidence")
FRAMEWORK_LABELS = {
    "pci": "PCI DSS 4.0",
    "soc2": "SOC 2 Security",
    "ai-rmf": "NIST AI RMF 1.0",
}
SECRET_KEYWORDS = (
    "authorization",
    "client_secret",
    "connection_string",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
)
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0", "*", "internet", "any"}
AI_SERVICES = {"ai-foundry", "azure-ml", "bedrock", "sagemaker", "vertex-ai"}
AI_ENDPOINT_KINDS = {"deployment", "endpoint", "inference-endpoint"}
AI_GOVERNANCE_KINDS = {"ai-guardrail", "dataset", "guardrail", "model", "model-package", "training-job", "vector-index", "vector-store"}
SEGMENTATION_KINDS = {"network-policy", "firewall-rule"}
AI_RMF_CONTROL_FOCUS = {
    "ai-rmf.govern.ai-service-governance": "GOVERN",
    "ai-rmf.map.ai-system-inventory": "MAP",
    "ai-rmf.measure.ai-logging-and-monitoring": "MEASURE",
    "ai-rmf.manage.ai-safeguards-and-network-boundaries": "MANAGE",
}


def _load_json(path: str | None) -> dict[str, Any]:
    if path:
        return json.loads(Path(path).read_text())
    return json.load(sys.stdin)


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "enabled", "enforced"}
    return bool(value)


def _clean(mapping: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in mapping.items() if value not in (None, "", [], {})}


def _secret_like(key: str) -> bool:
    key = key.lower().replace("-", "_")
    return any(fragment in key for fragment in SECRET_KEYWORDS)


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, child in value.items():
            if _secret_like(key):
                continue
            cleaned_child = _sanitize(child)
            if cleaned_child in (None, {}, []):
                continue
            cleaned[key] = cleaned_child
        return cleaned
    if isinstance(value, list):
        cleaned_list = [_sanitize(item) for item in value]
        return [item for item in cleaned_list if item not in (None, {}, [])]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _normalize_frameworks(frameworks: list[str] | None) -> list[str]:
    if not frameworks:
        return ["pci", "soc2"]
    normalized = []
    for item in frameworks:
        key = item.strip().lower()
        if key not in SUPPORTED_FRAMEWORKS:
            raise ValueError(
                f"unsupported framework `{item}`; supported values: {', '.join(SUPPORTED_FRAMEWORKS)}"
            )
        if key not in normalized:
            normalized.append(key)
    return normalized


def _time_to_epoch_ms(value: str | None) -> int:
    text = _string(value)
    if not text:
        return 0
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return int(datetime.fromisoformat(text).timestamp() * 1000)
    except ValueError:
        return 0


def _asset(provider: str, service: str, kind: str, identifier: str | None, **kwargs: Any) -> dict[str, Any]:
    if not _string(identifier):
        raise ValueError(f"{provider}:{service}:{kind} asset is missing an identifier")
    return _clean(
        {
            "provider": provider,
            "service": service,
            "kind": kind,
            "id": identifier,
            **kwargs,
        }
    )


def _is_public_cidr(value: Any) -> bool:
    text = (_string(value) or "").lower()
    return text in PUBLIC_CIDRS


def _aws_assets(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    iam = snapshot.get("iam", {}) or {}
    ec2 = snapshot.get("ec2", {}) or {}
    s3 = snapshot.get("s3", {}) or {}
    kms = snapshot.get("kms", {}) or {}
    cloudtrail = snapshot.get("cloudtrail", {}) or {}
    bedrock = snapshot.get("bedrock", {}) or {}
    sagemaker = snapshot.get("sagemaker", {}) or {}

    for user in iam.get("users", []):
        assets.append(
            _asset(
                "aws",
                "iam",
                "user",
                user.get("UserName") or user.get("Arn"),
                name=user.get("UserName"),
                mfa_enabled=_bool(user.get("MFAEnabled")),
            )
        )
    for role in iam.get("roles", []):
        assets.append(
            _asset(
                "aws",
                "iam",
                "role",
                role.get("RoleName") or role.get("Arn"),
                name=role.get("RoleName"),
            )
        )
    for bucket in s3.get("buckets", []):
        encrypted = _bool(bucket.get("encrypted")) or bool(bucket.get("kms_key_id") or bucket.get("encryption"))
        assets.append(
            _asset(
                "aws",
                "s3",
                "bucket",
                bucket.get("Name") or bucket.get("Arn"),
                name=bucket.get("Name"),
                encrypted=encrypted,
                public=_bool(bucket.get("public")) or _bool(bucket.get("public_access")),
                logged=_bool(bucket.get("logging_enabled")),
            )
        )
    for key in kms.get("keys", []):
        assets.append(
            _asset(
                "aws",
                "kms",
                "key",
                key.get("KeyId") or key.get("Arn"),
                name=key.get("Alias"),
                rotation_enabled=_bool(key.get("RotationEnabled")),
            )
        )
    for trail in cloudtrail.get("trails", []):
        assets.append(
            _asset(
                "aws",
                "cloudtrail",
                "audit-trail",
                trail.get("Name") or trail.get("TrailARN"),
                name=trail.get("Name"),
                logged=_bool(trail.get("IsLogging")),
                encrypted=bool(trail.get("KmsKeyId")),
                multi_region=_bool(trail.get("IsMultiRegionTrail")),
            )
        )
    for instance in ec2.get("instances", []):
        assets.append(
            _asset(
                "aws",
                "ec2",
                "instance",
                instance.get("InstanceId"),
                name=instance.get("InstanceId"),
                public=bool(instance.get("PublicIpAddress") or instance.get("PublicDnsName")),
                encrypted=_bool(instance.get("Encrypted")),
            )
        )
    for group in ec2.get("security_groups", []):
        public = any(
            _is_public_cidr(rule.get("cidr") or rule.get("CidrIp") or rule.get("source"))
            for rule in group.get("ingress", [])
            if isinstance(rule, dict)
        )
        assets.append(
            _asset(
                "aws",
                "ec2",
                "network-policy",
                group.get("GroupId"),
                name=group.get("GroupName"),
                public=public,
            )
        )
    for model in bedrock.get("custom_models", []):
        assets.append(
            _asset(
                "aws",
                "bedrock",
                "model",
                model.get("modelArn"),
                name=model.get("modelName"),
            )
        )
    for guardrail in bedrock.get("guardrails", []):
        assets.append(
            _asset(
                "aws",
                "bedrock",
                "ai-guardrail",
                guardrail.get("id") or guardrail.get("guardrailArn"),
                name=guardrail.get("name"),
            )
        )
    for knowledge_base in bedrock.get("knowledge_bases", []):
        assets.append(
            _asset(
                "aws",
                "bedrock",
                "vector-store",
                knowledge_base.get("knowledgeBaseId") or knowledge_base.get("knowledgeBaseArn"),
                name=knowledge_base.get("name"),
                encrypted=_bool(knowledge_base.get("encrypted")),
            )
        )
    for package in sagemaker.get("model_packages", []):
        assets.append(
            _asset(
                "aws",
                "sagemaker",
                "model-package",
                package.get("ModelPackageArn") or package.get("ModelPackageName"),
                name=package.get("ModelPackageName") or package.get("ModelPackageGroupName"),
            )
        )
    for job in sagemaker.get("training_jobs", []):
        assets.append(
            _asset(
                "aws",
                "sagemaker",
                "training-job",
                job.get("TrainingJobArn") or job.get("TrainingJobName"),
                name=job.get("TrainingJobName"),
                encrypted=_bool(job.get("VolumeKmsKeyId")) or _bool(job.get("OutputDataConfig", {}).get("KmsKeyId")),
                logged=_bool(job.get("EnableNetworkIsolation")) or _bool(job.get("EnableInterContainerTrafficEncryption")),
            )
        )
    for dataset in sagemaker.get("datasets", []):
        assets.append(
            _asset(
                "aws",
                "sagemaker",
                "dataset",
                dataset.get("DatasetArn") or dataset.get("DatasetName"),
                name=dataset.get("DatasetName"),
                encrypted=_bool(dataset.get("KmsKeyId")),
            )
        )
    for endpoint in sagemaker.get("endpoints", []):
        assets.append(
            _asset(
                "aws",
                "sagemaker",
                "endpoint",
                endpoint.get("EndpointArn") or endpoint.get("EndpointName"),
                name=endpoint.get("EndpointName"),
                public=_bool(endpoint.get("public")),
                encrypted=_bool(endpoint.get("KmsKeyId")) or _bool(endpoint.get("DataCaptureConfig", {}).get("KmsKeyId")),
                logged=_bool(endpoint.get("DataCaptureConfig", {}).get("EnableCapture")),
            )
        )
    return assets


def _gcp_assets(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    iam = snapshot.get("iam", {}) or {}
    compute = snapshot.get("compute", {}) or {}
    storage = snapshot.get("storage", {}) or {}
    kms = snapshot.get("kms", {}) or {}
    logging = snapshot.get("logging", {}) or {}
    vertex = snapshot.get("vertex_ai", {}) or {}

    for account in iam.get("service_accounts", []):
        assets.append(
            _asset(
                "gcp",
                "iam",
                "service-account",
                account.get("email") or account.get("name"),
                name=account.get("displayName") or account.get("email"),
                disabled=_bool(account.get("disabled")),
            )
        )
    for bucket in storage.get("buckets", []):
        encrypted = bool(bucket.get("defaultKmsKeyName") or bucket.get("encryption"))
        assets.append(
            _asset(
                "gcp",
                "storage",
                "bucket",
                bucket.get("name"),
                name=bucket.get("name"),
                encrypted=encrypted,
                public=_bool(bucket.get("public")),
                logged=_bool(bucket.get("logging")),
            )
        )
    for key in kms.get("keys", []):
        assets.append(
            _asset(
                "gcp",
                "kms",
                "key",
                key.get("name"),
                name=key.get("name"),
                rotation_enabled=bool(key.get("rotationPeriod") or key.get("nextRotationTime")),
            )
        )
    for sink in logging.get("sinks", []):
        assets.append(
            _asset(
                "gcp",
                "logging",
                "logging-sink",
                sink.get("name"),
                name=sink.get("name"),
                logged=True,
            )
        )
    for instance in compute.get("instances", []):
        public = False
        for nic in instance.get("networkInterfaces", []) or []:
            if nic.get("accessConfigs"):
                public = True
                break
        assets.append(
            _asset(
                "gcp",
                "compute",
                "instance",
                instance.get("id") or instance.get("name"),
                name=instance.get("name"),
                public=public,
            )
        )
    for firewall in compute.get("firewalls", []):
        public = any(_is_public_cidr(source) for source in firewall.get("sourceRanges", []) or [])
        assets.append(
            _asset(
                "gcp",
                "compute",
                "firewall-rule",
                firewall.get("name"),
                name=firewall.get("name"),
                public=public,
            )
        )
    for model in vertex.get("models", []):
        assets.append(
            _asset(
                "gcp",
                "vertex-ai",
                "model",
                model.get("name"),
                name=model.get("displayName") or model.get("name"),
            )
        )
    for dataset in vertex.get("datasets", []):
        assets.append(
            _asset(
                "gcp",
                "vertex-ai",
                "dataset",
                dataset.get("name"),
                name=dataset.get("displayName") or dataset.get("name"),
                encrypted=bool(dataset.get("encryptionSpec", {}).get("kmsKeyName")),
            )
        )
    for pipeline in vertex.get("training_pipelines", []):
        assets.append(
            _asset(
                "gcp",
                "vertex-ai",
                "training-job",
                pipeline.get("name"),
                name=pipeline.get("displayName") or pipeline.get("name"),
                encrypted=bool(pipeline.get("encryptionSpec", {}).get("kmsKeyName")),
                logged=_bool(pipeline.get("enableContainerLogging")),
            )
        )
    for index in vertex.get("indexes", []):
        assets.append(
            _asset(
                "gcp",
                "vertex-ai",
                "vector-index",
                index.get("name"),
                name=index.get("displayName") or index.get("name"),
                encrypted=bool(index.get("encryptionSpec", {}).get("kmsKeyName")),
            )
        )
    for endpoint in vertex.get("endpoints", []):
        assets.append(
            _asset(
                "gcp",
                "vertex-ai",
                "endpoint",
                endpoint.get("name"),
                name=endpoint.get("displayName") or endpoint.get("name"),
                public=_bool(endpoint.get("public")),
                encrypted=bool(endpoint.get("encryptionSpec", {}).get("kmsKeyName")),
            )
        )
    for index_endpoint in vertex.get("index_endpoints", []):
        assets.append(
            _asset(
                "gcp",
                "vertex-ai",
                "endpoint",
                index_endpoint.get("name"),
                name=index_endpoint.get("displayName") or index_endpoint.get("name"),
                public=_bool(index_endpoint.get("public")),
                encrypted=bool(index_endpoint.get("encryptionSpec", {}).get("kmsKeyName")),
            )
        )
    return assets


def _azure_assets(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    entra = snapshot.get("entra", {}) or {}
    compute = snapshot.get("compute", {}) or {}
    storage = snapshot.get("storage", {}) or {}
    key_vault = snapshot.get("key_vault", {}) or {}
    monitor = snapshot.get("monitor", {}) or {}
    network = snapshot.get("network", {}) or {}
    ai_foundry = snapshot.get("ai_foundry", {}) or {}

    for user in entra.get("users", []):
        assets.append(
            _asset(
                "azure",
                "entra",
                "user",
                user.get("id") or user.get("userPrincipalName"),
                name=user.get("userPrincipalName") or user.get("displayName"),
            )
        )
    for principal in entra.get("service_principals", []):
        assets.append(
            _asset(
                "azure",
                "entra",
                "service-principal",
                principal.get("id") or principal.get("appId"),
                name=principal.get("displayName") or principal.get("appId"),
            )
        )
    for identity in entra.get("managed_identities", []):
        assets.append(
            _asset(
                "azure",
                "entra",
                "managed-identity",
                identity.get("id") or identity.get("clientId"),
                name=identity.get("name") or identity.get("clientId"),
            )
        )
    for account in storage.get("accounts", []):
        encrypted = _bool(account.get("encrypted")) or _bool(account.get("encryption_enabled"))
        assets.append(
            _asset(
                "azure",
                "storage",
                "storage-account",
                account.get("id") or account.get("name"),
                name=account.get("name"),
                encrypted=encrypted,
                public=_bool(account.get("allowBlobPublicAccess")),
                logged=_bool(account.get("logging_enabled")),
            )
        )
    for vault in key_vault.get("vaults", []):
        assets.append(
            _asset(
                "azure",
                "key-vault",
                "key-vault",
                vault.get("id") or vault.get("name"),
                name=vault.get("name"),
                public=_bool(vault.get("publicNetworkAccess")),
            )
        )
    for setting in monitor.get("diagnostic_settings", []):
        assets.append(
            _asset(
                "azure",
                "monitor",
                "diagnostic-setting",
                setting.get("id") or setting.get("name"),
                name=setting.get("name"),
                logged=True,
            )
        )
    for vm in compute.get("virtual_machines", []):
        assets.append(
            _asset(
                "azure",
                "compute",
                "virtual-machine",
                vm.get("id") or vm.get("name"),
                name=vm.get("name"),
                public=_bool(vm.get("public_ip")) or _bool(vm.get("publicIpAddress")),
                encrypted=_bool(vm.get("encryption_at_host")),
            )
        )
    for nsg in network.get("nsgs", []):
        public = False
        for rule in nsg.get("securityRules", []) or []:
            access = (_string(rule.get("access")) or "").lower()
            direction = (_string(rule.get("direction")) or "").lower()
            source = (
                _string(rule.get("sourceAddressPrefix"))
                or _string(rule.get("source"))
                or _string(rule.get("sourceAddressPrefixes"))
            )
            if access == "allow" and direction in {"inbound", ""} and _is_public_cidr(source):
                public = True
                break
        assets.append(
            _asset(
                "azure",
                "network",
                "network-policy",
                nsg.get("id") or nsg.get("name"),
                name=nsg.get("name"),
                public=public,
            )
        )
    for deployment in ai_foundry.get("deployments", []):
        assets.append(
            _asset(
                "azure",
                "ai-foundry",
                "endpoint",
                deployment.get("id") or deployment.get("name"),
                name=deployment.get("name"),
                public=_bool(deployment.get("public")),
                encrypted=_bool(deployment.get("cmk_enabled")) or _bool(deployment.get("encrypted")),
                logged=_bool(deployment.get("diagnostic_logging")) or _bool(deployment.get("logging_enabled")),
            )
        )
    for project in ai_foundry.get("projects", []):
        assets.append(
            _asset(
                "azure",
                "ai-foundry",
                "runtime",
                project.get("id") or project.get("name"),
                name=project.get("name"),
                logged=_bool(project.get("diagnostic_logging")) or _bool(project.get("logging_enabled")),
            )
        )
    for model in ai_foundry.get("models", []):
        assets.append(
            _asset(
                "azure",
                "ai-foundry",
                "model",
                model.get("id") or model.get("name"),
                name=model.get("name"),
            )
        )
    azure_ml = snapshot.get("azure_ml", {}) or {}
    for model in azure_ml.get("models", []):
        assets.append(
            _asset(
                "azure",
                "azure-ml",
                "model",
                model.get("id") or model.get("name"),
                name=model.get("name"),
            )
        )
    for dataset in azure_ml.get("data_assets", []):
        assets.append(
            _asset(
                "azure",
                "azure-ml",
                "dataset",
                dataset.get("id") or dataset.get("name"),
                name=dataset.get("name"),
                encrypted=_bool(dataset.get("cmk_enabled")) or _bool(dataset.get("encrypted")),
            )
        )
    for endpoint in azure_ml.get("online_endpoints", []):
        assets.append(
            _asset(
                "azure",
                "azure-ml",
                "endpoint",
                endpoint.get("id") or endpoint.get("name"),
                name=endpoint.get("name"),
                public=_bool(endpoint.get("public")) or _bool(endpoint.get("public_network_access")),
                encrypted=_bool(endpoint.get("cmk_enabled")) or _bool(endpoint.get("encrypted")),
                logged=_bool(endpoint.get("app_insights_enabled")) or _bool(endpoint.get("logging_enabled")),
            )
        )
    for deployment in azure_ml.get("deployments", []):
        assets.append(
            _asset(
                "azure",
                "azure-ml",
                "deployment",
                deployment.get("id") or deployment.get("name"),
                name=deployment.get("name"),
                logged=_bool(deployment.get("logging_enabled")),
            )
        )
    return assets


def normalize_inventory(document: dict[str, Any]) -> dict[str, Any]:
    sanitized = _sanitize(document)
    providers: list[str] = []
    assets: list[dict[str, Any]] = []

    if isinstance(sanitized.get("aws"), dict):
        providers.append("aws")
        assets.extend(_aws_assets(sanitized["aws"]))
    if isinstance(sanitized.get("gcp"), dict):
        providers.append("gcp")
        assets.extend(_gcp_assets(sanitized["gcp"]))
    if isinstance(sanitized.get("azure"), dict):
        providers.append("azure")
        assets.extend(_azure_assets(sanitized["azure"]))

    if not providers or not assets:
        raise ValueError("input must include at least one supported provider inventory with assets")

    deduped = {}
    for asset in assets:
        deduped[(asset["provider"], asset["service"], asset["kind"], asset["id"])] = asset

    return {
        "source_kind": "cloud-inventory-snapshot",
        "source_id": sanitized.get("inventory_id") or sanitized.get("snapshot_id"),
        "collected_at": sanitized.get("collected_at") or sanitized.get("captured_at"),
        "providers": sorted(providers),
        "assets": sorted(deduped.values(), key=lambda item: json.dumps(item, sort_keys=True)),
    }


def _summaries(normalized: dict[str, Any]) -> dict[str, Any]:
    assets = normalized["assets"]
    services = sorted({_string(asset.get("service")) or "unknown" for asset in assets})
    kinds = Counter((_string(asset.get("kind")) or "unknown") for asset in assets)

    identity_assets = [
        asset
        for asset in assets
        if asset["kind"] in {"user", "role", "service-account", "service-principal", "managed-identity"}
    ]
    public_assets = [asset for asset in assets if _bool(asset.get("public"))]
    encrypted_assets = [asset for asset in assets if _bool(asset.get("encrypted"))]
    logging_assets = [asset for asset in assets if _bool(asset.get("logged"))]
    key_assets = [asset for asset in assets if asset["kind"] in {"key", "key-vault"}]
    segmentation_assets = [asset for asset in assets if asset["kind"] in SEGMENTATION_KINDS]
    ai_assets = [asset for asset in assets if asset["service"] in AI_SERVICES]
    ai_endpoint_assets = [asset for asset in ai_assets if asset["kind"] in AI_ENDPOINT_KINDS]
    ai_public_assets = [asset for asset in ai_endpoint_assets if _bool(asset.get("public"))]
    ai_governance_assets = [asset for asset in ai_assets if asset["kind"] in AI_GOVERNANCE_KINDS]
    provider_surface_counts: dict[str, dict[str, int]] = {}

    for provider in normalized["providers"]:
        provider_assets = [asset for asset in assets if asset["provider"] == provider]
        provider_surface_counts[provider] = {
            "asset_count": len(provider_assets),
            "public_exposure_assets": sum(1 for asset in provider_assets if _bool(asset.get("public"))),
            "logging_assets": sum(1 for asset in provider_assets if _bool(asset.get("logged"))),
            "encrypted_assets": sum(1 for asset in provider_assets if _bool(asset.get("encrypted"))),
            "key_management_assets": sum(1 for asset in provider_assets if asset["kind"] in {"key", "key-vault"}),
            "segmentation_assets": sum(1 for asset in provider_assets if asset["kind"] in SEGMENTATION_KINDS),
        }

    return {
        "providers": normalized["providers"],
        "services": services,
        "asset_count": len(assets),
        "kind_counts": dict(sorted(kinds.items())),
        "control_surface_counts": {
            "identity_assets": len(identity_assets),
            "public_assets": len(public_assets),
            "encrypted_assets": len(encrypted_assets),
            "logging_assets": len(logging_assets),
            "key_assets": len(key_assets),
            "segmentation_assets": len(segmentation_assets),
            "ai_assets": len(ai_assets),
            "ai_endpoint_assets": len(ai_endpoint_assets),
            "ai_public_assets": len(ai_public_assets),
            "ai_governance_assets": len(ai_governance_assets),
        },
        "provider_control_surface_counts": provider_surface_counts,
    }


def _status(has_enough: bool, has_some: bool) -> str:
    if has_enough:
        return "evidence-ready"
    if has_some:
        return "partial"
    return "missing"


def _control(
    framework: str,
    control_id: str,
    title: str,
    description: str,
    evidence: list[dict[str, Any]],
    gaps: list[str],
    framework_mappings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status = _status(not gaps and bool(evidence), bool(evidence))
    return {
        "framework": FRAMEWORK_LABELS[framework],
        "control_id": control_id,
        "title": title,
        "status": status,
        "description": description,
        "evidence": evidence,
        "gaps": gaps,
        "framework_mappings": framework_mappings or {},
    }


def _sample(assets: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    return [
        _clean(
            {
                "provider": asset.get("provider"),
                "service": asset.get("service"),
                "kind": asset.get("kind"),
                "id": asset.get("id"),
                "name": asset.get("name"),
            }
        )
        for asset in assets[:limit]
    ]


def _controls_for(framework: str, normalized: dict[str, Any]) -> list[dict[str, Any]]:
    assets = normalized["assets"]
    identities = [
        asset
        for asset in assets
        if asset["kind"] in {"user", "role", "service-account", "service-principal", "managed-identity"}
    ]
    public_assets = [asset for asset in assets if _bool(asset.get("public"))]
    encrypted_assets = [asset for asset in assets if _bool(asset.get("encrypted"))]
    logging_assets = [asset for asset in assets if _bool(asset.get("logged"))]
    key_assets = [asset for asset in assets if asset["kind"] in {"key", "key-vault"}]
    ai_assets = [asset for asset in assets if asset["service"] in AI_SERVICES]
    ai_endpoint_assets = [asset for asset in ai_assets if asset["kind"] in AI_ENDPOINT_KINDS]
    ai_governance_assets = [asset for asset in ai_assets if asset["kind"] in AI_GOVERNANCE_KINDS]

    if framework == "pci":
        return [
            _control(
                framework,
                "inventory.identity-surface",
                "Identity inventory evidence",
                "Inventory-backed evidence for cloud identities, roles, and service principals.",
                _sample(identities),
                [] if identities else ["No identity inventory present in the supplied snapshot."],
            ),
            _control(
                framework,
                "inventory.external-exposure",
                "External exposure evidence",
                "Inventory-backed evidence for public endpoints, public IPs, and permissive network controls.",
                _sample(public_assets),
                [] if public_assets else ["No explicit external exposure inventory was present in the supplied snapshot."],
            ),
            _control(
                framework,
                "inventory.encryption-and-keys",
                "Encryption and key-management evidence",
                "Inventory-backed evidence for encrypted assets and key-management surfaces.",
                _sample(encrypted_assets + key_assets),
                [] if encrypted_assets or key_assets else [
                    "No encryption or key-management inventory was present in the supplied snapshot."
                ],
            ),
            _control(
                framework,
                "inventory.audit-logging",
                "Audit logging evidence",
                "Inventory-backed evidence for CloudTrail, audit logs, diagnostic settings, or equivalent logging surfaces.",
                _sample(logging_assets),
                [] if logging_assets else ["No logging inventory was present in the supplied snapshot."],
            ),
            _control(
                framework,
                "inventory.ai-service-surface",
                "AI service surface evidence",
                "Inventory-backed evidence for model endpoints, deployments, and AI-facing service surfaces across AWS, GCP, and Azure.",
                _sample(ai_endpoint_assets),
                [] if ai_endpoint_assets else ["No AI endpoint or deployment inventory was present in the supplied snapshot."],
            ),
            _control(
                framework,
                "inventory.ai-governance",
                "AI governance and data-path evidence",
                "Inventory-backed evidence for models, datasets, vector stores, training jobs, and guardrails associated with AI services.",
                _sample(ai_governance_assets),
                [] if ai_governance_assets else ["No AI governance inventory was present in the supplied snapshot."],
            ),
        ]

    if framework == "ai-rmf":
        return [
            _control(
                framework,
                "ai-rmf.govern.ai-service-governance",
                "AI governance surface evidence",
                "Inventory-backed evidence for guardrails, models, datasets, vector stores, and training paths that contribute to AI governance scope.",
                _sample(ai_governance_assets),
                [] if ai_governance_assets else ["No AI governance inventory was present in the supplied snapshot."],
                framework_mappings={"nist_ai_rmf": AI_RMF_CONTROL_FOCUS["ai-rmf.govern.ai-service-governance"]},
            ),
            _control(
                framework,
                "ai-rmf.map.ai-system-inventory",
                "AI system inventory evidence",
                "Inventory-backed evidence for AI endpoints, deployments, models, datasets, and supporting cloud providers.",
                _sample(ai_assets),
                [] if ai_assets else ["No AI system inventory was present in the supplied snapshot."],
                framework_mappings={"nist_ai_rmf": AI_RMF_CONTROL_FOCUS["ai-rmf.map.ai-system-inventory"]},
            ),
            _control(
                framework,
                "ai-rmf.measure.ai-logging-and-monitoring",
                "AI logging and monitoring evidence",
                "Inventory-backed evidence for endpoint logging, audit trails, and diagnostic surfaces supporting AI monitoring.",
                _sample(logging_assets + [asset for asset in ai_endpoint_assets if _bool(asset.get("logged"))]),
                [] if logging_assets else ["No logging inventory was present in the supplied snapshot."],
                framework_mappings={"nist_ai_rmf": AI_RMF_CONTROL_FOCUS["ai-rmf.measure.ai-logging-and-monitoring"]},
            ),
            _control(
                framework,
                "ai-rmf.manage.ai-safeguards-and-network-boundaries",
                "AI safeguards and network boundary evidence",
                "Inventory-backed evidence for private AI endpoints, encryption, and guardrail surfaces that support AI risk treatment.",
                _sample(
                    [asset for asset in ai_endpoint_assets if not _bool(asset.get("public"))]
                    + [asset for asset in ai_governance_assets if asset.get("kind") in {"ai-guardrail", "guardrail"}]
                    + encrypted_assets
                ),
                [] if ai_endpoint_assets or ai_governance_assets or encrypted_assets else [
                    "No AI safeguard, private endpoint, or encryption inventory was present in the supplied snapshot."
                ],
                framework_mappings={"nist_ai_rmf": AI_RMF_CONTROL_FOCUS["ai-rmf.manage.ai-safeguards-and-network-boundaries"]},
            ),
        ]

    return [
        _control(
            framework,
            "cc6.identity-and-access",
            "Identity and access evidence",
            "Inventory-backed evidence for users, roles, service accounts, and service principals.",
            _sample(identities),
            [] if identities else ["No identity inventory present in the supplied snapshot."],
        ),
        _control(
            framework,
            "cc6.external-surface",
            "External surface evidence",
            "Inventory-backed evidence for public assets and permissive network controls.",
            _sample(public_assets),
            [] if public_assets else ["No explicit public-surface inventory was present in the supplied snapshot."],
        ),
        _control(
            framework,
            "cc6.protection-of-data",
            "Data protection evidence",
            "Inventory-backed evidence for encryption-enabled resources and key-management systems.",
            _sample(encrypted_assets + key_assets),
            [] if encrypted_assets or key_assets else [
                "No encryption or key-management inventory was present in the supplied snapshot."
            ],
        ),
        _control(
            framework,
            "cc7.logging-and-monitoring",
            "Logging and monitoring evidence",
            "Inventory-backed evidence for audit logging and diagnostic coverage.",
            _sample(logging_assets),
            [] if logging_assets else ["No logging inventory was present in the supplied snapshot."],
        ),
        _control(
            framework,
            "cc6.ai-service-surface",
            "AI service surface evidence",
            "Inventory-backed evidence for model-serving endpoints, AI deployments, and externally reachable AI service surfaces.",
            _sample(ai_endpoint_assets),
            [] if ai_endpoint_assets else ["No AI endpoint or deployment inventory was present in the supplied snapshot."],
        ),
        _control(
            framework,
            "cc7.ai-governance-and-monitoring",
            "AI governance and monitoring evidence",
            "Inventory-backed evidence for models, datasets, vector stores, training jobs, and guardrail surfaces associated with AI services.",
            _sample(ai_governance_assets),
            [] if ai_governance_assets else ["No AI governance inventory was present in the supplied snapshot."],
        ),
    ]


def build_evidence(document: dict[str, Any], frameworks: list[str] | None = None) -> dict[str, Any]:
    normalized = normalize_inventory(document)
    selected = _normalize_frameworks(frameworks)
    controls = [control for framework in selected for control in _controls_for(framework, normalized)]
    summary = _summaries(normalized)

    evidence_key = {
        "source_kind": normalized["source_kind"],
        "source_id": normalized.get("source_id"),
        "collected_at": normalized.get("collected_at"),
        "providers": normalized["providers"],
        "summary": summary,
        "controls": controls,
    }
    evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(evidence_key, sort_keys=True)))

    return {
        "artifact_type": "technical-control-evidence",
        "generated_by": SKILL_NAME,
        "evidence_id": evidence_id,
        "source_kind": normalized["source_kind"],
        "source_id": normalized.get("source_id"),
        "collected_at": normalized.get("collected_at"),
        "frameworks": [FRAMEWORK_LABELS[framework] for framework in selected],
        "inventory_summary": summary,
        "controls": controls,
    }


def to_ocsf_live_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    time_ms = _time_to_epoch_ms(evidence.get("collected_at"))
    return {
        "activity_id": 99,
        "activity_name": "Other",
        "category_uid": 5,
        "category_name": "Discovery",
        "class_uid": 5040,
        "class_name": "Live Evidence Info",
        "type_uid": 504099,
        "type_name": "Live Evidence Info: Other",
        "severity_id": 1,
        "severity": "Informational",
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": evidence["evidence_id"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "profiles": ["cloud", "security_control"],
        },
        "message": "Discovery-layer technical control evidence generated from cross-cloud inventory.",
        "unmapped": {
            "cloud_security_technical_evidence": evidence,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="JSON file path. Reads stdin when omitted.")
    parser.add_argument(
        "--framework",
        action="append",
        dest="frameworks",
        default=None,
        help="Evidence family to emit. Repeat for multiple values: pci, soc2.",
    )
    parser.add_argument(
        "--output-format",
        choices=SUPPORTED_OUTPUT_FORMATS,
        default="native",
        help="Emit native evidence JSON or an OCSF Live Evidence bridge event.",
    )
    parser.add_argument("-o", "--output", help="Write the evidence JSON to this file.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args(argv)

    try:
        payload = _load_json(args.input)
        result = build_evidence(payload, args.frameworks)
        if args.output_format == "ocsf-live-evidence":
            result = to_ocsf_live_evidence(result)
    except ValueError as exc:
        _warn(str(exc))
        return 2

    json_text = json.dumps(result, indent=2 if args.pretty else None, sort_keys=True)
    if args.output:
        Path(args.output).write_text(f"{json_text}\n")
    else:
        sys.stdout.write(f"{json_text}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
