"""Generate a deterministic AI BOM from cloud AI inventory snapshots."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.evaluation_ocsf import findings_to_ocsf  # noqa: E402

SKILL_NAME = "discover-ai-bom"
BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.7"
SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.7.schema.json"
BOM_VERSION = 1
POLICY_BENCHMARK_NAME = "AI BOM Policy Audit"
POLICY_PROVIDER = "Multi"
POLICY_FRAMEWORKS = [
    "CycloneDX ML-BOM",
    "NIST AI RMF",
    "OWASP LLM Top 10",
    "OWASP MCP Top 10",
    "MITRE ATLAS",
]
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
SERVICE_KINDS = {"deployment", "endpoint", "inference-endpoint", "vector-store"}
COMPONENT_TYPES = {
    "dataset": "data",
    "guardrail": "application",
    "model": "machine-learning-model",
    "model-package": "machine-learning-model",
    "runtime": "platform",
    "training-job": "application",
    "vector-index": "data",
}
KIND_ALIASES = {
    "guardrails": "guardrail",
    "datasets": "dataset",
    "data-assets": "dataset",
    "data_assets": "dataset",
    "index": "vector-index",
    "indexes": "vector-index",
    "index-endpoint": "endpoint",
    "index_endpoints": "endpoint",
    "knowledge-base": "vector-store",
    "knowledge_bases": "vector-store",
    "model-package": "model-package",
    "model-packages": "model-package",
    "online-endpoint": "endpoint",
    "online-endpoints": "endpoint",
    "training-jobs": "training-job",
    "training_pipelines": "training-job",
}
UNPINNED_VERSION_MARKERS = {
    "latest",
    "main",
    "master",
    "stable",
    "prod",
    "production",
    "unspecified",
}
TRUSTED_REGISTRY_HOST_SUFFIXES = (
    "huggingface.co",
    "hf.co",
    "amazonaws.com",
    "azurecr.io",
    "gcr.io",
    "pkg.dev",
    "docker.io",
    "ghcr.io",
)
INTERNAL_REGISTRY_HOST_SUFFIXES = (".internal", ".corp", ".local", ".lan")
LICENSE_FLAG_MARKERS = (
    "non-commercial",
    "noncommercial",
    "research-only",
    "research only",
    "commercial-restricted",
    "personal use only",
    "personal-use-only",
)


@dataclass(frozen=True)
class PolicyFinding:
    check_id: str
    title: str
    section: str
    severity: str
    status: str
    detail: str
    remediation: str
    resources: list[str]
    nist_ai_rmf: str = ""
    mitre_atlas: str = ""


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _load_json(path: str | None) -> dict[str, Any]:
    if path:
        return json.loads(Path(path).read_text())
    return json.load(sys.stdin)


def _secret_like(key: str) -> bool:
    key = key.lower().replace("-", "_")
    return any(fragment in key for fragment in SECRET_KEYWORDS)


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, child in value.items():
            if _secret_like(key):
                continue
            sanitized = _sanitize_value(child)
            if sanitized in (None, {}, []):
                continue
            cleaned[key] = sanitized
        return cleaned
    if isinstance(value, list):
        cleaned_list = [_sanitize_value(item) for item in value]
        return [item for item in cleaned_list if item not in (None, {}, [])]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _clean_dict(mapping: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in mapping.items() if value not in (None, "", [], {})}


def _string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _kind(value: str | None) -> str:
    normalized = (value or "component").strip().lower()
    return KIND_ALIASES.get(normalized, normalized)


def _make_asset(**kwargs: Any) -> dict[str, Any]:
    asset = _clean_dict({key: _sanitize_value(value) for key, value in kwargs.items()})
    asset["kind"] = _kind(_string(asset.get("kind")))
    if "dependencies" in asset:
        deps = asset["dependencies"]
        if not isinstance(deps, list):
            raise ValueError("asset `dependencies` must be a list when provided")
        asset["dependencies"] = sorted({_string(dep) for dep in deps if _string(dep)})
    return asset


def _asset_identity(asset: dict[str, Any]) -> str:
    provider = _string(asset.get("provider")) or "unknown"
    service = _string(asset.get("service")) or "unknown"
    kind = _kind(_string(asset.get("kind")))
    identifier = _string(asset.get("id")) or _string(asset.get("name"))
    if not identifier:
        raise ValueError("asset must include at least one of `id` or `name`")
    return f"{provider}:{service}:{kind}:{identifier}"


def _normalize_assets(document: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(document.get("assets"), list):
        assets = [_make_asset(**asset) for asset in document["assets"]]
    else:
        assets = []
        assets.extend(_normalize_aws(document))
        assets.extend(_normalize_gcp(document))
        assets.extend(_normalize_azure(document))

    if not assets:
        raise ValueError(
            "inventory must include `assets[]` or at least one supported provider snapshot"
        )

    deduped: dict[str, dict[str, Any]] = {}
    for asset in assets:
        identity = _asset_identity(asset)
        if identity in deduped:
            merged = deepcopy(deduped[identity])
            for key, value in asset.items():
                if key == "dependencies":
                    merged[key] = sorted(set(merged.get(key, [])) | set(value))
                    continue
                if key not in merged or merged[key] in (None, "", [], {}):
                    merged[key] = value
            deduped[identity] = merged
        else:
            deduped[identity] = asset

    return sorted(deduped.values(), key=_asset_identity)


def _normalize_aws(document: dict[str, Any]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    provider = (document.get("provider") or "aws").lower()
    sagemaker = document.get("sagemaker", {}) or {}
    bedrock = document.get("bedrock", {}) or {}

    for package in sagemaker.get("model_packages", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="sagemaker",
                kind="model-package",
                id=package.get("ModelPackageArn"),
                name=package.get("ModelPackageName") or package.get("ModelPackageGroupName"),
                version=package.get("ModelPackageVersion"),
                status=package.get("ModelApprovalStatus"),
                region=package.get("Region"),
            )
        )

    for endpoint in sagemaker.get("endpoints", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="sagemaker",
                kind="endpoint",
                id=endpoint.get("EndpointArn"),
                name=endpoint.get("EndpointName"),
                status=endpoint.get("EndpointStatus"),
                region=endpoint.get("Region"),
                dependencies=[endpoint.get("ModelPackageArn"), endpoint.get("ModelArn")],
            )
        )

    for job in sagemaker.get("training_jobs", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="sagemaker",
                kind="training-job",
                id=job.get("TrainingJobArn") or job.get("TrainingJobName"),
                name=job.get("TrainingJobName"),
                status=job.get("TrainingJobStatus"),
                region=job.get("Region"),
            )
        )

    for dataset in sagemaker.get("datasets", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="sagemaker",
                kind="dataset",
                id=dataset.get("DatasetArn") or dataset.get("DatasetName"),
                name=dataset.get("DatasetName"),
                version=dataset.get("DatasetVersion"),
                region=dataset.get("Region"),
            )
        )

    for model in bedrock.get("custom_models", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="bedrock",
                kind="model",
                id=model.get("modelArn"),
                name=model.get("modelName"),
                version=model.get("modelArn"),
                status=model.get("modelStatus"),
                dependencies=[model.get("baseModelArn"), model.get("foundationModelArn")],
            )
        )

    for guardrail in bedrock.get("guardrails", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="bedrock",
                kind="guardrail",
                id=guardrail.get("id") or guardrail.get("guardrailArn"),
                name=guardrail.get("name"),
                version=guardrail.get("version"),
                status=guardrail.get("status"),
            )
        )

    for knowledge_base in bedrock.get("knowledge_bases", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="bedrock",
                kind="vector-store",
                id=knowledge_base.get("knowledgeBaseId") or knowledge_base.get("knowledgeBaseArn"),
                name=knowledge_base.get("name"),
                status=knowledge_base.get("status"),
            )
        )

    return assets


def _normalize_gcp(document: dict[str, Any]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    provider = (document.get("provider") or "gcp").lower()
    vertex = document.get("vertex_ai", {}) or {}

    for model in vertex.get("models", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="vertex-ai",
                kind="model",
                id=model.get("name"),
                name=model.get("displayName") or model.get("name"),
                version=model.get("versionId"),
                region=model.get("region"),
                labels=model.get("labels"),
            )
        )

    for endpoint in vertex.get("endpoints", []):
        deployed_models = endpoint.get("deployedModels", [])
        deps = [item.get("model") for item in deployed_models if item.get("model")]
        assets.append(
            _make_asset(
                provider=provider,
                service="vertex-ai",
                kind="endpoint",
                id=endpoint.get("name"),
                name=endpoint.get("displayName") or endpoint.get("name"),
                region=endpoint.get("region"),
                dependencies=deps,
                labels=endpoint.get("labels"),
            )
        )

    for dataset in vertex.get("datasets", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="vertex-ai",
                kind="dataset",
                id=dataset.get("name"),
                name=dataset.get("displayName") or dataset.get("name"),
                region=dataset.get("region"),
                labels=dataset.get("labels"),
            )
        )

    for pipeline in vertex.get("training_pipelines", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="vertex-ai",
                kind="training-job",
                id=pipeline.get("name"),
                name=pipeline.get("displayName") or pipeline.get("name"),
                status=pipeline.get("state"),
                region=pipeline.get("region"),
                labels=pipeline.get("labels"),
            )
        )

    for index in vertex.get("indexes", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="vertex-ai",
                kind="vector-index",
                id=index.get("name"),
                name=index.get("displayName") or index.get("name"),
                region=index.get("region"),
                labels=index.get("labels"),
            )
        )

    for index_endpoint in vertex.get("index_endpoints", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="vertex-ai",
                kind="endpoint",
                id=index_endpoint.get("name"),
                name=index_endpoint.get("displayName") or index_endpoint.get("name"),
                region=index_endpoint.get("region"),
                dependencies=[
                    item.get("index")
                    for item in index_endpoint.get("deployedIndexes", [])
                    if item.get("index")
                ],
                labels=index_endpoint.get("labels"),
            )
        )

    return assets


def _normalize_azure(document: dict[str, Any]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    provider = (document.get("provider") or "azure").lower()
    aml = document.get("azure_ml", {}) or {}
    ai_foundry = document.get("ai_foundry", {}) or {}

    for model in aml.get("models", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="azure-ml",
                kind="model",
                id=model.get("id"),
                name=model.get("name"),
                version=model.get("version"),
                labels=model.get("tags"),
            )
        )

    for endpoint in aml.get("online_endpoints", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="azure-ml",
                kind="endpoint",
                id=endpoint.get("id") or endpoint.get("name"),
                name=endpoint.get("name"),
                status=endpoint.get("provisioning_state") or endpoint.get("auth_mode"),
                dependencies=[
                    deployment.get("id") for deployment in endpoint.get("deployments", [])
                ],
                labels=endpoint.get("tags"),
            )
        )

    for deployment in aml.get("deployments", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="azure-ml",
                kind="deployment",
                id=deployment.get("id") or deployment.get("name"),
                name=deployment.get("name"),
                version=deployment.get("version"),
                dependencies=[deployment.get("model"), deployment.get("endpoint_name")],
            )
        )

    for dataset in aml.get("data_assets", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="azure-ml",
                kind="dataset",
                id=dataset.get("id") or dataset.get("name"),
                name=dataset.get("name"),
                version=dataset.get("version"),
            )
        )

    for compute in aml.get("compute_clusters", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="azure-ml",
                kind="runtime",
                id=compute.get("id") or compute.get("name"),
                name=compute.get("name"),
                version=compute.get("size") or compute.get("vmSize"),
                status=compute.get("state"),
            )
        )

    for deployment in ai_foundry.get("deployments", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="ai-foundry",
                kind="endpoint",
                id=deployment.get("id") or deployment.get("name"),
                name=deployment.get("name"),
                status=deployment.get("provisioning_state") or deployment.get("status"),
                dependencies=[deployment.get("model"), deployment.get("project_id")],
            )
        )

    for project in ai_foundry.get("projects", []):
        assets.append(
            _make_asset(
                provider=provider,
                service="ai-foundry",
                kind="runtime",
                id=project.get("id") or project.get("name"),
                name=project.get("name"),
                status=project.get("status"),
            )
        )

    return assets


def _property_items(asset: dict[str, Any]) -> list[dict[str, str]]:
    props: dict[str, str] = {}
    for key in (
        "provider",
        "service",
        "kind",
        "region",
        "framework",
        "runtime",
        "status",
        "sensitivity",
        "owner",
    ):
        value = _string(asset.get(key))
        if value:
            props[f"cloud-security:{key}"] = value

    for parent_key in ("labels", "tags", "properties"):
        mapping = asset.get(parent_key)
        if isinstance(mapping, dict):
            for key, value in mapping.items():
                if _secret_like(key):
                    _warn(
                        f"dropped secret-like property `{key}` from asset `{asset.get('name') or asset.get('id')}`"
                    )
                    continue
                rendered = _string(value)
                if rendered:
                    props[f"cloud-security:{parent_key}.{key}"] = rendered

    return [{"name": key, "value": props[key]} for key in sorted(props)]


def _bom_ref(asset: dict[str, Any]) -> str:
    return _asset_identity(asset)


def _asset_display_name(asset: dict[str, Any]) -> str:
    return _string(asset.get("name")) or _string(asset.get("id")) or _bom_ref(asset)


def _policy_resource(asset: dict[str, Any]) -> list[str]:
    return [_bom_ref(asset)]


def _version_is_pinned(version: str | None) -> bool:
    if version is None:
        return False
    normalized = version.strip().lower()
    if not normalized or normalized in UNPINNED_VERSION_MARKERS:
        return False
    if normalized.startswith("sha256:"):
        return True
    if normalized.startswith("v") and any(ch.isdigit() for ch in normalized[1:]):
        return True
    return any(ch.isdigit() for ch in normalized)


def _registry_candidates(asset: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in ("registry", "image", "image_uri", "model_uri", "source_uri", "repository", "uri"):
        value = _string(asset.get(key))
        if value:
            candidates.append(value)

    for parent_key in ("properties", "labels", "tags"):
        mapping = asset.get(parent_key)
        if not isinstance(mapping, dict):
            continue
        for key, value in mapping.items():
            if "registry" in key.lower() or key.lower() in {
                "image",
                "image_uri",
                "model_uri",
                "source_uri",
                "repository",
                "uri",
            }:
                rendered = _string(value)
                if rendered:
                    candidates.append(rendered)
    return candidates


def _extract_registry_host(value: str) -> str | None:
    if "://" in value:
        parsed = urlparse(value)
        return parsed.netloc.lower() or None

    head = value.split("/", 1)[0].lower()
    if "." in head or ":" in head:
        return head
    return None


def _registry_is_trusted(host: str | None) -> bool:
    if not host:
        return True
    if host.endswith(INTERNAL_REGISTRY_HOST_SUFFIXES):
        return True
    return host.endswith(TRUSTED_REGISTRY_HOST_SUFFIXES)


def _has_provenance(asset: dict[str, Any]) -> bool:
    keys = (
        "provenance",
        "provenance_uri",
        "provenance_attestation",
        "attestation",
        "attestation_uri",
        "sigstore_verified",
        "slsa_level",
    )
    for key in keys:
        value = asset.get(key)
        if isinstance(value, bool) and value:
            return True
        if _string(value):
            return True

    for parent_key in ("properties", "labels", "tags"):
        mapping = asset.get(parent_key)
        if not isinstance(mapping, dict):
            continue
        for key, value in mapping.items():
            lowered = key.lower()
            if (
                lowered in keys
                or "provenance" in lowered
                or "attestation" in lowered
                or "sigstore" in lowered
            ):
                if isinstance(value, bool) and value:
                    return True
                if _string(value):
                    return True
    return False


def _license_values(asset: dict[str, Any]) -> list[str]:
    values: list[str] = []
    raw = asset.get("license")
    if _string(raw):
        values.append(_string(raw) or "")
    licenses = asset.get("licenses")
    if isinstance(licenses, list):
        values.extend(_string(item) or "" for item in licenses if _string(item))
    elif _string(licenses):
        values.append(_string(licenses) or "")

    for parent_key in ("properties", "labels", "tags"):
        mapping = asset.get(parent_key)
        if not isinstance(mapping, dict):
            continue
        for key, value in mapping.items():
            if "license" in key.lower():
                rendered = _string(value)
                if rendered:
                    values.append(rendered)
    return values


def build_policy_findings(
    document: dict[str, Any], *, output_format: str = "ocsf"
) -> list[dict[str, Any]]:
    assets = _normalize_assets(document)
    findings: list[PolicyFinding] = []

    for asset in assets:
        kind = asset["kind"]
        display_name = _asset_display_name(asset)
        resources = _policy_resource(asset)

        if kind in {"model", "model-package"}:
            version = _string(asset.get("version"))
            if not _version_is_pinned(version):
                findings.append(
                    PolicyFinding(
                        check_id="AI-BOM-1",
                        title="Model version is not pinned",
                        section="versioning",
                        severity="MEDIUM",
                        status="FAIL",
                        detail=f"Asset `{display_name}` does not declare a stable version or digest pin.",
                        remediation="Record an explicit model version or immutable digest before promoting the asset.",
                        resources=resources,
                        nist_ai_rmf="GOVERN, MANAGE",
                    )
                )

            if not _has_provenance(asset):
                findings.append(
                    PolicyFinding(
                        check_id="AI-BOM-3",
                        title="Model provenance attestation is missing",
                        section="provenance",
                        severity="HIGH",
                        status="FAIL",
                        detail=f"Asset `{display_name}` does not declare provenance or attestation metadata.",
                        remediation="Attach provenance evidence such as Sigstore verification, SLSA level, or an attestation URI.",
                        resources=resources,
                        nist_ai_rmf="GOVERN, MEASURE, MANAGE",
                    )
                )

            flagged_licenses = [
                value
                for value in _license_values(asset)
                if any(marker in value.lower() for marker in LICENSE_FLAG_MARKERS)
            ]
            if flagged_licenses:
                findings.append(
                    PolicyFinding(
                        check_id="AI-BOM-4",
                        title="Model license carries production restrictions",
                        section="licensing",
                        severity="HIGH",
                        status="FAIL",
                        detail=f"Asset `{display_name}` declares restricted license metadata: {', '.join(sorted(set(flagged_licenses)))}.",
                        remediation="Use a production-approved license or document an approved exception before deployment.",
                        resources=resources,
                        nist_ai_rmf="GOVERN",
                    )
                )

        registry_hosts = sorted(
            {
                host
                for candidate in _registry_candidates(asset)
                if (host := _extract_registry_host(candidate)) and not _registry_is_trusted(host)
            }
        )
        if registry_hosts:
            findings.append(
                PolicyFinding(
                    check_id="AI-BOM-2",
                    title="Asset references an untrusted registry",
                    section="supply-chain",
                    severity="HIGH",
                    status="FAIL",
                    detail=f"Asset `{display_name}` references registry host(s) outside the trusted/internal allowlist: {', '.join(registry_hosts)}.",
                    remediation="Promote the asset into an internal or approved verified registry before production use.",
                    resources=resources,
                    nist_ai_rmf="MAP, MANAGE",
                )
            )

    if output_format == "native":
        return [finding.__dict__.copy() for finding in findings]
    if output_format != "ocsf":
        raise ValueError(f"unsupported policy finding format: {output_format}")
    return findings_to_ocsf(
        findings,
        skill_name=SKILL_NAME,
        benchmark_name=POLICY_BENCHMARK_NAME,
        provider=POLICY_PROVIDER,
        frameworks=POLICY_FRAMEWORKS,
    )


def _to_component(asset: dict[str, Any]) -> dict[str, Any]:
    component_type = COMPONENT_TYPES.get(asset["kind"], "application")
    return _clean_dict(
        {
            "type": component_type,
            "bom-ref": _bom_ref(asset),
            "name": _string(asset.get("name")) or _string(asset.get("id")),
            "version": _string(asset.get("version")) or "unspecified",
            "group": f"{asset['provider']}/{asset['service']}",
            "description": _string(asset.get("description")),
            "properties": _property_items(asset),
        }
    )


def _to_service(asset: dict[str, Any]) -> dict[str, Any]:
    return _clean_dict(
        {
            "bom-ref": _bom_ref(asset),
            "name": _string(asset.get("name")) or _string(asset.get("id")),
            "group": f"{asset['provider']}/{asset['service']}",
            "description": _string(asset.get("description")),
            "endpoints": [_string(asset.get("endpoint_url"))]
            if _string(asset.get("endpoint_url"))
            else None,
            "properties": _property_items(asset),
        }
    )


def _metadata_properties(
    document: dict[str, Any], assets: list[dict[str, Any]]
) -> list[dict[str, str]]:
    counts: defaultdict[str, int] = defaultdict(int)
    for asset in assets:
        counts[f"cloud-security:count.{asset['provider']}.{asset['kind']}"] += 1

    props = {
        "cloud-security:inventory.kind": "ai-bom",
        "cloud-security:inventory.asset_count": str(len(assets)),
    }
    collected_at = _string(document.get("collected_at"))
    if collected_at:
        props["cloud-security:inventory.collected_at"] = collected_at
    inventory_id = _string(document.get("inventory_id"))
    if inventory_id:
        props["cloud-security:inventory.id"] = inventory_id
    for key, value in counts.items():
        props[key] = str(value)
    return [{"name": key, "value": props[key]} for key in sorted(props)]


def _serial_number(document: dict[str, Any], assets: list[dict[str, Any]]) -> str:
    seed = {
        "inventory_id": document.get("inventory_id"),
        "collected_at": document.get("collected_at"),
        "assets": assets,
    }
    canonical = json.dumps(seed, sort_keys=True, separators=(",", ":"))
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, canonical)}"


def build_bom(document: dict[str, Any]) -> dict[str, Any]:
    assets = _normalize_assets(document)
    components: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []

    for asset in assets:
        if asset["kind"] in SERVICE_KINDS:
            services.append(_to_service(asset))
        else:
            components.append(_to_component(asset))

    dependencies: list[dict[str, Any]] = []
    for asset in assets:
        refs = [dep_text for dep in asset.get("dependencies", []) if (dep_text := _string(dep))]
        if refs:
            dependencies.append({"ref": _bom_ref(asset), "dependsOn": sorted(set(refs))})

    bom = {
        "$schema": SCHEMA_URL,
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial_number(document, assets),
        "version": BOM_VERSION,
        "metadata": _clean_dict(
            {
                "timestamp": _string(document.get("collected_at")),
                "component": {
                    "type": "platform",
                    "name": SKILL_NAME,
                    "version": "0.1.0",
                },
                "properties": _metadata_properties(document, assets),
            }
        ),
        "components": sorted(components, key=lambda item: item["bom-ref"]),
        "services": sorted(services, key=lambda item: item["bom-ref"]),
        "dependencies": sorted(dependencies, key=lambda item: item["ref"]),
    }
    return bom


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic AI BOM from AI asset inventory snapshots."
    )
    parser.add_argument(
        "input", nargs="?", help="Path to the inventory JSON file. Reads stdin when omitted."
    )
    parser.add_argument("-o", "--output", help="Write BOM JSON to this path instead of stdout.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print the BOM JSON.")
    parser.add_argument(
        "--emit-policy-findings",
        action="store_true",
        help="Emit AI BOM policy findings as JSONL instead of the BOM.",
    )
    parser.add_argument(
        "--policy-findings-output",
        help="Write AI BOM policy findings as JSONL to this path while still emitting the BOM.",
    )
    parser.add_argument(
        "--policy-findings-format",
        choices=("native", "ocsf"),
        default="ocsf",
        help="Render policy findings as repo-native dicts or OCSF 2003 Compliance Findings.",
    )
    args = parser.parse_args(argv)

    try:
        document = _load_json(args.input)
        bom = build_bom(document)
        policy_findings = build_policy_findings(document, output_format=args.policy_findings_format)
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.policy_findings_output:
        policy_payload = "".join(
            json.dumps(record, separators=(",", ":")) + "\n" for record in policy_findings
        )
        Path(args.policy_findings_output).write_text(policy_payload)

    if args.emit_policy_findings:
        payload = "".join(
            json.dumps(record, separators=(",", ":")) + "\n" for record in policy_findings
        )
    else:
        payload = json.dumps(bom, indent=2 if args.pretty else None, sort_keys=args.pretty)
        if args.pretty:
            payload += "\n"

    if args.output:
        Path(args.output).write_text(payload)
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
