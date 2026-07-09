"""Model Serving Security Benchmark — audit model deployment infrastructure.

Checks the security posture of AI model serving endpoints across:
- Authentication & authorization
- Rate limiting & abuse prevention
- Data egress controls
- Prompt injection surface
- Container/runtime isolation
- TLS & network security
- Logging & observability
- Safety layer configuration

Supports: API gateway configs, Kubernetes deployments, Docker Compose,
cloud-native serving (SageMaker, Vertex AI, Azure ML, Bedrock).

Read-only — no write permissions required. Safe to run in production.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.evaluation_ocsf import findings_to_native, findings_to_ocsf  # noqa: E402

SKILL_NAME = "model-serving-security"
# Framework depth markers (coverage_summary.py)
# control_id="LLM01"
# control_id="LLM07"
BENCHMARK_NAME = "Model Serving Security Benchmark"
PROVIDER_NAME = "Multi"
OUTPUT_FORMATS = ("native", "ocsf")

FRAMEWORKS = (
    "MITRE ATLAS",
    "NIST CSF 2.0",
    "NIST AI RMF 1.0",
    "OWASP LLM Top 10",
    "SOC 2 TSC",
)

PROVIDERS = ("aws", "azure", "gcp", "multi")
ASSET_CLASSES = ("ai-endpoints", "models", "identities", "network", "logging", "guardrails")
AI_FRAMEWORK_FOCUS = {
    "auth": {
        "nist_ai_rmf": "GOVERN, MANAGE",
        "scope": "identity, access, and provider workload identity on AI endpoints",
    },
    "abuse_prevention": {
        "nist_ai_rmf": "MAP, MANAGE",
        "scope": "rate limiting and input constraints for misuse and cost containment",
    },
    "data_egress": {
        "nist_ai_rmf": "MAP, MEASURE, MANAGE",
        "scope": "training-data leakage, PII handling, and output filtering",
    },
    "runtime": {
        "nist_ai_rmf": "MANAGE",
        "scope": "container and runtime isolation on serving infrastructure",
    },
    "network": {
        "nist_ai_rmf": "MAP, MANAGE",
        "scope": "public exposure, TLS, and private network isolation",
    },
    "safety": {
        "nist_ai_rmf": "GOVERN, MEASURE, MANAGE",
        "scope": "guardrails, content safety, audit logging, and version traceability",
    },
}


@dataclass
class Finding:
    check_id: str
    title: str
    section: str
    severity: str
    status: str  # PASS | FAIL | WARN | ERROR | SKIP
    detail: str = ""
    remediation: str = ""
    mitre_atlas: str = ""
    nist_csf: str = ""
    nist_ai_rmf: str = ""
    resources: list[str] = field(default_factory=list)


def benchmark_metadata() -> dict[str, object]:
    """Return machine-readable framework and section coverage for wrappers and docs."""
    return {
        "frameworks": list(FRAMEWORKS),
        "providers": list(PROVIDERS),
        "asset_classes": list(ASSET_CLASSES),
        "ai_framework_focus": AI_FRAMEWORK_FOCUS,
        "check_count": sum(len(checks) for checks in ALL_CHECKS.values()),
        "sections": {name: len(checks) for name, checks in ALL_CHECKS.items()},
    }


def _iter_endpoints(config: dict) -> list[dict]:
    endpoints = list(config.get("endpoints", []))

    aws = config.get("aws", {}) or {}
    sagemaker = aws.get("sagemaker", {}) or {}
    for endpoint in sagemaker.get("endpoints", []):
        endpoints.append(
            {
                "name": endpoint.get("EndpointName", "unknown"),
                "auth": {
                    "type": endpoint.get("AuthMode", endpoint.get("auth_mode", "iam")),
                    "enabled": endpoint.get("AuthEnabled", True),
                    "identity": endpoint.get("ExecutionRoleArn") or endpoint.get("RoleArn"),
                },
                "network": {
                    "public": endpoint.get("public", False),
                    "vpc": bool(endpoint.get("VpcConfig")),
                    "private_endpoint": bool(endpoint.get("VpcConfig")),
                },
                "tls": {"enabled": endpoint.get("tls_enabled", True)},
                "logging": {
                    "enabled": bool(endpoint.get("DataCaptureConfig", {}).get("EnableCapture")),
                },
                "guardrails": {
                    "enabled": bool(endpoint.get("GuardrailConfiguration"))
                    or bool(endpoint.get("guardrail_id"))
                    or bool(endpoint.get("guardrails", {}).get("enabled")),
                },
                "rate_limit": endpoint.get("rate_limit", {}),
                "limits": endpoint.get("limits", {}),
            }
        )

    gcp = config.get("gcp", {}) or {}
    vertex = gcp.get("vertex_ai", {}) or {}
    for endpoint in vertex.get("endpoints", []) + vertex.get("index_endpoints", []):
        endpoints.append(
            {
                "name": endpoint.get("displayName", endpoint.get("name", "unknown")),
                "auth": {
                    "type": endpoint.get("auth_mode", "iam"),
                    "enabled": endpoint.get("auth_enabled", True),
                    "identity": endpoint.get("serviceAccount") or endpoint.get("service_account"),
                },
                "network": {
                    "public": endpoint.get("public", False),
                    "vpc": bool(endpoint.get("privateServiceConnectConfig")),
                    "private_endpoint": bool(endpoint.get("privateServiceConnectConfig")),
                },
                "tls": {"enabled": True},
                "logging": {
                    "enabled": bool(endpoint.get("logging_enabled"))
                    or bool(endpoint.get("enable_access_logging")),
                },
                "guardrails": {
                    "enabled": bool(endpoint.get("safetySettings"))
                    or bool(endpoint.get("contentFilter")),
                },
                "rate_limit": endpoint.get("rate_limit", {}),
                "limits": endpoint.get("limits", {}),
            }
        )

    azure = config.get("azure", {}) or {}
    azure_ml = azure.get("azure_ml", {}) or {}
    for endpoint in azure_ml.get("online_endpoints", []):
        endpoints.append(
            {
                "name": endpoint.get("name", "unknown"),
                "auth": {
                    "type": endpoint.get("auth_mode", "key"),
                    "enabled": endpoint.get("auth_mode", "key") != "none",
                    "identity": (endpoint.get("identity", {}) or {}).get("type")
                    or endpoint.get("managed_identity"),
                },
                "network": {
                    "public": endpoint.get("public", False)
                    or endpoint.get("public_network_access", False),
                    "vpc": bool(endpoint.get("private_endpoint")),
                    "private_endpoint": bool(endpoint.get("private_endpoint")),
                },
                "tls": {"enabled": True},
                "logging": {
                    "enabled": bool(endpoint.get("app_insights_enabled"))
                    or bool(endpoint.get("logging_enabled")),
                },
                "guardrails": {
                    "enabled": bool(endpoint.get("rai_policy_name"))
                    or bool(endpoint.get("content_safety"))
                    or bool(endpoint.get("guardrails", {}).get("enabled")),
                },
                "rate_limit": endpoint.get("rate_limit", {}),
                "limits": endpoint.get("limits", {}),
            }
        )

    ai_foundry = azure.get("ai_foundry", {}) or {}
    for deployment in ai_foundry.get("deployments", []):
        endpoints.append(
            {
                "name": deployment.get("name", "unknown"),
                "auth": {
                    "type": deployment.get("auth_mode", "key"),
                    "enabled": deployment.get("auth_mode", "key") != "none",
                    "identity": deployment.get("managed_identity")
                    or (deployment.get("identity", {}) or {}).get("type"),
                },
                "network": {
                    "public": deployment.get("public", False)
                    or deployment.get("public_network_access", False),
                    "vpc": bool(deployment.get("private_endpoint")),
                    "private_endpoint": bool(deployment.get("private_endpoint")),
                },
                "tls": {"enabled": True},
                "logging": {"enabled": bool(deployment.get("logging_enabled"))},
                "guardrails": {
                    "enabled": bool(deployment.get("content_safety"))
                    or bool(deployment.get("guardrails", {}).get("enabled")),
                },
                "rate_limit": deployment.get("rate_limit", {}),
                "limits": deployment.get("limits", {}),
            }
        )

    return endpoints


def _iter_models(config: dict) -> list[dict]:
    models = list(config.get("models", []))
    for provider in ("aws", "gcp", "azure"):
        section = config.get(provider, {}) or {}
        if provider == "aws":
            sagemaker = section.get("sagemaker", {}) or {}
            models.extend(sagemaker.get("model_packages", []))
            models.extend((section.get("bedrock", {}) or {}).get("custom_models", []))
        elif provider == "gcp":
            vertex = section.get("vertex_ai", {}) or {}
            models.extend(vertex.get("models", []))
        elif provider == "azure":
            azure_ml = section.get("azure_ml", {}) or {}
            models.extend(azure_ml.get("models", []))
            models.extend((section.get("ai_foundry", {}) or {}).get("models", []))
    return models


# ═══════════════════════════════════════════════════════════════════════════
# Section 1 — Authentication & Authorization
# ═══════════════════════════════════════════════════════════════════════════


def check_1_1_endpoint_auth_required(config: dict) -> Finding:
    """MS-1.1 — Model endpoints must require authentication."""
    endpoints = _iter_endpoints(config)
    unauthenticated = []
    for ep in endpoints:
        auth = ep.get("auth", ep.get("authentication", {}))
        if not auth or auth.get("type") == "none" or auth.get("enabled") is False:
            unauthenticated.append(ep.get("name", ep.get("url", "unknown")))
    return Finding(
        check_id="MS-1.1",
        title="Endpoint authentication required",
        section="auth",
        severity="CRITICAL",
        status="FAIL" if unauthenticated else "PASS",
        detail=f"{len(unauthenticated)} endpoints without auth"
        if unauthenticated
        else "All endpoints require authentication",
        remediation="Enable API key, OAuth2, or mTLS on all model serving endpoints",
        mitre_atlas="AML.T0024",
        nist_csf="PR.AC-1",
        nist_ai_rmf="GOVERN, MANAGE",
        resources=unauthenticated,
    )


def check_1_2_no_hardcoded_api_keys(config: dict, scan_paths: list[str] | None = None) -> Finding:
    """MS-1.2 — No hardcoded API keys in serving configuration."""
    secret_patterns = [
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        re.compile(r"AKIA[A-Z0-9]{16}"),
        re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        re.compile(r"key-[a-zA-Z0-9]{32,}"),
        re.compile(r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
    ]
    config_str = json.dumps(config)
    found = []
    for pattern in secret_patterns:
        matches = pattern.findall(config_str)
        for m in matches:
            found.append(f"{pattern.pattern[:20]}... matched ({len(m)} chars)")

    # Scan files if paths provided
    if scan_paths:
        for path_str in scan_paths:
            path = Path(path_str)
            if not path.exists():
                continue
            files = path.rglob("*.yaml") if path.is_dir() else [path]
            for f in files:
                if f.stat().st_size > 1_000_000:
                    continue
                try:
                    content = f.read_text(errors="ignore")
                    for pattern in secret_patterns:
                        if pattern.search(content):
                            found.append(f"{f.name}: matches {pattern.pattern[:20]}...")
                except OSError:
                    pass

    return Finding(
        check_id="MS-1.2",
        title="No hardcoded API keys in serving config",
        section="auth",
        severity="CRITICAL",
        status="FAIL" if found else "PASS",
        detail=f"{len(found)} potential hardcoded secrets"
        if found
        else "No hardcoded secrets found",
        remediation="Use Secrets Manager, Vault, or environment variable references instead of inline secrets",
        mitre_atlas="AML.T0024",
        nist_csf="PR.AC-4",
        nist_ai_rmf="GOVERN, MANAGE",
        resources=found[:10],
    )


def check_1_3_rbac_model_access(config: dict) -> Finding:
    """MS-1.3 — Role-based access control on model endpoints."""
    endpoints = _iter_endpoints(config)
    no_rbac = []
    for ep in endpoints:
        auth = ep.get("auth", ep.get("authentication", {}))
        roles = auth.get("roles", auth.get("rbac", auth.get("permissions", [])))
        if not roles and auth.get("type") not in ("none", None):
            no_rbac.append(ep.get("name", "unknown"))
    return Finding(
        check_id="MS-1.3",
        title="RBAC on model endpoints",
        section="auth",
        severity="HIGH",
        status="FAIL" if no_rbac else "PASS",
        detail=f"{len(no_rbac)} endpoints without RBAC"
        if no_rbac
        else "All endpoints have role-based access",
        remediation="Configure role-based permissions per endpoint (admin, user, read-only)",
        mitre_atlas="AML.T0024",
        nist_csf="PR.AC-4",
        nist_ai_rmf="GOVERN, MANAGE",
        resources=no_rbac,
    )


def check_1_4_workload_identity_required(config: dict) -> Finding:
    """MS-1.4 — Provider-managed workload identity on AI endpoints."""
    endpoints = _iter_endpoints(config)
    missing_identity = []
    for ep in endpoints:
        auth = ep.get("auth", ep.get("authentication", {}))
        identity = auth.get("identity") or ep.get("identity") or ep.get("service_account")
        if not identity:
            missing_identity.append(ep.get("name", "unknown"))
    return Finding(
        check_id="MS-1.4",
        title="Managed identity or workload identity on endpoints",
        section="auth",
        severity="HIGH",
        status="FAIL" if missing_identity else "PASS",
        detail=f"{len(missing_identity)} endpoints without workload identity"
        if missing_identity
        else "All endpoints use provider-managed identity",
        remediation="Use IAM roles, Vertex AI service accounts, Azure managed identity, or equivalent provider-native workload identity.",
        mitre_atlas="AML.T0024",
        nist_csf="PR.AC-4",
        nist_ai_rmf="GOVERN, MANAGE",
        resources=missing_identity,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 2 — Rate Limiting & Abuse Prevention
# ═══════════════════════════════════════════════════════════════════════════


def check_2_1_rate_limiting_enabled(config: dict) -> Finding:
    """MS-2.1 — Rate limiting on inference endpoints."""
    endpoints = _iter_endpoints(config)
    no_rate_limit = []
    for ep in endpoints:
        rl = ep.get("rate_limit", ep.get("rateLimit", ep.get("throttle", {})))
        if not rl or rl.get("enabled") is False:
            no_rate_limit.append(ep.get("name", "unknown"))
    return Finding(
        check_id="MS-2.1",
        title="Rate limiting on inference endpoints",
        section="abuse_prevention",
        severity="HIGH",
        status="FAIL" if no_rate_limit else "PASS",
        detail=f"{len(no_rate_limit)} endpoints without rate limiting"
        if no_rate_limit
        else "All endpoints rate-limited",
        remediation="Set per-client RPM/RPD limits to prevent abuse and cost overruns",
        mitre_atlas="AML.T0042",
        nist_csf="PR.DS-4",
        nist_ai_rmf="MAP, MANAGE",
        resources=no_rate_limit,
    )


def check_2_2_input_size_limits(config: dict) -> Finding:
    """MS-2.2 — Input size/token limits on endpoints."""
    endpoints = _iter_endpoints(config)
    no_limits = []
    for ep in endpoints:
        limits = ep.get("limits", ep.get("input_limits", {}))
        max_tokens = limits.get("max_tokens", limits.get("max_input_tokens", 0))
        max_bytes = limits.get("max_bytes", limits.get("max_input_size", 0))
        if not max_tokens and not max_bytes:
            no_limits.append(ep.get("name", "unknown"))
    return Finding(
        check_id="MS-2.2",
        title="Input size/token limits",
        section="abuse_prevention",
        severity="MEDIUM",
        status="FAIL" if no_limits else "PASS",
        detail=f"{len(no_limits)} endpoints without input size limits"
        if no_limits
        else "All endpoints have input limits",
        remediation="Set max_tokens and max_input_size to prevent resource exhaustion",
        mitre_atlas="AML.T0042",
        nist_csf="PR.DS-4",
        nist_ai_rmf="MAP, MANAGE",
        resources=no_limits,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 3 — Data Egress & Privacy
# ═══════════════════════════════════════════════════════════════════════════


def check_3_1_output_filtering(config: dict) -> Finding:
    """MS-3.1 — Output content filtering enabled."""
    safety = config.get("safety", config.get("content_safety", config.get("guardrails", {})))
    output_filter = safety.get("output_filter", safety.get("content_filter", safety.get("enabled")))
    if output_filter is False or (not safety and not config.get("guardrails")):
        return Finding(
            check_id="MS-3.1",
            title="Output content filtering",
            section="data_egress",
            severity="HIGH",
            status="FAIL",
            detail="No output content filtering configured",
            remediation="Enable content safety filters to prevent PII leakage, harmful content, and prompt injection echoing",
            mitre_atlas="AML.T0048.002",
            nist_csf="PR.DS-5",
            nist_ai_rmf="MEASURE, MANAGE",
        )
    return Finding(
        check_id="MS-3.1",
        title="Output content filtering",
        section="data_egress",
        severity="HIGH",
        status="PASS",
        detail="Output content filtering is enabled",
        mitre_atlas="AML.T0048.002",
        nist_csf="PR.DS-5",
        nist_ai_rmf="MEASURE, MANAGE",
    )


def check_3_2_no_training_data_in_response(config: dict) -> Finding:
    """MS-3.2 — Training data not exposed via model responses."""
    privacy = config.get("privacy", config.get("data_protection", {}))
    memorization_guard = privacy.get(
        "memorization_guard", privacy.get("training_data_filter", False)
    )
    return Finding(
        check_id="MS-3.2",
        title="Training data memorization guard",
        section="data_egress",
        severity="HIGH",
        status="PASS" if memorization_guard else "WARN",
        detail="Memorization guard enabled"
        if memorization_guard
        else "No memorization guard configured — model may leak training data",
        remediation="Enable training data memorization detection to prevent data extraction attacks",
        mitre_atlas="AML.T0025",
        nist_csf="PR.DS-5",
        nist_ai_rmf="MAP, MEASURE, MANAGE",
    )


def check_3_3_logging_no_pii(config: dict) -> Finding:
    """MS-3.3 — Request/response logs do not contain PII."""
    logging_cfg = config.get("logging", config.get("observability", {}).get("logging", {}))
    redaction = logging_cfg.get("redact_pii", logging_cfg.get("pii_redaction", False))
    log_requests = logging_cfg.get("log_requests", logging_cfg.get("log_prompts", False))
    if log_requests and not redaction:
        return Finding(
            check_id="MS-3.3",
            title="PII redaction in logs",
            section="data_egress",
            severity="HIGH",
            status="FAIL",
            detail="Request logging enabled without PII redaction",
            remediation="Enable pii_redaction in logging config or disable request body logging",
            mitre_atlas="AML.T0025",
            nist_csf="PR.DS-5",
            nist_ai_rmf="MEASURE, MANAGE",
        )
    return Finding(
        check_id="MS-3.3",
        title="PII redaction in logs",
        section="data_egress",
        severity="HIGH",
        status="PASS",
        detail="PII redaction enabled or request logging disabled",
        mitre_atlas="AML.T0025",
        nist_csf="PR.DS-5",
        nist_ai_rmf="MEASURE, MANAGE",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 4 — Container & Runtime Isolation
# ═══════════════════════════════════════════════════════════════════════════


def check_4_1_no_privileged_containers(config: dict) -> Finding:
    """MS-4.1 — Model serving containers not running privileged."""
    containers = config.get("containers", config.get("deployments", []))
    privileged = []
    for c in containers:
        sec = c.get("security_context", c.get("securityContext", {}))
        if sec.get("privileged", False):
            privileged.append(c.get("name", "unknown"))
    return Finding(
        check_id="MS-4.1",
        title="No privileged containers",
        section="runtime",
        severity="CRITICAL",
        status="FAIL" if privileged else "PASS",
        detail=f"{len(privileged)} privileged containers"
        if privileged
        else "No privileged containers",
        remediation="Remove privileged: true from all model serving containers. Use specific capabilities instead.",
        mitre_atlas="AML.T0011",
        nist_csf="PR.AC-4",
        nist_ai_rmf="MANAGE",
        resources=privileged,
    )


def check_4_2_read_only_rootfs(config: dict) -> Finding:
    """MS-4.2 — Container root filesystem is read-only."""
    containers = config.get("containers", config.get("deployments", []))
    writable = []
    for c in containers:
        sec = c.get("security_context", c.get("securityContext", {}))
        if not sec.get("readOnlyRootFilesystem", sec.get("read_only_rootfs", False)):
            writable.append(c.get("name", "unknown"))
    return Finding(
        check_id="MS-4.2",
        title="Read-only root filesystem",
        section="runtime",
        severity="MEDIUM",
        status="FAIL" if writable else "PASS",
        detail=f"{len(writable)} containers with writable rootfs"
        if writable
        else "All containers have read-only rootfs",
        remediation="Set readOnlyRootFilesystem: true and use emptyDir volumes for temp data",
        mitre_atlas="AML.T0011",
        nist_csf="PR.DS-6",
        nist_ai_rmf="MANAGE",
        resources=writable,
    )


def check_4_3_non_root_user(config: dict) -> Finding:
    """MS-4.3 — Containers run as non-root user."""
    containers = config.get("containers", config.get("deployments", []))
    root_containers = []
    for c in containers:
        sec = c.get("security_context", c.get("securityContext", {}))
        run_as = sec.get("runAsNonRoot", sec.get("run_as_non_root"))
        run_as_user = sec.get("runAsUser", sec.get("run_as_user", 0))
        if run_as is False or (run_as is None and run_as_user == 0):
            root_containers.append(c.get("name", "unknown"))
    return Finding(
        check_id="MS-4.3",
        title="Non-root container user",
        section="runtime",
        severity="HIGH",
        status="FAIL" if root_containers else "PASS",
        detail=f"{len(root_containers)} containers running as root"
        if root_containers
        else "All containers run as non-root",
        remediation="Set runAsNonRoot: true and runAsUser to a non-zero UID",
        mitre_atlas="AML.T0011",
        nist_csf="PR.AC-4",
        nist_ai_rmf="MANAGE",
        resources=root_containers,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 5 — TLS & Network
# ═══════════════════════════════════════════════════════════════════════════


def check_5_1_tls_enforced(config: dict) -> Finding:
    """MS-5.1 — TLS enforced on all model endpoints."""
    endpoints = _iter_endpoints(config)
    no_tls = []
    for ep in endpoints:
        url = ep.get("url", ep.get("endpoint", ""))
        tls = ep.get("tls", ep.get("ssl", {}))
        if url.startswith("http://") or tls.get("enabled") is False:
            no_tls.append(ep.get("name", url))
    return Finding(
        check_id="MS-5.1",
        title="TLS enforced on endpoints",
        section="network",
        severity="CRITICAL",
        status="FAIL" if no_tls else "PASS",
        detail=f"{len(no_tls)} endpoints without TLS" if no_tls else "All endpoints enforce TLS",
        remediation="Enable TLS 1.2+ on all model serving endpoints. Redirect HTTP to HTTPS.",
        nist_csf="PR.DS-2",
        nist_ai_rmf="MAP, MANAGE",
        resources=no_tls,
    )


def check_5_2_no_public_endpoints(config: dict) -> Finding:
    """MS-5.2 — Model endpoints not publicly accessible without gateway."""
    endpoints = _iter_endpoints(config)
    public = []
    for ep in endpoints:
        visibility = ep.get("visibility", ep.get("access", ""))
        network = ep.get("network", {})
        if (
            visibility == "public"
            or network.get("public", False)
            or not network.get("vpc", network.get("private", True))
        ):
            public.append(ep.get("name", "unknown"))
    return Finding(
        check_id="MS-5.2",
        title="No public model endpoints",
        section="network",
        severity="HIGH",
        status="FAIL" if public else "PASS",
        detail=f"{len(public)} publicly accessible endpoints"
        if public
        else "All endpoints behind VPC/gateway",
        remediation="Place model endpoints behind API gateway or VPC. No direct public access.",
        mitre_atlas="AML.T0024",
        nist_csf="PR.AC-5",
        nist_ai_rmf="MAP, MANAGE",
        resources=public,
    )


def check_5_3_private_network_isolation(config: dict) -> Finding:
    """MS-5.3 — Provider-private networking on model endpoints."""
    endpoints = _iter_endpoints(config)
    missing_private = []
    for ep in endpoints:
        network = ep.get("network", {})
        if network.get("public", False):
            missing_private.append(ep.get("name", "unknown"))
            continue
        if not (network.get("vpc") or network.get("private") or network.get("private_endpoint")):
            missing_private.append(ep.get("name", "unknown"))
    return Finding(
        check_id="MS-5.3",
        title="Private network isolation on endpoints",
        section="network",
        severity="HIGH",
        status="FAIL" if missing_private else "PASS",
        detail=f"{len(missing_private)} endpoints without private network attachment"
        if missing_private
        else "All endpoints use private network isolation",
        remediation="Attach SageMaker endpoints to VPCs, Vertex AI endpoints to PSC/private networking, or Azure ML/Foundry endpoints to private endpoints.",
        mitre_atlas="AML.T0024",
        nist_csf="PR.AC-5",
        nist_ai_rmf="MAP, MANAGE",
        resources=missing_private,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 6 — Safety Layers
# ═══════════════════════════════════════════════════════════════════════════


def check_6_1_prompt_injection_guard(config: dict) -> Finding:
    """MS-6.1 — Prompt injection detection enabled."""
    safety = config.get("safety", config.get("guardrails", config.get("content_safety", {})))
    injection_guard = safety.get(
        "prompt_injection", safety.get("injection_detection", safety.get("input_guard", False))
    )
    return Finding(
        check_id="MS-6.1",
        title="Prompt injection detection",
        section="safety",
        severity="HIGH",
        status="PASS" if injection_guard else "FAIL",
        detail="Prompt injection guard enabled"
        if injection_guard
        else "No prompt injection detection configured",
        remediation="Enable prompt injection detection to prevent adversarial input attacks",
        mitre_atlas="AML.T0051",
        nist_csf="DE.CM-4",
        nist_ai_rmf="MEASURE, MANAGE",
    )


def check_6_2_content_safety_enabled(config: dict) -> Finding:
    """MS-6.2 — Content safety classification enabled."""
    safety = config.get("safety", config.get("guardrails", config.get("content_safety", {})))
    enabled = safety.get("enabled", safety.get("content_classification", False))
    categories = safety.get("categories", safety.get("blocked_categories", []))
    return Finding(
        check_id="MS-6.2",
        title="Content safety classification",
        section="safety",
        severity="HIGH",
        status="PASS" if enabled or categories else "FAIL",
        detail=f"Content safety enabled ({len(categories)} blocked categories)"
        if enabled or categories
        else "No content safety classification configured",
        remediation="Enable content safety with blocked categories (violence, hate, self-harm, sexual)",
        mitre_atlas="AML.T0048",
        nist_csf="DE.CM-4",
        nist_ai_rmf="GOVERN, MEASURE, MANAGE",
    )


def check_6_3_model_versioning(config: dict) -> Finding:
    """MS-6.3 — Model versions tracked and auditable."""
    models = _iter_models(config) or config.get("deployments", [])
    no_version = []
    for m in models:
        version = m.get("version", m.get("model_version", m.get("tag", "")))
        if not version or version in ("latest", ""):
            no_version.append(m.get("name", m.get("model", "unknown")))
    return Finding(
        check_id="MS-6.3",
        title="Model version tracking",
        section="safety",
        severity="MEDIUM",
        status="FAIL" if no_version else "PASS",
        detail=f"{len(no_version)} models without explicit version"
        if no_version
        else "All models have explicit versions",
        remediation="Pin model versions (never use 'latest'). Enable model registry with immutable tags.",
        mitre_atlas="AML.T0010",
        nist_csf="PR.DS-6",
        nist_ai_rmf="GOVERN, MEASURE",
        resources=no_version,
    )


def check_6_4_guardrails_attached(config: dict) -> Finding:
    """MS-6.4 — Provider guardrails or content safety attached to AI endpoints."""
    endpoints = _iter_endpoints(config)
    missing_guardrails = []
    for ep in endpoints:
        safety = ep.get("guardrails", ep.get("safety", {}))
        if not safety or safety.get("enabled") is False:
            missing_guardrails.append(ep.get("name", "unknown"))
    return Finding(
        check_id="MS-6.4",
        title="Guardrails attached to AI endpoints",
        section="safety",
        severity="HIGH",
        status="FAIL" if missing_guardrails else "PASS",
        detail=f"{len(missing_guardrails)} endpoints without guardrails or content safety attachment"
        if missing_guardrails
        else "All endpoints attach guardrails or content safety layers",
        remediation="Attach Bedrock guardrails, Vertex AI safety settings, Azure AI content safety, or equivalent provider-native safety layers.",
        mitre_atlas="AML.T0048",
        nist_csf="DE.CM-4",
        nist_ai_rmf="GOVERN, MEASURE, MANAGE",
        resources=missing_guardrails,
    )


def check_6_5_ai_endpoint_audit_logging(config: dict) -> Finding:
    """MS-6.5 — AI endpoint audit logging or access logging enabled."""
    endpoints = _iter_endpoints(config)
    no_logging = []
    for ep in endpoints:
        logging_cfg = ep.get("logging", {})
        if not logging_cfg or logging_cfg.get("enabled") is False:
            no_logging.append(ep.get("name", "unknown"))
    return Finding(
        check_id="MS-6.5",
        title="Audit logging on AI endpoints",
        section="safety",
        severity="MEDIUM",
        status="FAIL" if no_logging else "PASS",
        detail=f"{len(no_logging)} endpoints without audit or access logging"
        if no_logging
        else "All endpoints have audit logging or access capture enabled",
        remediation="Enable provider-native endpoint access logging, diagnostics, or request capture on all AI endpoints.",
        mitre_atlas="AML.T0010",
        nist_csf="DE.CM-3",
        nist_ai_rmf="MEASURE, MANAGE",
        resources=no_logging,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

ALL_CHECKS = {
    "auth": [
        check_1_1_endpoint_auth_required,
        check_1_2_no_hardcoded_api_keys,
        check_1_3_rbac_model_access,
        check_1_4_workload_identity_required,
    ],
    "abuse_prevention": [check_2_1_rate_limiting_enabled, check_2_2_input_size_limits],
    "data_egress": [
        check_3_1_output_filtering,
        check_3_2_no_training_data_in_response,
        check_3_3_logging_no_pii,
    ],
    "runtime": [
        check_4_1_no_privileged_containers,
        check_4_2_read_only_rootfs,
        check_4_3_non_root_user,
    ],
    "network": [
        check_5_1_tls_enforced,
        check_5_2_no_public_endpoints,
        check_5_3_private_network_isolation,
    ],
    "safety": [
        check_6_1_prompt_injection_guard,
        check_6_2_content_safety_enabled,
        check_6_3_model_versioning,
        check_6_4_guardrails_attached,
        check_6_5_ai_endpoint_audit_logging,
    ],
}


def run_benchmark(
    config: dict, *, section: str | None = None, scan_paths: list[str] | None = None
) -> list[Finding]:
    """Run all or section-specific checks against a serving config."""
    findings: list[Finding] = []
    sections = {section: ALL_CHECKS[section]} if section and section in ALL_CHECKS else ALL_CHECKS
    for _section_name, checks in sections.items():
        for check_fn in checks:
            if check_fn == check_1_2_no_hardcoded_api_keys:
                findings.append(check_fn(config, scan_paths))
            else:
                findings.append(check_fn(config))
    return findings


def print_summary(findings: list[Finding]) -> None:
    """Print human-readable summary."""
    total = len(findings)
    passed = sum(1 for f in findings if f.status == "PASS")
    failed = sum(1 for f in findings if f.status == "FAIL")
    warned = sum(1 for f in findings if f.status == "WARN")

    print(f"\n{'=' * 60}")
    print("  Model Serving Security Benchmark — Results")
    print(f"{'=' * 60}\n")

    current_section = ""
    for f in findings:
        if f.section != current_section:
            current_section = f.section
            print(f"\n  [{current_section.upper()}]")

        icon = {"PASS": "+", "FAIL": "x", "WARN": "!", "ERROR": "?", "SKIP": "-"}[f.status]
        sev = f"[{f.severity}]"
        print(f"  [{icon}] {f.check_id} {sev:12s} {f.title}")
        if f.status in ("FAIL", "WARN"):
            print(f"      {f.detail}")
            if f.remediation:
                print(f"      FIX: {f.remediation}")

    print(f"\n  {'─' * 56}")
    print(f"  Total: {total} | Passed: {passed} | Failed: {failed} | Warnings: {warned}")
    print(f"  Pass rate: {passed / total * 100:.0f}%\n" if total else "")


def load_config(path: str) -> dict:
    """Load serving config from JSON or YAML file."""
    p = Path(path)
    if not p.exists():
        print(f"Error: Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    content = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml

            return yaml.safe_load(content) or {}
        except ImportError:
            print(
                "Error: PyYAML required for YAML configs. Install with: pip install pyyaml",
                file=sys.stderr,
            )
            sys.exit(1)
    return json.loads(content)


def main() -> None:
    parser = argparse.ArgumentParser(description="Model Serving Security Benchmark")
    parser.add_argument("config", help="Path to serving config file (JSON/YAML)")
    parser.add_argument(
        "--section", choices=list(ALL_CHECKS.keys()), help="Run specific section only"
    )
    parser.add_argument(
        "--scan-paths", nargs="*", help="Additional paths to scan for hardcoded secrets"
    )
    parser.add_argument(
        "--output", choices=["console", "json"], default="console", help="Output format"
    )
    parser.add_argument("--output-format", choices=list(OUTPUT_FORMATS), default="native")
    args = parser.parse_args()

    config = load_config(args.config)
    findings = run_benchmark(config, section=args.section, scan_paths=args.scan_paths)

    if args.output == "json":
        rendered = (
            findings_to_ocsf(
                findings,
                skill_name=SKILL_NAME,
                benchmark_name=BENCHMARK_NAME,
                provider=PROVIDER_NAME,
                frameworks=list(FRAMEWORKS),
            )
            if args.output_format == "ocsf"
            else findings_to_native(findings)
        )
        print(json.dumps(rendered, indent=2))
    else:
        print_summary(findings)

    critical_or_high_fails = sum(
        1 for f in findings if f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH")
    )
    sys.exit(1 if critical_or_high_fails else 0)


if __name__ == "__main__":
    main()
