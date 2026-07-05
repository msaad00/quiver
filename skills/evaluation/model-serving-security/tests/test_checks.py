"""Tests for model serving security benchmark checks."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checks import (
    BENCHMARK_NAME,
    PROVIDER_NAME,
    SKILL_NAME,
    Finding,
    benchmark_metadata,
    check_1_1_endpoint_auth_required,
    check_1_2_no_hardcoded_api_keys,
    check_1_3_rbac_model_access,
    check_1_4_workload_identity_required,
    check_2_1_rate_limiting_enabled,
    check_2_2_input_size_limits,
    check_3_1_output_filtering,
    check_3_3_logging_no_pii,
    check_4_1_no_privileged_containers,
    check_4_2_read_only_rootfs,
    check_4_3_non_root_user,
    check_5_1_tls_enforced,
    check_5_2_no_public_endpoints,
    check_5_3_private_network_isolation,
    check_6_1_prompt_injection_guard,
    check_6_2_content_safety_enabled,
    check_6_3_model_versioning,
    check_6_4_guardrails_attached,
    check_6_5_ai_endpoint_audit_logging,
    findings_to_ocsf,
    run_benchmark,
)

# ═══════════════════════════════════════════════════════════════════════════
# Auth checks
# ═══════════════════════════════════════════════════════════════════════════


class TestAuthChecks:
    def test_1_1_no_auth_fails(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "none"}}]}
        f = check_1_1_endpoint_auth_required(config)
        assert f.status == "FAIL"
        assert f.severity == "CRITICAL"

    def test_1_1_with_auth_passes(self):
        config = {
            "endpoints": [{"name": "inference", "auth": {"type": "api_key", "enabled": True}}]
        }
        f = check_1_1_endpoint_auth_required(config)
        assert f.status == "PASS"

    def test_1_1_empty_endpoints_passes(self):
        f = check_1_1_endpoint_auth_required({"endpoints": []})
        assert f.status == "PASS"

    def test_1_2_hardcoded_key_fails(self):
        config = {"endpoints": [{"api_key": "sk-1234567890abcdefghij1234567890abcdefghij"}]}
        f = check_1_2_no_hardcoded_api_keys(config)
        assert f.status == "FAIL"

    def test_1_2_clean_config_passes(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "env_ref"}}]}
        f = check_1_2_no_hardcoded_api_keys(config)
        assert f.status == "PASS"

    def test_1_3_rbac_passes(self):
        config = {
            "endpoints": [
                {"name": "inference", "auth": {"type": "oauth2", "roles": ["admin", "user"]}}
            ]
        }
        f = check_1_3_rbac_model_access(config)
        assert f.status == "PASS"

    def test_1_3_no_rbac_fails(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "api_key"}}]}
        f = check_1_3_rbac_model_access(config)
        assert f.status == "FAIL"

    def test_1_4_workload_identity_fails(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "oauth2"}}]}
        f = check_1_4_workload_identity_required(config)
        assert f.status == "FAIL"

    def test_1_4_sagemaker_execution_role_passes(self):
        config = {
            "aws": {
                "sagemaker": {
                    "endpoints": [
                        {
                            "EndpointName": "fraud",
                            "ExecutionRoleArn": "arn:aws:iam::123:role/sagemaker-runtime",
                        }
                    ]
                }
            }
        }
        f = check_1_4_workload_identity_required(config)
        assert f.status == "PASS"
        assert f.nist_ai_rmf == "GOVERN, MANAGE"


class TestOcsfProjection:
    def test_findings_can_render_as_compliance_findings(self):
        finding = Finding(
            check_id="MOD-1.1",
            title="Endpoint authentication required",
            section="auth",
            severity="CRITICAL",
            status="FAIL",
            detail="Public model endpoint has no authn control",
            remediation="Require IAM, OAuth, or workload identity",
            mitre_atlas="AML.TA0003",
            nist_csf="PR.AC-1",
            nist_ai_rmf="GOVERN",
            resources=["inference-endpoint"],
        )

        rendered = findings_to_ocsf(
            [finding],
            skill_name=SKILL_NAME,
            benchmark_name=BENCHMARK_NAME,
            provider=PROVIDER_NAME,
            frameworks=list(benchmark_metadata()["frameworks"]),
        )

        assert rendered[0]["class_uid"] == 2003
        assert rendered[0]["finding_info"]["types"] == ["MOD-1.1"]
        assert rendered[0]["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert "GOVERN" in rendered[0]["compliance"]["requirements"]


# ═══════════════════════════════════════════════════════════════════════════
# Abuse prevention
# ═══════════════════════════════════════════════════════════════════════════


class TestAbusePrevention:
    def test_2_1_rate_limit_fails(self):
        config = {"endpoints": [{"name": "inference", "rate_limit": {"enabled": False}}]}
        f = check_2_1_rate_limiting_enabled(config)
        assert f.status == "FAIL"

    def test_2_1_rate_limit_passes(self):
        config = {"endpoints": [{"name": "inference", "rate_limit": {"rpm": 100}}]}
        f = check_2_1_rate_limiting_enabled(config)
        assert f.status == "PASS"

    def test_2_2_no_limits_fails(self):
        config = {"endpoints": [{"name": "inference", "limits": {}}]}
        f = check_2_2_input_size_limits(config)
        assert f.status == "FAIL"

    def test_2_2_with_limits_passes(self):
        config = {"endpoints": [{"name": "inference", "limits": {"max_tokens": 4096}}]}
        f = check_2_2_input_size_limits(config)
        assert f.status == "PASS"


# ═══════════════════════════════════════════════════════════════════════════
# Data egress
# ═══════════════════════════════════════════════════════════════════════════


class TestDataEgress:
    def test_3_1_no_filter_fails(self):
        f = check_3_1_output_filtering({})
        assert f.status == "FAIL"

    def test_3_1_filter_enabled_passes(self):
        config = {"safety": {"output_filter": True}}
        f = check_3_1_output_filtering(config)
        assert f.status == "PASS"

    def test_3_3_logging_no_redaction_fails(self):
        config = {"logging": {"log_requests": True, "redact_pii": False}}
        f = check_3_3_logging_no_pii(config)
        assert f.status == "FAIL"

    def test_3_3_logging_with_redaction_passes(self):
        config = {"logging": {"log_requests": True, "redact_pii": True}}
        f = check_3_3_logging_no_pii(config)
        assert f.status == "PASS"


# ═══════════════════════════════════════════════════════════════════════════
# Runtime
# ═══════════════════════════════════════════════════════════════════════════


class TestRuntime:
    def test_4_1_privileged_fails(self):
        config = {"containers": [{"name": "model", "security_context": {"privileged": True}}]}
        f = check_4_1_no_privileged_containers(config)
        assert f.status == "FAIL"
        assert f.severity == "CRITICAL"

    def test_4_1_not_privileged_passes(self):
        config = {"containers": [{"name": "model", "security_context": {"privileged": False}}]}
        f = check_4_1_no_privileged_containers(config)
        assert f.status == "PASS"

    def test_4_2_writable_rootfs_fails(self):
        config = {"containers": [{"name": "model", "security_context": {}}]}
        f = check_4_2_read_only_rootfs(config)
        assert f.status == "FAIL"

    def test_4_3_root_user_fails(self):
        config = {"containers": [{"name": "model", "security_context": {"runAsUser": 0}}]}
        f = check_4_3_non_root_user(config)
        assert f.status == "FAIL"

    def test_4_3_non_root_passes(self):
        config = {
            "containers": [
                {"name": "model", "security_context": {"runAsNonRoot": True, "runAsUser": 1000}}
            ]
        }
        f = check_4_3_non_root_user(config)
        assert f.status == "PASS"


# ═══════════════════════════════════════════════════════════════════════════
# Network
# ═══════════════════════════════════════════════════════════════════════════


class TestNetwork:
    def test_5_1_http_fails(self):
        config = {"endpoints": [{"name": "inference", "url": "http://model.internal:8080"}]}
        f = check_5_1_tls_enforced(config)
        assert f.status == "FAIL"

    def test_5_1_https_passes(self):
        config = {"endpoints": [{"name": "inference", "url": "https://model.internal:8443"}]}
        f = check_5_1_tls_enforced(config)
        assert f.status == "PASS"

    def test_5_2_public_fails(self):
        config = {"endpoints": [{"name": "inference", "visibility": "public"}]}
        f = check_5_2_no_public_endpoints(config)
        assert f.status == "FAIL"

    def test_5_3_private_network_isolation_fails(self):
        config = {"endpoints": [{"name": "inference", "network": {"public": False}}]}
        f = check_5_3_private_network_isolation(config)
        assert f.status == "FAIL"

    def test_5_3_vertex_private_service_connect_passes(self):
        config = {
            "gcp": {
                "vertex_ai": {
                    "endpoints": [
                        {
                            "name": "projects/p/locations/us/endpoints/1",
                            "displayName": "fraud-endpoint",
                            "serviceAccount": "svc@example.iam.gserviceaccount.com",
                            "privateServiceConnectConfig": {"enablePrivateServiceConnect": True},
                        }
                    ]
                }
            }
        }
        f = check_5_3_private_network_isolation(config)
        assert f.status == "PASS"


# ═══════════════════════════════════════════════════════════════════════════
# Safety
# ═══════════════════════════════════════════════════════════════════════════


class TestSafety:
    def test_6_1_no_injection_guard_fails(self):
        f = check_6_1_prompt_injection_guard({})
        assert f.status == "FAIL"

    def test_6_1_injection_guard_passes(self):
        config = {"safety": {"prompt_injection": True}}
        f = check_6_1_prompt_injection_guard(config)
        assert f.status == "PASS"

    def test_6_2_no_content_safety_fails(self):
        f = check_6_2_content_safety_enabled({})
        assert f.status == "FAIL"

    def test_6_3_latest_tag_fails(self):
        config = {"models": [{"name": "claude", "version": "latest"}]}
        f = check_6_3_model_versioning(config)
        assert f.status == "FAIL"

    def test_6_3_pinned_version_passes(self):
        config = {"models": [{"name": "claude", "version": "3.5-sonnet-20241022"}]}
        f = check_6_3_model_versioning(config)
        assert f.status == "PASS"

    def test_6_4_guardrails_attached_fails(self):
        config = {"endpoints": [{"name": "inference", "guardrails": {"enabled": False}}]}
        f = check_6_4_guardrails_attached(config)
        assert f.status == "FAIL"

    def test_benchmark_metadata_declares_ai_rmf_scope(self):
        metadata = benchmark_metadata()
        assert "NIST AI RMF 1.0" in metadata["frameworks"]
        assert metadata["ai_framework_focus"]["safety"]["nist_ai_rmf"] == "GOVERN, MEASURE, MANAGE"

    def test_6_4_azure_content_safety_passes(self):
        config = {
            "azure": {
                "ai_foundry": {
                    "deployments": [
                        {
                            "name": "chat-prod",
                            "content_safety": True,
                            "logging_enabled": True,
                            "identity": {"type": "SystemAssigned"},
                            "private_endpoint": True,
                        }
                    ]
                }
            }
        }
        f = check_6_4_guardrails_attached(config)
        assert f.status == "PASS"

    def test_6_5_ai_endpoint_audit_logging_fails(self):
        config = {"endpoints": [{"name": "inference", "logging": {"enabled": False}}]}
        f = check_6_5_ai_endpoint_audit_logging(config)
        assert f.status == "FAIL"

    def test_6_5_ai_endpoint_audit_logging_passes(self):
        config = {
            "aws": {
                "sagemaker": {
                    "endpoints": [
                        {
                            "EndpointName": "fraud",
                            "DataCaptureConfig": {"EnableCapture": True},
                            "ExecutionRoleArn": "arn:aws:iam::123:role/sagemaker-runtime",
                            "VpcConfig": {"Subnets": ["subnet-1"]},
                        }
                    ]
                }
            }
        }
        f = check_6_5_ai_endpoint_audit_logging(config)
        assert f.status == "PASS"


# ═══════════════════════════════════════════════════════════════════════════
# Integration
# ═══════════════════════════════════════════════════════════════════════════


class TestBenchmarkRunner:
    def test_run_all_sections(self):
        config = {
            "endpoints": [
                {
                    "name": "inference",
                    "auth": {"type": "api_key", "identity": "runtime-role", "roles": ["user"]},
                    "url": "https://model:8443",
                    "network": {"vpc": True},
                    "guardrails": {"enabled": True},
                    "logging": {"enabled": True},
                }
            ],
            "containers": [
                {
                    "name": "model",
                    "security_context": {"runAsNonRoot": True, "readOnlyRootFilesystem": True},
                }
            ],
        }
        findings = run_benchmark(config)
        assert len(findings) == 20  # All 20 checks
        assert all(isinstance(f, Finding) for f in findings)

    def test_run_single_section(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "api_key"}}]}
        findings = run_benchmark(config, section="auth")
        assert len(findings) == 4  # 4 auth checks

    def test_finding_has_compliance_mappings(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "none"}}]}
        findings = run_benchmark(config, section="auth")
        for f in findings:
            assert f.nist_csf, f"Check {f.check_id} missing NIST CSF mapping"
