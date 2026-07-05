"""Tests for GPU cluster security benchmark checks."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checks import (
    Finding,
    benchmark_metadata,
    check_1_1_no_privileged_gpu_pods,
    check_1_2_gpu_device_plugin,
    check_1_3_no_host_ipc,
    check_2_1_driver_version,
    check_2_2_cuda_version,
    check_3_1_infiniband_segmentation,
    check_3_2_gpu_network_policy,
    check_4_1_shm_size_limits,
    check_4_2_model_weights_encrypted,
    check_5_1_namespace_isolation,
    check_5_2_resource_quotas,
    check_6_1_dcgm_monitoring,
    check_6_2_audit_logging,
    run_benchmark,
)


class TestRuntimeIsolation:
    def test_1_1_privileged_gpu_fails(self):
        config = {
            "pods": [
                {
                    "name": "training-gpu",
                    "security_context": {"privileged": True},
                    "resources": {"limits": {"nvidia.com/gpu": 8}},
                }
            ]
        }
        f = check_1_1_no_privileged_gpu_pods(config)
        assert f.status == "FAIL"
        assert f.severity == "CRITICAL"

    def test_1_1_non_privileged_passes(self):
        config = {
            "pods": [
                {
                    "name": "training-gpu",
                    "security_context": {"privileged": False},
                    "resources": {"limits": {"nvidia.com/gpu": 8}},
                }
            ]
        }
        f = check_1_1_no_privileged_gpu_pods(config)
        assert f.status == "PASS"

    def test_1_2_dev_mount_fails(self):
        config = {
            "pods": [{"name": "gpu-pod", "volumes": [{"hostPath": {"path": "/dev/nvidia0"}}]}]
        }
        f = check_1_2_gpu_device_plugin(config)
        assert f.status == "FAIL"

    def test_1_2_no_dev_mount_passes(self):
        config = {"pods": [{"name": "gpu-pod", "volumes": [{"name": "data", "emptyDir": {}}]}]}
        f = check_1_2_gpu_device_plugin(config)
        assert f.status == "PASS"

    def test_1_3_host_ipc_fails(self):
        config = {"pods": [{"name": "nccl-pod", "spec": {"hostIPC": True}}]}
        f = check_1_3_no_host_ipc(config)
        assert f.status == "FAIL"

    def test_1_3_no_host_ipc_passes(self):
        config = {"pods": [{"name": "nccl-pod", "spec": {"hostIPC": False}}]}
        f = check_1_3_no_host_ipc(config)
        assert f.status == "PASS"


class TestDriverSecurity:
    def test_2_1_vulnerable_driver_fails(self):
        config = {"nodes": [{"name": "gpu-node-1", "driver_version": "535.129.03"}]}
        f = check_2_1_driver_version(config)
        assert f.status == "FAIL"
        assert "CVE-2024-0074" in f.resources[0]

    def test_2_1_safe_driver_passes(self):
        config = {"nodes": [{"name": "gpu-node-1", "driver_version": "550.54.14"}]}
        f = check_2_1_driver_version(config)
        assert f.status == "PASS"

    def test_2_1_no_nodes_skips(self):
        f = check_2_1_driver_version({})
        assert f.status == "SKIP"

    def test_2_2_old_cuda_fails(self):
        config = {"nodes": [{"name": "gpu-node-1", "cuda_version": "11.8"}]}
        f = check_2_2_cuda_version(config)
        assert f.status == "FAIL"

    def test_2_2_current_cuda_passes(self):
        config = {"nodes": [{"name": "gpu-node-1", "cuda_version": "12.4"}]}
        f = check_2_2_cuda_version(config)
        assert f.status == "PASS"


class TestNetworkSegmentation:
    def test_3_1_ib_segmented_passes(self):
        config = {
            "network": {
                "infiniband": {"partitions": ["tenant-a", "tenant-b"], "tenant_isolation": True}
            }
        }
        f = check_3_1_infiniband_segmentation(config)
        assert f.status == "PASS"

    def test_3_1_ib_not_segmented_fails(self):
        config = {"network": {"infiniband": {"partitions": [], "tenant_isolation": False}}}
        f = check_3_1_infiniband_segmentation(config)
        assert f.status == "FAIL"

    def test_3_1_no_ib_skips(self):
        f = check_3_1_infiniband_segmentation({})
        assert f.status == "SKIP"

    def test_3_2_no_network_policy_fails(self):
        config = {"namespaces": [{"name": "gpu-training", "network_policies": []}]}
        f = check_3_2_gpu_network_policy(config)
        assert f.status == "FAIL"

    def test_3_2_with_policy_passes(self):
        config = {
            "namespaces": [{"name": "gpu-training", "network_policies": [{"name": "default-deny"}]}]
        }
        f = check_3_2_gpu_network_policy(config)
        assert f.status == "PASS"


class TestStorage:
    def test_4_1_unlimited_shm_fails(self):
        config = {
            "pods": [
                {
                    "name": "training",
                    "volumes": [{"name": "dshm", "emptyDir": {"medium": "Memory"}}],
                }
            ]
        }
        f = check_4_1_shm_size_limits(config)
        assert f.status == "FAIL"

    def test_4_1_limited_shm_passes(self):
        config = {
            "pods": [
                {
                    "name": "training",
                    "volumes": [
                        {"name": "dshm", "emptyDir": {"medium": "Memory", "sizeLimit": "8Gi"}}
                    ],
                }
            ]
        }
        f = check_4_1_shm_size_limits(config)
        assert f.status == "PASS"

    def test_4_2_unencrypted_fails(self):
        config = {"storage": {"volumes": [{"name": "model-weights", "encrypted": False}]}}
        f = check_4_2_model_weights_encrypted(config)
        assert f.status == "FAIL"

    def test_4_2_encrypted_passes(self):
        config = {
            "storage": {
                "encryption_at_rest": True,
                "volumes": [{"name": "model-weights", "encrypted": True}],
            }
        }
        f = check_4_2_model_weights_encrypted(config)
        assert f.status == "PASS"


class TestTenantIsolation:
    def test_5_1_shared_namespace_fails(self):
        config = {"namespaces": [{"name": "gpu-shared", "shared": True}]}
        f = check_5_1_namespace_isolation(config)
        assert f.status == "FAIL"

    def test_5_1_isolated_passes(self):
        config = {"namespaces": [{"name": "tenant-a-gpu", "shared": False}]}
        f = check_5_1_namespace_isolation(config)
        assert f.status == "PASS"

    def test_5_2_no_quota_fails(self):
        config = {"namespaces": [{"name": "gpu-ns", "resource_quota": {}}]}
        f = check_5_2_resource_quotas(config)
        assert f.status == "FAIL"

    def test_5_2_with_quota_passes(self):
        config = {"namespaces": [{"name": "gpu-ns", "resource_quota": {"nvidia.com/gpu": 8}}]}
        f = check_5_2_resource_quotas(config)
        assert f.status == "PASS"


class TestObservability:
    def test_6_1_no_dcgm_fails(self):
        f = check_6_1_dcgm_monitoring({})
        assert f.status == "FAIL"

    def test_6_1_dcgm_enabled_passes(self):
        config = {"monitoring": {"dcgm": True}}
        f = check_6_1_dcgm_monitoring(config)
        assert f.status == "PASS"

    def test_6_2_no_audit_fails(self):
        f = check_6_2_audit_logging({})
        assert f.status == "FAIL"

    def test_6_2_audit_enabled_passes(self):
        config = {"logging": {"gpu_workloads": True}}
        f = check_6_2_audit_logging(config)
        assert f.status == "PASS"


class TestBenchmarkRunner:
    def test_run_all(self):
        config = {
            "pods": [{"name": "gpu", "security_context": {}, "volumes": []}],
            "nodes": [{"name": "n1", "driver_version": "550.54.14", "cuda_version": "12.4"}],
            "namespaces": [
                {
                    "name": "gpu-ns",
                    "network_policies": [{"name": "deny"}],
                    "resource_quota": {"nvidia.com/gpu": 4},
                }
            ],
        }
        findings = run_benchmark(config)
        assert len(findings) == 13
        assert all(isinstance(f, Finding) for f in findings)

    def test_run_single_section(self):
        config = {"pods": [{"name": "gpu", "security_context": {"privileged": False}}]}
        findings = run_benchmark(config, section="runtime")
        assert len(findings) == 3

    def test_findings_have_compliance(self):
        config = {
            "pods": [
                {
                    "name": "gpu",
                    "security_context": {"privileged": True},
                    "resources": {"limits": {"nvidia.com/gpu": 1}},
                }
            ]
        }
        findings = run_benchmark(config, section="runtime")
        for f in findings:
            assert f.nist_csf, f"{f.check_id} missing NIST CSF"

    def test_benchmark_metadata_declares_ai_frameworks(self):
        metadata = benchmark_metadata()
        assert "MITRE ATLAS" in metadata["frameworks"]
        assert "NIST AI RMF 1.0" in metadata["frameworks"]
        assert metadata["check_count"] == 13
        assert metadata["sections"]["tenant"] == 2
        assert metadata["ai_framework_focus"]["tenant"]["mitre_atlas"]
