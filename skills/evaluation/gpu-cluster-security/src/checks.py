"""GPU Cluster Security Benchmark — audit GPU infrastructure security posture.

Checks the security of GPU compute clusters including:
- Container runtime isolation (no --privileged for GPU workloads)
- GPU driver CVE exposure
- InfiniBand / RDMA network segmentation
- CUDA version compliance
- Shared memory and /dev/shm exposure
- Model weight encryption at rest
- Tenant namespace isolation
- DCGM/GPU metrics for anomaly baselines
- Device plugin security

Supports: Kubernetes GPU clusters, Docker GPU workloads, bare-metal GPU nodes.
Input: cluster config JSON/YAML or Kubernetes resource dumps.

Read-only — no write permissions required. Safe to run in production.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.evaluation_ocsf import findings_to_native, findings_to_ocsf  # noqa: E402

SKILL_NAME = "gpu-cluster-security"
BENCHMARK_NAME = "GPU Cluster Security Benchmark"
PROVIDER_NAME = "Multi"
OUTPUT_FORMATS = ("native", "ocsf")

FRAMEWORKS = (
    "MITRE ATT&CK v14",
    "MITRE ATLAS",
    "NIST CSF 2.0",
    "NIST AI RMF 1.0",
    "CIS Controls v8",
    "CIS Kubernetes Benchmark",
)

PROVIDERS = ("aws", "azure", "gcp", "kubernetes", "containers", "multi")
ASSET_CLASSES = ("gpu-fleets", "clusters", "containers", "runtime", "tenancy")

AI_FRAMEWORK_FOCUS = {
    "runtime": {
        "mitre_atlas": "AI platform runtime hardening for GPU workloads",
        "nist_ai_rmf": "MANAGE, GOVERN",
    },
    "driver": {
        "mitre_atlas": "GPU compute integrity and vulnerable dependency exposure",
        "nist_ai_rmf": "MEASURE, MANAGE",
    },
    "network": {
        "mitre_atlas": "Tenant boundary protection for AI infrastructure traffic",
        "nist_ai_rmf": "MAP, MANAGE",
    },
    "storage": {
        "mitre_atlas": "Model and artifact protection against unauthorized access",
        "nist_ai_rmf": "MAP, MANAGE",
    },
    "tenant": {
        "mitre_atlas": "GPU tenancy controls against account and cost abuse",
        "nist_ai_rmf": "GOVERN, MANAGE",
    },
    "observability": {
        "mitre_atlas": "Detection and investigation support for AI infrastructure misuse",
        "nist_ai_rmf": "MEASURE, MANAGE",
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
    mitre_attack: str = ""
    nist_csf: str = ""
    cis_control: str = ""
    resources: list[str] = field(default_factory=list)


def benchmark_metadata() -> dict[str, object]:
    """Return machine-readable benchmark metadata for wrappers and docs."""
    return {
        "frameworks": list(FRAMEWORKS),
        "providers": list(PROVIDERS),
        "asset_classes": list(ASSET_CLASSES),
        "ai_framework_focus": AI_FRAMEWORK_FOCUS,
        "check_count": sum(len(checks) for checks in ALL_CHECKS.values()),
        "sections": {name: len(checks) for name, checks in ALL_CHECKS.items()},
    }


# ═══════════════════════════════════════════════════════════════════════════
# Section 1 — Container Runtime Isolation
# ═══════════════════════════════════════════════════════════════════════════


def check_1_1_no_privileged_gpu_pods(config: dict) -> Finding:
    """GPU-1.1 — GPU workloads must not run in privileged mode."""
    pods = config.get("pods", config.get("containers", config.get("workloads", [])))
    privileged = []
    for pod in pods:
        sec = pod.get("security_context", pod.get("securityContext", {}))
        gpu_req = pod.get("resources", {}).get("limits", {}).get("nvidia.com/gpu", 0)
        if sec.get("privileged", False) and (gpu_req or "gpu" in pod.get("name", "").lower()):
            privileged.append(pod.get("name", "unknown"))
    return Finding(
        check_id="GPU-1.1",
        title="No privileged GPU containers",
        section="runtime",
        severity="CRITICAL",
        status="FAIL" if privileged else "PASS",
        detail=f"{len(privileged)} privileged GPU containers"
        if privileged
        else "No privileged GPU containers",
        remediation="Remove privileged: true. GPU access should use device plugin (nvidia.com/gpu resource limits) not --privileged.",
        mitre_attack="T1611",
        nist_csf="PR.AC-4",
        cis_control="5.2.1",
        resources=privileged,
    )


def check_1_2_gpu_device_plugin(config: dict) -> Finding:
    """GPU-1.2 — GPU access via device plugin, not /dev bind mounts."""
    pods = config.get("pods", config.get("containers", []))
    dev_mounts = []
    for pod in pods:
        volumes = pod.get("volumes", [])
        volume_mounts = pod.get("volume_mounts", pod.get("volumeMounts", []))
        for v in volumes + volume_mounts:
            path = v.get("hostPath", v.get("host_path", v.get("mountPath", "")))
            if isinstance(path, dict):
                path = path.get("path", "")
            if "/dev/nvidia" in str(path) or "/dev/dri" in str(path):
                dev_mounts.append(f"{pod.get('name', 'unknown')}: {path}")
    return Finding(
        check_id="GPU-1.2",
        title="GPU via device plugin, not /dev mounts",
        section="runtime",
        severity="HIGH",
        status="FAIL" if dev_mounts else "PASS",
        detail=f"{len(dev_mounts)} pods with direct /dev/nvidia mounts"
        if dev_mounts
        else "All GPU access via device plugin",
        remediation="Use nvidia.com/gpu resource limits instead of hostPath /dev/nvidia* mounts",
        mitre_attack="T1611",
        nist_csf="PR.AC-4",
        cis_control="5.2.4",
        resources=dev_mounts,
    )


def check_1_3_no_host_ipc(config: dict) -> Finding:
    """GPU-1.3 — GPU pods do not share host IPC namespace."""
    pods = config.get("pods", config.get("containers", []))
    host_ipc = []
    for pod in pods:
        spec = pod.get("spec", pod)
        if spec.get("hostIPC", spec.get("host_ipc", False)):
            host_ipc.append(pod.get("name", "unknown"))
    return Finding(
        check_id="GPU-1.3",
        title="No host IPC namespace sharing",
        section="runtime",
        severity="HIGH",
        status="FAIL" if host_ipc else "PASS",
        detail=f"{len(host_ipc)} pods with hostIPC: true" if host_ipc else "No pods share host IPC",
        remediation="Set hostIPC: false. NCCL can use socket-based transport instead of shared memory for multi-GPU.",
        mitre_attack="T1610",
        nist_csf="PR.AC-4",
        resources=host_ipc,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 2 — GPU Driver & CUDA Security
# ═══════════════════════════════════════════════════════════════════════════


# Known vulnerable NVIDIA driver versions (critical CVEs)
_VULNERABLE_DRIVERS: dict[str, str] = {
    "535.129.03": "CVE-2024-0074 (code execution)",
    "535.104.05": "CVE-2024-0074 (code execution)",
    "530.30.02": "CVE-2023-31018 (DoS)",
    "525.60.13": "CVE-2023-25516 (info disclosure)",
    "515.76": "CVE-2022-42263 (buffer overflow)",
    "510.47.03": "CVE-2022-28183 (OOB read)",
}

# Minimum recommended CUDA versions
_MIN_CUDA_VERSION = "12.2"


def check_2_1_driver_version(config: dict) -> Finding:
    """GPU-2.1 — GPU driver version not in known-vulnerable list."""
    nodes = config.get("nodes", config.get("gpu_nodes", []))
    vulnerable = []
    for node in nodes:
        driver = node.get("driver_version", node.get("nvidia_driver", ""))
        if driver in _VULNERABLE_DRIVERS:
            vulnerable.append(
                f"{node.get('name', 'unknown')}: {driver} ({_VULNERABLE_DRIVERS[driver]})"
            )
    if not nodes:
        return Finding(
            check_id="GPU-2.1",
            title="GPU driver not vulnerable",
            section="driver",
            severity="CRITICAL",
            status="SKIP",
            detail="No GPU nodes in config",
            nist_csf="ID.RA-1",
        )
    return Finding(
        check_id="GPU-2.1",
        title="GPU driver not vulnerable",
        section="driver",
        severity="CRITICAL",
        status="FAIL" if vulnerable else "PASS",
        detail=f"{len(vulnerable)} nodes with vulnerable drivers"
        if vulnerable
        else "All drivers pass CVE check",
        remediation="Upgrade NVIDIA drivers to latest stable release. See https://nvidia.com/security",
        mitre_attack="T1203",
        nist_csf="ID.RA-1",
        cis_control="7.4",
        resources=vulnerable,
    )


def check_2_2_cuda_version(config: dict) -> Finding:
    """GPU-2.2 — CUDA toolkit meets minimum version."""
    nodes = config.get("nodes", config.get("gpu_nodes", []))
    old_cuda = []
    for node in nodes:
        cuda = node.get("cuda_version", node.get("cuda", ""))
        if cuda and cuda < _MIN_CUDA_VERSION:
            old_cuda.append(f"{node.get('name', 'unknown')}: CUDA {cuda}")
    if not nodes:
        return Finding(
            check_id="GPU-2.2",
            title=f"CUDA >= {_MIN_CUDA_VERSION}",
            section="driver",
            severity="MEDIUM",
            status="SKIP",
            detail="No GPU nodes in config",
        )
    return Finding(
        check_id="GPU-2.2",
        title=f"CUDA >= {_MIN_CUDA_VERSION}",
        section="driver",
        severity="MEDIUM",
        status="FAIL" if old_cuda else "PASS",
        detail=f"{len(old_cuda)} nodes with old CUDA"
        if old_cuda
        else f"All nodes meet CUDA {_MIN_CUDA_VERSION}+",
        remediation=f"Upgrade CUDA toolkit to {_MIN_CUDA_VERSION}+",
        nist_csf="PR.IP-12",
        cis_control="7.4",
        resources=old_cuda,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 3 — Network Segmentation
# ═══════════════════════════════════════════════════════════════════════════


def check_3_1_infiniband_segmentation(config: dict) -> Finding:
    """GPU-3.1 — InfiniBand/RDMA traffic segmented by tenant."""
    network = config.get("network", config.get("networking", {}))
    ib_config = network.get("infiniband", network.get("rdma", {}))
    if not ib_config:
        return Finding(
            check_id="GPU-3.1",
            title="InfiniBand tenant segmentation",
            section="network",
            severity="HIGH",
            status="SKIP",
            detail="No InfiniBand configuration found",
        )
    partitions = ib_config.get("partitions", ib_config.get("pkeys", []))
    tenant_isolated = ib_config.get("tenant_isolation", len(partitions) > 1)
    return Finding(
        check_id="GPU-3.1",
        title="InfiniBand tenant segmentation",
        section="network",
        severity="HIGH",
        status="PASS" if tenant_isolated else "FAIL",
        detail=f"{len(partitions)} IB partitions configured"
        if tenant_isolated
        else "InfiniBand not segmented by tenant",
        remediation="Configure IB partition keys (pkeys) per tenant namespace to isolate RDMA traffic",
        mitre_attack="T1599",
        nist_csf="PR.AC-5",
        resources=[f"partition: {p}" for p in partitions],
    )


def check_3_2_gpu_network_policy(config: dict) -> Finding:
    """GPU-3.2 — Kubernetes NetworkPolicy applied to GPU namespaces."""
    namespaces = config.get("namespaces", config.get("gpu_namespaces", []))
    no_policy = []
    for ns in namespaces:
        policies = ns.get("network_policies", ns.get("networkPolicies", []))
        if not policies:
            no_policy.append(ns.get("name", "unknown"))
    if not namespaces:
        return Finding(
            check_id="GPU-3.2",
            title="NetworkPolicy on GPU namespaces",
            section="network",
            severity="HIGH",
            status="SKIP",
            detail="No GPU namespaces in config",
        )
    return Finding(
        check_id="GPU-3.2",
        title="NetworkPolicy on GPU namespaces",
        section="network",
        severity="HIGH",
        status="FAIL" if no_policy else "PASS",
        detail=f"{len(no_policy)} GPU namespaces without NetworkPolicy"
        if no_policy
        else "All GPU namespaces have NetworkPolicy",
        remediation="Apply default-deny NetworkPolicy to GPU namespaces. Allow only required ingress/egress.",
        mitre_attack="T1046",
        nist_csf="PR.AC-5",
        cis_control="13.1",
        resources=no_policy,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 4 — Shared Memory & Storage
# ═══════════════════════════════════════════════════════════════════════════


def check_4_1_shm_size_limits(config: dict) -> Finding:
    """GPU-4.1 — Shared memory (/dev/shm) has size limits."""
    pods = config.get("pods", config.get("containers", []))
    unlimited_shm = []
    for pod in pods:
        volumes = pod.get("volumes", [])
        for v in volumes:
            if v.get("name") == "dshm" or v.get("emptyDir", {}).get("medium") == "Memory":
                size = v.get("emptyDir", {}).get("sizeLimit", "")
                if not size:
                    unlimited_shm.append(pod.get("name", "unknown"))
    return Finding(
        check_id="GPU-4.1",
        title="Shared memory size limits",
        section="storage",
        severity="MEDIUM",
        status="FAIL" if unlimited_shm else "PASS",
        detail=f"{len(unlimited_shm)} pods with unlimited /dev/shm"
        if unlimited_shm
        else "All /dev/shm volumes have size limits",
        remediation="Set sizeLimit on emptyDir medium: Memory volumes (e.g., 8Gi for training, 2Gi for inference)",
        nist_csf="PR.DS-4",
        resources=unlimited_shm,
    )


def check_4_2_model_weights_encrypted(config: dict) -> Finding:
    """GPU-4.2 — Model weight storage encrypted at rest."""
    storage = config.get("storage", config.get("model_storage", {}))
    encryption = storage.get(
        "encryption_at_rest", storage.get("encrypted", storage.get("kms", False))
    )
    volumes = storage.get("volumes", storage.get("persistent_volumes", []))
    unencrypted = []
    for v in volumes:
        if not v.get("encrypted", v.get("encryption", True)):
            unencrypted.append(v.get("name", "unknown"))
    if not encryption and not volumes:
        return Finding(
            check_id="GPU-4.2",
            title="Model weights encrypted at rest",
            section="storage",
            severity="HIGH",
            status="WARN",
            detail="No model storage configuration found",
            remediation="Enable encryption at rest for all model weight storage (EBS encryption, GCE CMEK, Azure SSE)",
            nist_csf="PR.DS-1",
        )
    return Finding(
        check_id="GPU-4.2",
        title="Model weights encrypted at rest",
        section="storage",
        severity="HIGH",
        status="FAIL" if unencrypted else "PASS",
        detail=f"{len(unencrypted)} unencrypted model volumes"
        if unencrypted
        else "All model storage encrypted",
        remediation="Enable KMS/CMEK encryption on all persistent volumes storing model weights",
        mitre_attack="T1530",
        nist_csf="PR.DS-1",
        cis_control="3.11",
        resources=unencrypted,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 5 — Tenant Isolation
# ═══════════════════════════════════════════════════════════════════════════


def check_5_1_namespace_isolation(config: dict) -> Finding:
    """GPU-5.1 — GPU workloads isolated by namespace per tenant."""
    namespaces = config.get("namespaces", config.get("gpu_namespaces", []))
    shared = []
    for ns in namespaces:
        tenants = ns.get("tenants", ns.get("labels", {}).get("tenants", []))
        if isinstance(tenants, list) and len(tenants) > 1:
            shared.append(f"{ns.get('name', 'unknown')}: {len(tenants)} tenants")
        elif ns.get("shared", False):
            shared.append(f"{ns.get('name', 'unknown')}: marked shared")
    return Finding(
        check_id="GPU-5.1",
        title="Namespace isolation per tenant",
        section="tenant",
        severity="HIGH",
        status="FAIL" if shared else "PASS",
        detail=f"{len(shared)} shared GPU namespaces"
        if shared
        else "GPU namespaces are tenant-isolated",
        remediation="Assign dedicated namespaces per tenant. Use ResourceQuota to cap GPU allocation per namespace.",
        mitre_attack="T1078",
        nist_csf="PR.AC-4",
        resources=shared,
    )


def check_5_2_resource_quotas(config: dict) -> Finding:
    """GPU-5.2 — GPU resource quotas enforced per namespace."""
    namespaces = config.get("namespaces", config.get("gpu_namespaces", []))
    no_quota = []
    for ns in namespaces:
        quota = ns.get("resource_quota", ns.get("resourceQuota", {}))
        gpu_limit = quota.get("nvidia.com/gpu", quota.get("limits", {}).get("nvidia.com/gpu"))
        if not gpu_limit:
            no_quota.append(ns.get("name", "unknown"))
    if not namespaces:
        return Finding(
            check_id="GPU-5.2",
            title="GPU resource quotas",
            section="tenant",
            severity="MEDIUM",
            status="SKIP",
            detail="No GPU namespaces in config",
        )
    return Finding(
        check_id="GPU-5.2",
        title="GPU resource quotas",
        section="tenant",
        severity="MEDIUM",
        status="FAIL" if no_quota else "PASS",
        detail=f"{len(no_quota)} namespaces without GPU quota"
        if no_quota
        else "All namespaces have GPU quota",
        remediation="Set ResourceQuota with nvidia.com/gpu limits per namespace",
        nist_csf="PR.DS-4",
        cis_control="13.6",
        resources=no_quota,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 6 — Observability & Anomaly Detection
# ═══════════════════════════════════════════════════════════════════════════


def check_6_1_dcgm_monitoring(config: dict) -> Finding:
    """GPU-6.1 — DCGM or equivalent GPU monitoring enabled."""
    monitoring = config.get("monitoring", config.get("observability", {}))
    dcgm = monitoring.get(
        "dcgm", monitoring.get("gpu_metrics", monitoring.get("nvidia_dcgm", False))
    )
    return Finding(
        check_id="GPU-6.1",
        title="GPU monitoring (DCGM) enabled",
        section="observability",
        severity="MEDIUM",
        status="PASS" if dcgm else "FAIL",
        detail="DCGM/GPU monitoring enabled" if dcgm else "No GPU monitoring configured",
        remediation="Deploy NVIDIA DCGM Exporter for Prometheus. Monitor: GPU utilization, memory, temperature, ECC errors.",
        nist_csf="DE.CM-1",
        cis_control="8.5",
    )


def check_6_2_audit_logging(config: dict) -> Finding:
    """GPU-6.2 — GPU workload audit logging enabled."""
    logging_cfg = config.get("logging", config.get("audit", {}))
    gpu_audit = logging_cfg.get("gpu_workloads", logging_cfg.get("enabled", False))
    return Finding(
        check_id="GPU-6.2",
        title="GPU workload audit logging",
        section="observability",
        severity="HIGH",
        status="PASS" if gpu_audit else "FAIL",
        detail="GPU audit logging enabled" if gpu_audit else "No GPU workload audit logging",
        remediation="Enable Kubernetes audit logging for GPU namespace operations (create, delete, exec)",
        mitre_attack="T1562.002",
        nist_csf="DE.AE-3",
        cis_control="8.2",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

ALL_CHECKS = {
    "runtime": [
        check_1_1_no_privileged_gpu_pods,
        check_1_2_gpu_device_plugin,
        check_1_3_no_host_ipc,
    ],
    "driver": [check_2_1_driver_version, check_2_2_cuda_version],
    "network": [check_3_1_infiniband_segmentation, check_3_2_gpu_network_policy],
    "storage": [check_4_1_shm_size_limits, check_4_2_model_weights_encrypted],
    "tenant": [check_5_1_namespace_isolation, check_5_2_resource_quotas],
    "observability": [check_6_1_dcgm_monitoring, check_6_2_audit_logging],
}


def run_benchmark(config: dict, *, section: str | None = None) -> list[Finding]:
    """Run all or section-specific GPU security checks."""
    findings: list[Finding] = []
    sections = {section: ALL_CHECKS[section]} if section and section in ALL_CHECKS else ALL_CHECKS
    for _section_name, checks in sections.items():
        for check_fn in checks:
            findings.append(check_fn(config))
    return findings


def print_summary(findings: list[Finding]) -> None:
    """Print human-readable summary."""
    total = len(findings)
    passed = sum(1 for f in findings if f.status == "PASS")
    failed = sum(1 for f in findings if f.status == "FAIL")
    skipped = sum(1 for f in findings if f.status == "SKIP")

    print(f"\n{'=' * 60}")
    print("  GPU Cluster Security Benchmark — Results")
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
    print(f"  Total: {total} | Passed: {passed} | Failed: {failed} | Skipped: {skipped}")
    print(f"  Pass rate: {passed / max(total - skipped, 1) * 100:.0f}%\n")


def load_config(path: str) -> dict:
    """Load cluster config from JSON or YAML."""
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
            print("Error: PyYAML required for YAML configs", file=sys.stderr)
            sys.exit(1)
    return json.loads(content)


def main() -> None:
    parser = argparse.ArgumentParser(description="GPU Cluster Security Benchmark")
    parser.add_argument("config", help="Path to cluster config file (JSON/YAML)")
    parser.add_argument(
        "--section", choices=list(ALL_CHECKS.keys()), help="Run specific section only"
    )
    parser.add_argument(
        "--output", choices=["console", "json"], default="console", help="Output format"
    )
    parser.add_argument("--output-format", choices=list(OUTPUT_FORMATS), default="native")
    args = parser.parse_args()

    config = load_config(args.config)
    findings = run_benchmark(config, section=args.section)

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
