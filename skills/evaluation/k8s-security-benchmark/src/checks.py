"""Kubernetes Security Benchmark — audit K8s cluster and workload security.

Checks pod security, RBAC hygiene, network policies, secrets management,
admission control, and API server configuration. Works with exported
Kubernetes resource JSON/YAML or live kubectl access.

Read-only — no write permissions. Safe to run in production.
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
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "k8s-security-benchmark"
BENCHMARK_NAME = "Kubernetes Security Benchmark"
PROVIDER_NAME = "Kubernetes"
OUTPUT_FORMATS = ("native", "ocsf")


@dataclass
class Finding:
    check_id: str
    title: str
    section: str
    severity: str
    status: str
    detail: str = ""
    remediation: str = ""
    cis_k8s: str = ""
    nist_csf: str = ""
    resources: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Resilience helpers — survive None / wrong-type fields without raising.
# ---------------------------------------------------------------------------


def _safe_dict(value: object) -> dict:
    """Coerce a value to a dict; treat None/wrong-type as empty."""
    return value if isinstance(value, dict) else {}


def _safe_list(value: object) -> list:
    """Coerce a value to a list; treat None/wrong-type as empty."""
    return value if isinstance(value, list) else []


def _safe_pods(config: object, *, check_id: str) -> list[dict]:
    """Return the pod list, surviving non-dict configs and non-list pods fields.

    Emits a stderr telemetry record when the input shape forces a skip.
    """
    if not isinstance(config, dict):
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="check_skipped",
            message=f"{check_id}: config is not a dict (got {type(config).__name__})",
            check_id=check_id,
        )
        return []
    pods = config.get("pods")
    if pods is None:
        return []
    if not isinstance(pods, list):
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="check_skipped",
            message=f"{check_id}: 'pods' is not a list",
            check_id=check_id,
        )
        return []
    return [p for p in pods if isinstance(p, dict)]


def _pod_containers(pod: dict) -> list[dict]:
    """Return container dicts from either flat 'containers' or 'spec.containers'."""
    containers = pod.get("containers")
    if containers is None:
        spec = _safe_dict(pod.get("spec"))
        containers = spec.get("containers")
    if not isinstance(containers, list):
        return []
    return [c for c in containers if isinstance(c, dict)]


def _pod_field(pod: dict, key: str, default=False):
    """Read a top-level pod field falling back to spec.{key}."""
    if key in pod:
        return pod.get(key, default)
    spec = _safe_dict(pod.get("spec"))
    return spec.get(key, default)


# ═══════════════════════════════════════════════════════════════════════════
# Section 1 — Pod Security
# ═══════════════════════════════════════════════════════════════════════════


def check_1_1_no_privileged_pods(config: dict) -> Finding:
    """K8S-1.1 — No pods running in privileged mode."""
    pods = _safe_pods(config, check_id="K8S-1.1")
    privileged = []
    for pod in pods:
        for c in _pod_containers(pod):
            sec = _safe_dict(c.get("securityContext") or c.get("security_context"))
            if sec.get("privileged", False):
                privileged.append(f"{pod.get('name', 'unknown')}:{c.get('name', 'unknown')}")
    return Finding(
        check_id="K8S-1.1",
        title="No privileged pods",
        section="pod_security",
        severity="CRITICAL",
        status="FAIL" if privileged else "PASS",
        detail=f"{len(privileged)} privileged containers"
        if privileged
        else "No privileged containers",
        remediation="Remove privileged: true. Use specific capabilities instead.",
        cis_k8s="5.2.1",
        nist_csf="PR.AC-4",
        resources=privileged,
    )


def check_1_2_no_host_pid(config: dict) -> Finding:
    """K8S-1.2 — No pods sharing host PID namespace."""
    pods = _safe_pods(config, check_id="K8S-1.2")
    host_pid = [p.get("name", "unknown") for p in pods if _pod_field(p, "hostPID", False)]
    return Finding(
        check_id="K8S-1.2",
        title="No host PID namespace",
        section="pod_security",
        severity="HIGH",
        status="FAIL" if host_pid else "PASS",
        detail=f"{len(host_pid)} pods with hostPID" if host_pid else "No pods share host PID",
        remediation="Set hostPID: false on all pod specs.",
        cis_k8s="5.2.2",
        nist_csf="PR.AC-4",
        resources=host_pid,
    )


def check_1_3_no_host_network(config: dict) -> Finding:
    """K8S-1.3 — No pods using host network."""
    pods = _safe_pods(config, check_id="K8S-1.3")
    host_net = [p.get("name", "unknown") for p in pods if _pod_field(p, "hostNetwork", False)]
    return Finding(
        check_id="K8S-1.3",
        title="No host network",
        section="pod_security",
        severity="HIGH",
        status="FAIL" if host_net else "PASS",
        detail=f"{len(host_net)} pods with hostNetwork" if host_net else "No pods use host network",
        remediation="Set hostNetwork: false. Use Services and Ingress instead.",
        cis_k8s="5.2.4",
        nist_csf="PR.AC-5",
        resources=host_net,
    )


def check_1_4_drop_all_capabilities(config: dict) -> Finding:
    """K8S-1.4 — Containers drop ALL capabilities."""
    pods = _safe_pods(config, check_id="K8S-1.4")
    no_drop = []
    for pod in pods:
        for c in _pod_containers(pod):
            sec = _safe_dict(c.get("securityContext") or c.get("security_context"))
            caps = _safe_dict(sec.get("capabilities"))
            drop = caps.get("drop")
            drop_list = drop if isinstance(drop, list) else []
            normalized = [d.upper() for d in drop_list if isinstance(d, str)]
            if "ALL" not in normalized:
                no_drop.append(f"{pod.get('name', 'unknown')}:{c.get('name', 'unknown')}")
    return Finding(
        check_id="K8S-1.4",
        title="Drop ALL capabilities",
        section="pod_security",
        severity="MEDIUM",
        status="FAIL" if no_drop else "PASS",
        detail=f"{len(no_drop)} containers not dropping ALL"
        if no_drop
        else "All containers drop ALL capabilities",
        remediation="Add securityContext.capabilities.drop: ['ALL'] to every container.",
        cis_k8s="5.2.7",
        nist_csf="PR.AC-4",
        resources=no_drop,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 2 — RBAC
# ═══════════════════════════════════════════════════════════════════════════


def check_2_1_no_cluster_admin_default(config: dict) -> Finding:
    """K8S-2.1 — No ClusterRoleBinding to cluster-admin for default SA."""
    bindings = _safe_list(config.get("cluster_role_bindings")) if isinstance(config, dict) else []
    dangerous = []
    for b in bindings:
        if not isinstance(b, dict):
            continue
        role_ref = _safe_dict(b.get("roleRef"))
        if role_ref.get("name") == "cluster-admin":
            for subj in _safe_list(b.get("subjects")):
                if not isinstance(subj, dict):
                    continue
                if subj.get("name") == "default" or subj.get("namespace") == "kube-system":
                    dangerous.append(b.get("name", "unknown"))
    return Finding(
        check_id="K8S-2.1",
        title="No cluster-admin on default SA",
        section="rbac",
        severity="CRITICAL",
        status="FAIL" if dangerous else "PASS",
        detail=f"{len(dangerous)} bindings give cluster-admin to default/system"
        if dangerous
        else "No dangerous cluster-admin bindings",
        remediation="Remove cluster-admin bindings from default service accounts. Use scoped roles.",
        cis_k8s="5.1.1",
        nist_csf="PR.AC-4",
        resources=dangerous,
    )


def check_2_2_no_wildcard_permissions(config: dict) -> Finding:
    """K8S-2.2 — No roles with wildcard (*) permissions."""
    if not isinstance(config, dict):
        roles: list = []
    else:
        roles = _safe_list(config.get("roles")) + _safe_list(config.get("cluster_roles"))
    wildcard = []
    for role in roles:
        if not isinstance(role, dict):
            continue
        for rule in _safe_list(role.get("rules")):
            if not isinstance(rule, dict):
                continue
            verbs = _safe_list(rule.get("verbs"))
            resources = _safe_list(rule.get("resources"))
            if "*" in verbs or "*" in resources:
                wildcard.append(role.get("name", "unknown"))
    return Finding(
        check_id="K8S-2.2",
        title="No wildcard RBAC permissions",
        section="rbac",
        severity="HIGH",
        status="FAIL" if wildcard else "PASS",
        detail=f"{len(set(wildcard))} roles with wildcard"
        if wildcard
        else "No wildcard permissions",
        remediation="Replace * verbs/resources with explicit least-privilege lists.",
        cis_k8s="5.1.3",
        nist_csf="PR.AC-4",
        resources=list(set(wildcard)),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 3 — Network Policies
# ═══════════════════════════════════════════════════════════════════════════


def check_3_1_default_deny(config: dict) -> Finding:
    """K8S-3.1 — Default deny NetworkPolicy per namespace."""
    namespaces = _safe_list(config.get("namespaces")) if isinstance(config, dict) else []
    no_deny = []
    for ns in namespaces:
        if not isinstance(ns, dict):
            continue
        policies = _safe_list(ns.get("network_policies"))
        has_deny = any(
            isinstance(p, dict) and "deny" in str(p.get("name", "")).lower() for p in policies
        )
        if not has_deny and not policies:
            no_deny.append(ns.get("name", "unknown"))
    return Finding(
        check_id="K8S-3.1",
        title="Default deny NetworkPolicy",
        section="network",
        severity="HIGH",
        status="FAIL" if no_deny else "PASS",
        detail=f"{len(no_deny)} namespaces without default deny"
        if no_deny
        else "All namespaces have deny policy",
        remediation="Apply a default-deny NetworkPolicy to every namespace.",
        cis_k8s="5.3.2",
        nist_csf="PR.AC-5",
        resources=no_deny,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 4 — Secrets
# ═══════════════════════════════════════════════════════════════════════════


def check_4_1_no_env_secrets(config: dict) -> Finding:
    """K8S-4.1 — Secrets not passed via environment variables."""
    pods = _safe_pods(config, check_id="K8S-4.1")
    env_secrets = []
    for pod in pods:
        for c in _pod_containers(pod):
            for env in _safe_list(c.get("env")):
                if not isinstance(env, dict):
                    continue
                value_from = _safe_dict(env.get("valueFrom"))
                if value_from.get("secretKeyRef"):
                    env_secrets.append(f"{pod.get('name', 'unknown')}:{env.get('name', 'unknown')}")
    return Finding(
        check_id="K8S-4.1",
        title="Secrets not via env vars",
        section="secrets",
        severity="MEDIUM",
        status="FAIL" if env_secrets else "PASS",
        detail=f"{len(env_secrets)} secrets exposed via env"
        if env_secrets
        else "No secrets in environment variables",
        remediation="Mount secrets as volumes instead of env vars. Env vars appear in logs and process listings.",
        cis_k8s="5.4.1",
        nist_csf="PR.DS-5",
        resources=env_secrets,
    )


def check_4_2_secrets_encrypted_etcd(config: dict) -> Finding:
    """K8S-4.2 — Secrets encryption at rest configured."""
    api_server = _safe_dict(config.get("api_server")) if isinstance(config, dict) else {}
    encryption = api_server.get("encryption_config") or api_server.get(
        "encryption-provider-config", ""
    )
    return Finding(
        check_id="K8S-4.2",
        title="Secrets encrypted at rest (etcd)",
        section="secrets",
        severity="HIGH",
        status="PASS" if encryption else "FAIL",
        detail="Encryption provider configured"
        if encryption
        else "No encryption-at-rest for secrets in etcd",
        remediation="Configure EncryptionConfiguration with aescbc or kms provider.",
        cis_k8s="5.4.2",
        nist_csf="PR.DS-1",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 5 — Images
# ═══════════════════════════════════════════════════════════════════════════


def check_5_1_no_latest_tag(config: dict) -> Finding:
    """K8S-5.1 — No containers using :latest image tag."""
    pods = _safe_pods(config, check_id="K8S-5.1")
    latest = []
    for pod in pods:
        for c in _pod_containers(pod):
            image = c.get("image")
            if not isinstance(image, str) or not image:
                latest.append(f"{pod.get('name', 'unknown')}:<missing>")
                continue
            if image.endswith(":latest") or ":" not in image:
                latest.append(f"{pod.get('name', 'unknown')}:{image}")
    return Finding(
        check_id="K8S-5.1",
        title="No :latest image tags",
        section="images",
        severity="MEDIUM",
        status="FAIL" if latest else "PASS",
        detail=f"{len(latest)} containers using :latest"
        if latest
        else "All images pinned to specific tags",
        remediation="Pin images to SHA digests or semantic version tags. Never use :latest.",
        cis_k8s="5.5.1",
        nist_csf="PR.DS-6",
        resources=latest,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

ALL_CHECKS = {
    "pod_security": [
        check_1_1_no_privileged_pods,
        check_1_2_no_host_pid,
        check_1_3_no_host_network,
        check_1_4_drop_all_capabilities,
    ],
    "rbac": [check_2_1_no_cluster_admin_default, check_2_2_no_wildcard_permissions],
    "network": [check_3_1_default_deny],
    "secrets": [check_4_1_no_env_secrets, check_4_2_secrets_encrypted_etcd],
    "images": [check_5_1_no_latest_tag],
}


def run_benchmark(config: dict, *, section: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    sections = {section: ALL_CHECKS[section]} if section and section in ALL_CHECKS else ALL_CHECKS
    for checks in sections.values():
        for check_fn in checks:
            findings.append(check_fn(config))
    return findings


def print_summary(findings: list[Finding]) -> None:
    total = len(findings)
    passed = sum(1 for f in findings if f.status == "PASS")
    failed = sum(1 for f in findings if f.status == "FAIL")
    print(f"\n{'=' * 60}")
    print("  Kubernetes Security Benchmark — Results")
    print(f"{'=' * 60}\n")
    current = ""
    for f in findings:
        if f.section != current:
            current = f.section
            print(f"\n  [{current.upper()}]")
        icon = {"PASS": "+", "FAIL": "x", "WARN": "!", "ERROR": "?", "SKIP": "-"}[f.status]
        print(f"  [{icon}] {f.check_id} [{f.severity:8s}] {f.title}")
        if f.status == "FAIL":
            print(f"      {f.detail}")
            if f.remediation:
                print(f"      FIX: {f.remediation}")
    print(f"\n  {'─' * 56}")
    print(f"  Total: {total} | Passed: {passed} | Failed: {failed}")
    print(f"  Pass rate: {passed / total * 100:.0f}%\n" if total else "")


def main() -> None:
    parser = argparse.ArgumentParser(description="Kubernetes Security Benchmark")
    parser.add_argument("config", help="Path to K8s config (JSON/YAML)")
    parser.add_argument("--section", choices=list(ALL_CHECKS.keys()))
    parser.add_argument("--output", choices=["console", "json"], default="console")
    parser.add_argument("--output-format", choices=list(OUTPUT_FORMATS), default="native")
    args = parser.parse_args()
    p = Path(args.config)
    content = p.read_text()
    config = json.loads(content) if p.suffix == ".json" else __import__("yaml").safe_load(content)
    findings = run_benchmark(config, section=args.section)
    if args.output == "json":
        rendered = (
            findings_to_ocsf(
                findings,
                skill_name=SKILL_NAME,
                benchmark_name=BENCHMARK_NAME,
                provider=PROVIDER_NAME,
                frameworks=["CIS Kubernetes Benchmark", "NIST CSF 2.0"],
            )
            if args.output_format == "ocsf"
            else findings_to_native(findings)
        )
        print(json.dumps(rendered, indent=2))
    else:
        print_summary(findings)
    sys.exit(
        1 if any(f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH") for f in findings) else 0
    )


if __name__ == "__main__":
    if "--worker" in sys.argv:
        from skills._shared.worker_harness import run_worker

        raise SystemExit(run_worker(main))
    main()
