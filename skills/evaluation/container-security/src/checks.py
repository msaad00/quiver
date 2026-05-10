"""Container Security Benchmark — audit container image and runtime security.

Checks Dockerfile best practices, image configuration, runtime security,
and supply chain integrity. Works with Dockerfile analysis, image config
JSON, or container runtime dumps.

Read-only — analyzes configs only, does not pull or execute images.
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

SKILL_NAME = "container-security"
BENCHMARK_NAME = "Container Security Benchmark"
PROVIDER_NAME = "Containers"
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
    cis_docker: str = ""
    nist_csf: str = ""
    resources: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# Section 1 — Dockerfile Best Practices
# ═══════════════════════════════════════════════════════════════════════════


def check_1_1_no_root_user(config: dict) -> Finding:
    """CTR-1.1 — Container does not run as root."""
    images = config.get("images", config.get("containers", []))
    root_images = []
    for img in images:
        user = img.get("user", img.get("User", ""))
        if not user or user == "root" or user == "0":
            root_images.append(img.get("name", img.get("image", "unknown")))
    return Finding(
        check_id="CTR-1.1",
        title="No root user",
        section="dockerfile",
        severity="HIGH",
        status="FAIL" if root_images else "PASS",
        detail=f"{len(root_images)} images run as root" if root_images else "All images use non-root user",
        remediation="Add USER directive with non-root UID in Dockerfile. Never run as root.",
        cis_docker="4.1",
        nist_csf="PR.AC-4",
        resources=root_images,
    )


def check_1_2_no_latest_base(config: dict) -> Finding:
    """CTR-1.2 — Base image uses specific tag, not :latest."""
    images = config.get("images", config.get("containers", []))
    latest = []
    for img in images:
        base = img.get("base_image", img.get("from", ""))
        if base and (base.endswith(":latest") or ":" not in base):
            latest.append(f"{img.get('name', 'unknown')}: FROM {base}")
    return Finding(
        check_id="CTR-1.2",
        title="No :latest base images",
        section="dockerfile",
        severity="MEDIUM",
        status="FAIL" if latest else "PASS",
        detail=f"{len(latest)} images use :latest base" if latest else "All base images pinned",
        remediation="Pin base images to SHA digest or specific version tag.",
        cis_docker="4.2",
        nist_csf="PR.DS-6",
        resources=latest,
    )


def check_1_3_healthcheck_defined(config: dict) -> Finding:
    """CTR-1.3 — HEALTHCHECK instruction defined."""
    images = config.get("images", config.get("containers", []))
    no_health = []
    for img in images:
        healthcheck = img.get("healthcheck", img.get("Healthcheck"))
        if not healthcheck:
            no_health.append(img.get("name", "unknown"))
    return Finding(
        check_id="CTR-1.3",
        title="HEALTHCHECK defined",
        section="dockerfile",
        severity="LOW",
        status="FAIL" if no_health else "PASS",
        detail=f"{len(no_health)} images without healthcheck" if no_health else "All images have HEALTHCHECK",
        remediation="Add HEALTHCHECK instruction to Dockerfile for orchestrator liveness probes.",
        cis_docker="4.6",
        nist_csf="DE.CM-1",
        resources=no_health,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 2 — Image Security
# ═══════════════════════════════════════════════════════════════════════════


def check_2_1_no_secrets_in_env(config: dict) -> Finding:
    """CTR-2.1 — No secrets in environment variables."""
    secret_patterns = re.compile(r"(?i)(password|secret|token|api_key|private_key|credentials)")
    images = config.get("images", config.get("containers", []))
    exposed = []
    for img in images:
        for env in img.get("env", img.get("Env", [])):
            key = env.split("=")[0] if isinstance(env, str) else env.get("name", "")
            if secret_patterns.search(key):
                exposed.append(f"{img.get('name', 'unknown')}: {key}")
    return Finding(
        check_id="CTR-2.1",
        title="No secrets in env vars",
        section="image_security",
        severity="CRITICAL",
        status="FAIL" if exposed else "PASS",
        detail=f"{len(exposed)} potential secrets in env" if exposed else "No secrets in environment variables",
        remediation="Use mounted secrets or external secret managers. Never bake secrets into images.",
        cis_docker="4.5",
        nist_csf="PR.DS-5",
        resources=exposed[:10],
    )


def check_2_2_minimal_packages(config: dict) -> Finding:
    """CTR-2.2 — Image uses minimal base (alpine, slim, distroless)."""
    images = config.get("images", config.get("containers", []))
    bloated = []
    minimal_indicators = ("alpine", "slim", "distroless", "scratch", "busybox", "ubi-minimal")
    for img in images:
        base = img.get("base_image", img.get("from", "")).lower()
        if base and not any(m in base for m in minimal_indicators):
            bloated.append(f"{img.get('name', 'unknown')}: {base}")
    return Finding(
        check_id="CTR-2.2",
        title="Minimal base image",
        section="image_security",
        severity="MEDIUM",
        status="FAIL" if bloated else "PASS",
        detail=f"{len(bloated)} images not using minimal base" if bloated else "All images use minimal bases",
        remediation="Use alpine, slim, or distroless base images to reduce attack surface.",
        cis_docker="4.3",
        nist_csf="PR.IP-1",
        resources=bloated,
    )


def check_2_3_no_add_instruction(config: dict) -> Finding:
    """CTR-2.3 — COPY used instead of ADD."""
    images = config.get("images", config.get("containers", []))
    uses_add = []
    for img in images:
        instructions = img.get("instructions", img.get("history", []))
        for inst in instructions:
            cmd = inst if isinstance(inst, str) else inst.get("created_by", "")
            if cmd.strip().upper().startswith("ADD ") and not cmd.strip().upper().startswith("ADD --CHOWN"):
                uses_add.append(img.get("name", "unknown"))
                break
    return Finding(
        check_id="CTR-2.3",
        title="COPY instead of ADD",
        section="image_security",
        severity="LOW",
        status="FAIL" if uses_add else "PASS",
        detail=f"{len(uses_add)} images using ADD" if uses_add else "No images use ADD instruction",
        remediation="Replace ADD with COPY. ADD has implicit tar extraction and URL fetching — use explicit commands.",
        cis_docker="4.9",
        nist_csf="PR.IP-1",
        resources=uses_add,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 3 — Runtime Security
# ═══════════════════════════════════════════════════════════════════════════


def check_3_1_read_only_rootfs(config: dict) -> Finding:
    """CTR-3.1 — Read-only root filesystem."""
    containers = config.get("containers", config.get("images", []))
    writable = []
    for c in containers:
        sec = c.get("security_context", c.get("securityContext", {}))
        if not sec.get("readOnlyRootFilesystem", sec.get("read_only_rootfs", False)):
            writable.append(c.get("name", "unknown"))
    return Finding(
        check_id="CTR-3.1",
        title="Read-only root filesystem",
        section="runtime",
        severity="MEDIUM",
        status="FAIL" if writable else "PASS",
        detail=f"{len(writable)} containers with writable rootfs" if writable else "All containers read-only",
        remediation="Set readOnlyRootFilesystem: true. Use emptyDir for temp data.",
        cis_docker="5.12",
        nist_csf="PR.DS-6",
        resources=writable,
    )


def check_3_2_resource_limits(config: dict) -> Finding:
    """CTR-3.2 — CPU and memory limits set."""
    containers = config.get("containers", config.get("images", []))
    no_limits = []
    for c in containers:
        res = c.get("resources", {})
        limits = res.get("limits", {})
        if not limits.get("cpu") and not limits.get("memory"):
            no_limits.append(c.get("name", "unknown"))
    return Finding(
        check_id="CTR-3.2",
        title="Resource limits set",
        section="runtime",
        severity="MEDIUM",
        status="FAIL" if no_limits else "PASS",
        detail=f"{len(no_limits)} containers without resource limits" if no_limits else "All containers have limits",
        remediation="Set resources.limits.cpu and resources.limits.memory on every container.",
        cis_docker="5.14",
        nist_csf="PR.DS-4",
        resources=no_limits,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

ALL_CHECKS = {
    "dockerfile": [check_1_1_no_root_user, check_1_2_no_latest_base, check_1_3_healthcheck_defined],
    "image_security": [check_2_1_no_secrets_in_env, check_2_2_minimal_packages, check_2_3_no_add_instruction],
    "runtime": [check_3_1_read_only_rootfs, check_3_2_resource_limits],
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
    print("  Container Security Benchmark — Results")
    print(f"{'=' * 60}\n")
    current = ""
    for f in findings:
        if f.section != current:
            current = f.section
            print(f"\n  [{current.upper()}]")
        icon = {"PASS": "+", "FAIL": "x"}[f.status]
        print(f"  [{icon}] {f.check_id} [{f.severity:8s}] {f.title}")
        if f.status == "FAIL":
            print(f"      {f.detail}")
            if f.remediation:
                print(f"      FIX: {f.remediation}")
    print(f"\n  {'─' * 56}")
    print(f"  Total: {total} | Passed: {passed} | Failed: {failed}")
    print(f"  Pass rate: {passed / total * 100:.0f}%\n" if total else "")


def main() -> None:
    parser = argparse.ArgumentParser(description="Container Security Benchmark")
    parser.add_argument("config", help="Path to container config (JSON/YAML)")
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
                frameworks=["CIS Docker Benchmark", "NIST CSF 2.0"],
            )
            if args.output_format == "ocsf"
            else findings_to_native(findings)
        )
        print(json.dumps(rendered, indent=2))
    else:
        print_summary(findings)
    sys.exit(1 if any(f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH") for f in findings) else 0)


if __name__ == "__main__":
    if "--worker" in sys.argv:
        from skills._shared.worker_harness import run_worker

        raise SystemExit(run_worker(main))
    main()
