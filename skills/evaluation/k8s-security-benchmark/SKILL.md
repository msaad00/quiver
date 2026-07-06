---
name: k8s-security-benchmark
description: >-
  Audit Kubernetes cluster and workload security against the CIS Kubernetes
  Benchmark. Runs 10 read-only checks covering pod security standards, RBAC
  hygiene, network policies, secrets management, and image pinning. Works with
  exported K8s resource JSON or live kubectl output. Use when the user mentions
  Kubernetes security, pod security, RBAC audit, network policy check, K8s
  hardening, or CIS Kubernetes benchmark. Do NOT use for container runtime
  hardening (use container-security), GPU workload isolation (use
  gpu-cluster-security), or to mutate cluster state (this skill is assessment-only
  and never calls write APIs). Do NOT use against a cluster you do not own or
  have explicit authorisation to scan.
purpose: Audit Kubernetes cluster and workload security against the CIS Kubernetes Benchmark.
capability: evaluate
persistence: none
telemetry: stderr_jsonl
privilege_escalation: read
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native, ocsf
concurrency_safety: operator_coordinated
compatibility: >-
  Requires Python 3.11+. No cloud SDKs needed — works with exported JSON/YAML.
  Optional: kubectl for live cluster dumps. Read-only — no write permissions.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/evaluation/k8s-security-benchmark
  version: 0.1.0
  frameworks:
    - CIS Kubernetes Benchmark
    - NIST CSF 2.0
  cloud: any
  optional_bins:
    - kubectl
---

# Kubernetes Security Benchmark

10 automated checks across 5 domains — pod security, RBAC, network policies,
secrets, and image management. Each check mapped to CIS Kubernetes Benchmark
and NIST CSF 2.0.

## Architecture

```mermaid
flowchart LR
    K8S["K8s Resources\nPods · RBAC · NetworkPolicy\nSecrets · Images"]
    BENCH["checks.py\n10 checks · 5 domains"]
    OUT["JSON / Console"]

    K8S --> BENCH --> OUT

    style K8S fill:#1e293b,stroke:#475569,color:#e2e8f0
    style BENCH fill:#164e63,stroke:#22d3ee,color:#e2e8f0
```

## Controls

| # | Check | Severity | CIS K8s |
|---|-------|----------|---------|
| K8S-1.1 | No privileged pods | CRITICAL | 5.2.1 |
| K8S-1.2 | No host PID namespace | HIGH | 5.2.2 |
| K8S-1.3 | No host network | HIGH | 5.2.4 |
| K8S-1.4 | Drop ALL capabilities | MEDIUM | 5.2.7 |
| K8S-2.1 | No cluster-admin on default SA | CRITICAL | 5.1.1 |
| K8S-2.2 | No wildcard RBAC permissions | HIGH | 5.1.3 |
| K8S-3.1 | Default deny NetworkPolicy | HIGH | 5.3.2 |
| K8S-4.1 | Secrets not via env vars | MEDIUM | 5.4.1 |
| K8S-4.2 | Secrets encrypted at rest | HIGH | 5.4.2 |
| K8S-5.1 | No :latest image tags | MEDIUM | 5.5.1 |

## Usage

```bash
python src/checks.py cluster-config.json
python src/checks.py config.yaml --section pod_security
python src/checks.py config.json --output json --output-format ocsf
```

## Security Guardrails

- **Read-only**: Analyzes exported configs. No kubectl write commands.
- **No cluster access required**: Works with JSON/YAML dumps.
- **Human-in-the-loop**: Assessment automated, remediation requires human.

## Tests

```bash
cd skills/k8s-security-benchmark
pytest tests/ -v -o "testpaths=tests"
```
