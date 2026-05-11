---
name: container-security
description: >-
  Audit container image and runtime security against the CIS Docker Benchmark.
  Runs 8 read-only checks covering Dockerfile best practices, image
  configuration, secrets exposure, base image selection, and runtime isolation.
  Works with Dockerfile text, image config JSON, or runtime dumps. Use when the
  user mentions container security, Docker hardening, image scanning, Dockerfile
  audit, or CIS Docker benchmark. Do NOT use to pull, run, or mutate images
  (this skill only reads configs, it never touches a Docker daemon). Do NOT use
  for Kubernetes cluster posture (use k8s-security-benchmark) or GPU runtime
  isolation (use gpu-cluster-security).
purpose: Audit container image and runtime security against the CIS Docker Benchmark.
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
  Requires Python 3.11+. No Docker daemon needed — works with config files.
  Optional: PyYAML for YAML parsing. Read-only — no image pulls or execution.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/evaluation/container-security
  version: 0.1.0
  frameworks:
    - CIS Docker Benchmark
    - NIST CSF 2.0
  cloud: any
---

# Container Security Benchmark

8 automated checks across 3 domains — Dockerfile best practices, image
security, and runtime isolation. Each check mapped to CIS Docker Benchmark
and NIST CSF 2.0.

## Architecture

```mermaid
flowchart LR
    IMG["Container Config\nDockerfile · Image JSON\nRuntime dumps"]
    BENCH["checks.py\n8 checks · 3 domains"]
    OUT["JSON / Console"]

    IMG --> BENCH --> OUT

    style IMG fill:#1e293b,stroke:#475569,color:#e2e8f0
    style BENCH fill:#164e63,stroke:#22d3ee,color:#e2e8f0
```

## Controls

| # | Check | Severity | CIS Docker |
|---|-------|----------|-----------|
| CTR-1.1 | No root user | HIGH | 4.1 |
| CTR-1.2 | No :latest base image | MEDIUM | 4.2 |
| CTR-1.3 | HEALTHCHECK defined | LOW | 4.6 |
| CTR-2.1 | No secrets in env vars | CRITICAL | 4.5 |
| CTR-2.2 | Minimal base image | MEDIUM | 4.3 |
| CTR-2.3 | COPY instead of ADD | LOW | 4.9 |
| CTR-3.1 | Read-only root filesystem | MEDIUM | 5.12 |
| CTR-3.2 | Resource limits set | MEDIUM | 5.14 |

## Usage

```bash
python src/checks.py container-config.json
python src/checks.py config.yaml --section dockerfile
python src/checks.py config.json --output json --output-format ocsf
```

## Security Guardrails

- **Read-only**: Analyzes config files. No Docker daemon interaction.
- **No image pulls**: Does not pull, build, or execute container images.
- **Human-in-the-loop**: Assessment automated, Dockerfile changes require human.

## Tests

```bash
cd skills/container-security
pytest tests/ -v -o "testpaths=tests"
```
