---
name: discover-control-evidence
description: >-
  Generate deterministic technical-control evidence from discovery-layer
  inventory artifacts. Supports CycloneDX-aligned AI BOM documents from
  discover-ai-bom and graph snapshots from discover-environment. Produces a
  machine-readable evidence package for PCI DSS 4.0 and SOC 2 security reviews
  without claiming pass/fail attestation. Use when the user mentions PCI
  evidence, SOC 2 evidence, audit evidence, control evidence, inventory-backed
  evidence, or wants a reviewable JSON package that shows what AI or cloud
  assets exist, which services are externally reachable, and which dependency
  relationships are documented. Do NOT use as a compliance certification tool,
  benchmark evaluator, or remediation planner. Do NOT use on raw logs or
  findings — this skill expects inventory artifacts, not events.
purpose: Generate deterministic technical-control evidence from discovery-layer inventory artifacts.
capability: discover
persistence: none
telemetry: stderr_jsonl
privilege_escalation: read
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: canonical
output_formats: native, bridge
concurrency_safety: operator_coordinated
compatibility: >-
  Requires Python 3.11+. Read-only. Accepts discovery-layer JSON from stdin or
  a file path. Produces deterministic JSON evidence suitable for CLI, CI, MCP,
  and persistent pipelines.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/discovery/discover-control-evidence
  version: 0.1.0
  frameworks:
    - PCI DSS 4.0
    - SOC 2 TSC
    - CycloneDX ML-BOM
    - MITRE ATLAS
  cloud: multi
  capability: read-only
---

# discover-control-evidence

Transforms trusted discovery artifacts into a technical evidence package. The
goal is to give auditors, security engineers, and agents a single JSON document
that shows what was inventoried and which evidence domains are currently
covered, without pretending that inventory alone proves compliance.

## Use when

- You need machine-readable evidence for PCI DSS 4.0 or SOC 2 reviews
- You want to summarize AI BOM or environment-graph artifacts into review-ready evidence
- You need inventory-backed evidence for endpoints, dependencies, datasets, guardrails, and providers
- You want stable JSON that can be diffed over time or attached to tickets and audits

## Do NOT use

- As a benchmark or control pass/fail engine
- As a replacement for auditor judgement or formal attestation
- On raw logs, OCSF findings, or cloud audit streams
- To infer exploitability or blast radius on its own

## Input contract

The skill accepts one JSON document in either of these shapes:

1. **CycloneDX-aligned AI BOM**
   - `bomFormat: CycloneDX`
   - `components[]`, `services[]`, optional `dependencies[]`

2. **Environment graph**
   - `nodes[]`, `edges[]`, optional `stats`

## Output contract

The skill emits one deterministic JSON document:

- `artifact_type: technical-control-evidence`
- `frameworks[]` with the requested evidence families
- `inventory_summary` with providers, services, asset counts, and dependency counts
- `controls[]` with evidence-ready / partial / missing status per control domain
- `gaps[]` only when the source artifact cannot support a given evidence domain

By default this is native evidence JSON, not an attestation. When `--output-format ocsf-live-evidence` is used, the skill emits a Discovery-category OCSF bridge event for `Live Evidence Info [5040]` and carries the deterministic evidence payload under `unmapped.cloud_security_technical_evidence`.

## Usage

```bash
# From an AI BOM
python src/discover.py ai-bom.json > evidence.json

# From an environment graph
python src/discover.py graph.json --framework pci --framework soc2 > evidence.json

# Pretty-print to a file
python src/discover.py ai-bom.json --pretty -o control-evidence.json

# Emit an OCSF Discovery bridge event
python src/discover.py graph.json --output-format ocsf-live-evidence > control-evidence.ocsf.json
```

## Security guardrails

- Read-only only. No network calls, no subprocesses, no writes outside the requested output file.
- Secret-like fields are dropped before evidence is generated.
- Unknown source shapes fail closed with a non-zero exit.
- The skill never emits “compliant” / “non-compliant”; it only reports evidence presence and gaps.

## See also

- [`../discover-ai-bom/SKILL.md`](../discover-ai-bom/SKILL.md) — AI BOM generation
- [`../discover-environment/SKILL.md`](../discover-environment/SKILL.md) — graph inventory generation
- [`../../evaluation/model-serving-security/SKILL.md`](../../evaluation/model-serving-security/SKILL.md) — posture checks for AI services
