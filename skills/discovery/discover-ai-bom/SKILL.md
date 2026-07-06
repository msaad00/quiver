---
name: discover-ai-bom
description: >-
  Generate a deterministic, CycloneDX-aligned AI BOM from point-in-time AI asset
  inventory snapshots. Supports normalized multi-cloud inventory documents plus
  provider-shaped snapshots for AWS SageMaker and Bedrock, Google Vertex AI, and
  Azure Machine Learning. Use when the user mentions AI BOM, model inventory,
  AI asset discovery, evidence collection for AI systems, PCI / SOC 2 technical
  evidence, or wants a portable bill of materials for models, endpoints,
  datasets, vector stores, runtimes, and guardrails. Do NOT use on raw cloud
  audit logs or OCSF findings — this skill expects asset inventory, not events.
  Do NOT use as a live monitor or to claim compliance by itself — it produces a
  point-in-time inventory artifact and never mutates cloud state.
purpose: Generate a deterministic, CycloneDX-aligned AI BOM from point-in-time AI asset inventory snapshots.
capability: discover
persistence: none
telemetry: stderr_jsonl
privilege_escalation: read
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw, canonical
output_formats: native
concurrency_safety: operator_coordinated
compatibility: >-
  Requires Python 3.11+. No cloud SDKs required when inventory snapshots are
  already exported. Read-only — validates and normalizes inventory into a
  CycloneDX-aligned JSON BOM. Never calls cloud write APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/discovery/discover-ai-bom
  version: 0.1.0
  frameworks:
    - CycloneDX ML-BOM
    - NIST AI RMF
    - MITRE ATLAS
    - PCI DSS 4.0
    - SOC 2 TSC
  cloud: multi
  capability: read-only
---

# discover-ai-bom

Builds a deterministic AI BOM from a point-in-time inventory snapshot. The
result is a JSON document that is easy to diff, archive, and feed into agent
workflows, audit evidence pipelines, or future sink skills.

## Use when

- You need a portable inventory of AI systems, models, endpoints, datasets, vector stores, runtimes, and guardrails
- You want one artifact that can support AI security reviews, PCI / SOC 2 technical evidence, or internal architecture reviews
- You already have inventory exported from AWS, GCP, Azure, or a normalized collector and need to normalize it
- You want to capture AI estate drift over time using deterministic output

## Do NOT use

- On raw logs, findings, or event streams — this is inventory, not telemetry
- To infer exploitability or benchmark pass/fail by itself
- As a live control plane or remediation trigger
- To include secrets, tokens, or connection strings in the BOM

## Input contract

The skill accepts one JSON document, either:

1. **Normalized inventory**

```json
{
  "inventory_id": "ai-estate-prod-2026-04-12",
  "collected_at": "2026-04-12T00:00:00Z",
  "assets": [
    {
      "provider": "aws",
      "service": "sagemaker",
      "kind": "model",
      "id": "arn:aws:sagemaker:us-east-1:123456789012:model-package/fraud-model/5",
      "name": "fraud-model",
      "version": "5",
      "region": "us-east-1",
      "framework": "xgboost",
      "dependencies": ["endpoint:fraud-endpoint"],
      "sensitivity": "restricted"
    }
  ]
}
```

2. **Provider-shaped snapshots**

- AWS: `sagemaker.model_packages[]`, `sagemaker.endpoints[]`, `sagemaker.training_jobs[]`, `sagemaker.datasets[]`, `bedrock.custom_models[]`, `bedrock.guardrails[]`, `bedrock.knowledge_bases[]`
- GCP: `vertex_ai.models[]`, `vertex_ai.endpoints[]`, `vertex_ai.datasets[]`, `vertex_ai.training_pipelines[]`, `vertex_ai.indexes[]`, `vertex_ai.index_endpoints[]`
- Azure: `azure_ml.models[]`, `azure_ml.online_endpoints[]`, `azure_ml.deployments[]`, `azure_ml.data_assets[]`, `azure_ml.compute_clusters[]`, `ai_foundry.deployments[]`, `ai_foundry.projects[]`

## Output contract

The skill emits a **CycloneDX-aligned JSON BOM** with:

- deterministic `serialNumber`
- `components[]` for models, datasets, runtimes, and policy objects
- `services[]` for deployed endpoints, vector stores, and externally reachable inference surfaces
- `dependencies[]` for explicit inventory relationships
- sanitized properties only — secret-like keys are dropped

By default the BOM remains an inventory artifact, not a compliance verdict.
When `--emit-policy-findings` or `--policy-findings-output` is used, the skill
also emits per-asset AI BOM policy violations for:

- unpinned model versions
- untrusted registries outside the trusted/internal allowlist
- missing provenance / attestation metadata
- restricted model licenses

Policy findings render as OCSF Compliance Finding `2003` by default so CI,
sinks, and agent wrappers can consume them directly.

## Usage

```bash
# normalized inventory
python src/discover.py inventory.json > ai-bom.json

# stdin
cat inventory.json | python src/discover.py > ai-bom.json

# pretty output
python src/discover.py inventory.json --pretty -o ai-bom.json

# keep the BOM, but also write OCSF 2003 policy findings as JSONL
python src/discover.py inventory.json --policy-findings-output ai-bom-policy.ocsf.jsonl

# emit policy findings only
python src/discover.py inventory.json --emit-policy-findings > ai-bom-policy.ocsf.jsonl
```

## Security guardrails

- Read-only only. No cloud writes. No subprocesses.
- Drops secret-like keys such as `password`, `token`, `secret`, `api_key`, and `connection_string`.
- Produces deterministic output for stable diffing and review.
- Treats malformed inventory as a contract error and exits non-zero.

## See also

- [`../discover-environment/SKILL.md`](../discover-environment/SKILL.md) — graph-oriented environment discovery
- [`../../evaluation/model-serving-security/SKILL.md`](../../evaluation/model-serving-security/SKILL.md) — AI service posture checks
- [`../../evaluation/gpu-cluster-security/SKILL.md`](../../evaluation/gpu-cluster-security/SKILL.md) — AI infra / GPU posture checks
