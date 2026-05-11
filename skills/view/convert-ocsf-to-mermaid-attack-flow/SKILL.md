---
name: convert-ocsf-to-mermaid-attack-flow
description: >-
  Convert OCSF 1.8 Detection Findings (class 2004) into Mermaid flowchart
  syntax suitable for inline rendering in PR comments, README files, and
  Markdown wikis. Produces a left-to-right attack flow showing each finding
  as actor → action → target chains, with MITRE ATT&CK technique IDs as
  edge labels and severity-coloured nodes. Multiple findings collapse into
  a single diagram so a reviewer sees the full attack chain in one
  picture. Use when the user mentions Mermaid, attack flow diagram, PR
  comment visualisation, README diagram for a detection result, or wants
  to embed a finding summary in Markdown without uploading SARIF. Do NOT
  use as a SARIF replacement (different audience: humans reading PRs vs
  GitHub code scanning UI). Do NOT use for non-finding OCSF events
  (class_uid != 2004) — those don't have the MITRE / actor / target
  structure this skill expects.
purpose: Convert OCSF 1.8 Detection Findings (class 2004) into Mermaid flowchart syntax suitable for inline rendering in PR comments, README files, and Markdown wikis. Produces a left-to-right attack flow showing each finding...
capability: view
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native
concurrency_safety: stateless
---

# convert-ocsf-to-mermaid-attack-flow

Cross-vendor view-layer skill: takes OCSF 1.8 Detection Findings on stdin, emits a Mermaid flowchart on stdout. Built once, used by every detection-engineering pipeline that wants to surface findings in a PR comment, a README, or any Markdown surface that renders Mermaid (GitHub does so natively).

## Output shape

A single Mermaid `flowchart LR` block. One node per actor, one node per target, one edge per finding. Edge labels carry the MITRE technique uid (e.g. `T1611`). Nodes are coloured by maximum severity observed for that node:

- Red — any finding involving this node was severity Critical (5) or Fatal (6)
- Orange — High (4)
- Yellow — Medium (3)
- Grey — Low (2), Informational (1), or Unknown (0)

The diagram is enclosed in triple backticks with a `mermaid` language tag so it renders inline on GitHub.

## Field mapping

| OCSF Detection Finding (2004) field | Mermaid element |
|---|---|
| `observables[]` where `name == "actor.name"` | actor node (left side of the chain) |
| `observables[]` where `name` matches `*.name` (target / pod / bucket / secret / tool) | target node (right side) |
| `finding_info.attacks[0].technique.uid` | edge label |
| `finding_info.title` | edge tooltip (shown on hover in some renderers) |
| `severity_id` | node colour (max severity wins for shared nodes) |
| `metadata.product.feature.name` | edge prefix (so the reviewer knows which detector fired) |

## Example output (from the K8s priv-esc golden fixture)

\`\`\`mermaid
flowchart LR
    classDef critical fill:#3f1d1d,stroke:#f87171,color:#fecaca
    classDef high     fill:#3a2a0e,stroke:#fb923c,color:#fed7aa
    classDef medium   fill:#3a3a0e,stroke:#fbbf24,color:#fef08a
    classDef low      fill:#1e293b,stroke:#64748b,color:#cbd5e1

    A0["system:serviceaccount:default:builder"]:::critical
    T0["secret · default/db-password"]:::high
    T1["pod · default/web-xyz"]:::critical
    T2["clusterrolebinding · attacker-cluster-admin"]:::critical

    A0 -- "T1552.007 · secret-enum" --> T0
    A0 -- "T1611 · pod-exec" --> T1
    A0 -- "T1098 · rbac-self-grant" --> T2
\`\`\`

## Multi-actor handling

When findings involve multiple distinct actors, each actor gets its own node. Cross-actor correlations stay separate — the Mermaid diagram is a *visualisation* of findings, not a derived correlation. If you want correlation, run a higher-level detect skill first.

## Usage

```bash
# Pipe step in a detection pipeline
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python skills/detection/detect-privilege-escalation-k8s/src/detect.py \
  | python src/convert.py \
  > attack-flow.mmd

# Or paste the output directly into a PR comment / GitHub issue
python src/convert.py < findings.ocsf.jsonl
```

## Tests

Golden fixture parity against [`../golden/k8s_priv_esc_findings.ocsf.jsonl`](../golden/k8s_priv_esc_findings.ocsf.jsonl) → [`../golden/k8s_priv_esc_attack_flow.mmd`](../golden/k8s_priv_esc_attack_flow.mmd). Plus unit tests for severity → class mapping, multi-actor handling, edge deduplication, MITRE label formatting, and node ID safety (Mermaid IDs cannot contain spaces or special chars).
