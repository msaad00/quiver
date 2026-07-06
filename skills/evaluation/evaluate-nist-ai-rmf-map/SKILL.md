---
name: evaluate-nist-ai-rmf-map
description: >-
  Implements 10 of the NIST AI RMF 1.0 MAP function's ~18 documented
  subcategories. Use when an org wants to programmatically validate
  their NIST AI RMF MAP posture against a manifest of system / model
  cards documenting intended purpose, scientific basis, capabilities,
  limitations, benefits, costs, and impacts. The skill verifies that
  the manifest exists, is current (within declared review cadence),
  declares evidence, and covers at least 50% of the population each
  subcategory applies to. Emits one OCSF Compliance Finding (class
  2003) per subcategory with `compliance.requirement` set to the
  subcategory ID and `compliance.status` ∈ {pass, partial, fail,
  not_applicable}. Use when the user mentions NIST AI RMF MAP,
  system-card / model-card completeness audit, AI use-case
  categorisation, AI impact mapping, or AI scope review. Do NOT use
  as a substitute for the qualitative org-level assessment NIST AI
  RMF requires; this is a manifest-completeness + freshness check,
  not the assessment itself. Do NOT use to grade GOVERN, MEASURE,
  or MANAGE — those ship as sibling skills.
purpose: Implements 10 of the NIST AI RMF 1.0 MAP function's ~18 documented subcategories. Use when an org wants to programmatically validate their NIST AI RMF MAP posture against a manifest of system / model cards documenting...
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
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. No cloud SDKs needed — reads one local manifest
  file. Optional: PyYAML for YAML manifest parsing. Read-only — no write
  permissions, no API calls, no network access.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/evaluation/evaluate-nist-ai-rmf-map
  version: 0.1.0
  frameworks:
    - NIST AI RMF 1.0
    - OCSF 1.8
    - NIST CSF 2.0
  cloud: any
---

# Evaluate — NIST AI RMF 1.0 MAP

Manifest-completeness + freshness audit of the MAP function. Reads a
JSON/YAML manifest keyed by subcategory ID; emits one OCSF Compliance
Finding (class 2003) per implemented subcategory.

## Honest scope

This skill implements **10 of ~18** documented MAP subcategories. It is
a system-card / model-card completeness audit — not the qualitative
NIST AI RMF assessment. The narrative the program owner attaches to
each card is what the assessment grades; this skill verifies that the
cards exist, are current, and reference the populations the framework
asks for.

## Use when

- CI-gated drift detection on AI system / model cards
- Machine-readable evidence that system cards remain fresh and complete
- Single command that asserts intended purpose, scientific basis, benefits, costs, and impacts are all documented per AI system
- OCSF-format findings that flow into the same SIEM as other posture skills

## Do NOT use

- As a substitute for the qualitative NIST AI RMF assessment
- To grade GOVERN, MEASURE, or MANAGE — those ship as sibling skills
- To author the system cards themselves — this skill only validates them

## Manifest contract

The manifest is JSON or YAML; path is the positional CLI argument or the
`NIST_AI_RMF_MAP_MANIFEST` environment variable. Top level may be flat
or under a `subcategories:` key. Each entry:

```yaml
subcategories:
  MAP-1.1:
    documented: true
    review_cadence_days: 180
    last_reviewed: "2026-02-01"
    evidence_uri: "https://wiki.example/system-cards/fraud-detector-v3"
    coverage: 1.0
    resources:
      - "model://fraud-detector-v3"
  # ...
```

Per-entry fields are the same as the other NIST AI RMF skills:
`documented`, `review_cadence_days`, `last_reviewed` (ISO date),
`evidence_uri`, `coverage` (0..1), `resources` (optional list), and
`not_applicable` / `not_applicable_reason` for opt-out.

## Implemented subcategories

| ID | Title | Severity |
|---|---|---|
| MAP-1.1 | Intended purposes documented | HIGH |
| MAP-1.2 | AI categorized per intended use | HIGH |
| MAP-1.3 | AI capabilities + limitations + assumptions documented | HIGH |
| MAP-2.1 | System task + AI capability documented | MEDIUM |
| MAP-2.2 | Information about scientific / technical foundations | MEDIUM |
| MAP-3.1 | System benefits documented | MEDIUM |
| MAP-3.2 | Costs documented | MEDIUM |
| MAP-4.1 | Approaches for mapping AI risks documented | HIGH |
| MAP-5.1 | Impacts on individuals + groups documented | HIGH |
| MAP-5.2 | Likelihood + magnitude of impacts assessed | HIGH |

## Roadmap — documented, not yet implemented

The NIST AI RMF 1.0 MAP function documents ~18 subcategories total.
The following are intentionally out of scope for this slice:

- MAP-1.4, MAP-1.5, MAP-1.6
- MAP-2.3
- MAP-3.3, MAP-3.4, MAP-3.5
- MAP-4.2

## Usage

```bash
python src/checks.py path/to/map.yaml
export NIST_AI_RMF_MAP_MANIFEST=/etc/airmf/map.yaml
python src/checks.py --output json --output-format ocsf
python src/checks.py path/to/map.yaml --subcategory MAP-1.1
```

## Output

PASS / PARTIAL / FAIL / NOT_APPLICABLE per subcategory. Exit code is 1
if any HIGH/CRITICAL subcategory FAILs, 0 otherwise.
