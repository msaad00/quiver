---
name: evaluate-nist-ai-rmf-manage
description: >-
  Implements 10 of the NIST AI RMF 1.0 MANAGE function's ~14 documented
  subcategories. Use when an org wants to programmatically validate
  their NIST AI RMF MANAGE posture against a manifest of risk-register
  rows, response plans, communication records, allocated resources,
  incident-response mechanisms, third-party monitoring, and ongoing
  risk-tracking plans. The skill verifies that the manifest exists, is
  current (within declared review cadence), declares evidence, and
  covers at least 50% of the population each subcategory applies to.
  Emits one OCSF Compliance Finding (class 2003) per subcategory with
  `compliance.requirement` set to the subcategory ID and
  `compliance.status` ∈ {pass, partial, fail, not_applicable}. Use
  when the user mentions NIST AI RMF MANAGE, AI risk-register audit,
  AI risk treatment / response review, AI incident-response readiness,
  or third-party AI risk monitoring. Do NOT use as a substitute for
  the qualitative org-level assessment NIST AI RMF requires; this is
  a manifest-completeness + freshness check, not the assessment itself.
  Do NOT use to grade GOVERN, MAP, or MEASURE — those ship as sibling
  skills.
purpose: Implements 10 of the NIST AI RMF 1.0 MANAGE function's ~14 documented subcategories. Use when an org wants to programmatically validate their NIST AI RMF MANAGE posture against a manifest of risk-register rows, respon...
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/evaluation/evaluate-nist-ai-rmf-manage
  version: 0.1.0
  frameworks:
    - NIST AI RMF 1.0
    - OCSF 1.8
    - NIST CSF 2.0
  cloud: any
---

# Evaluate — NIST AI RMF 1.0 MANAGE

Manifest-completeness + freshness audit of the MANAGE function. Reads a
JSON/YAML manifest keyed by subcategory ID; emits one OCSF Compliance
Finding (class 2003) per implemented subcategory.

## Honest scope

This skill implements **10 of ~14** documented MANAGE subcategories. It
is a risk-register + response-plan completeness audit — not the
qualitative NIST AI RMF assessment. The narrative the program owner
attaches to each register row is what the assessment grades; this skill
verifies that the rows exist, are current, and reference the
populations the framework asks for.

## Use when

- CI-gated drift detection on the AI risk register
- Machine-readable evidence that response plans, incident mechanisms, and third-party monitoring stay fresh
- Single command that asserts risks are prioritized, responses planned, decisions communicated, and ongoing monitoring documented
- OCSF-format findings that flow into the same SIEM as other posture skills

## Do NOT use

- As a substitute for the qualitative NIST AI RMF assessment
- To grade GOVERN, MAP, or MEASURE — those ship as sibling skills
- To execute the treatments themselves — this skill only validates that they were planned + reviewed

## Manifest contract

The manifest is JSON or YAML; path is the positional CLI argument or the
`NIST_AI_RMF_MANAGE_MANIFEST` environment variable.

```yaml
subcategories:
  MANAGE-1.1:
    documented: true
    review_cadence_days: 90
    last_reviewed: "2026-04-15"
    evidence_uri: "https://wiki/ai-risk-register-q2"
    coverage: 1.0
    resources:
      - "risk-register://airmf-2026"
  MANAGE-2.4:
    documented: true
    review_cadence_days: 365
    last_reviewed: "2025-12-01"
    evidence_uri: "https://wiki/ai-incident-response-plan"
    coverage: 0.95
  # ...
```

Per-entry fields: `documented`, `review_cadence_days`, `last_reviewed`,
`evidence_uri`, `coverage` (0..1), `resources` (optional), plus
`not_applicable` / `not_applicable_reason`.

## Implemented subcategories

| ID | Title | Severity |
|---|---|---|
| MANAGE-1.1 | Risks prioritized | HIGH |
| MANAGE-1.2 | Treatment of high-priority risks responded to | HIGH |
| MANAGE-1.3 | Decisions on response approach communicated | MEDIUM |
| MANAGE-1.4 | Negative impacts mitigated | HIGH |
| MANAGE-2.1 | Resources allocated for risk management | MEDIUM |
| MANAGE-2.2 | Mechanisms for sustained risk management | MEDIUM |
| MANAGE-2.4 | Mechanisms for incident response | HIGH |
| MANAGE-3.1 | Third-party risks regularly monitored | HIGH |
| MANAGE-3.2 | Mechanisms to track + report on risk management | MEDIUM |
| MANAGE-4.1 | Plans for ongoing risk monitoring | MEDIUM |

## Roadmap — documented, not yet implemented

The NIST AI RMF 1.0 MANAGE function documents ~14 subcategories total.
The following are intentionally out of scope for this slice:

- MANAGE-2.3
- MANAGE-3.3
- MANAGE-4.2, MANAGE-4.3

## Usage

```bash
python src/checks.py path/to/manage.yaml
export NIST_AI_RMF_MANAGE_MANIFEST=/etc/airmf/manage.yaml
python src/checks.py --output json --output-format ocsf
python src/checks.py path/to/manage.yaml --subcategory MANAGE-1.1
```

## Output

PASS / PARTIAL / FAIL / NOT_APPLICABLE per subcategory. Exit code is 1
if any HIGH/CRITICAL subcategory FAILs, 0 otherwise.
