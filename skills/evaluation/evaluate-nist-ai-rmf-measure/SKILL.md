---
name: evaluate-nist-ai-rmf-measure
description: >-
  Implements 10 of the NIST AI RMF 1.0 MEASURE function's ~21 documented
  subcategories. Use when an org wants to programmatically validate
  their NIST AI RMF MEASURE posture against a manifest of metric runs,
  test-set results, safety / security / privacy assessments, and
  monitoring plans. The skill verifies that the manifest exists, is
  current (within declared review cadence), declares evidence, and
  covers at least 50% of the population each subcategory applies to.
  Emits one OCSF Compliance Finding (class 2003) per subcategory with
  `compliance.requirement` set to the subcategory ID and
  `compliance.status` ∈ {pass, partial, fail, not_applicable}. Use when
  the user mentions NIST AI RMF MEASURE, AI test-set coverage audit,
  AI safety / security / privacy measurement, AI model evaluation
  freshness, or ongoing AI monitoring posture. Do NOT use as a
  substitute for the qualitative org-level assessment NIST AI RMF
  requires; this is a manifest-completeness + freshness check, not the
  assessment itself. Do NOT use to grade GOVERN, MAP, or MANAGE —
  those ship as sibling skills.
purpose: Implements 10 of the NIST AI RMF 1.0 MEASURE function's ~21 documented subcategories. Use when an org wants to programmatically validate their NIST AI RMF MEASURE posture against a manifest of metric runs, test-set re...
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/evaluation/evaluate-nist-ai-rmf-measure
  version: 0.1.0
  frameworks:
    - NIST AI RMF 1.0
    - OCSF 1.8
    - NIST CSF 2.0
  cloud: any
---

# Evaluate — NIST AI RMF 1.0 MEASURE

Manifest-completeness + freshness audit of the MEASURE function. Reads
a JSON/YAML manifest keyed by subcategory ID; emits one OCSF Compliance
Finding (class 2003) per implemented subcategory.

## Honest scope

This skill implements **10 of ~21** documented MEASURE subcategories.
It is a metric-run completeness + freshness audit — not the qualitative
NIST AI RMF assessment. The narrative the program owner attaches to
each metric run is what the assessment grades; this skill verifies that
the runs exist, are current, and reference the populations the framework
asks for.

## Use when

- CI-gated drift detection on AI test-set coverage
- Machine-readable evidence that safety / security / privacy metrics remain fresh
- Single command that asserts measurement approaches, performance, reliability, safety, security, privacy, and ongoing monitoring are documented per AI system
- OCSF-format findings that flow into the same SIEM as other posture skills

## Do NOT use

- As a substitute for the qualitative NIST AI RMF assessment
- To grade GOVERN, MAP, or MANAGE — those ship as sibling skills
- To run the underlying metrics — this skill only validates that they ran

## Manifest contract

The manifest is JSON or YAML; path is the positional CLI argument or the
`NIST_AI_RMF_MEASURE_MANIFEST` environment variable.

```yaml
subcategories:
  MEASURE-2.1:
    documented: true
    review_cadence_days: 90
    last_reviewed: "2026-04-15"
    evidence_uri: "s3://airmf/measure/test-sets-q2.json"
    coverage: 0.9
    resources:
      - "test-set://fraud-v3-q2-balanced"
  # ...
```

Per-entry fields: `documented`, `review_cadence_days`, `last_reviewed`,
`evidence_uri`, `coverage` (0..1), `resources` (optional), plus
`not_applicable` / `not_applicable_reason`.

## Implemented subcategories

| ID | Title | Severity |
|---|---|---|
| MEASURE-1.1 | Measurement approaches selected | HIGH |
| MEASURE-1.3 | Internal experts + external stakeholders consulted | MEDIUM |
| MEASURE-2.1 | Test sets + metrics for trustworthy characteristics | HIGH |
| MEASURE-2.3 | Performance evaluated under nominal conditions | HIGH |
| MEASURE-2.4 | System validated for context-of-use | HIGH |
| MEASURE-2.5 | Reliability assessed under context-of-use | MEDIUM |
| MEASURE-2.6 | Safety risks measured + documented | HIGH |
| MEASURE-2.7 | Security + resilience assessed | HIGH |
| MEASURE-2.10 | Privacy risks measured | HIGH |
| MEASURE-3.1 | Approaches for ongoing monitoring documented | MEDIUM |

## Roadmap — documented, not yet implemented

The NIST AI RMF 1.0 MEASURE function documents ~21 subcategories total.
The following are intentionally out of scope for this slice:

- MEASURE-1.2
- MEASURE-2.2, MEASURE-2.8, MEASURE-2.9, MEASURE-2.11, MEASURE-2.12, MEASURE-2.13
- MEASURE-3.2, MEASURE-3.3
- MEASURE-4.1, MEASURE-4.2, MEASURE-4.3

## Usage

```bash
python src/checks.py path/to/measure.yaml
export NIST_AI_RMF_MEASURE_MANIFEST=/etc/airmf/measure.yaml
python src/checks.py --output json --output-format ocsf
python src/checks.py path/to/measure.yaml --subcategory MEASURE-2.1
```

## Output

PASS / PARTIAL / FAIL / NOT_APPLICABLE per subcategory. Exit code is 1
if any HIGH/CRITICAL subcategory FAILs, 0 otherwise.
