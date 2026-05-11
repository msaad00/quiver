---
name: evaluate-nist-ai-rmf-govern
description: >-
  Implements 10 of the NIST AI RMF 1.0 GOVERN function's ~25 documented
  subcategories. Use when an org wants to programmatically validate their
  NIST AI RMF posture against a manifest of policies, role assignments,
  training records, and inventory mechanisms. The skill verifies that the
  manifest exists, is current (within declared review cadence), declares
  evidence, and covers at least 50% of the population each subcategory
  applies to. Emits one OCSF Compliance Finding (class 2003) per
  subcategory with `compliance.requirement` set to the subcategory ID
  and `compliance.status` ∈ {pass, partial, fail, not_applicable}. Use
  when the user mentions NIST AI RMF GOVERN, AI governance posture,
  AI risk-management policy audit, AI roles + responsibilities review,
  or AI inventory completeness check. Do NOT use as a substitute for
  the qualitative org-level assessment NIST AI RMF requires; this is a
  manifest-completeness + freshness check, not the assessment itself.
  Do NOT use to grade the other three functions (MAP / MEASURE / MANAGE)
  — those ship as sibling skills.
purpose: Implements 10 of the NIST AI RMF 1.0 GOVERN function's ~25 documented subcategories. Use when an org wants to programmatically validate their NIST AI RMF posture against a manifest of policies, role assignments, train...
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/evaluation/evaluate-nist-ai-rmf-govern
  version: 0.1.0
  frameworks:
    - NIST AI RMF 1.0
    - OCSF 1.8
    - NIST CSF 2.0
  cloud: any
---

# Evaluate — NIST AI RMF 1.0 GOVERN

Manifest-completeness + freshness audit of the GOVERN function. Reads a
JSON/YAML manifest keyed by subcategory ID; emits one OCSF Compliance
Finding (class 2003) per implemented subcategory.

## Honest scope

This skill implements **10 of ~25** documented GOVERN subcategories. It
is a manifest-completeness and freshness check — not the qualitative
org-level assessment NIST AI RMF requires. The narrative the program
owner attaches to the manifest is what the assessment grades; this skill
verifies that the inputs to that grading exercise exist, are current,
and cover the populations the framework asks for.

## Use when

- You want CI-gated drift detection on the artefacts NIST AI RMF GOVERN expects
- You need machine-readable evidence ("manifest is fresh, coverage 80%") for an auditor
- You want a single command that asserts policies / roles / training / inventory all exist
- You want OCSF-format compliance findings that flow into the same SIEM as your other posture skills

## Do NOT use

- As a substitute for the qualitative NIST AI RMF assessment
- To grade MAP, MEASURE, or MANAGE — those ship as sibling skills
- To audit a single AI system in isolation — GOVERN is an organisation-level function

## Manifest contract

The manifest is a JSON or YAML mapping. Path is `--manifest <path>` or the
`NIST_AI_RMF_GOVERN_MANIFEST` environment variable. Top level may be flat
or under a `subcategories:` key. Each entry follows the same schema:

```yaml
subcategories:
  GOVERN-1.1:
    documented: true
    review_cadence_days: 365
    last_reviewed: "2026-01-15"
    evidence_uri: "s3://ai-rmf/policies/ai-risk-mgmt-v3.pdf"
    coverage: 1.0
    resources:
      - "policy://ai-risk-management-v3"
  GOVERN-1.2:
    documented: true
    review_cadence_days: 180
    last_reviewed: "2026-03-01"
    evidence_uri: "https://wiki.example/ai-rmf-roles"
    coverage: 0.9
  # ...
```

Per-entry fields:

| Field | Type | Required | Notes |
|---|---|---|---|
| `documented` | bool | yes | Set `true` once the artefact exists |
| `review_cadence_days` | int | yes | How often this subcategory must be re-reviewed |
| `last_reviewed` | ISO date | yes | UTC date of last review |
| `evidence_uri` | string | yes | Pointer to the artefact (S3, wiki, file://) |
| `coverage` | float 0..1 | yes | Fraction of population covered |
| `resources` | list[string] | no | Resource names the OCSF finding cites |
| `not_applicable` | bool | no | If true, the entry returns NOT_APPLICABLE |
| `not_applicable_reason` | string | no | Required when `not_applicable: true` |

## Implemented subcategories

| ID | Title | Severity |
|---|---|---|
| GOVERN-1.1 | AI risk management documented and reviewed | HIGH |
| GOVERN-1.2 | Roles, responsibilities, and lines of authority defined | HIGH |
| GOVERN-1.4 | AI risk management integrated with enterprise risk | MEDIUM |
| GOVERN-1.6 | Mechanisms to inventory AI systems | HIGH |
| GOVERN-2.1 | Workforce trained on AI risk | MEDIUM |
| GOVERN-3.1 | Policies for impacted communities | MEDIUM |
| GOVERN-4.1 | Organizational practices documented for AI development | MEDIUM |
| GOVERN-5.1 | Policies for third-party AI input | HIGH |
| GOVERN-6.1 | AI risk decisions communicated upward | MEDIUM |
| GOVERN-6.2 | Mechanisms to address AI risk in third-party transactions | HIGH |

## Roadmap — documented, not yet implemented

The NIST AI RMF 1.0 GOVERN function documents ~25 subcategories total.
The following are intentionally out of scope for this slice and will be
added in subsequent iterations:

- GOVERN-1.3, GOVERN-1.5, GOVERN-1.7
- GOVERN-2.2, GOVERN-2.3
- GOVERN-3.2
- GOVERN-4.2, GOVERN-4.3
- GOVERN-5.2
- GOVERN-6.3

## Usage

```bash
# Run all 10 GOVERN subcategories
python src/checks.py path/to/govern.yaml

# Or via env var
export NIST_AI_RMF_GOVERN_MANIFEST=/etc/airmf/govern.yaml
python src/checks.py

# Single subcategory
python src/checks.py path/to/govern.yaml --subcategory GOVERN-1.1

# OCSF output for SIEM ingest
python src/checks.py path/to/govern.yaml --output json --output-format ocsf
```

## Output

PASS / PARTIAL / FAIL / NOT_APPLICABLE per subcategory:

- **PASS** — documented, reviewed within cadence, evidence_uri set, coverage ≥ 50%
- **PARTIAL** — documented + coverage ≥ 50%, but stale or missing evidence pointer
- **FAIL** — undocumented, missing review metadata, or coverage < 50%
- **NOT_APPLICABLE** — entry sets `not_applicable: true` with a reason
- **ERROR** — manifest entry is malformed (not a mapping)

Exit code is 1 if any HIGH/CRITICAL subcategory FAILs, 0 otherwise.
