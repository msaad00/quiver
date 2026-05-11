---
name: ingest-gcp-scc-ocsf
description: >-
  Convert GCP Security Command Center findings into OCSF 1.8 Detection
  Finding (class 2004). Validates the minimal finding contract, preserves
  SCC metadata such as category, severity, state, and resource name, and
  emits deterministic OCSF-normalized passthrough findings. Use when the
  user has SCC findings and wants them normalized for storage, routing,
  enrichment, or rendering. Do NOT use on raw audit logs or posture
  benchmark output. Do NOT use as a detector; SCC already produced the
  finding and this skill only validates and normalizes it.
purpose: Convert GCP Security Command Center findings into OCSF 1.8 Detection Finding (class 2004). Validates the minimal finding contract, preserves SCC metadata such as category, severity, state, and resource name, and emits...
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: ocsf, native
concurrency_safety: stateless
---

# ingest-gcp-scc-ocsf

## Use when

- You have SCC findings from the API or export wrappers
- You need OCSF Detection Finding output for downstream systems
- You want parity with GuardDuty, Security Hub, and Defender passthroughs

## Do NOT use

- On raw GCP audit logs
- On non-SCC findings
- As a detection or remediation skill

## Input

JSONL or a top-level JSON array of:

- direct SCC finding objects
- wrapper objects containing `finding`
- wrapper objects containing `findings`

## Output

OCSF 1.8 Detection Findings with:

- SCC finding category and description in `finding_info`
- SCC severity mapped to OCSF severity_id
- GCP resource context in `resources[]` and `cloud`
- raw passthrough provenance preserved in `observables[]`

When `--output-format native` is selected, the skill emits the repo's native enriched finding shape instead of the OCSF envelope.

## Native output format

`--output-format native` returns one JSON object per SCC finding with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "detection_finding"`
- `event_uid` and `finding_uid`
- `provider`, `account_uid`, `region`
- `time_ms`
- `severity_id`, `severity`, `status_id`, `status`
- `title`, `description`, `finding_types`
- `resources`, `cloud`, `source`, and `evidence`

The native shape keeps the same normalized semantics as the OCSF projection,
but omits `class_uid`, `category_uid`, `type_uid`, and `metadata.product`.
