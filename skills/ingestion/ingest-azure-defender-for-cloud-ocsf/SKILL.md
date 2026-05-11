---
name: ingest-azure-defender-for-cloud-ocsf
description: >-
  Convert Azure Defender for Cloud alerts into OCSF 1.8 Detection Finding
  (class 2004). Validates the alert envelope, normalizes severity and
  resource context, and emits deterministic passthrough findings suitable
  for downstream enrichment or rendering. Supports `--output-format ocsf`
  and `--output-format native` from the same canonical internal finding
  shape. Use when the user has Defender for Cloud alerts and wants
  normalized findings. Do NOT use on Azure Activity Logs, NSG Flow Logs,
  or custom detections. Do NOT use as a detector; Defender already
  produced the alert and this skill only validates and normalizes it.
purpose: Convert Azure Defender for Cloud alerts into OCSF 1.8 Detection Finding (class 2004). Validates the alert envelope, normalizes severity and resource context, and emits deterministic passthrough findings suitable for d...
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

# ingest-azure-defender-for-cloud-ocsf

Thin passthrough ingestion skill: raw Defender for Cloud alert JSON in ->
canonical finding projection -> OCSF 1.8 Detection Finding JSONL or native
enriched finding JSONL out.

## Use when

- You have Defender for Cloud alert payloads from the API or wrappers
- You need OCSF Detection Finding or native enriched finding output
- You want parity with GuardDuty, Security Hub, and SCC passthroughs

## Do NOT use

- On Azure Activity Logs
- On NSG Flow Logs
- As a remediation skill

## Input

JSONL or a top-level JSON array of:

- direct Defender alert objects
- REST list wrappers containing `value`

## Output

`--output-format ocsf` returns OCSF 1.8 Detection Findings carrying:

- alert title and description
- Defender severity mapped to OCSF severity_id
- Azure resource and subscription context
- passthrough provenance in `observables[]`

## Native output format

`--output-format native` returns one JSON object per Defender alert with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "detection_finding"`
- `event_uid` and `finding_uid`
- `provider`, `account_uid`, `region`
- `time_ms`
- `severity_id`, `severity_label`, `status_id`, `status`
- `title`, `description`, `finding_types`
- `resources`, `cloud`, `source`, `compliance`, and `evidence`

The native shape keeps the same normalized semantics as the OCSF projection,
but omits the OCSF envelope fields such as `class_uid`, `category_uid`,
`type_uid`, and `metadata.product`.
