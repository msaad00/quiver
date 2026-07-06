---
name: ingest-workday-audit-ocsf
description: >-
  Convert Workday REST, Report-as-a-Service, or audit report exports into OCSF
  1.8 Account Change (3001) events for HR identity lifecycle monitoring.
  Recognizes termination, rehire, hire, and worker-change events from common
  Workday report fields while preserving tenant-specific fields under
  `unmapped.workday.raw`. Use when the user has Workday audit/report JSON and
  needs an OCSF stream for IAM departures, mass-termination detection, or
  downstream offboarding evidence. Do NOT use as a live Workday collector, on
  payroll or compensation content, or as remediation.
purpose: Convert Workday HR audit/report records into OCSF Account Change events.
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. No Workday SDK required when REST/RaaS/audit report
  payloads are already exported. Read-only normalizer; never calls Workday APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-workday-audit-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: workday
  capability: read-only
---

# ingest-workday-audit-ocsf

Normalize Workday audit/report exports into OCSF 1.8 Account Change events with
deterministic IDs and preserved tenant evidence.

## Use when

- You have Workday REST, RaaS, or audit report JSON already exported upstream
- You need termination, hire, rehire, or worker-change events in an OCSF stream
- You want `iam-departures-reconciler` or a detector to consume HR events without another direct Workday query
- You need native JSONL for a pipeline that is not OCSF-aware yet

## Do NOT use

- As a live collector; OAuth and Workday API collection stay upstream
- On payroll, compensation, benefits, or personal-data report content beyond lifecycle audit fields
- To infer findings directly; use detection skills on the normalized stream
- To terminate, rehire, disable, or otherwise change Workday or IAM state

## Input contract

Accepts these Workday export shapes:

1. A response object with `Report_Entry[]`
2. Objects with `data[]`, `events[]`, `items[]`, or `value[]`
3. A single audit/report object
4. A JSON array of audit/report objects
5. JSONL, one object or wrapper per line

The skill classifies common event names and report fields such as
`eventName`, `businessProcess`, `businessProcessType`, `action`,
`terminationDate`, `rehireDate`, `workerId`, `workerEmail`, `supervisoryOrg`,
and `initiatedBy`. Unsupported tenant-specific fields are preserved under
`unmapped.workday.raw` rather than guessed.

## Output contract

Default output is OCSF 1.8 Account Change JSONL:

- `activity_id=4` for termination
- `activity_id=1` for hire
- `activity_id=3` for rehire, worker-change, or generic account-change events

Every event includes:

- deterministic `metadata.uid`
- epoch-ms `time`
- `actor`, `user`, and `resources` where present
- Workday-native evidence under `unmapped.workday`

With `--output-format native`, the skill emits the repo-owned canonical
projection with `schema_mode: "native"` and a `workday` evidence block.

## Usage

```bash
python src/ingest.py workday-audit-report.json > workday-audit.ocsf.jsonl
python src/ingest.py workday-audit-report.json --output-format native > workday-audit.native.jsonl
```

## Security guardrails

- Read-only only. No Workday API calls and no token handling.
- Preserves raw report evidence for audit correlation.
- Keeps invalid records visible in `stderr_jsonl` so coverage gaps are measurable.

## Roadmap

Part of Workday vendor story issue #34.
