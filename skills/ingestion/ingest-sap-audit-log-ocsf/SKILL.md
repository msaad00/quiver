---
name: ingest-sap-audit-log-ocsf
description: >-
  Convert SAP Security Audit Log (SAL) exports into OCSF 1.8 Application
  Activity (6002) events. Accepts JSON/JSONL/CSV and common delimited text
  exports for logon, logoff, privileged profile, transaction start, RFC, and
  sensitive change activity, preserving SAP-native fields under
  `unmapped.sap.raw`. Use when the user has exported SAP SAL evidence and needs
  OCSF or native JSONL for privileged-access and mass-change detections. Do NOT
  use as a live SAP collector, on business record payloads, or as remediation.
purpose: Convert SAP Security Audit Log exports into OCSF Application Activity events.
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
  Requires Python 3.11+. No SAP SDK required when SAL exports are already
  available. Read-only normalizer; never calls SAP APIs or changes SAP state.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-sap-audit-log-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: sap
  capability: read-only
---

# ingest-sap-audit-log-ocsf

Normalize SAP Security Audit Log exports into OCSF 1.8 Application Activity
events with deterministic IDs and preserved vendor evidence.

## Use when

- You have SAP Security Audit Log JSON/JSONL/CSV or delimited text exports
- You need SAP logon, logoff, transaction, privileged profile, RFC, or change activity in one OCSF stream
- You want to feed SAP privileged-user or mass-change detectors without connecting to SAP
- You need native JSONL for a pipeline that is not OCSF-aware yet

## Do NOT use

- As a live collector; SAP connection, extraction, and credential handling stay upstream
- On business record content payloads or customer data
- To infer findings directly; use detection skills on the normalized stream
- To lock users, remove profiles, transport changes, or alter SAP configuration

## Input contract

Accepts these shapes:

1. A JSON object with `records[]`, `events[]`, `items[]`, `data[]`, `audit_log[]`, or `SecurityAuditLog[]`
2. A single SAL row object
3. A JSON array of row objects
4. JSONL, one row or wrapper per line
5. CSV or common `|`, `;`, or tab-delimited SAL exports with a header row
6. Headerless `date|time|client|user|terminal|transaction|message` rows

The skill recognizes common SAL export fields such as `timestamp`, `date`,
`time`, `client`, `user`, `terminal`, `source_ip`, `transaction`,
`message_id`, `message_text`, `program`, `table`, `role`, `profile`, and
`change_count`. Unknown fields are preserved under `unmapped.sap.raw`.

## Output contract

Default output is OCSF 1.8 Application Activity JSONL:

- `activity_id=2` for logon, transaction, and RFC activity
- `activity_id=3` for SAP change and privileged access activity
- `activity_id=99` for logoff and unclassified application activity
- `unmapped.sap.event_family` set to `login`, `logout`, `privileged_access`, `transaction`, `change`, `rfc`, or `application`

Every event includes:

- deterministic `metadata.uid`
- epoch-ms `time`
- `actor`, `src_endpoint`, `resources`, and `api` where present
- SAP-native evidence under `unmapped.sap`

With `--output-format native`, the skill emits the repo-owned canonical
projection with `schema_mode: "native"` and a `sap` evidence block.

## Usage

```bash
python src/ingest.py sap-security-audit-log.csv > sap.ocsf.jsonl
python src/ingest.py sap-security-audit-log.json --output-format native > sap.native.jsonl
```

## Security guardrails

- Read-only only. No SAP API calls and no credential handling.
- Preserves raw event evidence for audit correlation.
- Skips invalid rows with `stderr_jsonl` warnings rather than guessing.

## Roadmap

Part of SAP vendor story issue #36.
