---
name: ingest-salesforce-event-mon-ocsf
description: >-
  Convert Salesforce Event Monitoring exports into OCSF 1.8 Application
  Activity (6002) events. Accepts Event Monitoring JSON/JSONL and Event Log
  File CSV exports for login, logout, report export, Bulk API, API, Data Loader,
  report, and application activity families, preserving Salesforce-native
  fields under `unmapped.salesforce.raw`. Use when the user has Salesforce
  Event Monitoring data and needs OCSF or native JSONL for CRM data-exfil and
  API-anomaly detections. Do NOT use as a live Salesforce collector, on record
  content payloads, or as remediation.
purpose: Convert Salesforce Event Monitoring audit exports into OCSF Application Activity events.
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
  Requires Python 3.11+. No Salesforce SDK required when Event Monitoring
  payloads or Event Log File CSV exports are already available. Read-only
  normalizer; never calls Salesforce APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-salesforce-event-mon-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: salesforce
  capability: read-only
---

# ingest-salesforce-event-mon-ocsf

Normalize Salesforce Event Monitoring exports into OCSF 1.8 Application
Activity events with deterministic IDs and preserved vendor evidence.

## Use when

- You have Salesforce Event Monitoring JSON/JSONL or Event Log File CSV exports
- You need login, logout, report export, Bulk API, Data Loader, or API activity in one OCSF stream
- You want to feed Salesforce data-exfil or API-baseline detectors without re-querying Salesforce
- You need native JSONL for a pipeline that is not OCSF-aware yet

## Do NOT use

- As a live collector; OAuth and Salesforce API collection stay upstream
- On CRM record content payloads or field-level customer data
- To infer findings directly; use detection skills on the normalized stream
- To revoke sessions, connected apps, users, or any Salesforce state

## Input contract

Accepts these shapes:

1. A JSON object with `records[]`, `events[]`, `items[]`, or `data[]`
2. A single Event Monitoring row object
3. A JSON array of row objects
4. JSONL, one row or wrapper per line
5. Event Log File CSV with a header row

The skill recognizes common Event Monitoring fields such as `EVENT_TYPE`,
`TIMESTAMP`, `USER_ID`, `USERNAME`, `CLIENT_IP`, `CLIENT_NAME`,
`SESSION_KEY`, `REQUEST_ID`, `ROWS_PROCESSED`, `REPORT_ID`, `URI`, and
`METHOD`. Unknown fields are preserved under `unmapped.salesforce.raw`.

## Output contract

Default output is OCSF 1.8 Application Activity JSONL:

- `activity_id=2` for login, API, report, and export activity
- `activity_id=99` for logout and unclassified application activity
- `unmapped.salesforce.event_family` set to `login`, `logout`, `export`, `api`, `report`, or `application`

Every event includes:

- deterministic `metadata.uid`
- epoch-ms `time`
- `actor`, `src_endpoint`, `session`, `resources`, `api`, and `http_request` where present
- Salesforce-native evidence under `unmapped.salesforce`

With `--output-format native`, the skill emits the repo-owned canonical
projection with `schema_mode: "native"` and a `salesforce` evidence block.

## Usage

```bash
python src/ingest.py salesforce-event-log.csv > salesforce.ocsf.jsonl
python src/ingest.py salesforce-event-log.json --output-format native > salesforce.native.jsonl
```

## Security guardrails

- Read-only only. No Salesforce API calls and no token handling.
- Preserves raw event evidence for audit correlation.
- Skips invalid rows with `stderr_jsonl` warnings rather than guessing.

## Roadmap

Part of Salesforce vendor story issue #35.
