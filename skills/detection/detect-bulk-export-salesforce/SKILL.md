---
name: detect-bulk-export-salesforce
description: >-
  Detect large Salesforce report, Bulk API, Data Loader, or export activity
  followed by a logout/session close in the same Salesforce session or actor
  window. Reads OCSF 1.8 Application Activity (6002) or native records emitted
  by `ingest-salesforce-event-mon-ocsf`, applies row/byte thresholds, and emits
  OCSF Detection Finding (2004) tagged with MITRE ATT&CK T1567. Use when the
  user mentions Salesforce report export, CRM data exfiltration, Data Loader,
  Bulk API export, or suspicious logout after export. Do NOT use on raw
  Salesforce Event Monitoring data before normalization, non-Salesforce logs,
  or as remediation.
purpose: Detect Salesforce bulk data export followed by session close.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native, ocsf
concurrency_safety: stateless
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-bulk-export-salesforce
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - salesforce
---

# detect-bulk-export-salesforce

## Use when

- You normalized Salesforce Event Monitoring data with `ingest-salesforce-event-mon-ocsf`
- You need to catch report/Bulk API/Data Loader exports followed quickly by session close
- You want a stateless CRM exfiltration detector before downstream containment

## Do NOT use

- On raw Event Monitoring CSV or JSON before ingestion
- On GitHub, Slack, Workday, Snowflake, Databricks, or generic web logs
- As remediation; session revocation and connected-app containment require separate HITL-gated write skills

## Detection logic

One pass over Salesforce Application Activity events:

1. Require producer `ingest-salesforce-event-mon-ocsf`.
2. Require `unmapped.salesforce.event_family=export`.
3. Require `rows_processed >= SALESFORCE_BULK_EXPORT_MIN_ROWS` or `bytes >= SALESFORCE_BULK_EXPORT_MIN_BYTES`.
4. Correlate a later `event_family=logout` in the same session, or same actor when the session key is absent.
5. Ignore actors listed in `SALESFORCE_APPROVED_EXPORT_USERS`.

Defaults:

```bash
export SALESFORCE_BULK_EXPORT_MIN_ROWS=10000
export SALESFORCE_BULK_EXPORT_MIN_BYTES=52428800
export SALESFORCE_EXPORT_LOGOUT_WINDOW_MINUTES=30
```

## Output contract

Default output is OCSF Detection Finding (class `2004`) with:

- deterministic `metadata.uid`
- `finding_info.types[] = ["salesforce-bulk-export", "OWASP-Top-10-A01"]`
- MITRE ATT&CK `T1567`
- actor, client, source IP, row/byte thresholds, session key, and raw event IDs in evidence

Severity is `HIGH`.

## Usage

```bash
cat salesforce.ocsf.jsonl | python src/detect.py > salesforce-export-findings.ocsf.jsonl
```

## Roadmap

Part of Salesforce vendor story issue #35.
