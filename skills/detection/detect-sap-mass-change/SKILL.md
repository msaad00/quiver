---
name: detect-sap-mass-change
description: >-
  Detect bursts of SAP changes through sensitive transactions such as SU01,
  PFCG, SM30, SE16, SE38, SCC4, STMS, RZ10, and SM59. Reads OCSF 1.8
  Application Activity (6002) or native records emitted by
  `ingest-sap-audit-log-ocsf`, aggregates per actor/client/transaction window,
  and emits OCSF Detection Finding (2004) tagged with MITRE ATT&CK T1565. Use
  when the user mentions SAP mass change, sensitive transaction abuse, role
  changes, table maintenance, user maintenance, or transport/configuration
  manipulation. Do NOT use on raw SAP SAL exports before normalization,
  non-SAP logs, or as remediation.
purpose: Detect mass changes through sensitive SAP transactions.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-sap-mass-change
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - sap
---

# detect-sap-mass-change

## Use when

- You normalized SAP Security Audit Log events with `ingest-sap-audit-log-ocsf`
- You need to catch bursts through sensitive SAP transactions or table/user/role maintenance paths
- You want a stateless integrity detector before downstream change review

## Do NOT use

- On raw SAP SAL CSV, text, or JSON before ingestion
- On Salesforce, Slack, Workday, Snowflake, Databricks, or generic web logs
- As remediation; transport rollback, role removal, and user locking require separate HITL-gated write skills

## Detection logic

Aggregate SAP Application Activity events by actor, client, transaction, and time window:

1. Require producer `ingest-sap-audit-log-ocsf`.
2. Require `unmapped.sap.event_family` of `change`, `privileged_access`, or `transaction`.
3. Require transaction in `SAP_SENSITIVE_TRANSACTIONS`.
4. Sum `unmapped.sap.change_count`; events without a count contribute `1`.
5. Emit when the total is at least `SAP_MASS_CHANGE_EVENT_THRESHOLD`.
6. Ignore actors listed in `SAP_APPROVED_MASS_CHANGE_USERS`.

Defaults:

```bash
export SAP_MASS_CHANGE_WINDOW_MINUTES=15
export SAP_MASS_CHANGE_EVENT_THRESHOLD=25
export SAP_SENSITIVE_TRANSACTIONS=SU01,SU10,PFCG,SM30,SE16,SE16N,SE38,SE80,SCC4,STMS,RZ10,RZ11,SM59
```

## Output contract

Default output is OCSF Detection Finding (class `2004`) with:

- deterministic `metadata.uid`
- `finding_info.types[] = ["sap-mass-change", "OWASP-Top-10-A04"]`
- MITRE ATT&CK `T1565`
- actor, client, transaction, change count, threshold, window, and raw event ID evidence

Severity is `HIGH`.

## Usage

```bash
cat sap.ocsf.jsonl | python src/detect.py > sap-mass-change-findings.ocsf.jsonl
```

## Roadmap

Part of SAP vendor story issue #36.
