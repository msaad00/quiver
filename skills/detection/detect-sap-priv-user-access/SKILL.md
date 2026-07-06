---
name: detect-sap-priv-user-access
description: >-
  Detect SAP privileged user access from OCSF 1.8 Application Activity (6002)
  or native records emitted by `ingest-sap-audit-log-ocsf`. Flags logon,
  privileged profile, or sensitive transaction activity by SAP*, DDIC,
  EARLYWATCH, SAP_ALL, SAP_NEW, or configured privileged identities and emits
  OCSF Detection Finding (2004) tagged with MITRE ATT&CK T1078. Use when the
  user mentions SAP_ALL, SAP_NEW, SAP*, DDIC, privileged SAP logon, or SAP
  sensitive user access. Do NOT use on raw SAP SAL exports before
  normalization, non-SAP logs, or as remediation.
purpose: Detect privileged SAP user or profile access from normalized SAP SAL events.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-sap-priv-user-access
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - sap
---

# detect-sap-priv-user-access

## Use when

- You normalized SAP Security Audit Log events with `ingest-sap-audit-log-ocsf`
- You need to catch access by SAP*, DDIC, EARLYWATCH, SAP_ALL, SAP_NEW, or configured privileged users
- You want a stateless privileged-access finding before downstream review or containment

## Do NOT use

- On raw SAP SAL CSV, text, or JSON before ingestion
- On Salesforce, Slack, Workday, Snowflake, Databricks, or generic web logs
- As remediation; user lock, profile removal, and session termination require separate HITL-gated write skills

## Detection logic

One pass over SAP Application Activity events:

1. Require producer `ingest-sap-audit-log-ocsf`.
2. Require `unmapped.sap.event_family` of `login`, `privileged_access`, or `transaction`.
3. Match actor against `SAP_PRIVILEGED_USERS`, defaulting to `SAP*`, `DDIC`, and `EARLYWATCH`.
4. Match SAP privilege/profile evidence against `SAP_PRIVILEGED_PROFILES`, defaulting to `SAP_ALL` and `SAP_NEW`.
5. Ignore actors listed in `SAP_APPROVED_PRIVILEGED_USERS`.

## Output contract

Default output is OCSF Detection Finding (class `2004`) with:

- deterministic `metadata.uid`
- `finding_info.types[] = ["sap-privileged-user-access", "OWASP-Top-10-A01"]`
- MITRE ATT&CK `T1078`
- actor, SAP client, transaction, profile, source IP, and raw event ID evidence

Severity is `HIGH`.

## Usage

```bash
cat sap.ocsf.jsonl | python src/detect.py > sap-privileged-findings.ocsf.jsonl
```

## Roadmap

Part of SAP vendor story issue #36.
