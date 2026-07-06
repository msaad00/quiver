---
name: detect-api-anomaly-salesforce
description: >-
  Detect Salesforce API activity by a user or integration outside an
  operator-maintained baseline of approved clients, source IPs, or event-volume
  limits. Reads OCSF 1.8 Application Activity (6002) or native records emitted
  by `ingest-salesforce-event-mon-ocsf`, groups API events by actor and time
  window, and emits OCSF Detection Finding (2004) tagged with MITRE ATT&CK
  T1078.004. Use when the user mentions Salesforce API anomaly, suspicious
  integration, connected app drift, API usage spike, or unexpected source IP.
  Do NOT use on raw Event Monitoring data before normalization, non-Salesforce
  logs, or as remediation.
purpose: Detect Salesforce API activity outside an operator baseline.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-api-anomaly-salesforce
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - salesforce
---

# detect-api-anomaly-salesforce

## Use when

- You normalized Salesforce Event Monitoring data with `ingest-salesforce-event-mon-ocsf`
- You need to detect API activity from unexpected clients, source IPs, or event volume
- You want a stateless detector for suspicious integrations and valid-account abuse

## Do NOT use

- On raw Event Monitoring CSV or JSON before ingestion
- On generic web access logs or non-Salesforce SaaS audit events
- As remediation; connected-app disablement and session kill need HITL-gated write skills

## Detection logic

One pass over Salesforce Application Activity events:

1. Require producer `ingest-salesforce-event-mon-ocsf`.
2. Require `unmapped.salesforce.event_family=api`.
3. Group events by actor and `SALESFORCE_API_ANOMALY_WINDOW_MINUTES`. Default is `60`.
4. Compare clients, source IPs, and event count with `SALESFORCE_API_BASELINE_JSON`.
5. When no actor baseline exists, fire if count reaches `SALESFORCE_API_ANOMALY_EVENT_THRESHOLD`. Default is `25`.

Baseline example:

```bash
export SALESFORCE_API_BASELINE_JSON='{"005svc":{"client_names":["ApprovedClient"],"ips":["203.0.113.10"],"max_events":100}}'
export SALESFORCE_API_ALLOWED_CLIENTS="InternalGateway"
```

## Output contract

Default output is OCSF Detection Finding (class `2004`) with:

- deterministic `metadata.uid`
- `finding_info.types[] = ["salesforce-api-anomaly", "OWASP-Top-10-A01"]`
- MITRE ATT&CK `T1078.004`
- actor, reason, event count, clients, source IPs, operations, and raw event IDs in evidence

Severity is `HIGH`.

## Usage

```bash
cat salesforce.ocsf.jsonl | python src/detect.py > salesforce-api-findings.ocsf.jsonl
```

## Roadmap

Part of Salesforce vendor story issue #35.
