---
name: detect-gcp-audit-logs-disabled
description: >-
  Detect successful GCP Cloud Logging `DeleteSink` and `DeleteLog` API calls
  from OCSF 1.8 API Activity records emitted by ingest-gcp-audit-ocsf. Emits
  an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK
  T1562.001 (Disable or Modify Tools) when a log sink or log stream is
  explicitly deleted. Use when the user mentions "GCP audit logs disabled,"
  "logging sink deleted," "DeleteLog," or "defense evasion in GCP logging."
  Do NOT use as a posture-at-rest check, to infer IAM auditConfig changes, or
  to claim every possible GCP logging impairment path. This first slice only
  covers successful `DeleteSink` and `DeleteLog` events.
purpose: Detect successful GCP Cloud Logging `DeleteSink` and `DeleteLog` API calls from OCSF 1.8 API Activity records emitted by ingest-gcp-audit-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK...
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
compatibility: >-
  Requires Python 3.11+. Read-only — consumes OCSF 1.8 API Activity records
  from stdin/file and emits OCSF 1.8 Detection Finding 2004 to stdout. No GCP
  SDK; pairs with ingest-gcp-audit-ocsf upstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-gcp-audit-logs-disabled
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - CIS GCP Foundations
  cloud: gcp
  capability: read-only
---

# detect-gcp-audit-logs-disabled

Streaming detector for explicit GCP Cloud Logging impairment operations. This is
the next concrete slice under issue `#253`: it adds a tested GCP defense-evasion
detector instead of broadening ATT&CK claims without shipped code.

## Use when

- You stream GCP audit logs through `ingest-gcp-audit-ocsf` and want near-real-time defense-evasion findings
- You want to catch explicit deletion of logging sinks or log streams
- You are closing ATT&CK T1562.001 coverage with a read-only GCP detector

## Do NOT use

- As a posture-at-rest logging check; use [`cspm-gcp-cis-benchmark`](../../evaluation/cspm-gcp-cis-benchmark/)
- To infer IAM `auditConfigs` changes or sink-filter weakening; the shipped ingester does not preserve those request bodies
- To claim every possible GCP logging impairment path; this first slice is only `DeleteSink` and `DeleteLog`

## Rule

A finding fires on every successful Cloud Logging event from `ingest-gcp-audit-ocsf` where:

1. `api.operation` is `google.logging.v2.ConfigServiceV2.DeleteSink` or `google.logging.v2.LoggingServiceV2.DeleteLog`
2. `status_id == 1`
3. `resources[]` resolves a sink or log target name

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[].tactic_uid = TA0005` (Defense Evasion)
- `finding_info.attacks[].technique_uid = T1562.001` (Disable or Modify Tools)
- `observables[]` including `target.name`, `target.type`, `account.uid`, `actor.name`, and `api.operation`

The native projection (`--output-format native`) keeps the target and actor/account context in a flatter shape.

## Run

```bash
# GCP audit logs -> ingest -> detect (default OCSF output)
python skills/ingestion/ingest-gcp-audit-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-gcp-audit-logs-disabled/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-gcp-audit-logs-disabled/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-gcp-audit-ocsf`](../../ingestion/ingest-gcp-audit-ocsf/) — upstream ingester
- [`cspm-gcp-cis-benchmark`](../../evaluation/cspm-gcp-cis-benchmark/) — posture-at-rest logging coverage
- [`detect-cloudtrail-disabled`](../detect-cloudtrail-disabled/) — sibling AWS logging impairment detector
