---
name: detect-azure-activity-logs-disabled
description: >-
  Detect successful Azure `Microsoft.Insights/diagnosticSettings/delete`
  operations from OCSF 1.8 API Activity records emitted by
  ingest-azure-activity-ocsf. Emits an OCSF 1.8 Detection Finding
  (class 2004) tagged with MITRE ATT&CK T1562.001 (Disable or Modify Tools)
  when a diagnostic setting is explicitly deleted. Use when the user mentions
  "Azure activity logs disabled," "diagnostic settings deleted," or "defense
  evasion in Azure logging." Do NOT use as a posture-at-rest check, to infer
  every logging impairment path, or for metric/resource-log pipelines outside
  the Azure Activity Log surface. This first slice only covers successful
  diagnostic-settings delete events.
purpose: Detect successful Azure `Microsoft.Insights/diagnosticSettings/delete` operations from OCSF 1.8 API Activity records emitted by ingest-azure-activity-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004) tagged with...
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
  from stdin/file and emits OCSF 1.8 Detection Finding 2004 to stdout. No
  Azure SDK; pairs with ingest-azure-activity-ocsf upstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-azure-activity-logs-disabled
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - CIS Azure Foundations
  cloud: azure
  capability: read-only
---

# detect-azure-activity-logs-disabled

Streaming detector for explicit Azure diagnostic-settings deletion events. This is
the Azure defense-evasion counterpart to the AWS and GCP logging-impaired
detectors under issue `#253`.

## Use when

- You stream Azure Activity Logs through `ingest-azure-activity-ocsf` and want near-real-time defense-evasion findings
- You want to catch explicit deletion of Azure diagnostic settings
- You are closing ATT&CK T1562.001 coverage with a read-only Azure detector

## Do NOT use

- As a posture-at-rest logging check; use Azure benchmark/evidence skills
- To infer every Azure logging impairment path; this first slice does not claim workspace unlink, policy drift, or destination weakening
- For Azure resource logs or metrics ingestion paths outside Activity Log

## Rule

A finding fires on every successful Azure Activity event from `ingest-azure-activity-ocsf` where:

1. `api.operation` case-insensitively equals `Microsoft.Insights/diagnosticSettings/delete`
2. `status_id == 1`
3. `resources[]` resolves a diagnostic setting resource id

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[].tactic_uid = TA0005` (Defense Evasion)
- `finding_info.attacks[].technique_uid = T1562.001` (Disable or Modify Tools)
- `observables[]` including `target.uid`, `target.name`, `account.uid`, `actor.name`, and `api.operation`

The native projection (`--output-format native`) keeps the target resource id and actor/account context in a flatter shape.

## Run

```bash
# Azure Activity -> ingest -> detect (default OCSF output)
python skills/ingestion/ingest-azure-activity-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-azure-activity-logs-disabled/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-azure-activity-logs-disabled/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-azure-activity-ocsf`](../../ingestion/ingest-azure-activity-ocsf/) — upstream ingester
- [`detect-cloudtrail-disabled`](../detect-cloudtrail-disabled/) — sibling AWS logging impairment detector
- [`detect-gcp-audit-logs-disabled`](../detect-gcp-audit-logs-disabled/) — sibling GCP logging impairment detector
