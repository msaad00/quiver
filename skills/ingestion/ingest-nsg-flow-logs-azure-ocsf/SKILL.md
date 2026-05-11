---
name: ingest-nsg-flow-logs-azure-ocsf
description: >-
  Convert Azure NSG Flow Logs tuples into OCSF 1.8 Network Activity
  (class 4001). Parses the nested Azure Network Watcher flow-log export
  structure, supports tuple versions 1 and 2, normalizes allow or deny
  decisions, and preserves subscription and boundary context. Use when the
  user has Azure NSG Flow Logs and wants OCSF-normalized or repo-native
  network telemetry for correlation, detection, or storage. Use
  `--output-format ocsf` for OCSF 1.8 output and `--output-format native`
  for the repo's native network-activity JSONL emitted from the same
  canonical internal model. Do NOT use on Azure Activity Logs or Defender
  alerts. Do NOT use on AWS or GCP flow-log formats.
purpose: Convert Azure NSG Flow Logs tuples into OCSF 1.8 Network Activity (class 4001). Parses the nested Azure Network Watcher flow-log export structure, supports tuple versions 1 and 2, normalizes allow or deny decisions, a...
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

# ingest-nsg-flow-logs-azure-ocsf

## Use when

- You have Azure NSG Flow Logs from Network Watcher exports
- You need OCSF Network Activity output
- You want parity with AWS VPC Flow Logs and GCP VPC Flow Logs ingestors

## Do NOT use

- On Azure Activity Log events
- On Defender for Cloud alerts
- As a detector or remediation skill

## Input

JSON or JSONL of Azure NSG Flow Logs export payloads. The skill walks:

- `records[]` / `Records[]`
- `properties.flows[]`
- nested `flows[]`
- `flowTuples[]`

## Output

By default, the skill emits OCSF 1.8 Network Activity (class `4001`) JSONL with:

- source and destination IP/port
- packet and byte counters where tuple version provides them
- `cloud.provider = Azure`
- subscription and NSG boundary context

## Native output format

With `--output-format native`, the skill emits repo-native enriched JSONL with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "network_activity"`
- `event_uid`
- `provider`, `account_uid`, `region`
- `time_ms`
- `activity_id`, `activity_name`, `status_id`, `status`
- `src`, `dst`, `traffic`, `connection`, `cloud`
- `disposition`
- `source.kind = "azure.nsg-flow-logs"` plus NSG rule, MAC, and flow-state context

Native output is not raw Azure JSON and not a stripped OCSF envelope. It is the
repo's stable network-activity schema rendered from the same canonical internal
record as the OCSF path.

## Usage

```bash
python skills/ingestion/ingest-nsg-flow-logs-azure-ocsf/src/ingest.py --output-format native sample.json
```
