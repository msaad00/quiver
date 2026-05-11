---
name: ingest-vpc-flow-logs-gcp-ocsf
description: >-
  Convert raw GCP VPC Flow Logs records into OCSF 1.8 Network Activity
  (class 4001). Accepts Cloud Logging LogEntry envelopes or bare
  jsonPayload-shaped records, maps connection metadata, byte counters,
  VPC and instance context, and normalizes accepted or denied traffic into
  a deterministic OCSF or repo-native stream. Use when the user has GCP
  VPC Flow Logs and wants OCSF-normalized or repo-native network telemetry
  for correlation, detection, or rendering. Use `--output-format ocsf`
  for OCSF 1.8 output and `--output-format native` for the repo's native
  network-activity JSONL emitted from the same canonical internal model.
  Do NOT use on firewall rule logs, packet mirroring, or raw pcap. Do NOT
  use when the source is AWS or Azure network telemetry.
purpose: Convert raw GCP VPC Flow Logs records into OCSF 1.8 Network Activity (class 4001). Accepts Cloud Logging LogEntry envelopes or bare jsonPayload-shaped records, maps connection metadata, byte counters, VPC and instance...
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

# ingest-vpc-flow-logs-gcp-ocsf

## Use when

- You have GCP VPC Flow Logs from Cloud Logging exports
- You need OCSF Network Activity for downstream detection or storage
- You want a parity path alongside AWS VPC Flow Logs and Azure NSG Flow Logs

## Do NOT use

- On non-GCP network telemetry
- On raw pcap or packet mirroring captures
- As a detection skill; this only normalizes telemetry

## Input

JSONL or a top-level JSON array of GCP VPC Flow Logs entries. Supports both:

- full Cloud Logging `LogEntry` envelopes with `jsonPayload`
- bare `jsonPayload`-style objects containing `connection`, `src_*`, `dest_*`, and counter fields

## Output

By default, the skill emits OCSF 1.8 Network Activity (class `4001`) JSONL with:

- `src_endpoint` / `dst_endpoint`
- `traffic.bytes` and `traffic.packets`
- `connection_info.protocol_*`, `direction`, and `boundary`
- `cloud.provider = GCP`
- `cloud.account.uid` from the project

## Native output format

With `--output-format native`, the skill emits repo-native enriched JSONL with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "network_activity"`
- `event_uid`
- `provider`, `account_uid`, `region`
- `time_ms`, `start_time_ms`, `end_time_ms`
- `activity_id`, `activity_name`, `status_id`, `status`
- `src`, `dst`, `traffic`, `connection`, `cloud`
- `disposition`
- `source.kind = "gcp.vpc-flow-logs"` plus reporter and VPC context

Native output is not raw GCP JSON and not a stripped OCSF envelope. It is the
repo's stable network-activity schema rendered from the same canonical internal
record as the OCSF path.

## Usage

```bash
python skills/ingestion/ingest-vpc-flow-logs-gcp-ocsf/src/ingest.py --output-format native sample.jsonl
```

## Notes

- `disposition` maps to OCSF activity IDs where present; when absent, records default to accepted traffic
- byte and packet counters are aggregated across both directions when both are present
- timestamps preserve flow `start_time` / `end_time` when the source provides them
