---
name: ingest-vpc-flow-logs-ocsf
description: >-
  Convert raw AWS VPC Flow Logs (v5 format, space-delimited) into OCSF 1.8
  Network Activity events (class 4001). Handles both the canonical v5 field
  order and custom field orders via a header-driven parser. Maps source /
  destination IP, ports, protocol, byte counts, packet counts, action
  (ACCEPT / REJECT), TCP flags, flow direction, and the VPC / subnet /
  ENI / instance identifiers into OCSF src_endpoint / dst_endpoint /
  traffic / connection_info / cloud fields. Sets activity_id based on
  action. Emits one OCSF event per flow log record. Use when the user
  mentions VPC Flow Logs, AWS network telemetry, east-west traffic, or
  wants to feed VPC Flow into a SIEM or lateral-movement detector. Do
  NOT use for GCP VPC Flow Logs (use ingest-vpc-flow-logs-gcp-ocsf),
  Azure NSG Flow Logs (use ingest-nsg-flow-logs-azure-ocsf), or CloudTrail
  (use ingest-cloudtrail-ocsf). Do NOT use as a
  detection skill — this only normalises network flows.
purpose: Convert raw AWS VPC Flow Logs (v5 format, space-delimited) into OCSF 1.8 Network Activity events (class 4001). Handles both the canonical v5 field order and custom field orders via a header-driven parser. Maps source...
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

# ingest-vpc-flow-logs-ocsf

Thin ingestion skill: raw AWS VPC Flow Log records in → canonical network-flow projection → OCSF 1.8 Network Activity JSONL or native enriched network-flow JSONL out. No detection logic, no AWS API calls, no side effects.

## Wire contract

Reads VPC Flow Logs in the **v5 space-delimited format** that AWS delivers to CloudWatch Logs Insights, S3, or Kinesis Firehose. Each record is one line. The first line may be a header declaring the field order (CloudWatch delivery includes it; S3 delivery does not). When no header is present, the skill falls back to the canonical v5 default order:

```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
```

The skill also understands the v5 extended fields if they are declared in the header: `vpc-id subnet-id instance-id tcp-flags type pkt-srcaddr pkt-dstaddr region az-id sublocation-type sublocation-id pkt-src-aws-service pkt-dst-aws-service flow-direction traffic-path`.

By default it writes OCSF 1.8 **Network Activity** (`class_uid: 4001`, `category_uid: 4`). See [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md).

When `--output-format native` is selected, it emits the same flow in the repo's native enriched shape with stable `event_uid`, normalized source/destination, byte counters, protocol/direction, and AWS scope fields, but without the OCSF envelope.

## Native output format

`--output-format native` returns one JSON object per flow with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "network_activity"`
- `event_uid`
- `provider`, `account_uid`, `region`
- `time_ms`, `start_time_ms`, `end_time_ms`
- `activity_id`, `activity_name`
- `status_id`, `status`
- `src`, `dst`, `traffic`, `connection`, `cloud`, and `source`

The native shape preserves the same normalized network semantics as the OCSF
projection while omitting the OCSF envelope fields such as `class_uid`,
`category_uid`, `type_uid`, and `metadata.product`.

## activity_id mapping

VPC Flow Logs have an `action` field with two values: `ACCEPT` and `REJECT`. OCSF Network Activity activity ids map as:

| `action` | OCSF activity | id |
|---|---|---:|
| `ACCEPT` | Traffic (allowed) | 6 |
| `REJECT` | Traffic Denied | 7 |
| missing / `-` | Unknown | 0 |

## Field mapping

| VPC Flow Log field | OCSF field |
|---|---|
| `srcaddr` | `src_endpoint.ip` |
| `srcport` | `src_endpoint.port` |
| `dstaddr` | `dst_endpoint.ip` |
| `dstport` | `dst_endpoint.port` |
| `protocol` (numeric) | `connection_info.protocol_num` and `connection_info.protocol_name` (mapped via IANA numbers for TCP=6, UDP=17, ICMP=1) |
| `packets` | `traffic.packets` |
| `bytes` | `traffic.bytes` |
| `tcp-flags` (bitmask) | `connection_info.tcp_flags` (comma-joined symbolic names) |
| `start`, `end` (seconds) | `start_time` and `end_time` (ms epoch) |
| `end` | `time` (ms epoch — the event "time" is the flow end time) |
| `action` | derives `activity_id` per the table above |
| `account-id` | `cloud.account.uid` |
| `region` | `cloud.region` |
| `interface-id` | `src_endpoint.interface_uid` (+ `dst_endpoint.interface_uid` for the destination side when known) |
| `vpc-id` | `connection_info.boundary` (custom extension to carry the VPC) |
| `subnet-id` | set on the source endpoint — attackers care about same-subnet vs cross-subnet |
| `instance-id` | `src_endpoint.instance_uid` |
| `flow-direction` | `connection_info.direction` (`ingress` / `egress`) |
| `log-status` | dropped if `NODATA` or `SKIPDATA` (those records have no real fields) |

`cloud.provider` is hard-coded to `"AWS"`.

## Protocol number → name

Standard IANA mapping. Full table in `src/ingest.py` (`_PROTOCOL_NAMES`). The subset VPC Flow actually emits:

| num | name |
|---:|---|
| 1 | ICMP |
| 6 | TCP |
| 17 | UDP |
| 47 | GRE |
| 50 | ESP |
| 51 | AH |
| 58 | ICMPv6 |

Unknown numbers fall through as `""` (and `protocol_num` is still set).

## TCP flags decoder

`tcp-flags` in v5 is a **bitmask of OR'd flag bits**, not a space-separated list:

| bit | flag |
|---:|---|
| 1 | FIN |
| 2 | SYN |
| 4 | RST |
| 8 | PSH |
| 16 | ACK |
| 32 | URG |

So `tcp-flags=18` means `SYN|ACK`. The skill decodes this into a comma-joined string for `connection_info.tcp_flags` so SQL consumers can grep.

## What's NOT mapped

- `pkt-srcaddr` / `pkt-dstaddr` (inner packet addrs for ENI-terminated flows) — low-signal unless tracking NAT, add on demand
- `pkt-src-aws-service` / `pkt-dst-aws-service` — AWS service name inference, useful but lossy
- `traffic-path` (1–8 enum for via-NAT-gateway, via-TGW, etc.) — useful for path analysis, add in a follow-up
- `type` (IPv4 / IPv6 / EFA) — always present but the OCSF schema doesn't have a native slot without custom extension

## Usage

```bash
# Single file from S3 (after sync / gunzip)
python src/ingest.py vpc-flow.log > vpc-flow.ocsf.jsonl

# Same input, native enriched output
python src/ingest.py vpc-flow.log --output-format native > vpc-flow.native.jsonl

# Piped from CloudWatch Logs Insights query output (JSON format)
aws logs start-query --log-group-name "/aws/vpc/flow" ... \
  | jq -r '.results[][] | select(.field=="@message") | .value' \
  | python src/ingest.py
```

## Behaviour on malformed input

- One bad line → stderr warning, line skipped, pipeline continues
- Header line (starts with `version` word) → consumed, sets the field-order map
- `NODATA` / `SKIPDATA` status → stderr note, line skipped (those records have no usable flow data)
- Unknown field in header → ignored (forward compatibility for v6+ fields)

## Tests

Golden fixture parity against [`../golden/vpc_flow_logs_raw_sample.log`](../golden/vpc_flow_logs_raw_sample.log) → [`../golden/vpc_flow_logs_sample.ocsf.jsonl`](../golden/vpc_flow_logs_sample.ocsf.jsonl). Plus unit tests for every field mapping, the `tcp-flags` bitmask decoder, the protocol-number table, ACCEPT vs REJECT activity mapping, header-driven vs default field order, and `NODATA` / `SKIPDATA` skipping.
