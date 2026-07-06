# SIEM Index Guide

This repo supports `native`, `canonical`, `ocsf`, and `bridge` modes. This guide covers the **OCSF and bridge outputs** you may index into Splunk, Sentinel, Chronicle, ClickHouse, Elastic, Snowflake, or Security Lake-adjacent stores. If you store canonical or native artifacts as well, keep their entity keys and normalized UTC time fields aligned with the same indexing model.

## Goals

- preserve deterministic event identity
- make cross-cloud search cheap
- make finding dedupe explicit
- keep just-in-time and persistent ingestion compatible

## Required index fields

These should be parsed and indexed for every OCSF event:

| Field | Why it matters |
|---|---|
| `metadata.uid` | event-level dedupe key for emitted OCSF events |
| `metadata.product.vendor_name` | producer identity |
| `metadata.product.feature.name` | emitting skill |
| `category_uid` / `class_uid` / `type_uid` | fast class and event-type filters |
| `time` | canonical UTC event time in epoch milliseconds |
| `severity_id` / `status_id` | triage and filtering |

For findings, also index:

| Field | Why it matters |
|---|---|
| `finding_info.uid` | finding-level identity across replay and sink merges |
| `finding_info.types[]` | rule family / finding family |
| `finding_info.attacks[].technique.uid` | ATT&CK / ATLAS pivoting |

For cloud correlation, index when present:

| Field | Why it matters |
|---|---|
| `cloud.provider` | provider partitioning |
| `cloud.account.uid` | account / project / subscription pivot |
| `cloud.region` | region / location pivot |
| `resources[].uid` / `resources[].name` / `resources[].type` | asset lookup |
| `actor.user.uid` / `actor.user.name` | identity correlation |
| `src_endpoint.ip` / `dst_endpoint.ip` | network pivoting |

## Dedupe rules

- **Event-level dedupe:** use `metadata.uid`
- **Finding-level dedupe:** use `finding_info.uid`
- **Bridge evidence dedupe:** use `metadata.uid` and keep the native evidence payload under `unmapped.*`

Do not dedupe on `time` alone. Replays, backfills, and multi-sink fanout will produce duplicate timestamps by design.

## Time and timezone handling

- all OCSF `time`, `start_time`, `end_time`, `first_seen_time`, and `last_seen_time` values are **UTC epoch milliseconds**
- convert to local time only in the presentation layer
- keep the raw epoch-ms field indexed even if the SIEM creates a derived datetime field

## Just-in-time vs persistent ingestion

The repo supports both:

- **just-in-time / CLI / MCP**
  - ideal for ad hoc investigation and local triage
  - index `metadata.uid` and `finding_info.uid` the same way as persistent pipelines
- **persistent / continuous**
  - use the same fields, but add sink-side merge-on-UID behavior
  - preserve `metadata.uid` through transport and sink transforms

The point is that a one-off CLI run and a queued/serverless run should produce index-compatible documents.

## Data protection and integrity

- TLS in transit for any remote sink or transport
- encryption at rest in the destination store
- treat inbound logs, findings, and scanner output as untrusted input until parsed and validated
- never strip `metadata.uid`, `metadata.product.*`, or `finding_info.uid` during ETL

## Search patterns

Useful filters:

- producer:
  - `metadata.product.vendor_name="msaad00/cloud-ai-security-skills"`
  - `metadata.product.feature.name="detect-lateral-movement"`
- class:
  - `class_uid=2004` for Detection Findings
  - `class_uid=2003` for Compliance Findings
  - `class_uid=5023` for Cloud Resources Inventory bridge events
  - `class_uid=5040` for Live Evidence bridge events
- provider:
  - `cloud.provider in ("AWS","Azure","GCP","Kubernetes")`
- framework:
  - `finding_info.attacks.technique.uid=*`
  - `unmapped.cloud_security_technical_evidence.frameworks=*`

## Compatibility notes

Some repo-local bridge/profile identifiers intentionally keep older names:

- `cloud_security_mcp`
- `cloud-security.environment-graph.v1`
- `cloud-security:*` CycloneDX AI BOM property keys

These are compatibility contracts, not the public repo identity. For product attribution and indexing, rely on `metadata.product.*`.
