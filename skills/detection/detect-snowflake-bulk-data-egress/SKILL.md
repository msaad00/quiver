---
name: detect-snowflake-bulk-data-egress
description: >-
  Detect single-principal bulk data egress out of Snowflake. Reads OCSF 1.8 API
  Activity (class 6003) records carrying `actor.user.uid`, `api.operation`, and
  Snowflake-shaped `unmapped.snowflake.{rows_unloaded,bytes_scanned,stage_name}`
  fields, groups them by principal across a sliding window, and emits an OCSF
  1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1567 Exfiltration
  Over Web Service whenever cumulative bytes_scanned, rows_unloaded, and
  distinct stage usage cross the configured thresholds. Use when you suspect a
  Snowflake account, SCIM-provisioned user, or service principal is staging
  large query results out via `COPY INTO <external_stage>` or `GET @stage/...`.
  Do NOT use on raw Snowflake QUERY_HISTORY rows — normalize them through the
  upstream Snowflake ingest pipeline first. Do NOT use as a generic data-loss
  detector for non-Snowflake warehouses.
purpose: Detect single-principal bulk data egress out of Snowflake.
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
concurrency_safety: requires_consistent_sharding
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-snowflake-bulk-data-egress
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - snowflake
---

# detect-snowflake-bulk-data-egress

## Attack pattern

A compromised Snowflake account, SCIM-provisioned user, or service principal
exfiltrates a large volume of data by repeatedly unloading query results to an
external stage. The shape on the wire is:

- `COPY INTO @<external_stage> FROM <table>` writing rows to S3 / GCS / Azure
- `GET @<external_stage>/...` pulling staged files down to the client

Both surfaces are visible in Snowflake QUERY_HISTORY and ACCESS_HISTORY and
both materialize in OCSF 1.8 API Activity (class `6003`) once normalized. A
single legitimate ETL job tends to use one stage; an attacker exfiltrating
data tends to fan out across multiple stages and inflate cumulative
`bytes_scanned` / `rows_unloaded` for one principal.

This skill keeps the logic narrow to that pattern. It does not flag every
single-event large query, and it does not guess at every Snowflake operation
that could move data.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` identifies a Snowflake ingest source:

1. Group by `actor.user.uid`.
2. Sort by event time.
3. Maintain a sliding window (default 60 minutes, configurable via
   `SNOWFLAKE_EGRESS_WINDOW_MIN`).
4. Inside the window, accumulate per-principal:
   - cumulative `unmapped.snowflake.bytes_scanned`
   - cumulative `unmapped.snowflake.rows_unloaded`
   - distinct `unmapped.snowflake.stage_name`s
5. Fire **once per (principal, window)** when:
   - cumulative `bytes_scanned` >= `SNOWFLAKE_EGRESS_BYTE_THRESHOLD`
     (default `5_368_709_120` bytes = 5 GiB), **OR**
   - cumulative `rows_unloaded` >= `SNOWFLAKE_EGRESS_ROW_THRESHOLD`
     (default `1_000_000`),
   - **AND** distinct `stage_name` count >= `SNOWFLAKE_EGRESS_MIN_STAGES`
     (default `3`).

The detector emits one finding per (principal, window) — never per row — and
suppresses repeat findings until there is a quiet period longer than the
configured window.

Operators can tune the burst logic at runtime without forking the skill:

- `SNOWFLAKE_EGRESS_WINDOW_MIN`
- `SNOWFLAKE_EGRESS_BYTE_THRESHOLD`
- `SNOWFLAKE_EGRESS_ROW_THRESHOLD`
- `SNOWFLAKE_EGRESS_MIN_STAGES`

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["snowflake-bulk-data-egress", "OWASP-Top-10-A04"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1567` (tactic
  `TA0010 Exfiltration`)
- `evidence.bytes_scanned`, `evidence.rows_unloaded`, `evidence.stage_names`,
  `evidence.raw_event_uids`
- `observables[]` carrying the impacted principal, stage names, and
  cumulative volumes

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py \
  > snowflake_bulk_egress_findings.ocsf.jsonl

# Same input, native finding projection out:
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > snowflake_bulk_egress_findings.native.jsonl
```

## Do NOT use

- On raw Snowflake QUERY_HISTORY / ACCESS_HISTORY JSON before OCSF
  normalization
- As a generic data-loss detector for Databricks / ClickHouse / BigQuery
- As a remediation skill — quarantine of a Snowflake principal lives in the
  remediation layer
- On non-Snowflake API Activity 6003 (we filter on the Snowflake-shaped
  `unmapped.snowflake.*` block plus the producer source skill)

## Tests

The test suite covers:

- positive: 3+ stages crossing the byte threshold fires once per principal
- positive: 3+ stages crossing the row threshold fires when bytes are below
- negative: single-stage burst over the byte threshold does NOT fire (legit
  ETL pattern)
- negative: single event over both thresholds does NOT fire (pattern requires
  >=2 events to hit >=3 distinct stages by definition)
- edge: out-of-order events still fire once
- edge: events from a non-Snowflake producer are ignored
- edge: duplicate `metadata.uid` does not inflate counts
- env-override: the four threshold env vars are honored

## Roadmap

This is the first warehouse-platform vendor-depth detector for issue #436.
Remaining 17 detectors (5 more Snowflake, 6 Databricks, 6 ClickHouse) stay
open and will reuse the same input contract.
