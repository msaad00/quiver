---
name: detect-snowflake-warehouse-resize-burst
description: >-
  Detect sudden compute scaling on a Snowflake warehouse that crosses the
  configured size-jump threshold inside a sliding window. Reads OCSF 1.8 API
  Activity (class 6003) records normalized from Snowflake `query_history`
  carrying `actor.user.uid`, `api.operation == "ALTER_WAREHOUSE"`, and
  Snowflake-shaped `unmapped.snowflake.{warehouse_name,warehouse_size_from,
  warehouse_size_to}` fields, groups them by warehouse, and emits one OCSF
  1.8 Detection Finding (class 2004) per (warehouse, window) tagged with
  MITRE ATT&CK T1496 Resource Hijacking. Use when the user suspects compute
  hijacking (e.g. crypto-mining via warehouse, runaway scheduled job, account
  takeover). Do NOT use on raw Snowflake QUERY_HISTORY JSON before OCSF
  normalization, as a billing-cost detector, or on non-Snowflake API
  Activity 6003.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native, ocsf
concurrency_safety: requires_consistent_sharding
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-snowflake-warehouse-resize-burst
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - snowflake
---

# detect-snowflake-warehouse-resize-burst

## Attack pattern

Snowflake warehouses are billed per second of active compute. An attacker
who reaches a role with `MODIFY` on a warehouse can scale it up several
sizes in seconds (XSMALL → XLARGE / X4LARGE / 6XLARGE) and run sustained
queries — turning the victim's account into a paid compute pool for
crypto-mining, model training, or large-batch scraping. The scale-up
event itself is the cheap anchor; spotting the burst before billing
runs is the high-leverage detection.

On the wire the pattern is:

- `ALTER WAREHOUSE <name> SET WAREHOUSE_SIZE = '<larger-size>'`
- repeated rapidly to ratchet through sizes

Both surfaces materialize in Snowflake QUERY_HISTORY and normalize into
OCSF 1.8 API Activity (class `6003`) once ingested.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` identifies a Snowflake ingest source:

1. Filter to `api.operation == "ALTER_WAREHOUSE"` with
   `unmapped.snowflake.warehouse_name` and both `warehouse_size_from`
   and `warehouse_size_to` populated.
2. Require a successful event (`status_id == 1`).
3. Group by `warehouse_name`, sort by event time.
4. Maintain a sliding window (default 60 minutes, configurable via
   `SNOWFLAKE_RESIZE_WINDOW_MIN`).
5. Inside the window, track the smallest `size_index` observed (from
   the earliest `warehouse_size_from`) and the largest reached.
6. Fire once per (warehouse, window) when the cumulative jump
   `max_index - min_index >= SNOWFLAKE_RESIZE_MIN_SIZE_JUMP` (default 3,
   e.g. XSMALL → LARGE).

The detector emits one finding per (warehouse, window) — never per
ALTER. It suppresses repeat findings until the warehouse has been
quiet for longer than the configured window.

Operators can tune the burst logic at runtime without forking:

- `SNOWFLAKE_RESIZE_WINDOW_MIN` — sliding window in minutes (default 60)
- `SNOWFLAKE_RESIZE_MIN_SIZE_JUMP` — minimum size-index jump (default 3)

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["snowflake-warehouse-resize-burst", "OWASP-Top-10-A04"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1496` (tactic
  `TA0040 Impact`)
- `evidence.warehouse_name`, `evidence.min_size`, `evidence.max_size`,
  `evidence.size_jump`, `evidence.events_observed`
- `observables[]` carrying the impacted warehouse and size endpoints

Severity is `MEDIUM` (severity_id `3`).

## Usage

```bash
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py \
  > snowflake_resize_burst_findings.ocsf.jsonl
```

## Do NOT use

- On raw Snowflake QUERY_HISTORY JSON before OCSF normalization
- As a billing / cost detector
- As a remediation skill — warehouse-resize lockdown lives in the
  remediation layer
- On non-Snowflake API Activity 6003

## Tests

The test suite covers:

- positive: 3-size jump fires once per warehouse / window
- positive: incremental 1-size steps that sum to 3 also fire
- negative: 2-size jump stays under threshold
- negative: failed ALTER does not fire
- negative: events from a non-Snowflake producer are ignored
- edge: out-of-order events still fire once
- edge: duplicate `metadata.uid` does not inflate counts
- env-override: `SNOWFLAKE_RESIZE_MIN_SIZE_JUMP` and
  `SNOWFLAKE_RESIZE_WINDOW_MIN` honored

## Roadmap

Fourth of 18 warehouse-platform vendor-depth detectors for issue #436.
