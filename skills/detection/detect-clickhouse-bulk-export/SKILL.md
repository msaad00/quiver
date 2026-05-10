---
name: detect-clickhouse-bulk-export
description: >-
  Detect single-principal bulk row export out of a ClickHouse cluster. Reads
  OCSF 1.8 API Activity (class 6003) records carrying `actor.user.uid`,
  `api.operation`, and ClickHouse-shaped
  `unmapped.clickhouse.{query_kind,read_bytes,read_rows,written_bytes,written_rows,query,exception}`
  fields, groups them by principal across a sliding window, and emits an OCSF
  1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1567
  Exfiltration Over Web Service whenever cumulative `read_bytes` for queries
  whose SQL text matches an external-export pattern (`INTO OUTFILE`,
  `INSERT INTO FUNCTION s3(`, `URL(`) crosses the configured byte threshold.
  Use when you suspect a compromised ClickHouse account or service principal
  is dumping rows to S3, an external HTTP endpoint, or a local OUTFILE. Do
  NOT use on raw ClickHouse `system.query_log` rows — normalize them through
  the upstream ClickHouse ingest pipeline first. Do NOT use as a generic
  data-loss detector for non-ClickHouse warehouses.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native, ocsf
concurrency_safety: requires_consistent_sharding
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-clickhouse-bulk-export
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - clickhouse
---

# detect-clickhouse-bulk-export

## Attack pattern

A compromised ClickHouse account or service principal exfiltrates a large
volume of data by writing query results to an external destination. The
shape on the wire is one of:

- `SELECT ... FROM <table> INTO OUTFILE '<path>'` — local file dump on the
  client side or on the server filesystem
- `INSERT INTO FUNCTION s3('<url>', ...) SELECT ... FROM <table>` — push
  rows directly into a (typically external / cross-tenant) object store
- `INSERT INTO FUNCTION url('<url>', ...) SELECT ...` — POST rows to an
  arbitrary HTTP endpoint via the `url(...)` table function or the `URL`
  table engine

All three surfaces are visible in ClickHouse `system.query_log` and all
three materialize in OCSF 1.8 API Activity (class `6003`) once normalized.
Legitimate ETL tends to write to one well-known sink — an attacker tends
to cross the byte threshold quickly because export queries naturally
re-read large slices of the underlying tables.

This skill keeps the logic narrow to that pattern. It does not flag every
single-event large query, and it does not attempt to reason about every
ClickHouse statement that could move data.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.vendor_name == "ClickHouse"`:

1. Drop failed queries (`unmapped.clickhouse.exception` non-empty) — a
   query that errored never moved any rows out.
2. Keep only queries whose `unmapped.clickhouse.query` text matches one of
   the export patterns (case-insensitive):
   - `INTO OUTFILE`
   - `INSERT INTO FUNCTION s3(`
   - `URL(`
3. Group the remaining events by `actor.user.uid`.
4. Sort by event time.
5. Maintain a sliding window (default 60 minutes, configurable via
   `CLICKHOUSE_EXPORT_WINDOW_MIN`).
6. Inside the window, accumulate per-principal cumulative
   `unmapped.clickhouse.read_bytes`.
7. Fire **once per (principal, window)** when cumulative `read_bytes`
   crosses `CLICKHOUSE_EXPORT_BYTE_THRESHOLD` (default `10_737_418_240`
   bytes = 10 GiB).

The detector emits one finding per (principal, window) — never per row —
and suppresses repeat findings until there is a quiet period longer than
the configured window.

Operators can tune the burst logic at runtime without forking the skill:

- `CLICKHOUSE_EXPORT_WINDOW_MIN`
- `CLICKHOUSE_EXPORT_BYTE_THRESHOLD`

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["clickhouse-bulk-export", "OWASP-Top-10-A04"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1567` (tactic
  `TA0010 Exfiltration`)
- `evidence.read_bytes`, `evidence.read_rows`, `evidence.written_bytes`,
  `evidence.written_rows`, `evidence.export_targets`,
  `evidence.raw_event_uids`
- `observables[]` carrying the impacted principal, distinct export
  targets, and cumulative volumes

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
cat clickhouse_query_log.ocsf.jsonl \
  | python src/detect.py \
  > clickhouse_bulk_export_findings.ocsf.jsonl

# Same input, native finding projection out:
cat clickhouse_query_log.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > clickhouse_bulk_export_findings.native.jsonl
```

## Do NOT use

- On raw ClickHouse `system.query_log` JSON before OCSF normalization
- As a generic data-loss detector for Snowflake / Databricks / BigQuery
- As a remediation skill — quarantine of a ClickHouse principal lives in
  the remediation layer
- On non-ClickHouse API Activity 6003 (we filter on
  `metadata.product.vendor_name == "ClickHouse"` plus the export-pattern
  match in the SQL text)

## Tests

The test suite covers:

- positive: multiple `INTO OUTFILE` / `INSERT INTO FUNCTION s3(...)` /
  `URL(...)` queries cumulatively crossing the byte threshold fires once
  per principal
- negative: failed queries (`exception` set) are skipped even if their
  `read_bytes` is large
- negative: a single non-export `SELECT` over the threshold does not fire
- positive: multiple statements aggregate into one finding
- edge: malformed payloads (missing `unmapped.clickhouse` block, bad JSON)
  are skipped without crashing the pipeline

## Roadmap

This is the first ClickHouse detector for issue #436. Five more ClickHouse
detectors stay open and will reuse the same input contract.
