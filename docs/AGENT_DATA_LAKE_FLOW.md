# Agent Data Lake Flow

This repo supports three practical lake/runtime cases. Use the narrowest path that matches the data you already have.

## 1. Raw vendor data

`raw vendor data -> source-* | ingest-* | detect-*`

Use this when the lake holds original vendor payloads. The flow is:

1. `source-*` adapters read the vendor data.
2. `ingest-*` skills normalize it with deterministic reference transforms.
3. `detect-*` skills evaluate the normalized result.

Source adapters are read-only. They do not mutate the lake.

## 2. OCSF or repo-native lake data

`OCSF / repo-native lake data -> source-* | detect-*`

Use this when the lake already contains OCSF, canonical, or other repo-native records. In this case:

1. `source-*` adapters read the stored lake shape.
2. `detect-*` skills consume it directly.

No ingest step is required if the lake record is already in the detection-ready shape.

## 3. Custom schema lake data

`custom schema lake data -> agent-written SQL projection -> detect-*`

Use this when the lake schema is customer-specific and does not match the repo contract. The agent writes a SQL projection that maps the custom tables into the fields expected by `detect-*`.

Keep the projection small and explicit:

- select only the columns needed for detection
- preserve stable identifiers and timestamps
- avoid introducing write-back or schema changes

## Operator rule

Prefer read-only source access, deterministic ingest transforms, and the smallest projection that gets the data into `detect-*`.

## Hero deployment — ClickHouse security data lake

When the user wants the **full** repo-owned lake (write side + schema + read
side + replay loop), the documented hero use case is
[`CLICKHOUSE_DATA_LAKE.md`](CLICKHOUSE_DATA_LAKE.md). It composes
`sink-clickhouse-jsonl`, [`packs/clickhouse/`](../packs/clickhouse/), and
`source-clickhouse-query` into one closed loop with content-addressed uids,
TTL-managed retention, and tenant-isolating row policies.

The same closed loop ships warehouse-native on Snowflake — see
[`SNOWFLAKE_DATA_LAKE.md`](SNOWFLAKE_DATA_LAKE.md), which composes
`sink-snowflake-jsonl`, [`packs/snowflake/`](../packs/snowflake/), and
`source-snowflake-query` with dynamic-table rollups, row access policies, and
an optional Snowflake-managed Iceberg variant for open-format storage. Pick the
ClickHouse lane for a self-hosted low-latency lake, the Snowflake lane for a
governed open lakehouse, AWS Security Lake for an OCSF-native object lake —
by substrate, not by feature.
