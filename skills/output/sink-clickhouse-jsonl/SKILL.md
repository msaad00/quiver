---
name: sink-clickhouse-jsonl
description: >-
  Append JSONL records from stdin into a pre-provisioned ClickHouse table using
  the official ClickHouse client insert API only. Dry-run is the default and
  emits a native sink-result summary without writing. Use when the user
  already has findings, evidence, or audit rows and wants to persist them to
  ClickHouse without changing the producing skill. Do NOT use for DDL, schema
  creation, table mutation, or arbitrary SQL execution. Do NOT use as an
  ingest, detect, or evaluation skill.
purpose: Append JSONL records from stdin into a pre-provisioned ClickHouse table using the official ClickHouse client insert API only.
capability: write-sink
persistence: audit_log
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: human_required
execution_modes: jit, mcp, persistent
side_effects: writes-database
input_formats: raw, native, ocsf
output_formats: native
concurrency_safety: operator_coordinated
network_egress: "*.clickhouse.cloud"
caller_roles: security_engineer, platform_engineer
approver_roles: security_lead, data_platform_owner
min_approvers: 1
---

# sink-clickhouse-jsonl

Append-only ClickHouse sink: JSONL in on `stdin`, client-side insert into a
pre-provisioned ClickHouse table, native sink-result summary out on `stdout`.

## Use when

- Findings, evidence, or audit records already exist on stdin as JSONL
- You need a repo-owned persistence step after `detect-*`, `discover-*`, `view/*`, or another sink-safe producer
- The target ClickHouse table already exists and should remain append-only

## Do NOT use

- For `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `OPTIMIZE`, or grant operations
- For schema migration or table bootstrap
- As a detector, ingest normalizer, or remediation workflow by itself
- When you need to write to a system other than ClickHouse

## Do NOT do

- Do **not** point this skill at privileged admin tables
- Do **not** use `--apply` without an operator approval step outside the CLI
- Do **not** pass arbitrary SQL as a table name
- Do **not** assume this skill creates or changes schema for you

## Input

Reads JSONL from `stdin`. Each line must be a valid JSON object.

Accepted source shapes:

- repo-native event or finding JSON
- OCSF JSON
- raw JSON objects you intentionally want to persist as-is

Required CLI argument:

- `--table <table>` where `<table>` is a validated ClickHouse identifier path:
  - `table`
  - `database.table`

Safety flags:

- default mode is dry-run
- `--apply` executes writes
- `--dry-run` keeps the write path disabled explicitly

## Output

Emits one repo-native sink-result JSON object to `stdout`:

- `schema_mode: "native"`
- `record_type: "sink_result"`
- `sink: "clickhouse"`
- `table`
- `dry_run`
- `input_records`
- `inserted_records`
- `would_insert_records`
- `schema_modes`

## Sink table contract

This skill expects a pre-created table with at least these columns:

```sql
CREATE TABLE security.findings_sink (
  payload String,
  schema_mode LowCardinality(String),
  event_uid String,
  finding_uid String,
  ingested_at DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (schema_mode, event_uid, finding_uid);
```

The skill only inserts into:

- `payload`
- `schema_mode`
- `event_uid`
- `finding_uid`

It does not create, alter, or merge schema.

## Examples

```bash
# Dry-run by default
python skills/detection/detect-lateral-movement/src/detect.py < events.ocsf.jsonl \
  | python skills/output/sink-clickhouse-jsonl/src/sink.py \
      --table security.findings_sink

# Explicit apply for direct operator use
python skills/discovery/discover-control-evidence/src/discover.py \
  | python skills/output/sink-clickhouse-jsonl/src/sink.py \
      --table security.evidence_sink \
      --apply
```

## Credentials

Uses the standard ClickHouse connector environment variables:

- `CLICKHOUSE_HOST`
- `CLICKHOUSE_USER`
- `CLICKHOUSE_PASSWORD`

Optional:

- `CLICKHOUSE_PORT`
- `CLICKHOUSE_DATABASE`
- `CLICKHOUSE_SECURE`

Prefer manager-injected credentials and TLS-enabled ClickHouse Cloud endpoints.
