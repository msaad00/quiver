---
name: sink-snowflake-jsonl
description: >-
  Append JSONL records from stdin into a pre-provisioned Snowflake table using
  parameterized inserts only. Dry-run is the default and emits a native
  sink-result summary without writing. Use when the user already has findings,
  evidence, or audit rows and wants to persist them to Snowflake without
  changing the producing skill. Do NOT use for DDL, schema creation, table
  mutation, or arbitrary SQL execution. Do NOT use as an ingest, detect, or
  evaluation skill.
purpose: Append JSONL records from stdin into a pre-provisioned Snowflake table using parameterized inserts only.
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
network_egress: "*.snowflakecomputing.com"
caller_roles: security_engineer, platform_engineer
approver_roles: security_lead, data_platform_owner
min_approvers: 1
---

# sink-snowflake-jsonl

Append-only Snowflake sink: JSONL in on `stdin`, parameterized `INSERT` into a
pre-provisioned Snowflake table, native sink-result summary out on `stdout`.

## Use when

- Findings, evidence, or audit records already exist on stdin as JSONL
- You need a repo-owned persistence step after `detect-*`, `discover-*`, `view/*`, or another sink-safe producer
- The target Snowflake table already exists and should remain append-only

## Do NOT use

- For `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `MERGE`, `COPY`, or grant operations
- For schema migration or table bootstrap
- As a detector, ingest normalizer, or remediation workflow by itself
- When you need to write to a system other than Snowflake

## Do NOT do

- Do **not** point this skill at privileged admin tables
- Do **not** use `--apply` without an operator approval step outside the CLI
- Do **not** pass arbitrary SQL or quoted identifiers as the table name
- Do **not** assume this skill creates or changes schema for you

## Input

Reads JSONL from `stdin`. Each line must be a valid JSON object.

Accepted source shapes:

- repo-native event or finding JSON
- OCSF JSON
- bridge JSON
- raw JSON objects you intentionally want to persist as-is

Required CLI argument:

- `--table <table>` where `<table>` is a validated Snowflake identifier path:
  - `table`
  - `schema.table`
  - `database.schema.table`

Safety flags:

- default mode is dry-run
- `--apply` executes writes
- `--dry-run` keeps the write path disabled explicitly

## Output

Emits one repo-native sink-result JSON object to `stdout`:

- `schema_mode: "native"`
- `record_type: "sink_result"`
- `sink: "snowflake"`
- `table`
- `dry_run`
- `input_records`
- `inserted_records`
- `would_insert_records`
- `schema_modes`

## Sink table contract

This skill expects a pre-created table with at least these columns:

```sql
CREATE TABLE security_db.ops.findings_sink (
  payload VARIANT NOT NULL,
  schema_mode VARCHAR,
  event_uid VARCHAR,
  finding_uid VARCHAR,
  ingested_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
);
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
  | python skills/output/sink-snowflake-jsonl/src/sink.py \
      --table security_db.ops.findings_sink

# Explicit apply for direct operator use
python skills/discovery/discover-control-evidence/src/discover.py \
  | python skills/output/sink-snowflake-jsonl/src/sink.py \
      --table security_db.ops.evidence_sink \
      --apply
```

## Credentials

Uses the standard Snowflake connector environment variables:

- `SNOWFLAKE_ACCOUNT`
- `SNOWFLAKE_USER`
- `SNOWFLAKE_PASSWORD`

Optional:

- `SNOWFLAKE_WAREHOUSE`
- `SNOWFLAKE_DATABASE`
- `SNOWFLAKE_SCHEMA`
- `SNOWFLAKE_ROLE`

Prefer short-lived, manager-injected credentials or federation where your
Snowflake environment supports them.
