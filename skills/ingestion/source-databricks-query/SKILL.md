---
name: source-databricks-query
description: >-
  Run a read-only Databricks SQL query and emit the result set as raw JSONL
  rows for downstream ingestion, detection, or view skills. Accepts explicit
  `--query` SQL or reads the query from stdin when no `--query` is provided.
  Only `SELECT`, `WITH`, `SHOW`, and `DESCRIBE` statements are allowed, and
  multiple statements, SQL comments, session controls, optimizer/admin verbs,
  dynamic identifier helpers, and common control/write keywords are rejected.
  Use when the user already has security data in Databricks and wants to pipe
  lake rows into existing skills without exporting files first. Do NOT use
  for writes, DDL, or admin changes. Do NOT use as a detector or normalizer
  by itself.
purpose: Run a read-only Databricks SQL query and emit the result set as raw JSONL rows for downstream ingestion, detection, or view skills.
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: raw
concurrency_safety: stateless
network_egress: "*.databricks.com"
---

# source-databricks-query

Read-only source adapter: Databricks SQL query in, raw JSONL rows out. This
skill does not normalize vendor data, detect threats, or write back to
Databricks. It exists so operators and agents can fetch already-landed lake
data and pipe it into the existing `ingest-*`, `detect-*`, `discover-*`, or
`view/*` skills.

## Use when

- Security data already lives in Databricks SQL
- You want to fetch rows directly into a skill pipeline
- You need a read-only source step before `ingest-*` or `detect-*`

## Do NOT use

- For `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `COPY`, `CREATE`, `ALTER`, `DROP`, or grant operations
- As a detection or remediation skill
- When the source data is not in Databricks

## Input

The skill accepts one read-only SQL statement via:

- `--query "SELECT ..."` on the CLI, or
- stdin when `--query` is omitted

Allowed statement families:

- `SELECT`
- `WITH`
- `SHOW`
- `DESCRIBE`

The skill rejects multiple statements, SQL comments, session or optimizer
controls, dynamic identifier helpers, unbalanced query shapes, and
non-read-only verbs.

## Output

Raw JSONL rows exactly as the Databricks SQL connector returns them,
serialized with JSON-safe string conversion for datetimes and other non-JSON-native values.

Typical compositions:

```bash
# Data already projected to the fields your downstream skill expects
python skills/ingestion/source-databricks-query/src/ingest.py \
  --query "SELECT raw_json FROM sec.cloudtrail_ocsf LIMIT 100" \
  | jq -c '.raw_json' \
  | python skills/detection/detect-lateral-movement/src/detect.py

# Data still in raw vendor shape
python skills/ingestion/source-databricks-query/src/ingest.py \
  --query "SELECT raw_event FROM sec.cloudtrail_raw LIMIT 100" \
  | jq -c '.raw_event' \
  | python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py
```

## Credentials

Uses the standard Databricks SQL connector environment variables:

- `DATABRICKS_SERVER_HOSTNAME`
- `DATABRICKS_HTTP_PATH`
- `DATABRICKS_TOKEN`

Optional:

- `DATABRICKS_CATALOG`
- `DATABRICKS_SCHEMA`

This skill is read-only but still egresses to Databricks. Prefer short-lived,
manager-injected credentials or workload identity patterns where your
Databricks environment supports them.
