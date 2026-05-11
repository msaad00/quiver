---
name: source-s3-select
description: >-
  Run a read-only Amazon S3 Select query against an existing object and emit
  the result set as raw JSONL rows for downstream ingestion, detection, or
  view skills. Accepts explicit `--expression` SQL or reads the expression from
  stdin when no `--expression` is provided. Only `SELECT` statements are
  allowed, and multiple statements are rejected. Use when the user already has
  security data in S3 and wants to pipe selected rows into existing skills
  without downloading full objects first. Do NOT use for writes, object
  mutation, or broad bucket inventory. Do NOT use as a detector or normalizer
  by itself.
purpose: Run a read-only Amazon S3 Select query against an existing object and emit the result set as raw JSONL rows for downstream ingestion, detection, or view skills.
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
network_egress: "*.amazonaws.com"
---

# source-s3-select

Read-only source adapter: Amazon S3 Select query in, raw JSONL rows out. This
skill does not normalize vendor data, detect threats, or write back to S3. It
exists so operators and agents can fetch already-landed lake data and pipe it
into the existing `ingest-*`, `detect-*`, `discover-*`, or `view/*` skills.

## Use when

- Security data already lives in S3 as JSON lines or JSON documents
- You want to fetch rows directly into a skill pipeline without downloading the full object
- You need a read-only source step before `ingest-*` or `detect-*`

## Do NOT use

- For `PUT`, `COPY`, `DELETE`, lifecycle, ACL, bucket-policy, or object-mutation operations
- As a detection or remediation skill
- When the source data is not in S3
- When the object format is not supported by S3 Select for JSON input

## Input

The skill accepts one read-only S3 Select expression via:

- `--expression "SELECT ..."` on the CLI, or
- stdin when `--expression` is omitted

Required location arguments:

- `--bucket`
- `--key`

Optional object parsing arguments:

- `--input-serialization lines|document` (default: `lines`)
- `--compression-type none|gzip|bzip2` (default: `none`)

Allowed statement family:

- `SELECT`

The skill rejects multiple statements and non-read-only verbs.

## Output

Raw JSONL rows exactly as S3 Select returns them for JSON output,
serialized one record per line. If a row is not a JSON object, it is wrapped
as `{"value": ...}` so downstream skills still receive valid JSONL.

Typical compositions:

```bash
# Data already projected to the fields your downstream skill expects
python skills/ingestion/source-s3-select/src/ingest.py \
  --bucket my-sec-lake \
  --key cloudtrail/ocsf.jsonl \
  --expression "SELECT s.raw_json FROM S3Object s LIMIT 100" \
  | jq -c '.raw_json' \
  | python skills/detection/detect-lateral-movement/src/detect.py

# Data still in raw vendor shape
python skills/ingestion/source-s3-select/src/ingest.py \
  --bucket my-sec-lake \
  --key cloudtrail/raw.jsonl \
  --expression "SELECT s.raw_event FROM S3Object s LIMIT 100" \
  | jq -c '.raw_event' \
  | python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py
```

## Credentials

Uses the standard AWS SDK credential chain and optional region configuration:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_PROFILE`
- `AWS_REGION` / `AWS_DEFAULT_REGION`

This skill is read-only but still egresses to AWS. Prefer short-lived,
manager-injected credentials or workload identity patterns.
