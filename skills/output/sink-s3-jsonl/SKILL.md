---
name: sink-s3-jsonl
description: >-
  Persist JSONL records from stdin into a new immutable object under a
  pre-provisioned Amazon S3 bucket and prefix. Dry-run is the default and
  emits a native sink-result summary without writing. Use when the user
  already has findings, evidence, or audit rows and wants to persist them to
  S3 without changing the producing skill. Do NOT use for bucket creation,
  object deletion, overwrite flows, or arbitrary AWS mutations. Do NOT use as
  an ingest, detect, or evaluation skill.
purpose: Persist JSONL records from stdin into a new immutable object under a pre-provisioned Amazon S3 bucket and prefix.
capability: write-sink
persistence: audit_log
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: human_required
execution_modes: jit, mcp, persistent
side_effects: writes-storage
input_formats: raw, native, ocsf
output_formats: native
concurrency_safety: operator_coordinated
network_egress: "*.amazonaws.com"
caller_roles: security_engineer, platform_engineer
approver_roles: security_lead, data_platform_owner
min_approvers: 1
---

# sink-s3-jsonl

Immutable S3 sink: JSONL in on `stdin`, one new object written under a
validated bucket and prefix, native sink-result summary out on `stdout`.

## Use when

- Findings, evidence, or audit records already exist on stdin as JSONL
- You need a repo-owned persistence step after `detect-*`, `discover-*`, `view/*`, or another sink-safe producer
- The target bucket already exists and should remain append-only through new objects

## Do NOT use

- For bucket creation, policy changes, ACL mutation, lifecycle changes, or object deletion
- For schema migration or data rewriting inside an existing object
- As a detector, ingest normalizer, or remediation workflow by itself
- When you need to write to a system other than Amazon S3

## Do NOT do

- Do **not** point this skill at privileged control-plane buckets
- Do **not** use `--apply` without an operator approval step outside the CLI
- Do **not** pass arbitrary S3 URIs or wildcard paths as the bucket name
- Do **not** assume this skill mutates or appends to an existing object

## Input

Reads JSONL from `stdin`. Each line must be a valid JSON object.

Accepted source shapes:

- repo-native event or finding JSON
- OCSF JSON
- raw JSON objects you intentionally want to persist as-is

Required CLI arguments:

- `--bucket <bucket>`
- `--prefix <prefix>`

Safety flags:

- default mode is dry-run
- `--apply` executes the object write
- `--dry-run` keeps the write path disabled explicitly

## Output

Emits one repo-native sink-result JSON object to `stdout`:

- `schema_mode: "native"`
- `record_type: "sink_result"`
- `sink: "s3"`
- `bucket`
- `prefix`
- `object_key`
- `dry_run`
- `input_records`
- `written_objects`
- `written_records`
- `would_write_objects`
- `would_write_records`
- `schema_modes`

## Sink object contract

This skill writes exactly one new NDJSON object per apply run:

- content type: `application/x-ndjson`
- body: one JSON object per line
- key shape: `<prefix>/YYYY/MM/DD/<timestamp>-<content-hash>.jsonl`

The skill does not overwrite, append to, or mutate an existing object key.

## Examples

```bash
# Dry-run by default
python skills/detection/detect-lateral-movement/src/detect.py < events.ocsf.jsonl \
  | python skills/output/sink-s3-jsonl/src/sink.py \
      --bucket my-sec-lake \
      --prefix findings/lateral-movement

# Explicit apply for direct operator use
python skills/discovery/discover-control-evidence/src/discover.py \
  | python skills/output/sink-s3-jsonl/src/sink.py \
      --bucket my-sec-lake \
      --prefix evidence/control-exports \
      --apply
```

## Credentials

Uses the standard AWS SDK credential chain and optional region configuration:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_PROFILE`
- `AWS_REGION` / `AWS_DEFAULT_REGION`

Prefer short-lived, manager-injected credentials or workload identity
patterns.
