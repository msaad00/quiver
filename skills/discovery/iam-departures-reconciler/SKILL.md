---
name: iam-departures-reconciler
description: >-
  Build a deterministic IAM departures manifest from HR termination sources
  before any cloud-specific remediation runs. Reconciles Workday, Snowflake,
  Databricks, or ClickHouse termination data into one canonical departure
  record shape, applies rehire and grace-window filters, and emits the exact
  manifest body consumed by the IAM departures write paths. Use when the user
  mentions identify departures, build an offboarding manifest, or reconcile
  HR terminations against IAM before cleanup. Do NOT use this skill to delete
  users, revoke credentials, or execute cloud remediation — use the
  cloud-specific `iam-departures-*` skills for write actions. Do NOT use it as
  an HR system of record or a generic provisioning workflow.
purpose: Build a deterministic IAM departures manifest from HR termination sources before any cloud-specific remediation runs.
capability: read-only
persistence: none
telemetry: stderr_jsonl
privilege_escalation: read
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native
concurrency_safety: operator_coordinated
network_egress: api.workday.com, *.snowflakecomputing.com, *.databricks.com, *.clickhouse.cloud
compatibility: >-
  Requires Python 3.11+. Optional source connectors depend on the selected HR
  source: snowflake-connector-python, databricks-sql-connector,
  clickhouse-connect, or httpx for the direct Workday API path.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/discovery/iam-departures-reconciler
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
  cloud: multi
---

# iam-departures-reconciler

Read-only planner for IAM departures. It normalizes HR termination records,
applies the shipped rehire and grace-window rules, performs deterministic
change detection, and emits the manifest JSON consumed by the cloud-specific
IAM departures write paths.

## Use when

- You need to identify which departed employees still map to cloud identities
- You want to build an offboarding manifest before AWS, GCP, or Azure cleanup
- You need one canonical departure record shape from Snowflake, Databricks, ClickHouse, or Workday
- You want deterministic manifest output that can be reviewed, diffed, or persisted by a runner

## Do NOT use

- To execute IAM deletions or credential revocation
- To bypass the cloud-specific approval and audit gates
- As an HR source of truth or identity-provisioning workflow
- On arbitrary audit logs or OCSF findings

## Output contract

The skill emits the same manifest body shape the shipped AWS parser expects:

- `export_timestamp`
- `source`
- `hash`
- `total_records`
- `actionable_count`
- `skipped_count`
- `skip_reasons`
- `entries[]`

This skill does not write to S3 itself. Operators or cloud-specific runners
can persist the emitted JSON under their native object-store prefix while
keeping the downstream parser and worker contracts unchanged.

## Usage

```bash
# Build a manifest from Snowflake-backed HR data
python src/discover.py --source snowflake --pretty > departures-manifest.json

# Compare against a previously persisted hash (read-only)
python src/discover.py --source workday --previous-hash 1c2f... --pretty

# Only report the content hash for orchestration logic
python src/discover.py --source databricks --hash-only
```

## Guardrails

- Read-only: no IAM, Graph, or cloud write APIs are called here.
- Rehire-aware: the same `should_remediate()` decision tree used by the shipped write path is preserved here.
- Deterministic: record hashing ignores observation timestamps so repeated runs on unchanged data stay stable.
- Source-bounded: unknown source names fail closed.

## See also

- [`../../remediation/iam-departures-aws/SKILL.md`](../../remediation/iam-departures-aws/SKILL.md) — AWS write path and audit trail
- [`../../remediation/iam-departures-gcp/SKILL.md`](../../remediation/iam-departures-gcp/SKILL.md) — GCP write path
- [`../../remediation/iam-departures-azure-entra/SKILL.md`](../../remediation/iam-departures-azure-entra/SKILL.md) — Azure Entra write path
