---
name: detect-snowflake-share-creation
description: >-
  Detect creation of a new Snowflake secure data share or addition of an
  external account to an existing share. Reads OCSF 1.8 API Activity (class
  6003) records normalized from Snowflake `query_history` / `grants_to_users`
  carrying `actor.user.uid`, `api.operation`, and Snowflake-shaped
  `unmapped.snowflake.{share_name,target_accounts,operation_kind}` fields, and
  emits one OCSF 1.8 Detection Finding (class 2004) per share-creation or
  share-account-addition event, tagged with MITRE ATT&CK T1537 Transfer Data
  to Cloud Account. Use when the user mentions "Snowflake share created",
  "ALTER SHARE ADD ACCOUNTS", "T1537 in Snowflake", or "data share to an
  external Snowflake account". Do NOT use on raw Snowflake QUERY_HISTORY JSON
  before OCSF normalization, as a generic data-loss detector for
  Databricks / ClickHouse, or as a remediation skill — share revocation lives
  in the remediation layer.
purpose: Detect creation of a new Snowflake secure data share or addition of an external account to an existing share.
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
concurrency_safety: stateless
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-snowflake-share-creation
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - snowflake
---

# detect-snowflake-share-creation

## Attack pattern

Snowflake secure data shares persist outside the granting account's control —
once a share is created and an external account is added, the consumer account
can query the underlying objects until the share is revoked. An attacker with
`ACCOUNTADMIN` or `SHARE` privileges who creates a share to an attacker-owned
Snowflake account exfiltrates data while bypassing classic egress detection
(no `COPY INTO @stage`, no `GET`, no S3 / GCS traffic on the producer side).

On the wire the pattern is:

- `CREATE SHARE <name>` — creates the share
- `GRANT USAGE ON DATABASE <db> TO SHARE <name>` — surfaces objects
- `ALTER SHARE <name> ADD ACCOUNTS = (<account>...)` — adds consumer accounts

This skill fires on the share-creation **anchor** and on `ADD ACCOUNTS`
events that introduce a new external account, both visible in Snowflake
`QUERY_HISTORY` and surfaced into OCSF 1.8 API Activity 6003.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` identifies a Snowflake ingest source:

1. Filter to share-related operations (`CREATE_SHARE`, `ALTER_SHARE_ADD_ACCOUNTS`).
2. Require a successful event (`status_id == 1`).
3. Require a non-empty `unmapped.snowflake.share_name`.
4. For `ALTER_SHARE_ADD_ACCOUNTS`, require a non-empty
   `unmapped.snowflake.target_accounts` list.
5. Emit one finding per anchor event.

The detector is stateless — every successful share-creation or
add-accounts event fires once. Operators can suppress legitimate share
creators via the standard upstream allow-list pipeline, not the skill.

Operators can tune the operation set at runtime without forking:

- `SNOWFLAKE_SHARE_OPERATIONS` — comma-separated, defaults to
  `CREATE_SHARE,ALTER_SHARE_ADD_ACCOUNTS`.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["snowflake-share-creation", "OWASP-Top-10-A04"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1537` (tactic
  `TA0010 Exfiltration`)
- `evidence.share_name`, `evidence.target_accounts`, `evidence.operation_kind`
- `observables[]` carrying the impacted principal and share name

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py \
  > snowflake_share_creation_findings.ocsf.jsonl

# Same input, native finding projection out:
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > snowflake_share_creation_findings.native.jsonl
```

## Do NOT use

- On raw Snowflake QUERY_HISTORY JSON before OCSF normalization
- As a generic data-loss detector for Databricks / ClickHouse / BigQuery
- As a remediation skill — share revocation lives in the remediation layer
- On non-Snowflake API Activity 6003 (we filter on the Snowflake-shaped
  `unmapped.snowflake.*` block plus the producer source skill)

## Tests

The test suite covers:

- positive: `CREATE SHARE` event fires once
- positive: `ALTER SHARE ADD ACCOUNTS` with a new account fires once
- negative: failed share-creation does not fire
- negative: non-share Snowflake operations are ignored
- negative: events from a non-Snowflake producer are ignored
- edge: missing `share_name` is ignored
- edge: duplicate `metadata.uid` does not inflate counts
- env-override: `SNOWFLAKE_SHARE_OPERATIONS` honored

## Roadmap

Second of 18 warehouse-platform vendor-depth detectors for issue #436. The
remaining detectors (1 more Snowflake, 5 Databricks, 5 ClickHouse) stay open
and will reuse the same input contract.
