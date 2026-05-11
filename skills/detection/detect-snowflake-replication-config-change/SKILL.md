---
name: detect-snowflake-replication-config-change
description: >-
  Detect creation or modification of Snowflake account-replication or
  database-replication configurations to accounts not on the authorized list.
  Reads OCSF 1.8 API Activity (class 6003) records normalized from
  `account_usage.query_history` carrying the Snowflake-shaped
  `unmapped.snowflake.{database_name,target_accounts,operation_kind}` block and
  emits an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK
  T1537 Transfer Data to Cloud Account whenever `ALTER ACCOUNT SET REPLICATION
  ENABLED` or `ALTER DATABASE ... ENABLE REPLICATION TO ACCOUNTS (...)` targets
  an account NOT in `SNOWFLAKE_AUTHORIZED_REPLICATION_TARGETS`. Default
  allowlist is empty and the detector fails open with a stderr warning when no
  allowlist is configured. Use when you suspect a compromised credential is
  setting up exfiltration of an entire database to an attacker-controlled
  Snowflake account. Do NOT use on raw Snowflake QUERY_HISTORY rows —
  normalize them through the upstream Snowflake ingest pipeline first. Do
  NOT use as a generic data-replication detector for non-Snowflake providers.
purpose: Detect Snowflake account / database replication config changes to unauthorized accounts.
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
concurrency_safety: requires_consistent_sharding
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-snowflake-replication-config-change
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - snowflake
---

# detect-snowflake-replication-config-change

## Attack pattern

Snowflake account replication and database replication allow an account to
push its data to one or more secondary Snowflake accounts. An attacker who
controls (or registers) a second Snowflake account can use the producer's
own replication primitives to exfiltrate entire databases without ever
hitting Snowflake's data egress paths:

- `ALTER ACCOUNT SET REPLICATION ENABLED` turns the account into a
  replication source.
- `ALTER DATABASE <name> ENABLE REPLICATION TO ACCOUNTS (<list>)` declares
  which downstream accounts may pull a primary database.
- `ALTER DATABASE <name> ENABLE FAILOVER TO ACCOUNTS (<list>)` does the same
  but with auto-promotion semantics.

This skill keeps the logic narrow to that pattern. It fires when ANY target
account is outside the operator-supplied allowlist of approved replication
partners — that allowlist is the operator's only opportunity to declare
"these are the partner orgs we replicate to".

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` identifies a Snowflake ingest source:

1. Filter to replication-configuration operations:
   `ALTER_ACCOUNT_SET_REPLICATION`, `ALTER_DATABASE_ENABLE_REPLICATION`,
   `ALTER_DATABASE_ENABLE_FAILOVER`, `CREATE_REPLICATION_GROUP`.
2. Resolve `unmapped.snowflake.target_accounts` (list of account locators).
3. Read `SNOWFLAKE_AUTHORIZED_REPLICATION_TARGETS` (comma-separated, case
   insensitive). When empty, the detector emits a stderr warning and fails
   open — every event still passes the filter but the finding is still
   generated so operators see the blind spot.
4. Fire **once per event** when ANY target account is outside the allowlist
   OR when the allowlist is empty.

The detector emits one finding per replication-configuration change — never
aggregated — and dedupes via `metadata.uid`.

Operators can tune the allowlist at runtime without forking the skill:

- `SNOWFLAKE_AUTHORIZED_REPLICATION_TARGETS`

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["snowflake-replication-config-change", "OWASP-Top-10-A04"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1537` (tactic
  `TA0010 Exfiltration`)
- `evidence.database_name`, `evidence.operation`, `evidence.target_accounts`,
  `evidence.unauthorized_accounts`, `evidence.allowlist_empty`,
  `evidence.raw_event_uids`
- `observables[]` carrying the impacted principal, database, and unauthorized
  target accounts

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
SNOWFLAKE_AUTHORIZED_REPLICATION_TARGETS=PARTNER_PROD_AB123,PARTNER_DR_XY789 \
  cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py \
  > snowflake_replication_config_change_findings.ocsf.jsonl

# Same input, native finding projection out:
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > snowflake_replication_config_change_findings.native.jsonl
```

## Do NOT use

- On raw Snowflake QUERY_HISTORY JSON before OCSF normalization
- As a generic data-replication detector for Databricks Delta Sharing or
  Snowflake secure shares (the `detect-snowflake-share-creation` skill
  already covers shares)
- As a remediation skill — disabling replication lives in the remediation
  layer
- On non-Snowflake API Activity 6003 (we filter on the Snowflake-shaped
  `unmapped.snowflake.*` block plus the producer source skill)

## Tests

The test suite covers:

- positive: `ALTER ACCOUNT SET REPLICATION ENABLED` fires when no allowlist
  is configured (fail-open with stderr warning)
- positive: `ALTER DATABASE ... ENABLE REPLICATION TO ACCOUNTS` to an
  unauthorized target fires
- positive: failover-to-accounts variant fires
- negative: replication to an account inside the allowlist does NOT fire
- negative: non-replication operations are ignored
- negative: events from a non-Snowflake producer are ignored
- edge: allowlist is case-insensitive
- edge: duplicate `metadata.uid` does not inflate counts

## Roadmap

Closes the Snowflake column under issue #436. Remaining 11 detectors
(Databricks + ClickHouse) stay open and reuse the same input contract.
