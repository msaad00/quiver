---
name: detect-snowflake-unauthorized-grant
description: >-
  Detect grants of privileged Snowflake roles by principals not on the
  documented allow-list. Reads OCSF 1.8 API Activity (class 6003) records
  normalized from Snowflake `query_history` / `grants_to_users` carrying
  `actor.user.uid` (the granter), `api.operation == "GRANT_ROLE"`, and
  Snowflake-shaped `unmapped.snowflake.{granted_role,grantee_user,
  grantee_role}` fields, and emits one OCSF 1.8 Detection Finding (class
  2004) when the granted role is privileged AND the granter is not on the
  authorized list, tagged with MITRE ATT&CK T1098.003 Add Office 365 /
  Azure / Snowflake Roles. Use when the user mentions "ACCOUNTADMIN granted
  outside the change window", "Snowflake role escalation", "T1098.003 in
  Snowflake", or "privileged grant by unauthorized identity". Do NOT use on
  raw Snowflake QUERY_HISTORY JSON before OCSF normalization, as a
  posture-at-rest grant inventory, or on non-Snowflake API Activity 6003.
purpose: Detect grants of privileged Snowflake roles by principals not on the documented allow-list.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-snowflake-unauthorized-grant
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - snowflake
---

# detect-snowflake-unauthorized-grant

## Attack pattern

Snowflake's role hierarchy puts a small set of system roles
(`ACCOUNTADMIN`, `SECURITYADMIN`, `ORGADMIN`) at the top of every account.
Any user holding one of these roles can read every table, alter every
warehouse, and grant the role onward. An attacker who reaches a role with
`OWNERSHIP` on `ACCOUNTADMIN` (or `MANAGE GRANTS`) can grant a privileged
role to an attacker-controlled identity outside the documented break-glass
process, persisting access until a human notices.

On the wire the pattern is:

- `GRANT ROLE ACCOUNTADMIN TO USER <name>`
- `GRANT ROLE SECURITYADMIN TO USER <name>`
- `GRANT ROLE ORGADMIN TO USER <name>`

This skill fires when the granted role is in the privileged-role list AND
the granter is **not** on the authorized-granters allow-list.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` identifies a Snowflake ingest source:

1. Filter to `api.operation == "GRANT_ROLE"`.
2. Require a successful event (`status_id == 1`).
3. Require a non-empty `unmapped.snowflake.granted_role`.
4. Require either `unmapped.snowflake.grantee_user` or
   `unmapped.snowflake.grantee_role` to be set.
5. Require the granted role (uppercased) to be in the privileged-role
   list (default `ACCOUNTADMIN,SECURITYADMIN,ORGADMIN`, configurable via
   `SNOWFLAKE_PRIVILEGED_ROLES`).
6. **Fail-open allow-list**: if `SNOWFLAKE_AUTHORIZED_GRANTERS` is empty
   the detector fires on every privileged grant (with `evidence.allowlist_mode`
   = `"fail-open"`). Operators must set the allow-list explicitly in
   prod; the warning is emitted to stderr telemetry on each fire.
7. When the allow-list is set, fire only when the granter is **not** on it.

The detector is stateless — one finding per anchor event.

Operators can tune the policy at runtime without forking:

- `SNOWFLAKE_PRIVILEGED_ROLES` — comma-separated, default
  `ACCOUNTADMIN,SECURITYADMIN,ORGADMIN`.
- `SNOWFLAKE_AUTHORIZED_GRANTERS` — comma-separated principal allow-list
  (e.g. `BREAK_GLASS_USER,SECURITYADMIN_BOT`); default empty = fail-open.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["snowflake-unauthorized-grant", "OWASP-Top-10-A01"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1098.003` (tactic
  `TA0003 Persistence`)
- `evidence.granted_role`, `evidence.granter`, `evidence.grantee_user`,
  `evidence.grantee_role`, `evidence.allowlist_mode`
- `observables[]` carrying granter, grantee, and granted role

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
export SNOWFLAKE_AUTHORIZED_GRANTERS="BREAK_GLASS_USER,SECURITYADMIN_BOT"
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py \
  > snowflake_unauthorized_grant_findings.ocsf.jsonl
```

## Do NOT use

- On raw Snowflake QUERY_HISTORY JSON before OCSF normalization
- As a posture-at-rest grant inventory
- As a remediation skill — grant revocation lives in the remediation layer
- On non-Snowflake API Activity 6003

## Tests

The test suite covers:

- positive: privileged grant by unknown granter fires (allow-list set)
- positive: privileged grant by unknown granter fires in fail-open mode
- negative: privileged grant by authorized granter does NOT fire
- negative: non-privileged role grant does NOT fire
- negative: failed grant does NOT fire
- negative: events from a non-Snowflake producer are ignored
- edge: missing `grantee_user` / `grantee_role` is ignored
- edge: duplicate `metadata.uid` does not inflate counts
- env-override: `SNOWFLAKE_PRIVILEGED_ROLES` and
  `SNOWFLAKE_AUTHORIZED_GRANTERS` honored

## Roadmap

Fifth of 18 warehouse-platform vendor-depth detectors for issue #436.
