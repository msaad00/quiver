---
name: detect-snowflake-session-policy-bypass
description: >-
  Detect Snowflake session-policy modifications that loosen idle-timeout or
  max-session-duration thresholds. Reads OCSF 1.8 API Activity (class 6003)
  records normalized from `account_usage.query_history` carrying the
  Snowflake-shaped `unmapped.snowflake.{policy_name,session_idle_timeout_mins,
  session_ui_idle_timeout_mins}` block and emits an OCSF 1.8 Detection Finding
  (class 2004) tagged with MITRE ATT&CK T1098.003 Account Manipulation:
  Additional Cloud Roles whenever an `ALTER SESSION POLICY` event raises the
  idle-timeout above a configured maximum (default 30 minutes). Use when you
  suspect a compromised credential is widening a session policy as a
  persistence vector. Do NOT use on raw Snowflake QUERY_HISTORY rows —
  normalize them through the upstream Snowflake ingest pipeline first. Do NOT
  use as a generic policy-drift detector.
purpose: Detect Snowflake session-policy idle-timeout widening.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-snowflake-session-policy-bypass
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - snowflake
---

# detect-snowflake-session-policy-bypass

## Attack pattern

Snowflake session policies (`CREATE SESSION POLICY`, `ALTER SESSION POLICY`)
control how long a session can stay idle (`SESSION_IDLE_TIMEOUT_MINS`) and how
long the web UI session can stay idle (`SESSION_UI_IDLE_TIMEOUT_MINS`) before
the user is forced to re-authenticate.

A compromised credential or insider trying to extend their useful session
window will raise those thresholds — often to the maximum 240 minutes — so
they don't have to re-enter MFA. On the wire this shows up as an
`ALTER_SESSION_POLICY` event with a new `SESSION_IDLE_TIMEOUT_MINS` /
`SESSION_UI_IDLE_TIMEOUT_MINS` value that exceeds the operator's documented
baseline.

This skill keeps the logic narrow to that pattern. It does not flag every
session-policy modification, and it does not guess at every other Snowflake
policy.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` identifies a Snowflake ingest source:

1. Filter to `ALTER_SESSION_POLICY` (and the equivalent kebab-cased forms)
   operations.
2. Inspect `unmapped.snowflake.session_idle_timeout_mins` and
   `unmapped.snowflake.session_ui_idle_timeout_mins`.
3. Fire **once per event** when either timeout exceeds
   `SNOWFLAKE_SESSION_POLICY_MAX_IDLE_MINS` (default `30`).

The detector emits one finding per policy change — never aggregated — because
each modification is independently auditable. Repeat findings for the same
policy at the same time are deduped via `metadata.uid`.

Operators can tune the threshold at runtime without forking the skill:

- `SNOWFLAKE_SESSION_POLICY_MAX_IDLE_MINS`

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["snowflake-session-policy-bypass", "OWASP-Top-10-A05"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1098.003` (tactic
  `TA0003 Persistence`)
- `evidence.policy_name`, `evidence.session_idle_timeout_mins`,
  `evidence.session_ui_idle_timeout_mins`, `evidence.threshold_mins`,
  `evidence.raw_event_uids`
- `observables[]` carrying the impacted principal, policy name, and timeouts

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py \
  > snowflake_session_policy_bypass_findings.ocsf.jsonl

# Same input, native finding projection out:
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > snowflake_session_policy_bypass_findings.native.jsonl
```

## Do NOT use

- On raw Snowflake QUERY_HISTORY JSON before OCSF normalization
- As a generic policy-drift detector for other Snowflake policy families
  (network policies, password policies, replication policies)
- As a remediation skill — reverting session-policy widening lives in the
  remediation layer
- On non-Snowflake API Activity 6003 (we filter on the Snowflake-shaped
  `unmapped.snowflake.*` block plus the producer source skill)

## Tests

The test suite covers:

- positive: idle timeout raised to 240 minutes fires
- positive: UI idle timeout raised to 60 minutes fires when general idle is
  unchanged
- negative: idle timeout set at or below the configured maximum does NOT fire
- negative: non-`ALTER_SESSION_POLICY` operation is ignored
- negative: events from a non-Snowflake producer are ignored
- edge: threshold env override raises the bar so the same input no longer
  fires
- edge: duplicate `metadata.uid` does not inflate counts

## Roadmap

Closes the Snowflake column under issue #436. Remaining 11 detectors
(Databricks + ClickHouse) stay open and reuse the same input contract.
