---
name: detect-snowflake-failed-mfa-burst
description: >-
  Detect high-velocity failed-MFA bursts on Snowflake user accounts. Reads OCSF
  1.8 Authentication (class 3002) records normalized from
  `account_usage.login_history` carrying `actor.user.uid`, `status_id`, and the
  Snowflake-shaped `unmapped.snowflake.{authentication_method,error_code,
  is_success}` block, groups failed-MFA events by principal across a sliding
  window, and emits an OCSF 1.8 Detection Finding (class 2004) tagged with
  MITRE ATT&CK T1110 Brute Force and T1621 Multi-Factor Authentication Request
  Generation whenever a single user fails MFA at or above a configured count
  inside the window. Use when you suspect credential stuffing, MFA bombing, or
  authenticator brute force against the Snowflake login surface. Do NOT use on
  raw Snowflake LOGIN_HISTORY rows — normalize them through the upstream
  Snowflake ingest pipeline first. Do NOT use as a generic failed-logon rule
  for non-Snowflake identity providers.
purpose: Detect high-velocity failed-MFA bursts on Snowflake user accounts.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-snowflake-failed-mfa-burst
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - snowflake
---

# detect-snowflake-failed-mfa-burst

## Attack pattern

A compromised set of Snowflake credentials, a credential-stuffing run, or an
MFA-bombing attempt drives a burst of failed-MFA login events against one
Snowflake user account. The shape on the wire is repeated
`account_usage.login_history` rows with `is_success = NO`,
`authentication_method` referencing an MFA factor (`MFA`, `DUO`, `OKTA`,
`TOTP`, `WEBAUTHN`), and a Snowflake-side error code (e.g. `390127`,
`390114`, `390100`).

A single legitimate user typically fails MFA once or twice. An attacker
spraying credentials or hammering an authenticator crosses a much higher
failure-count threshold inside a short window. This skill aggregates those
events per principal and fires once when the failed-MFA count crosses the
configured threshold inside the configured window.

This detector keeps the logic narrow to that pattern. It does not flag every
single failed login, and it does not guess at every error code that could
indicate auth trouble.

## Detection logic

One pass over OCSF 1.8 Authentication (class `3002`) events whose
`metadata.product.feature.name` identifies a Snowflake ingest source:

1. Filter to events where `unmapped.snowflake.is_success` is false (or the
   OCSF `status_id` indicates failure) and the authentication method is an
   MFA factor.
2. Group by `actor.user.uid`.
3. Sort by event time.
4. Maintain a sliding window (default 10 minutes, configurable via
   `SNOWFLAKE_MFA_FAIL_WINDOW_MIN`).
5. Inside the window, count per-principal failed-MFA events.
6. Fire **once per (principal, window)** when the cumulative failure count
   reaches `SNOWFLAKE_MFA_FAIL_THRESHOLD` (default `8`).

The detector emits one finding per (principal, window) — never per row — and
suppresses repeat findings until there is a quiet period longer than the
configured window.

Operators can tune the burst logic at runtime without forking the skill:

- `SNOWFLAKE_MFA_FAIL_WINDOW_MIN`
- `SNOWFLAKE_MFA_FAIL_THRESHOLD`

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["snowflake-failed-mfa-burst", "OWASP-Top-10-A07"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1110` (tactic
  `TA0006 Credential Access`) and `T1621`
- `evidence.failed_event_count`, `evidence.error_codes`,
  `evidence.authentication_methods`, `evidence.source_ips`,
  `evidence.raw_event_uids`
- `observables[]` carrying the impacted principal, source IPs, and
  authentication methods

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
# OCSF 1.8 Authentication 3002 in, OCSF Detection Finding 2004 out:
cat snowflake_login_history.ocsf.jsonl \
  | python src/detect.py \
  > snowflake_failed_mfa_burst_findings.ocsf.jsonl

# Same input, native finding projection out:
cat snowflake_login_history.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > snowflake_failed_mfa_burst_findings.native.jsonl
```

## Do NOT use

- On raw Snowflake LOGIN_HISTORY JSON before OCSF normalization
- As a generic failed-logon detector for Okta / Entra / Workday
- As a remediation skill — quarantine of a Snowflake principal lives in the
  remediation layer
- On non-Snowflake Authentication 3002 events (we filter on the
  Snowflake-shaped `unmapped.snowflake.*` block plus the producer source
  skill)

## Tests

The test suite covers:

- positive: 8 failed-MFA events from the same principal inside the window
  fires once
- positive: out-of-order events still fire once
- negative: 8 successful MFA events do NOT fire
- negative: non-MFA failed logins (password-only) do NOT fire
- negative: events from a non-Snowflake producer are ignored
- edge: threshold env override raises the bar so the same input no longer
  fires
- edge: duplicate `metadata.uid` does not inflate counts
- edge: two principals each fire separately

## Roadmap

Closes the Snowflake column under issue #436. Remaining 11 detectors
(Databricks + ClickHouse) stay open and reuse the same input contract.
