---
name: detect-slack-admin-elevation
description: >-
  Detect Slack Workspace Admin / Owner role grants performed outside the
  documented break-glass identity list or change window. Reads OCSF 1.8 User
  Access Management (class 3005) records normalized from Slack Audit Logs
  `role_change_to_admin` / `role_change_to_owner` events and emits OCSF 1.8
  Detection Finding (class 2004) when either the granting actor is not on the
  authorized-granters allow-list OR the event timestamp falls outside the
  configured UTC change window, tagged with MITRE ATT&CK T1098.003 Additional
  Cloud Roles. Use when the user mentions Slack admin escalation, owner grant
  abuse, or out-of-window privilege change. Do NOT use on raw Slack audit JSON
  before OCSF normalization, on Slack message bodies, or on non-Slack User
  Access Management 3005 events.
purpose: Detect Slack Workspace Admin / Owner role grants by unauthorized identities or outside an authorized UTC change window.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-slack-admin-elevation
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - slack
---

# detect-slack-admin-elevation

## Attack pattern

Slack Workspace Admin and Workspace Owner are the highest-privilege seats
inside an Enterprise Grid workspace. Either role can re-key SSO, change
retention, approve new third-party apps, and grant other admins. An attacker
who reaches an Owner-level identity (or a careless administrator working
outside a change window) can persist privileged access until a human notices.

On the wire the pattern is:

- a `role_change_to_admin` or `role_change_to_owner` audit event
- AND either:
  - the granter (`actor.user.uid`) is **not** on the authorized-granters
    allow-list, OR
  - the event hour (UTC) falls outside the configured change window

This skill fires under either condition.

## Detection logic

One pass over OCSF 1.8 User Access Management (class `3005`) events whose
`metadata.product.feature.name` identifies the Slack ingest source:

1. Filter to action `role_change_to_admin` or `role_change_to_owner`.
2. Require non-empty `actor.user.uid` (granter) and `user.uid` (grantee).
3. **Fail-open allow-list**: if `SLACK_AUTHORIZED_GRANTERS` is empty the
   detector fires on every admin/owner grant (with
   `evidence.allowlist_mode == "fail-open"`). Operators must set the
   allow-list explicitly in prod; a warning is emitted to stderr telemetry
   on each fire.
4. When the allow-list is set, fire when the granter is **not** on it.
5. Also fire when the UTC hour of `time` is outside the configured
   `SLACK_GRANT_WINDOW_HOURS_UTC` window (default `08-18`).

The detector is stateless — one finding per anchor event.

Operators can tune the policy at runtime without forking:

- `SLACK_AUTHORIZED_GRANTERS` — comma-separated principal allow-list
  (e.g. `U_BREAKGLASS,U_SECOPS_BOT`); default empty = fail-open.
- `SLACK_GRANT_WINDOW_HOURS_UTC` — `HH-HH` window in UTC, default `08-18`.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["slack-admin-elevation", "OWASP-Top-10-A01"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1098.003` (tactic
  `TA0003 Persistence`)
- `evidence.granter`, `evidence.grantee`, `evidence.new_role`,
  `evidence.allowlist_mode`, `evidence.window_violation`
- `observables[]` carrying granter, grantee, and granted role

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
export SLACK_AUTHORIZED_GRANTERS="U_BREAKGLASS,U_SECOPS_BOT"
export SLACK_GRANT_WINDOW_HOURS_UTC="08-18"
cat slack-audit.ocsf.jsonl \
  | python src/detect.py \
  > slack-admin-elevation-findings.ocsf.jsonl
```

## Do NOT use

- On raw Slack audit JSON before OCSF normalization
- As a remediation skill — admin revocation lives in the remediation layer
- On non-Slack User Access Management 3005 events

## Tests

The test suite covers:

- positive: unauthorized granter fires when allow-list is enforced
- positive: out-of-window grant fires even for an authorized granter
- positive: fail-open mode fires on every admin/owner grant
- negative: authorized granter inside the window does NOT fire
- negative: events from a non-Slack producer are ignored
- edge: invalid window string falls back to default
- env-override: both env vars honored
- frozen golden fixture for detector output parity

## Roadmap

Part of the Slack vendor story — see issue #33.
