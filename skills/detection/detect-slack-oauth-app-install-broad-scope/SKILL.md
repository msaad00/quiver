---
name: detect-slack-oauth-app-install-broad-scope
description: >-
  Detect third-party Slack apps installed with broad OAuth scopes — a common
  SaaS-exfiltration vector where an attacker (or a careless approver) wires a
  malicious or over-privileged third-party app into a workspace and uses its
  scope grants to read messages, files, and channel inventories. Reads OCSF
  1.8 API Activity (class 6003) records normalized from Slack Audit Logs API
  `app_installed` / `app_approved` events carrying `unmapped.slack.scopes` and
  `unmapped.slack.app.id`, and emits OCSF 1.8 Detection Finding (class 2004)
  tagged with MITRE ATT&CK T1098.005 Account Manipulation — Device
  Registration when the scope set is broad and the app is not on the operator
  pre-approval allow-list. Use when the user mentions Slack OAuth app abuse,
  broad-scope SaaS install, or third-party Slack tool spreading. Do NOT use on
  raw Slack audit JSON before OCSF normalization, on Slack message bodies, or
  on non-Slack API Activity 6003.
purpose: Detect third-party Slack apps installed with broad OAuth scopes (chat:write plus a read scope, or a wildcard) and not on the operator pre-approved allow-list.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-slack-oauth-app-install-broad-scope
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - slack
---

# detect-slack-oauth-app-install-broad-scope

## Attack pattern

Slack OAuth scopes are the per-app permission boundary. A malicious or
over-privileged app that holds both `chat:write` AND any of the message-read
scopes (`channels:read`, `groups:read`, `im:read`, `files:read`) — or a
wildcard like `*:write` — can ingest the workspace's conversations, exfil
them, and impersonate users to deliver follow-on payloads. Two real-world
incident patterns power this detector:

- supply-chain compromise of a marketplace app whose new build silently
  asks for additional scopes on next install / approval
- attacker pushes a custom workspace app with `chat:write` plus a read
  scope, then uses the token from outside the network perimeter

On the wire the pattern is:

- an `app_installed` or `app_approved` audit event
- `unmapped.slack.scopes` contains `chat:write` AND
  (`files:read` OR `channels:read` OR `groups:read` OR `im:read`)
- OR `unmapped.slack.scopes` contains a wildcard scope like `*:write`
- AND `unmapped.slack.app.id` is **not** in the configured
  `SLACK_PREAPPROVED_APP_IDS` allow-list

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` identifies the Slack ingest source:

1. Filter to action `app_installed` or `app_approved`.
2. Require a non-empty `unmapped.slack.app.id`.
3. Require a non-empty `unmapped.slack.scopes` list.
4. Mark the install as **broad-scope** when either:
   - `chat:write` is granted AND any of `files:read`, `channels:read`,
     `groups:read`, `im:read` is granted, OR
   - any scope matches the `*:write` wildcard family.
5. Require the app id to be **not** in `SLACK_PREAPPROVED_APP_IDS`.

The detector is stateless — one finding per install event.

Operators can tune the policy at runtime without forking:

- `SLACK_PREAPPROVED_APP_IDS` — comma-separated Slack app IDs, default
  empty (every broad-scope install fires).

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["slack-oauth-app-install-broad-scope", "OWASP-Top-10-A05"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1098.005` (tactic
  `TA0003 Persistence`)
- `evidence.app_id`, `evidence.app_name`, `evidence.scopes`,
  `evidence.broad_scope_reason`, `evidence.installer`
- `observables[]` carrying the installer, app id, and the granted scopes

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
export SLACK_PREAPPROVED_APP_IDS="A0001,A0002"
cat slack-audit.ocsf.jsonl \
  | python src/detect.py \
  > slack-oauth-app-install-broad-scope-findings.ocsf.jsonl
```

## Do NOT use

- On raw Slack audit JSON before OCSF normalization
- As a remediation skill — app uninstall lives in the remediation layer
- On non-Slack API Activity 6003

## Tests

The test suite covers:

- positive: `chat:write` + `files:read` install fires
- positive: wildcard `*:write` scope fires
- negative: pre-approved app id does not fire
- negative: narrow scope set (just `chat:read`) does not fire
- negative: events from a non-Slack producer are ignored
- edge: missing scopes list is ignored
- env-override: `SLACK_PREAPPROVED_APP_IDS` honored
- frozen golden fixture for detector output parity

## Roadmap

Part of the Slack vendor story — see issue #33.
