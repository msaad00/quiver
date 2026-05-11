---
name: detect-slack-external-channel-add
description: >-
  Detect a guest user from an external workspace being added to a sensitive
  Slack channel. Reads OCSF 1.8 User Access Management (class 3005) records
  normalized from Slack Audit Logs API events carrying
  `unmapped.slack.workspace_type == "external"` and a channel name that matches
  the configured sensitive-channel regex, and emits one OCSF 1.8 Detection
  Finding (class 2004) tagged with MITRE ATT&CK T1078.004 Valid Accounts —
  Cloud Accounts. Use when the user mentions "external guest added to a
  security channel", "Slack DLP risk via cross-workspace invite", or "Slack
  insider-threat via shared channel". Do NOT use on raw Slack audit JSON
  before OCSF normalization, on Slack message bodies, or on non-Slack User
  Access Management 3005 events.
purpose: Detect a guest user from an external workspace being added to a sensitive Slack channel.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-slack-external-channel-add
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - slack
---

# detect-slack-external-channel-add

## Attack pattern

Slack Enterprise Grid lets administrators connect external workspaces via
shared channels or guest invitations. When a user from an external workspace
is added to an internal Slack channel that carries sensitive content
(security, exec, finance, legal, engineering-leads), the cross-tenant
membership creates a DLP exposure and an insider-threat surface — the
external account can read every subsequent message, file share, and
attachment in the channel until the membership is revoked.

On the wire the pattern is:

- a `private_channel_member_added` or `workspace_user_added_to_workspace`
  audit event
- `unmapped.slack.workspace_type == "external"` (set by the Slack ingester
  when the entry's `details.workspace_type` is `external` or
  `details.is_external == true`)
- the channel name matches the configured sensitive-channel regex

This skill fires when all three conditions hold.

## Detection logic

One pass over OCSF 1.8 User Access Management (class `3005`) events whose
`metadata.product.feature.name` identifies the Slack ingest source:

1. Filter to action `private_channel_member_added`,
   `public_channel_member_added`, or `workspace_user_added_to_workspace`.
2. Require `unmapped.slack.workspace_type == "external"`.
3. Require a non-empty `unmapped.slack.channel.name`.
4. Require the channel name to match the sensitive-channel regex.
5. Require a non-empty `actor.user.uid` and a non-empty added-user identity.

The detector is stateless — one finding per anchor event.

Operators can tune the policy at runtime without forking:

- `SLACK_SENSITIVE_CHANNEL_PATTERNS` — Python regex, default
  `(?i)(security|sec-ops|finance|legal|engineering-leads|exec)`.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["slack-external-channel-add", "OWASP-Top-10-A01"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1078.004` (tactic
  `TA0001 Initial Access`)
- `evidence.channel_name`, `evidence.channel_id`, `evidence.added_user`,
  `evidence.adder`, `evidence.workspace_type`
- `observables[]` carrying the added external user, adder, and channel

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
cat slack-audit.ocsf.jsonl \
  | python src/detect.py \
  > slack-external-channel-add-findings.ocsf.jsonl
```

## Do NOT use

- On raw Slack audit JSON before OCSF normalization
- On Slack message bodies — this is a membership-change detector
- As a remediation skill — guest revocation lives in the remediation layer
- On non-Slack User Access Management 3005

## Tests

The test suite covers:

- positive: external workspace add to a sensitive channel fires
- positive: workspace_user_added_to_workspace with external marker fires
- negative: internal workspace add does NOT fire
- negative: external add to a non-sensitive channel does NOT fire
- negative: events from a non-Slack producer are ignored
- edge: missing channel name is ignored
- env-override: custom regex via `SLACK_SENSITIVE_CHANNEL_PATTERNS` honored
- frozen golden fixture for detector output parity

## Roadmap

Part of the Slack vendor story — see issue #33.
