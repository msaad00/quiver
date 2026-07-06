---
name: ingest-slack-audit-ocsf
description: >-
  Convert verified Slack Audit Logs API records (`/audit/v1/logs`) into OCSF
  1.8 events. Most actions normalize to API Activity (6003); session events
  (`user_login`, `user_logout`, `signout_all_sessions`) route to Authentication
  (3002); membership and admin-role-grant actions
  (`workspace_user_added_to_workspace`, `workspace_user_removed_from_workspace`,
  `private_channel_member_added`, `role_change_to_admin`,
  `role_change_to_owner`) route to User Access Management (3005). Preserves
  Slack natural IDs such as `id`, `date_create`, `workspace.id`, and
  `context.session_id` under `unmapped.slack.*` for SIEM-friendly dedupe and
  correlation. Use when the user mentions Slack audit log ingestion, Slack
  Enterprise Grid audit normalization, or feeding Slack workspace and channel
  events into an OCSF or canonical pipeline. Do NOT use for raw Slack message
  contents, Slack `conversations.history` payloads, or non-audit Slack events.
  Do NOT use as a detector — this skill only normalizes Slack audit payloads
  into OCSF or native output.
purpose: Convert verified Slack Audit Logs API records into OCSF 1.8 Authentication, API Activity, or User Access Management events while preserving Slack-native identifiers under `unmapped.slack.*`.
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. No Slack SDK required when Audit Logs API payloads
  are already exported. Read-only — validates raw Slack audit event shape and
  emits OCSF or native JSONL. Never calls Slack write APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-slack-audit-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: slack
  capability: read-only
---

# ingest-slack-audit-ocsf

Convert raw Slack Audit Logs API payloads into OCSF 1.8 events with
deterministic IDs and verified field mappings.

## Use when

- You have Slack Audit Logs API exports from `/audit/v1/logs` (Enterprise Grid) and need OCSF output
- You want to normalize Slack workspace, channel, and admin-role telemetry for SIEM, lake, MCP, or downstream detection use
- You need a portable Slack audit stream that preserves Slack `id`, `date_create`, workspace, and session identifiers
- You want channel-membership and role-grant events represented as OCSF User Access events instead of vendor-only audit records

## Do NOT use

- On Slack message bodies or `conversations.history` payloads
- To collect live Slack audit logs by itself — upstream collection and OAuth stay outside this skill
- To infer ATT&CK techniques or create findings directly
- To rewrite, mutate, or post to Slack workspaces, channels, or users

## Input contract

Accepts one of three raw Slack Audit Logs API shapes:

1. **`/audit/v1/logs` response object**

```json
{
  "entries": [
    {
      "id": "0123a45b-678c-90d1-e234-567f8901a2bc",
      "date_create": 1718323200,
      "action": "user_login",
      "actor": {"type": "user", "user": {"id": "U01234ABC", "name": "alice", "email": "alice@example.com"}},
      "entity": {"type": "user", "user": {"id": "U01234ABC"}},
      "context": {"location": {"type": "workspace", "id": "T01234XYZ"}, "ip_address": "203.0.113.10"}
    }
  ]
}
```

2. **Single entry**

```json
{
  "id": "0123a45b-678c-90d1-e234-567f8901a2bc",
  "date_create": 1718323200,
  "action": "user_login"
}
```

3. **NDJSON** — one entry per line.

The first slice intentionally supports a narrow, verified action family:

- `user_login`
- `user_logout`
- `signout_all_sessions`
- `workspace_user_added_to_workspace`
- `workspace_user_removed_from_workspace`
- `private_channel_member_added`
- `private_channel_member_removed`
- `public_channel_member_added`
- `public_channel_member_removed`
- `role_change_to_admin`
- `role_change_to_owner`
- `role_change_to_user`
- `app_installed`
- `app_approved`
- `app_uninstalled`
- `app_restricted`
- `file_downloaded`
- `file_shared`
- `channel_created`
- `private_channel_created`

Unsupported actions are skipped, never silently dropped. Each occurrence emits
an `unmapped_event_type` warning to `stderr` with the offending `action` and
event id. At end of run, an `unmapped_event_type_summary` info record reports
total skipped, distinct action types, and the top 10 unmapped actions with
counts — so blind spots surface immediately in CI logs.

## Output contract

Emits OCSF 1.8 JSONL by default, with `--output-format native` available for
the repo-owned canonical projection.

OCSF output uses these verified class mappings:

- **Authentication (3002)** for `user_login`, `user_logout`, `signout_all_sessions`
- **User Access Management (3005)** for membership add/remove and role-change actions
- **API Activity (6003)** for app-install lifecycle, file events, and channel-create events

Each output record includes:

- deterministic `metadata.uid` based on Slack `id` or a stable hash fallback
- UTC epoch-millisecond `time` from `date_create`
- Slack workspace and session correlation under `unmapped.slack.*`
- `actor`, `user`, `src_endpoint`, and `resources` where the raw event supports them

## Usage

```bash
# Audit Logs API export file
python src/ingest.py slack-audit.json > slack.ocsf.jsonl

# NDJSON from stdin
cat slack-audit.ndjson | python src/ingest.py > slack.ocsf.jsonl

# native projection for non-OCSF consumers
python src/ingest.py slack-audit.json --output-format native > slack.native.jsonl
```

## Security guardrails

- Read-only only. No Slack writes. No subprocesses.
- Keeps vendor-native IDs for dedupe and correlation instead of inventing new random IDs.
- Uses verified raw fields from official Slack docs only; unsupported actions are skipped rather than guessed.
- Normalizes into OCSF only where the class fit is explicit. Unmapped vendor-specific detail stays under `unmapped`.

## Native output format

When `--output-format native` is selected, the skill emits:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type`
- `event_uid`
- `provider`
- `activity_id`
- `event_type`
- `time_ms`
- `actor`, `user`, `src_endpoint`, `resources` where present
- `unmapped.slack.*` vendor-specific detail

## See also

- [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) — shared OCSF wire contract and version pinning
- [`../ingest-okta-system-log-ocsf/SKILL.md`](../ingest-okta-system-log-ocsf/SKILL.md) — Okta identity audit equivalent
- [`../../detection/detect-slack-external-channel-add/SKILL.md`](../../detection/detect-slack-external-channel-add/SKILL.md) — downstream external-channel-add detector
- [`../../detection/detect-slack-oauth-app-install-broad-scope/SKILL.md`](../../detection/detect-slack-oauth-app-install-broad-scope/SKILL.md) — downstream OAuth-app install detector
- [`../../detection/detect-slack-admin-elevation/SKILL.md`](../../detection/detect-slack-admin-elevation/SKILL.md) — downstream admin-role-grant detector
