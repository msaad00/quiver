# References — ingest-slack-audit-ocsf

## Source formats and schemas

- **Slack Audit Logs API** — https://api.slack.com/admins/audit-logs
- **Slack Audit Logs API `/audit/v1/logs`** — https://api.slack.com/admins/audit-logs-api
- **Slack Audit Logs Actions catalog** — https://api.slack.com/admins/audit-logs-call

## Output format

- **OCSF 1.8 Identity & Access Management category** — https://schema.ocsf.io/
- **OCSF 1.8 Authentication (3002)** — https://schema.ocsf.io/1.8.0/classes/authentication
- **OCSF 1.8 User Access Management (3005)** — https://schema.ocsf.io/1.8.0/classes/user_access
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 Actor object** — https://schema.ocsf.io/1.8.0/objects/actor

## Collection guidance

The skill itself reads JSON from stdin or local files and does not call Slack.
Upstream collectors should:

- follow pagination cursors when polling `/audit/v1/logs`
- preserve raw `id`, `date_create`, `context.location` (workspace identifier),
  `context.ip_address`, and `context.session_id`
- avoid crafting filtered windows manually for continuous exports — Slack
  guarantees `id` is globally unique per action which keeps dedupe deterministic

The skill keeps the source `date_create` and Slack natural IDs intact so
downstream correlation can reason about ordering and replay explicitly.
