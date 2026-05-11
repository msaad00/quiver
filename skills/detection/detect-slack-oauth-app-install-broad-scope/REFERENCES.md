# References — detect-slack-oauth-app-install-broad-scope

## Source formats and schemas

- **Slack Audit Logs API** — https://api.slack.com/admins/audit-logs
- **Slack Audit Logs Actions catalog** — https://api.slack.com/admins/audit-logs-call
- **Slack OAuth scopes catalog** — https://api.slack.com/scopes
- **Slack App management for admins** — https://api.slack.com/admins/apps
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1098.005 Account Manipulation — Device Registration** — https://attack.mitre.org/techniques/T1098/005/
- **MITRE ATT&CK TA0003 Persistence tactic** — https://attack.mitre.org/tactics/TA0003/
- **OWASP Top 10 — A05 Security Misconfiguration** — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream Slack ingest pipeline. The upstream
pipeline needs the `auditlogs:read` scope on the Slack Audit Logs API
(Enterprise Grid only).
