# References — detect-slack-external-channel-add

## Source formats and schemas

- **Slack Audit Logs API** — https://api.slack.com/admins/audit-logs
- **Slack Audit Logs `/audit/v1/logs` actions** — https://api.slack.com/admins/audit-logs-call
- **Slack Connect & shared channels** — https://api.slack.com/apis/connect
- **OCSF 1.8 User Access Management (3005)** — https://schema.ocsf.io/1.8.0/classes/user_access
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1078.004 Valid Accounts — Cloud Accounts** — https://attack.mitre.org/techniques/T1078/004/
- **MITRE ATT&CK TA0001 Initial Access tactic** — https://attack.mitre.org/tactics/TA0001/
- **OWASP Top 10 — A01 Broken Access Control** — https://owasp.org/Top10/A01_2021-Broken_Access_Control/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 User
Access Management 3005 events from the upstream Slack ingest pipeline. The
upstream pipeline needs the `auditlogs:read` scope on the Slack Audit Logs
API (Enterprise Grid only).
