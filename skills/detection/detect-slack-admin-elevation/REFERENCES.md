# References — detect-slack-admin-elevation

## Source formats and schemas

- **Slack Audit Logs API** — https://api.slack.com/admins/audit-logs
- **Slack Audit Logs Actions catalog** — https://api.slack.com/admins/audit-logs-call
- **Slack admin role assignment** — https://api.slack.com/methods/admin.users.setOwner
- **OCSF 1.8 User Access Management (3005)** — https://schema.ocsf.io/1.8.0/classes/user_access
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1098.003 Additional Cloud Roles** — https://attack.mitre.org/techniques/T1098/003/
- **MITRE ATT&CK TA0003 Persistence tactic** — https://attack.mitre.org/tactics/TA0003/
- **OWASP Top 10 — A01 Broken Access Control** — https://owasp.org/Top10/A01_2021-Broken_Access_Control/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 User
Access Management 3005 events from the upstream Slack ingest pipeline. The
upstream pipeline needs the `auditlogs:read` scope on the Slack Audit Logs
API (Enterprise Grid only).
