# References — detect-databricks-workspace-admin-grant

## Source formats and schemas

- **Databricks audit logs overview** — https://docs.databricks.com/en/admin/account-settings/audit-logs.html
- **Databricks account audit events (`accounts.setAdmin`)** — https://docs.databricks.com/en/admin/account-settings/audit-log-events.html#accounts-events
- **Databricks IAM group audit events (`iam.addUserToGroup`)** — https://docs.databricks.com/en/admin/account-settings/audit-log-events.html#iam-events
- **Databricks workspace and account admin roles** — https://docs.databricks.com/en/admin/users-groups/admin-roles.html
- **Databricks `admins` (workspace) and `account_admins` (account) groups** — https://docs.databricks.com/en/admin/users-groups/groups.html
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1098 Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **MITRE ATT&CK T1098.003 Additional Cloud Roles** — https://attack.mitre.org/techniques/T1098/003/
- **MITRE ATT&CK TA0003 Persistence tactic** — https://attack.mitre.org/tactics/TA0003/
- **OWASP Top 10 A01:2021 Broken Access Control** — https://owasp.org/Top10/A01_2021-Broken_Access_Control/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream `ingest-databricks-audit-ocsf`
pipeline (roadmap, tracked under #436).
