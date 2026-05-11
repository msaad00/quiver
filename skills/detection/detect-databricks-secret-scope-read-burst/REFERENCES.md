# References — detect-databricks-secret-scope-read-burst

## Source formats and schemas

- **Databricks audit logs overview** — https://docs.databricks.com/en/admin/account-settings/audit-logs.html
- **Databricks Secrets audit-log events (`secrets.getSecret`)** — https://docs.databricks.com/en/admin/account-settings/audit-log-events.html#secrets-events
- **Databricks Secrets API `getSecret`** — https://docs.databricks.com/api/workspace/secrets/getsecret
- **Databricks secret scopes overview** — https://docs.databricks.com/en/security/secrets/secret-scopes.html
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1552 Unsecured Credentials** — https://attack.mitre.org/techniques/T1552/
- **MITRE ATT&CK T1552.001 Credentials In Files** — https://attack.mitre.org/techniques/T1552/001/
- **MITRE ATT&CK TA0006 Credential Access tactic** — https://attack.mitre.org/tactics/TA0006/
- **OWASP Top 10 A07:2021 Identification and Authentication Failures** — https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream `ingest-databricks-audit-ocsf`
pipeline (roadmap, tracked under #436).
