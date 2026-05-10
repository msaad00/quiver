# References — detect-databricks-token-creation

## Source formats and schemas

- **Databricks audit logs overview** — https://docs.databricks.com/en/admin/account-settings/audit-logs.html
- **Databricks Token Management API (`tokens/create`)** — https://docs.databricks.com/api/workspace/tokenmanagement/createobotoken
- **Databricks personal access tokens (PATs)** — https://docs.databricks.com/en/dev-tools/auth/pat.html
- **Databricks workspace-level audit events catalog** — https://docs.databricks.com/en/admin/account-settings/audit-log-events.html
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1098 Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **MITRE ATT&CK T1098.001 Additional Cloud Credentials** — https://attack.mitre.org/techniques/T1098/001/
- **MITRE ATT&CK TA0003 Persistence tactic** — https://attack.mitre.org/tactics/TA0003/
- **OWASP LLM Top 10** — https://genai.owasp.org/llm-top-10/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream `ingest-databricks-audit-ocsf`
pipeline (roadmap, tracked under #436). The upstream ingester needs read
access to the Databricks account-level audit-log delivery target (typically
an S3 / GCS / ADLS bucket configured under
`AccountAdmin → Workspace settings → Audit log delivery`), and read access to
the Databricks Token Management list / get APIs is NOT required because
issuance is already captured in the audit feed.
