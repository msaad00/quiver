# References — detect-databricks-unity-catalog-cross-workspace-share

## Source formats and schemas

- **Databricks audit logs overview** — https://docs.databricks.com/en/admin/account-settings/audit-logs.html
- **Databricks Unity Catalog audit-log event reference** — https://docs.databricks.com/en/admin/account-settings/audit-log-events.html#unity-catalog-events
- **Databricks Delta Sharing — Create a recipient** — https://docs.databricks.com/en/data-sharing/create-recipient.html
- **Databricks Delta Sharing — Create and manage shares** — https://docs.databricks.com/en/data-sharing/create-share.html
- **Databricks Delta Sharing external recipient model (`recipient.type == "EXTERNAL"`)** — https://docs.databricks.com/en/data-sharing/recipient-type.html
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1537 Transfer Data to Cloud Account** — https://attack.mitre.org/techniques/T1537/
- **MITRE ATT&CK TA0010 Exfiltration tactic** — https://attack.mitre.org/tactics/TA0010/
- **OWASP Top 10 A04:2021 Insecure Design** — https://owasp.org/Top10/A04_2021-Insecure_Design/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream `ingest-databricks-audit-ocsf`
pipeline (roadmap, tracked under #436). The upstream ingester needs read
access to the Databricks account-level audit-log delivery target.
