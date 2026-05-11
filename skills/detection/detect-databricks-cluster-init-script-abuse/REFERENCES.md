# References — detect-databricks-cluster-init-script-abuse

## Source formats and schemas

- **Databricks audit logs overview** — https://docs.databricks.com/en/admin/account-settings/audit-logs.html
- **Databricks Clusters audit-log events (`clusters.create`, `clusters.edit`)** — https://docs.databricks.com/en/admin/account-settings/audit-log-events.html#clusters-events
- **Databricks cluster init scripts overview** — https://docs.databricks.com/en/init-scripts/index.html
- **Databricks cluster init-script storage locations (DBFS, S3, ADLS, workspace files)** — https://docs.databricks.com/en/init-scripts/cluster-scoped.html
- **Databricks REST `clusters/create` `init_scripts[]`** — https://docs.databricks.com/api/workspace/clusters/create
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1059.004 Unix Shell** — https://attack.mitre.org/techniques/T1059/004/
- **MITRE ATT&CK T1546 Boot or Logon Initialization Scripts** — https://attack.mitre.org/techniques/T1546/
- **MITRE ATT&CK TA0002 Execution tactic** — https://attack.mitre.org/tactics/TA0002/
- **MITRE ATT&CK TA0003 Persistence tactic** — https://attack.mitre.org/tactics/TA0003/
- **OWASP Top 10 A08:2021 Software and Data Integrity Failures** — https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream `ingest-databricks-audit-ocsf`
pipeline (roadmap, tracked under #436).
