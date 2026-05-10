# References — detect-snowflake-warehouse-resize-burst

## Source formats and schemas

- **Snowflake QUERY_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/query_history
- **Snowflake `ALTER WAREHOUSE`** — https://docs.snowflake.com/en/sql-reference/sql/alter-warehouse
- **Snowflake warehouse sizes** — https://docs.snowflake.com/en/user-guide/warehouses-overview#warehouse-size
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1496 Resource Hijacking** — https://attack.mitre.org/techniques/T1496/
- **MITRE ATT&CK TA0040 Impact tactic** — https://attack.mitre.org/tactics/TA0040/
- **OWASP Top 10 — A04 Insecure Design** — https://owasp.org/Top10/A04_2021-Insecure_Design/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream Snowflake ingest pipeline.
