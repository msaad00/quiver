# References — detect-snowflake-replication-config-change

## Source formats and schemas

- **Snowflake QUERY_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/query_history
- **Snowflake `ALTER ACCOUNT` (replication parameters)** — https://docs.snowflake.com/en/sql-reference/sql/alter-account
- **Snowflake `ALTER DATABASE ... ENABLE REPLICATION TO ACCOUNTS`** — https://docs.snowflake.com/en/sql-reference/sql/alter-database
- **Snowflake database replication overview** — https://docs.snowflake.com/en/user-guide/db-replication-intro
- **Snowflake replication and failover groups** — https://docs.snowflake.com/en/user-guide/account-replication-intro
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1537 Transfer Data to Cloud Account** — https://attack.mitre.org/techniques/T1537/
- **MITRE ATT&CK TA0010 Exfiltration tactic** — https://attack.mitre.org/tactics/TA0010/
- **OWASP Top 10 — A04 Insecure Design** — https://owasp.org/Top10/A04_2021-Insecure_Design/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream Snowflake ingest pipeline. The
upstream pipeline needs read access to
`SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`.
