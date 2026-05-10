# References — detect-snowflake-bulk-data-egress

## Source formats and schemas

- **Snowflake QUERY_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/query_history
- **Snowflake ACCESS_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/access_history
- **Snowflake `COPY INTO <location>` reference** — https://docs.snowflake.com/en/sql-reference/sql/copy-into-location
- **Snowflake `GET` command** — https://docs.snowflake.com/en/sql-reference/sql/get
- **Snowflake external stages** — https://docs.snowflake.com/en/user-guide/data-load-overview#external-stages
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1567 Exfiltration Over Web Service** — https://attack.mitre.org/techniques/T1567/
- **MITRE ATT&CK TA0010 Exfiltration tactic** — https://attack.mitre.org/tactics/TA0010/
- **OWASP Top 10 — A04 Insecure Design** — https://owasp.org/Top10/A04_2021-Insecure_Design/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream Snowflake ingest pipeline. The
upstream pipeline needs read access to `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`
and `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY`.
