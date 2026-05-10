# References — detect-snowflake-unauthorized-grant

## Source formats and schemas

- **Snowflake QUERY_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/query_history
- **Snowflake GRANTS_TO_USERS view** — https://docs.snowflake.com/en/sql-reference/account-usage/grants_to_users
- **Snowflake `GRANT <role>`** — https://docs.snowflake.com/en/sql-reference/sql/grant-role
- **Snowflake system-defined roles** — https://docs.snowflake.com/en/user-guide/security-access-control-overview#system-defined-roles
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1098.003 Add Office 365 / Azure / Snowflake Roles** — https://attack.mitre.org/techniques/T1098/003/
- **MITRE ATT&CK TA0003 Persistence tactic** — https://attack.mitre.org/tactics/TA0003/
- **OWASP Top 10 — A01 Broken Access Control** — https://owasp.org/Top10/A01_2021-Broken_Access_Control/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream Snowflake ingest pipeline. The
upstream pipeline needs read access to
`SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY` and
`SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`.
