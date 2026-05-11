# References — detect-snowflake-session-policy-bypass

## Source formats and schemas

- **Snowflake QUERY_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/query_history
- **Snowflake `CREATE SESSION POLICY`** — https://docs.snowflake.com/en/sql-reference/sql/create-session-policy
- **Snowflake `ALTER SESSION POLICY`** — https://docs.snowflake.com/en/sql-reference/sql/alter-session-policy
- **Snowflake session-policy concepts** — https://docs.snowflake.com/en/user-guide/session-policies
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1098.003 Account Manipulation: Additional Cloud Roles** — https://attack.mitre.org/techniques/T1098/003/
- **MITRE ATT&CK TA0003 Persistence tactic** — https://attack.mitre.org/tactics/TA0003/
- **OWASP Top 10 — A05 Security Misconfiguration** — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream Snowflake ingest pipeline. The
upstream pipeline needs read access to
`SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`.
