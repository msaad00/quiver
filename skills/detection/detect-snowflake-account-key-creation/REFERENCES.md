# References — detect-snowflake-account-key-creation

## Source formats and schemas

- **Snowflake QUERY_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/query_history
- **Snowflake key-pair authentication** — https://docs.snowflake.com/en/user-guide/key-pair-auth
- **Snowflake `ALTER USER`** — https://docs.snowflake.com/en/sql-reference/sql/alter-user
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1098.001 Additional Cloud Credentials** — https://attack.mitre.org/techniques/T1098/001/
- **MITRE ATT&CK TA0003 Persistence tactic** — https://attack.mitre.org/tactics/TA0003/
- **OWASP Top 10 — A07 Identification and Authentication Failures** — https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream Snowflake ingest pipeline.
