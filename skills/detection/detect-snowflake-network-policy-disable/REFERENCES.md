# References — detect-snowflake-network-policy-disable

## Source formats and schemas

- **Snowflake QUERY_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/query_history
- **Snowflake `CREATE NETWORK POLICY`** — https://docs.snowflake.com/en/sql-reference/sql/create-network-policy
- **Snowflake `ALTER NETWORK POLICY`** — https://docs.snowflake.com/en/sql-reference/sql/alter-network-policy
- **Snowflake `ALTER ACCOUNT` (network policy parameter)** — https://docs.snowflake.com/en/sql-reference/parameters#network-policy
- **Snowflake network-policy concepts** — https://docs.snowflake.com/en/user-guide/network-policies
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1562.007 Impair Defenses: Disable or Modify Cloud Firewall** — https://attack.mitre.org/techniques/T1562/007/
- **MITRE ATT&CK TA0005 Defense Evasion tactic** — https://attack.mitre.org/tactics/TA0005/
- **OWASP Top 10 — A05 Security Misconfiguration** — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream Snowflake ingest pipeline. The
upstream pipeline needs read access to
`SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`.
