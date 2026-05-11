# References — detect-snowflake-failed-mfa-burst

## Source formats and schemas

- **Snowflake LOGIN_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/login_history
- **Snowflake error codes** — https://docs.snowflake.com/en/user-guide/admin-account-identifier#error-codes
- **Snowflake MFA enrollment** — https://docs.snowflake.com/en/user-guide/security-mfa
- **OCSF 1.8 Authentication (3002)** — https://schema.ocsf.io/1.8.0/classes/authentication
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1110 Brute Force** — https://attack.mitre.org/techniques/T1110/
- **MITRE ATT&CK T1621 Multi-Factor Authentication Request Generation** — https://attack.mitre.org/techniques/T1621/
- **MITRE ATT&CK TA0006 Credential Access tactic** — https://attack.mitre.org/tactics/TA0006/
- **OWASP Top 10 — A07 Identification and Authentication Failures** — https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8
Authentication 3002 events from the upstream Snowflake ingest pipeline. The
upstream pipeline needs read access to
`SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`.
