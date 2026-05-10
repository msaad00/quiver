# References — detect-clickhouse-bulk-export

## Source formats and schemas

- **ClickHouse `system.query_log` table** — https://clickhouse.com/docs/en/operations/system-tables/query_log
- **ClickHouse `INTO OUTFILE` clause** — https://clickhouse.com/docs/en/sql-reference/statements/select/into-outfile
- **ClickHouse `s3` table function** — https://clickhouse.com/docs/en/sql-reference/table-functions/s3
- **ClickHouse `url` table function** — https://clickhouse.com/docs/en/sql-reference/table-functions/url
- **ClickHouse `URL` table engine** — https://clickhouse.com/docs/en/engines/table-engines/special/url
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1567 Exfiltration Over Web Service** — https://attack.mitre.org/techniques/T1567/
- **MITRE ATT&CK TA0010 Exfiltration tactic** — https://attack.mitre.org/tactics/TA0010/
- **OWASP Top 10 — A04 Insecure Design** — https://owasp.org/Top10/A04_2021-Insecure_Design/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream ClickHouse ingest pipeline. The
upstream pipeline needs a ClickHouse account with `SELECT` on
`system.query_log` (and on `system.query_views_log` if joined) — no other
grants are required.
