-- ClickHouse-native dashboard query catalog for the security data lake.
--
-- ClickHouse documents `system.dashboards` as the built-in source for the
-- HTTP `/dashboard` page, and notes that the page can render from any table
-- with the same schema. System tables are read-only, so this pack creates a
-- normal same-schema view under `security` instead of inserting into `system`.
--
-- Run once with an operator role:
--   clickhouse-client --multiquery < system_dashboards.sql
--
-- Reference: https://clickhouse.com/docs/operations/system-tables/dashboards

CREATE OR REPLACE VIEW security.dashboard_queries AS
SELECT
    'security-data-lake' AS dashboard,
    'Findings in window (total)' AS title,
    'SELECT toUInt64(sum(finding_count)) AS total FROM security.findings_by_rule_hourly WHERE bucket_hour >= {from:DateTime} AND bucket_hour < {to:DateTime}' AS query
UNION ALL
SELECT
    'security-data-lake',
    'OCSF events ingested (total)',
    'SELECT toUInt64(sum(event_count)) AS events FROM security.events_by_class_daily WHERE bucket_day >= toDate({from:DateTime}) AND bucket_day < toDate({to:DateTime})'
UNION ALL
SELECT
    'security-data-lake',
    'Remediation outcomes (total)',
    'SELECT toUInt64(sum(outcome_count)) AS remediations FROM security.remediations_by_outcome_daily WHERE bucket_day >= toDate({from:DateTime}) AND bucket_day < toDate({to:DateTime})'
UNION ALL
SELECT
    'security-data-lake',
    'Findings over time (by severity)',
    'SELECT toStartOfInterval(bucket_hour, INTERVAL {rounding:UInt32} SECOND) AS t, severity, sum(finding_count) AS findings FROM security.findings_by_rule_hourly WHERE bucket_hour >= {from:DateTime} AND bucket_hour < {to:DateTime} GROUP BY t, severity ORDER BY t'
UNION ALL
SELECT
    'security-data-lake',
    'Top rules by finding volume',
    'SELECT rule_uid, severity, sum(finding_count) AS findings FROM security.findings_by_rule_hourly WHERE bucket_hour >= {from:DateTime} AND bucket_hour < {to:DateTime} GROUP BY rule_uid, severity ORDER BY findings DESC LIMIT 25'
UNION ALL
SELECT
    'security-data-lake',
    'Ingest volume by OCSF class',
    'SELECT toStartOfInterval(toDateTime(bucket_day), INTERVAL {rounding:UInt32} SECOND) AS t, toString(class_uid) AS ocsf_class, sum(event_count) AS events FROM security.events_by_class_daily WHERE bucket_day >= toDate({from:DateTime}) AND bucket_day < toDate({to:DateTime}) GROUP BY t, ocsf_class ORDER BY t'
UNION ALL
SELECT
    'security-data-lake',
    'Remediation outcomes by skill',
    'SELECT skill_name, remediation_state, sum(outcome_count) AS outcomes FROM security.remediations_by_outcome_daily WHERE bucket_day >= toDate({from:DateTime}) AND bucket_day < toDate({to:DateTime}) GROUP BY skill_name, remediation_state ORDER BY outcomes DESC LIMIT 50';
