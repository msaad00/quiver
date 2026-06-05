-- Dynamic table: findings volume per rule per hour.
--
-- Powers the operator's at-a-glance "what fired last hour" dashboard and the
-- agent's quick triage. Reading the rolled-up table is O(rules x hours),
-- materially cheaper than rescanning `findings_sink`.
--
-- Why a dynamic table:
--   Snowflake refreshes this incrementally on the declared TARGET_LAG without
--   an external scheduler — the warehouse-native counterpart to a ClickHouse
--   materialized view. It is a volume counter over append-only rows; use
--   UID-aware queries over `findings_sink` when unique cardinality matters.

CREATE DYNAMIC TABLE IF NOT EXISTS security_db.ops.findings_by_rule_hourly
  TARGET_LAG = '1 hour'
  WAREHOUSE = security_lake_wh
  COMMENT = 'Hourly finding counts by rule/severity. Refreshes incrementally.'
  AS
    SELECT
        DATE_TRUNC('hour', ingested_at) AS bucket_hour,
        payload:finding_info.uid::string AS rule_uid,
        payload:severity::string AS severity,
        schema_mode AS schema_mode,
        COUNT(*) AS finding_count
    FROM security_db.ops.findings_sink
    GROUP BY 1, 2, 3, 4;
