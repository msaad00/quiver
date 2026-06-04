-- Dynamic table: remediation outcomes per day.
--
-- Closed-loop telemetry: how many remediations applied, dry-ran, failed, or
-- got denied by HITL today. Pair this with an operator dashboard or a daily
-- digest so the security team sees drift without opening the raw audit table.

CREATE DYNAMIC TABLE IF NOT EXISTS security_db.ops.remediations_by_outcome_daily
  TARGET_LAG = '24 hours'
  WAREHOUSE = security_lake_wh
  COMMENT = 'Daily remediation outcome counts by skill. Refreshes incrementally.'
  AS
    SELECT
        TO_DATE(ingested_at) AS bucket_day,
        payload:skill::string AS skill_name,
        payload:remediation_status::string AS remediation_state,
        COUNT(*) AS outcome_count
    FROM security_db.ops.audit_sink
    WHERE payload:record_type::string = 'remediation_audit'
    GROUP BY 1, 2, 3;
