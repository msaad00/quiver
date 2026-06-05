-- Findings sink — OCSF Detection Finding (2004) and repo-native finding rows.
--
-- Append-only. The `sink-snowflake-jsonl` skill is the only writer; it inserts
-- (payload, schema_mode, event_uid, finding_uid) and lets `ingested_at`
-- default. Operators run DDL; the sink never does.
--
-- Clustering : (schema_mode, finding_uid). Dedupe and replay joins prune on the
--              clustering key. Replays converge because finding_uid is
--              content-addressable (det-<rule>-<short(semantic_key)>).
-- Retention  : 365 days, enforced by the suspended retention task below.
-- Time Travel: 7 days, for operator UNDROP / point-in-time recovery.

CREATE TABLE IF NOT EXISTS security_db.ops.findings_sink (
    payload VARIANT NOT NULL,
    schema_mode STRING,
    event_uid STRING,
    finding_uid STRING,
    ingested_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
)
CLUSTER BY (schema_mode, finding_uid)
DATA_RETENTION_TIME_IN_DAYS = 7
COMMENT = 'OCSF 2004 + repo-native findings. Append-only; 365-day lifecycle.';

-- Lifecycle: drop finding rows older than 365 days. Created suspended; an
-- operator runs `ALTER TASK ... RESUME` after granting the task owner role.
CREATE TASK IF NOT EXISTS security_db.ops.findings_sink_retention
  WAREHOUSE = security_lake_wh
  SCHEDULE = 'USING CRON 0 3 * * * UTC'
  COMMENT = '365-day retention for findings_sink.'
  AS
    DELETE FROM security_db.ops.findings_sink
    WHERE ingested_at < DATEADD('day', -365, CURRENT_TIMESTAMP());
