-- Events sink — normalized OCSF events from any `ingest-*` skill.
--
-- This is the hot tier of the security data lake. Detection skills replay from
-- here through `source-snowflake-query`. Schema matches the sink contract: one
-- event per row, VARIANT payload, content-addressed event_uid.
--
-- Clustering : (schema_mode, event_uid). Replay-by-uid stays cheap; an explicit
--              ingested_at search-optimization path speeds up time-window scans
--              when enabled by the operator.
-- Retention  : 90 days hot, enforced by the suspended retention task below.
--              Cold copies should be tee'd to object storage via sink-s3-jsonl
--              at ingest time.

CREATE TABLE IF NOT EXISTS security_db.ops.events_sink (
    payload VARIANT NOT NULL,
    schema_mode STRING,
    event_uid STRING,
    finding_uid STRING,
    ingested_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
)
CLUSTER BY (schema_mode, event_uid)
DATA_RETENTION_TIME_IN_DAYS = 7
COMMENT = 'Normalized OCSF events — hot tier. Append-only; 90-day lifecycle.';

-- Optional: accelerate ad-hoc time-window scans without reclustering.
-- Operators enable per cost appetite.
-- ALTER TABLE security_db.ops.events_sink ADD SEARCH OPTIMIZATION;

CREATE TASK IF NOT EXISTS security_db.ops.events_sink_retention
  WAREHOUSE = security_lake_wh
  SCHEDULE = 'USING CRON 0 3 * * * UTC'
  COMMENT = '90-day retention for events_sink (hot tier).'
  AS
    DELETE FROM security_db.ops.events_sink
    WHERE ingested_at < DATEADD('day', -90, CURRENT_TIMESTAMP());
