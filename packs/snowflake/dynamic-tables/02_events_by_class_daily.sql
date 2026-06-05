-- Dynamic table: ingest volume per OCSF class per day.
--
-- Lets the operator confirm that every ingest-* skill is still landing rows in
-- the lake, and lets the agent answer "how much ingest did you get yesterday?"
-- without rescanning the raw events table.

CREATE DYNAMIC TABLE IF NOT EXISTS security_db.ops.events_by_class_daily
  TARGET_LAG = '24 hours'
  WAREHOUSE = security_lake_wh
  COMMENT = 'Daily event counts by OCSF class_uid. Refreshes incrementally.'
  AS
    SELECT
        TO_DATE(ingested_at) AS bucket_day,
        payload:class_uid::number AS class_uid,
        schema_mode AS schema_mode,
        COUNT(*) AS event_count
    FROM security_db.ops.events_sink
    GROUP BY 1, 2, 3;
