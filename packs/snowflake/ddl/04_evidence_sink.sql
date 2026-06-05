-- Evidence sink — control-evidence and posture artifacts.
--
-- Consumed by:
--   discover-control-evidence
--   discover-cloud-control-evidence
--   cspm-*-cis-benchmark (when materializing compliance evidence)
--
-- Compliance auditors read this table directly. Keep it append-only and keep
-- the retention long (compliance frameworks typically demand 7 years).

CREATE TABLE IF NOT EXISTS security_db.ops.evidence_sink (
    payload VARIANT NOT NULL,
    schema_mode STRING,
    event_uid STRING,
    finding_uid STRING,
    ingested_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
)
CLUSTER BY (schema_mode, finding_uid)
DATA_RETENTION_TIME_IN_DAYS = 14
COMMENT = 'Control evidence + posture artifacts. Append-only; ~7-year hold.';

-- Lifecycle: ~7 years (2557 days) for SOC 2 / PCI / HIPAA evidence holds.
-- Created suspended; resume only after the legal/compliance retention window
-- is confirmed for the deployment.
CREATE TASK IF NOT EXISTS security_db.ops.evidence_sink_retention
  WAREHOUSE = security_lake_wh
  SCHEDULE = 'USING CRON 0 4 * * 0 UTC'
  COMMENT = '~7-year retention for evidence_sink (compliance hold).'
  AS
    DELETE FROM security_db.ops.evidence_sink
    WHERE ingested_at < DATEADD('day', -2557, CURRENT_TIMESTAMP());
