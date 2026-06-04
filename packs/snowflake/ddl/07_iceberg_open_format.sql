-- Open-format variant — Snowflake-managed Apache Iceberg sink tables.
--
-- OPTIONAL. Apply this INSTEAD OF 02/03 (findings/events) when the lake must
-- stay in an open, externally-readable table format rather than Snowflake's
-- native format. The columns and the sink contract are identical — the sink
-- and source skills do not change — but the bytes land as Apache Iceberg
-- (Parquet data + Iceberg metadata) governed by the Snowflake Horizon Catalog.
--
-- Why this matters for a sovereign security lake:
--   * No lock-in — the same findings/events are readable and writable by
--     external engines (Apache Spark, Trino, Flink) through Horizon Catalog
--     endpoints, GA October 2025. The security team is never trapped in one
--     query engine.
--   * VARIANT payloads are supported in Snowflake-managed Iceberg, so the
--     content-addressed OCSF JSONL contract carries over unchanged.
--   * Horizon Catalog brings built-in classification, lineage, access history,
--     and risk monitoring over the open tables — the governance lane the
--     evidence and audit sinks rely on.
--
-- Prerequisite: an EXTERNAL VOLUME pointing at operator-owned object storage
-- (S3 / Azure / GCS) inside the customer's own cloud boundary. Use
-- 'SNOWFLAKE_MANAGED' only for a quick start; production sovereign lakes point
-- at a customer-owned bucket.

-- CREATE EXTERNAL VOLUME IF NOT EXISTS security_lake_vol
--   STORAGE_LOCATIONS = (
--     (NAME = 'lake'
--      STORAGE_PROVIDER = 'S3'
--      STORAGE_BASE_URL = 's3://your-security-lake-bucket/iceberg/'
--      STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::<acct>:role/snowflake-iceberg')
--   );

CREATE ICEBERG TABLE IF NOT EXISTS security_db.ops.findings_sink (
    payload VARIANT,
    schema_mode STRING,
    event_uid STRING,
    finding_uid STRING,
    ingested_at TIMESTAMP_LTZ
)
  CATALOG = 'SNOWFLAKE'
  EXTERNAL_VOLUME = 'security_lake_vol'
  BASE_LOCATION = 'findings_sink/'
  COMMENT = 'Open-format (Iceberg) findings sink. Horizon-governed; Spark-readable.';

CREATE ICEBERG TABLE IF NOT EXISTS security_db.ops.events_sink (
    payload VARIANT,
    schema_mode STRING,
    event_uid STRING,
    finding_uid STRING,
    ingested_at TIMESTAMP_LTZ
)
  CATALOG = 'SNOWFLAKE'
  EXTERNAL_VOLUME = 'security_lake_vol'
  BASE_LOCATION = 'events_sink/'
  COMMENT = 'Open-format (Iceberg) events sink. Horizon-governed; Spark-readable.';

-- Row access policy (06) and the rollup dynamic tables apply unchanged: a
-- dynamic table can read from an Iceberg base table, and a row access policy
-- attaches to an Iceberg table the same way as a standard table.
--
-- Lifecycle on managed Iceberg is automatic (Snowflake handles compaction and
-- snapshot retention); the DELETE-based retention tasks in 02/03 are only for
-- the native-format tables. Set snapshot retention via the table's
-- STORAGE_SERIALIZATION_POLICY / Horizon maintenance settings instead.
