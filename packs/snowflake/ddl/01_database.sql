-- Snowflake security data lake — database scaffold.
--
-- Run once, with an operator role that can `CREATE DATABASE` / `CREATE
-- WAREHOUSE`. The downstream `sink-snowflake-jsonl` and `source-snowflake-query`
-- skills hold no DDL rights; they only insert into / select from the
-- pre-provisioned tables below.
--
-- The schema path `security_db.ops` matches the sink-snowflake-jsonl table
-- contract (`security_db.ops.findings_sink`). Keep them aligned.

CREATE DATABASE IF NOT EXISTS security_db
  COMMENT = 'cloud-ai-security-skills — append-only security data lake';

CREATE SCHEMA IF NOT EXISTS security_db.ops
  COMMENT = 'Operational security lake: events, findings, evidence, audit.';

-- Dedicated warehouse for the auto-refreshing rollup dynamic tables and the
-- lifecycle retention tasks. Size XS; auto-suspend keeps it near-zero cost
-- between refreshes. The sink/source skills bring their own session warehouse
-- (SNOWFLAKE_WAREHOUSE) and do not depend on this one.
CREATE WAREHOUSE IF NOT EXISTS security_lake_wh
  WAREHOUSE_SIZE = 'XSMALL'
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE
  INITIALLY_SUSPENDED = TRUE
  COMMENT = 'Refreshes security_db.ops dynamic tables and retention tasks.';
