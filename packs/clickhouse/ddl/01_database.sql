-- ClickHouse security data lake — database scaffold.
--
-- Run once, with an operator role that can `CREATE DATABASE`. The downstream
-- `sink-clickhouse-jsonl` and `source-clickhouse-query` skills hold no DDL
-- rights; they only insert into / select from the pre-provisioned tables below.

CREATE DATABASE IF NOT EXISTS security
COMMENT 'cloud-ai-security-skills — append-only security data lake';
