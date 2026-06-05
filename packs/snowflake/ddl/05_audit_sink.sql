-- Audit sink — remediation + MCP audit trail.
--
-- Consumed by:
--   remediate-*  (every HITL-gated remediation skill dual-audits here)
--   mcp-server   (every dispatched tool call writes an audit row)
--
-- Auditors need millisecond timestamps and tamper-evident retention. There is
-- intentionally NO retention task on this table: audit rows fall under legal
-- hold and are pruned only by an approved process, never by table default.
-- A longer Time Travel window guards against accidental operator deletion.

CREATE TABLE IF NOT EXISTS security_db.ops.audit_sink (
    payload VARIANT NOT NULL,
    schema_mode STRING,
    event_uid STRING,
    finding_uid STRING,
    ingested_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
)
CLUSTER BY (schema_mode, event_uid)
DATA_RETENTION_TIME_IN_DAYS = 90
COMMENT = 'Remediation + MCP audit chain. Append-only; legal-hold retention.';
