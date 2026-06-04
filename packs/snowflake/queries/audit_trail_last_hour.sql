-- Pull the audit trail for the last hour across all remediation skills.
--
-- Use case: on-call incident review. The audit table is the source of truth
-- for every HITL-gated remediation; piping it through `view/*` renders the
-- chain as SARIF or Mermaid for incident handoff.

SELECT payload
FROM security_db.ops.audit_sink
WHERE ingested_at >= DATEADD('hour', -1, CURRENT_TIMESTAMP())
ORDER BY ingested_at DESC
