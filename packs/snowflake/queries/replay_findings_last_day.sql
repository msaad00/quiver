-- Replay every finding ingested in the last 24 hours.
--
-- Pipe through `source-snowflake-query` into a view-* skill to re-render the
-- same findings as SARIF or Mermaid without re-running detection.

SELECT payload
FROM security_db.ops.findings_sink
WHERE ingested_at >= DATEADD('day', -1, CURRENT_TIMESTAMP())
  AND schema_mode = 'ocsf'
ORDER BY ingested_at DESC
