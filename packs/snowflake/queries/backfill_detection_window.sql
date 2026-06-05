-- Backfill a detection over a historical OCSF event window.
--
-- Use case: a new `detect-*` rule shipped. Replay last 7 days of normalized
-- API Activity (6003) + Network Activity (4001) through the new detector
-- without re-ingesting from the vendor.
--
-- Compose:
--   source-snowflake-query --query "$(cat backfill_detection_window.sql)" \
--     | jq -c '.payload' \
--     | python skills/detection/detect-lateral-movement/src/detect.py \
--     | python skills/output/sink-snowflake-jsonl/src/sink.py \
--         --table security_db.ops.findings_sink --apply

SELECT payload
FROM security_db.ops.events_sink
WHERE ingested_at >= DATEADD('day', -7, CURRENT_TIMESTAMP())
  AND schema_mode = 'ocsf'
  AND payload:class_uid::number IN (6003, 4001)
ORDER BY ingested_at ASC
