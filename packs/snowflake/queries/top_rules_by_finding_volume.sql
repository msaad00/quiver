-- Top firing rules in the last 7 days, by finding volume.
--
-- Reads the rolled-up dynamic table — sub-second response on a year of
-- findings. Useful for "which rule is noisiest right now" triage.

SELECT
    rule_uid,
    severity,
    SUM(finding_count) AS findings
FROM security_db.ops.findings_by_rule_hourly
WHERE bucket_hour >= DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY rule_uid, severity
ORDER BY findings DESC
LIMIT 25
