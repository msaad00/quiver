-- ClickHouse Cloud SQL Console — saved-query bundle for the security data lake.
--
-- ClickHouse Cloud's SQL Console runs these directly: paste each statement
-- in, save it, and the Console renders the result as a table or chart.
-- Charts saved against these queries become the lake's operator panel
-- without leaving the ClickHouse Cloud trust boundary.
--
-- All queries read the rollup materialized views, so they avoid rescanning
-- raw OCSF JSONL rows. Time bounds are explicit so the Console can bind them
-- to its own date picker.

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Findings total (24h)
-- ─────────────────────────────────────────────────────────────────────────────
SELECT toUInt64(sum(finding_count)) AS total
FROM security.findings_by_rule_hourly
WHERE bucket_hour >= now() - INTERVAL 1 DAY;

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. OCSF events ingested (24h)
-- ─────────────────────────────────────────────────────────────────────────────
SELECT toUInt64(sum(event_count)) AS events
FROM security.events_by_class_daily
WHERE bucket_day >= today() - 1;

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. Remediation outcomes (24h)
-- ─────────────────────────────────────────────────────────────────────────────
SELECT toUInt64(sum(outcome_count)) AS remediations
FROM security.remediations_by_outcome_daily
WHERE bucket_day >= today() - 1;

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. Findings over time, hourly buckets, last 7 days, split by severity
--    (best rendered as a stacked area chart in the Console)
-- ─────────────────────────────────────────────────────────────────────────────
SELECT
    bucket_hour                AS t,
    severity                   AS severity,
    sum(finding_count)         AS findings
FROM security.findings_by_rule_hourly
WHERE bucket_hour >= now() - INTERVAL 7 DAY
GROUP BY t, severity
ORDER BY t;

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. Top firing rules in the last 7 days
-- ─────────────────────────────────────────────────────────────────────────────
SELECT
    rule_uid,
    severity,
    sum(finding_count) AS findings
FROM security.findings_by_rule_hourly
WHERE bucket_hour >= now() - INTERVAL 7 DAY
GROUP BY rule_uid, severity
ORDER BY findings DESC
LIMIT 25;

-- ─────────────────────────────────────────────────────────────────────────────
-- 6. Ingest volume by OCSF class, daily, last 30 days
--    (best rendered as a stacked area or bar chart)
-- ─────────────────────────────────────────────────────────────────────────────
SELECT
    bucket_day              AS t,
    toString(class_uid)     AS ocsf_class,
    sum(event_count)        AS events
FROM security.events_by_class_daily
WHERE bucket_day >= today() - 30
GROUP BY t, ocsf_class
ORDER BY t;

-- ─────────────────────────────────────────────────────────────────────────────
-- 7. Remediation outcomes by skill — closed-loop view, last 30 days
-- ─────────────────────────────────────────────────────────────────────────────
SELECT
    skill_name,
    remediation_state,
    sum(outcome_count) AS outcomes
FROM security.remediations_by_outcome_daily
WHERE bucket_day >= today() - 30
GROUP BY skill_name, remediation_state
ORDER BY outcomes DESC
LIMIT 50;

-- ─────────────────────────────────────────────────────────────────────────────
-- 8. Noisy-rule detector — rules with > 100 findings in the last hour
--    Pair this with a Cloud Console alert rule for SLO-style noise budgets.
-- ─────────────────────────────────────────────────────────────────────────────
SELECT
    rule_uid,
    severity,
    sum(finding_count) AS findings_last_hour
FROM security.findings_by_rule_hourly
WHERE bucket_hour >= now() - INTERVAL 1 HOUR
GROUP BY rule_uid, severity
HAVING findings_last_hour > 100
ORDER BY findings_last_hour DESC;
