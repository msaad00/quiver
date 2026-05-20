# ClickHouse security data lake — dashboards (ClickHouse-native)

Operator UX on top of the lake, kept close to the ClickHouse data model. The
pack ships a same-schema dashboard query catalog for self-hosted ClickHouse
and saved-query templates for ClickHouse Cloud.

ClickHouse ships two first-class dashboard surfaces — this pack uses both:

| Surface | Where | What this pack ships |
|---|---|---|
| **Embedded `/dashboard` page** (self-hosted ClickHouse) | Built-in `system.dashboards` schema; ClickHouse also documents same-schema custom tables | `system_dashboards.sql` — creates `security.dashboard_queries`, a same-schema query catalog |
| **ClickHouse Cloud SQL Console** | Cloud Console → SQL Console → Saved queries / Charts | `cloud_console_queries.sql` — 8 paste-and-save queries with chart-friendly column shapes |

Both surfaces drive off the rollup materialized views in
[`../materialized-views/`](../materialized-views/), so panel queries avoid
rescanning raw OCSF JSONL rows. The rollups are volume counters over
append-only inserts; if a replay can insert duplicates, use UID-aware raw-table
queries for unique cardinality questions.

## Install — self-hosted ClickHouse

Prereq: a ClickHouse server with the `/dashboard` page and the
`system.dashboards` schema available. The shipped SQL does not write to
`system`; it creates `security.dashboard_queries`.

```bash
clickhouse-client --multiquery < packs/clickhouse/dashboards/system_dashboards.sql

# inspect the query catalog:
clickhouse-client --query "SELECT title, query FROM security.dashboard_queries"
```

`system_dashboards.sql` uses `CREATE OR REPLACE VIEW`, so re-running it
refreshes the same catalog without duplicate rows. Time bounds
(`{from:DateTime}`, `{to:DateTime}`) and the `{rounding:UInt32}` interval
parameter follow ClickHouse's documented dashboard query shape.

## Install — ClickHouse Cloud

1. Cloud Console → SQL Console
2. Open `cloud_console_queries.sql`, paste each query
3. Save and (where the shape fits) attach a chart via the Console's chart
   builder

The shipped queries cover the same panel set as the self-hosted query catalog
(stats, severity-stacked timeseries, top-rules table, OCSF-class stack,
closed-loop remediation outcomes, noisy-rule SLO query).

## Panels

Both files ship the same panel set:

1. Findings in window (total)
2. OCSF events ingested (total)
3. Remediation outcomes (total)
4. Findings over time, by severity
5. Top rules by finding volume
6. Ingest volume by OCSF class
7. Remediation outcomes by skill — closed loop
8. Noisy-rule detector (Cloud Console only — pair with an alert rule)

## External dashboard tools

If your team already runs a dashboard tool, point it at the same materialized
views. The pack does not require that path: `system_dashboards.sql` and
`cloud_console_queries.sql` are enough to prove the lake with ClickHouse-native
SQL surfaces.

## Tenancy

When the row policy `findings_tenant_isolation` is active (see
[`../ddl/06_row_policies.sql`](../ddl/06_row_policies.sql)) every panel
query needs `SET tenant_uid = '…'` on the session. The embedded
dashboard page runs under the authenticated ClickHouse role, and the Cloud SQL
Console runs in the role of the signed-in user — so tenancy is enforced at the
connection layer, no extra wiring on the panel side.

## Customizing

- **More panels** — extend the materialized views in
  [`../materialized-views/`](../materialized-views/) first; the dashboards
  read from rolled-up tables so the views are the right knob to turn.
- **Alerts** — for the self-hosted dashboard page, write an outside
  scheduler that queries the same SQL on a cadence. For ClickHouse Cloud,
  the Console has alert support; the noisy-rule query (panel 8) is
  designed as a starter rule.
- **Severity palette** — both surfaces honor the values the rule emits
  into `findings_by_rule_hourly.severity`. If your team encodes severity
  differently, adjust the upstream detection skills' OCSF severity
  mapping — not the dashboard SQL.
