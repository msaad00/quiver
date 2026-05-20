# ClickHouse security data lake pack

The lake-substrate counterpart to the lateral-movement and
privilege-escalation-k8s query packs. This pack does not run a single
detection — it ships the **schema, materialized views, and replay queries**
that turn ClickHouse into a closed-loop security data lake for the skill set.

It is the DDL contract behind:
- `skills/output/sink-clickhouse-jsonl` (writes here)
- `skills/ingestion/source-clickhouse-query` (reads from here)

## Why ClickHouse for the security lake

| Property | What it buys you |
|---|---|
| MergeTree column-store | Columnar storage for high-volume append-only OCSF JSONL |
| Materialized views | Hot rollups for operator summaries without rescanning raw rows |
| `TTL` clauses | Per-table retention without an external lifecycle service |
| Row policies | Multi-tenant isolation via `JSONExtractString(payload, ..., uid)` |
| Self-hosted **or** ClickHouse Cloud | Sovereign deployment is one Helm chart away |
| Dashboard query catalog + Cloud SQL Console | ClickHouse-native operator queries over the same rollups |

## Layout

```
packs/clickhouse/
├── ddl/                                  # one-shot, operator-run
│   ├── 01_database.sql
│   ├── 02_findings_sink.sql              # OCSF 2004 + repo-native findings
│   ├── 03_events_sink.sql                # normalized OCSF events (hot tier)
│   ├── 04_evidence_sink.sql              # control evidence, 7-year retention
│   ├── 05_audit_sink.sql                 # remediation + MCP audit chain
│   └── 06_row_policies.sql               # tenant isolation via row policy
│
├── materialized-views/                   # volume rollups
│   ├── 01_findings_by_rule_hourly.sql
│   ├── 02_events_by_class_daily.sql
│   └── 03_remediations_by_outcome_daily.sql
│
├── queries/                              # read-side composition templates
│   ├── replay_findings_last_day.sql
│   ├── backfill_detection_window.sql
│   ├── audit_trail_last_hour.sql
│   └── top_rules_by_finding_volume.sql
│
├── dashboards/                           # ClickHouse-native operator UX
│   ├── system_dashboards.sql             # same-schema dashboard query catalog
│   ├── cloud_console_queries.sql         # paste-and-save queries for ClickHouse Cloud SQL Console
│   └── README.md
│
└── golden/expected_columns.json          # column-name lock for CI checks
```

## How the pack composes with shipped skills

```
   ingest-cloudtrail-ocsf            ┐
   ingest-vpc-flow-logs-ocsf         │
   ingest-guardduty-ocsf             │  → sink-clickhouse-jsonl
   ingest-okta-system-log-ocsf       │       --table security.events_sink --apply
   ingest-mcp-proxy-ocsf             │
   …                                 ┘
                                            │
                                            ▼
                          ┌──────────────────────────────────────┐
                          │ ClickHouse — security.events_sink    │
                          │ MergeTree, 90-day TTL, row-policied  │
                          └──────────────────────────────────────┘
                                            │
                          source-clickhouse-query
                            backfill_detection_window.sql
                                            │
                                            ▼
            ┌───────────────────────────────────────────────┐
            │ detect-lateral-movement                       │
            │ detect-mcp-tool-drift                         │
            │ detect-prompt-injection-mcp-proxy             │
            │ detect-credential-stuffing-okta               │
            │ …                                             │
            └───────────────────────────────────────────────┘
                                            │
                                            ▼
                          sink-clickhouse-jsonl
                            --table security.findings_sink --apply
                                            │
                                            ▼
                          ┌──────────────────────────────────────┐
                          │ ClickHouse — security.findings_sink  │
                          │ 365-day TTL                          │
                          └──────────────────────────────────────┘
                                            │
                          source-clickhouse-query
                          ↓                              ↓
            convert-ocsf-to-sarif        convert-ocsf-to-mermaid-attack-flow
              (audit handoff)              (incident review)
```

## Run

1. Apply the DDL once, in order, with an operator role:

```bash
for f in ddl/*.sql materialized-views/*.sql; do
  clickhouse-client --multiquery < "$f"
done
```

2. Wire the sink. The skill validates identifiers and defaults to dry-run:

```bash
python skills/detection/detect-lateral-movement/src/detect.py < events.ocsf.jsonl \
  | python skills/output/sink-clickhouse-jsonl/src/sink.py \
      --table security.findings_sink \
      --apply
```

3. Replay any time:

```bash
python skills/ingestion/source-clickhouse-query/src/ingest.py \
  --query "$(cat packs/clickhouse/queries/backfill_detection_window.sql)" \
  | jq -c '.payload | fromjson' \
  | python skills/detection/detect-lateral-movement/src/detect.py
```

## Non-goals

- This pack does not contain detection logic. Detection lives in
  `skills/detection/` — the SQL packs under `packs/lateral-movement/` and
  `packs/privilege-escalation-k8s/` are the warehouse-native lane for that.
- This pack does not own credentials. The sink and source skills both read
  `CLICKHOUSE_*` from the environment.
- This pack does not migrate schema. Apply DDL once; subsequent schema
  changes go through a documented migration, not an in-skill `ALTER`.

## Hero use case

The full ingest → lake → detect → replay narrative lives in
[`docs/CLICKHOUSE_DATA_LAKE.md`](../../docs/CLICKHOUSE_DATA_LAKE.md).
