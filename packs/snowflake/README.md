# Snowflake security data lake pack

The warehouse-native counterpart to the ClickHouse data-lake pack. This pack
does not run a single detection — it ships the **schema, dynamic-table
rollups, row access policies, and replay queries** that turn Snowflake into a
closed-loop security data lake for the skill set.

It is the DDL contract behind:
- `skills/output/sink-snowflake-jsonl` (writes here)
- `skills/ingestion/source-snowflake-query` (reads from here)

## Why Snowflake for the security lake

| Property | What it buys you |
|---|---|
| VARIANT columns | Native semi-structured storage for OCSF JSONL — no flattening |
| Dynamic tables | Incremental, auto-refreshing rollups without an external scheduler |
| Row access policies | Multi-tenant isolation via `payload:cloud.account.uid` + role mapping |
| Managed Iceberg + Horizon Catalog | Open Parquet/Iceberg format, externally readable by Spark/Trino — no lock-in |
| Trust Center | Snowflake-native risk + posture scanning feeds `discover-control-evidence` |
| Openflow / Snowpipe Streaming | Managed, in-VPC ingestion alternative to the batch sink |
| Time Travel + tasks | Point-in-time recovery plus operator-owned retention lifecycle |

## Layout

```
packs/snowflake/
├── ddl/                                  # one-shot, operator-run
│   ├── 01_database.sql                   # database, schema, rollup warehouse
│   ├── 02_findings_sink.sql              # OCSF 2004 + repo-native findings
│   ├── 03_events_sink.sql                # normalized OCSF events (hot tier)
│   ├── 04_evidence_sink.sql              # control evidence, ~7-year retention
│   ├── 05_audit_sink.sql                 # remediation + MCP audit chain
│   ├── 06_row_policies.sql               # tenant isolation via row access policy
│   └── 07_iceberg_open_format.sql        # OPTIONAL open-format (Iceberg) variant
│
├── dynamic-tables/                       # incremental rollups (auto-refresh)
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
└── golden/expected_columns.json          # column-name lock for CI checks
```

## How the pack composes with shipped skills

```
   ingest-cloudtrail-ocsf            ┐
   ingest-vpc-flow-logs-ocsf         │
   ingest-guardduty-ocsf             │  → sink-snowflake-jsonl
   ingest-okta-system-log-ocsf       │       --table security_db.ops.events_sink --apply
   ingest-mcp-proxy-ocsf             │
   …                                 ┘
                                            │
                                            ▼
                          ┌──────────────────────────────────────────┐
                          │ Snowflake — security_db.ops.events_sink  │
                          │ VARIANT, clustered, row-access-policied  │
                          └──────────────────────────────────────────┘
                                            │
                          source-snowflake-query
                            backfill_detection_window.sql
                                            │
                                            ▼
            ┌───────────────────────────────────────────────┐
            │ detect-lateral-movement                       │
            │ detect-snowflake-bulk-data-egress             │
            │ detect-snowflake-unauthorized-grant           │
            │ detect-prompt-injection-mcp-proxy             │
            │ …                                             │
            └───────────────────────────────────────────────┘
                                            │
                                            ▼
                          sink-snowflake-jsonl
                            --table security_db.ops.findings_sink --apply
                                            │
                                            ▼
                          ┌──────────────────────────────────────────┐
                          │ Snowflake — security_db.ops.findings_sink│
                          │ dynamic-table rollups for triage         │
                          └──────────────────────────────────────────┘
                                            │
                          source-snowflake-query
                          ↓                              ↓
            convert-ocsf-to-sarif        convert-ocsf-to-mermaid-attack-flow
              (audit handoff)              (incident review)
```

## Run

1. Apply the DDL once, in order, with an operator role:

```bash
cd packs/snowflake

for f in ddl/0[1-6]*.sql dynamic-tables/*.sql; do
  snowsql -f "$f"
done

# Open-format lake instead of native tables? Provision an external volume,
# then apply ddl/07 in place of ddl/02 and ddl/03.
```

2. Wire the sink. The skill validates identifiers and defaults to dry-run:

```bash
python skills/detection/detect-lateral-movement/src/detect.py < events.ocsf.jsonl \
  | python skills/output/sink-snowflake-jsonl/src/sink.py \
      --table security_db.ops.findings_sink \
      --apply
```

3. Replay any time:

```bash
python skills/ingestion/source-snowflake-query/src/ingest.py \
  --query "$(cat packs/snowflake/queries/backfill_detection_window.sql)" \
  | jq -c '.payload' \
  | python skills/detection/detect-lateral-movement/src/detect.py
```

## Non-goals

- This pack does not contain detection logic. Detection lives in
  `skills/detection/` — the SQL packs under `packs/lateral-movement/` and
  `packs/privilege-escalation-k8s/` are the warehouse-native lane for that.
- This pack does not own credentials. The sink and source skills both read
  `SNOWFLAKE_*` from the environment.
- This pack does not migrate schema. Apply DDL once; subsequent schema changes
  go through a documented migration, not an in-skill `ALTER`.

## Hero use case

The full ingest → lake → detect → replay narrative, plus how the recent
Snowflake capabilities (managed Iceberg, Horizon Catalog, Openflow, Trust
Center, dynamic tables) map onto each lane, lives in
[`docs/SNOWFLAKE_DATA_LAKE.md`](../../docs/SNOWFLAKE_DATA_LAKE.md).
