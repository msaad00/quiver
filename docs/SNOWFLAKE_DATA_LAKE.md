# Snowflake security data lake — hero use case

This is the end-to-end story for running cloud-ai-security-skills on top of a
Snowflake-backed security data lake. It is one of the lake patterns the repo
supports (see [`AGENT_DATA_LAKE_FLOW.md`](AGENT_DATA_LAKE_FLOW.md)) — the
**warehouse-native, open-lakehouse** lane, the enterprise counterpart to the
[ClickHouse lane](CLICKHOUSE_DATA_LAKE.md). Write-side, read-side, and replay
all live in this repo.

The pattern is **agentless, append-only, and replay-aware**. The skills mutate
no schema. The lake owns retention. Stable `event_uid` and `finding_uid` values
make replay windows duplicate-aware, while the shipped tables stay append-only.

> Want the schema instead? Jump to
> [`packs/snowflake`](../packs/snowflake/README.md). Want the wire contract?
> See [`SINK_CONTRACT.md`](SINK_CONTRACT.md).

## TL;DR

```
   any cloud / SaaS / IdP / K8s / MCP signal
                         │
                         ▼
                ingest-*  (22 skills)         ──── L1 normalize to OCSF 1.8
                         │
                         ▼
                sink-snowflake-jsonl --apply  ──── L7 append-only insert
                         │
                         ▼
   ┌──────────────────── Snowflake (security_db.ops) ──────────┐
   │  events_sink     (90 d  — hot)                            │
   │  findings_sink   (365 d — warm)                           │
   │  evidence_sink   (~7 yr — compliance hold)                │
   │  audit_sink      (legal-hold retention)                   │
   │  findings_by_rule_hourly        (dynamic table)           │
   │  events_by_class_daily          (dynamic table)           │
   │  remediations_by_outcome_daily  (dynamic table)           │
   └───────────────────────────────────────────────────────────┘
                         │
                         ▼
                source-snowflake-query         ──── read-only SQL gate
                         │
                         ▼
                detect-*  (incl. 9 Snowflake-native detectors)
                view-*    (SARIF / Mermaid)
                discover-control-evidence      ──── posture / compliance
                         │
                         ▼
                sink-snowflake-jsonl --apply   ──── findings / evidence / audit
```

Every repo-owned box on that diagram is shipped in this branch. No new
application code is needed to stand the lake up — only the pack DDL,
credentials, and an operator-chosen Snowflake account.

## Why Snowflake for this lane

Use the Snowflake lane when the customer has standardized on Snowflake as the
enterprise data platform and wants the security lake to live next to — and be
governed like — the rest of their data:

| Trait | Snowflake position |
|---|---|
| Managed elasticity | Per-workload warehouses scale read/replay independently of ingest. |
| Open table format | Snowflake-managed Apache Iceberg keeps the lake in open Parquet, readable/writable by Spark, Trino, and Flink through the Horizon Catalog — no engine lock-in. |
| Unified governance | Horizon Catalog applies classification, lineage, access history, and risk monitoring across every sink table. |
| Native posture scanning | Trust Center surfaces account risks that `discover-control-evidence` can fold into the evidence lane. |
| Zero-copy sharing | Findings and evidence can be shared to auditors or downstream accounts without ETL. |

Pick this lane for a **governed, elastic, open-format enterprise lake**. Pick
the ClickHouse lane for an operator-owned, low-latency self-hosted lake, or an
object-lake sink when the customer's S3 contract is the source of truth.

## Recent Snowflake capabilities this pack uses

Snowflake's platform moved fast in 2025; the pack is built on the current
shape, not the legacy one:

- **Dynamic tables** replace the old materialized-view / scheduled-task rollup
  pattern. The three rollups declare a `TARGET_LAG` and Snowflake refreshes
  them incrementally — no external scheduler, no manual `REFRESH`.
- **Snowflake-managed Iceberg tables** (write support GA October 2025) provide
  the open-format option in [`ddl/07_iceberg_open_format.sql`](../packs/snowflake/ddl/07_iceberg_open_format.sql).
  VARIANT payloads are supported, so the OCSF JSONL contract carries over with
  no schema change, and external engines read the same bytes via Horizon
  Catalog endpoints.
- **Horizon Catalog** is the governance plane over those tables: it is where
  the evidence and audit lanes get classification, lineage, and access-history
  for free, including over the open Iceberg tables.
- **Trust Center** is Snowflake's built-in risk/posture scanner. It is a
  first-party signal source for `discover-control-evidence` alongside the
  repo's CSPM skills.
- **Openflow** (Apache NiFi-based, GA on AWS/Azure, runnable in your own VPC)
  and **Snowpipe Streaming** are the managed, low-latency ingestion options
  when the batch `ingest-* | sink-snowflake-jsonl` pipe is not fast enough.

## Step 1 — Provision the lake (one shot)

Apply the DDL pack with an operator role. The downstream skills hold no DDL
rights:

```bash
cd packs/snowflake

for f in ddl/0[1-6]*.sql dynamic-tables/*.sql; do
  snowsql -f "$f"
done
```

This creates `security_db.ops.events_sink`, `…findings_sink`,
`…evidence_sink`, `…audit_sink`, the three rollup dynamic tables, and the row
access policy that isolates by `cloud.account.uid` through a role-mapping
table. For an open-format lake, provision an external volume and apply
`ddl/07_iceberg_open_format.sql` in place of `ddl/02` and `ddl/03`.

Grant the **runtime** role only:

```sql
GRANT SELECT, INSERT ON security_db.ops.events_sink     TO ROLE agent_bom_runtime;
GRANT SELECT, INSERT ON security_db.ops.findings_sink   TO ROLE agent_bom_runtime;
GRANT SELECT, INSERT ON security_db.ops.evidence_sink   TO ROLE agent_bom_runtime;
GRANT SELECT, INSERT ON security_db.ops.audit_sink      TO ROLE agent_bom_runtime;
GRANT SELECT          ON security_db.ops.findings_by_rule_hourly       TO ROLE agent_bom_runtime;
GRANT SELECT          ON security_db.ops.events_by_class_daily         TO ROLE agent_bom_runtime;
GRANT SELECT          ON security_db.ops.remediations_by_outcome_daily TO ROLE agent_bom_runtime;
```

Note: `INSERT` only — no `CREATE`, `ALTER`, `DROP`, `MERGE`, `COPY`, or
`TRUNCATE`. The retention tasks are created suspended; an operator resumes them
under a role that owns the lifecycle process.

## Step 2 — Wire ingest into the lake

Every shipped OCSF `ingest-*` skill emits JSONL on stdout. Pipe directly into
`sink-snowflake-jsonl`:

```bash
aws cloudtrail lookup-events --max-results 1000 \
  | python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py \
  | python skills/output/sink-snowflake-jsonl/src/sink.py \
      --table security_db.ops.events_sink \
      --apply
```

The same shape works for every other ingest skill (CloudTrail, VPC flow,
GuardDuty, Security Hub, GCP audit/SCC, Azure activity/Defender, Entra, K8s
audit, Okta, Workspace, MCP proxy, GitHub, Slack). Findings-shaped sources
(GuardDuty, Security Hub, SCC, Defender) target `findings_sink`; raw event
sources target `events_sink`. For high-volume, low-latency feeds, swap the
batch pipe for Snowpipe Streaming or an Openflow connector landing into the
same tables.

## Step 3 — Detect from the lake (replay or live)

The read-side skill is `source-snowflake-query`. It enforces a strict
read-only SQL allowlist (`SELECT`, `WITH`, `SHOW`, `DESCRIBE`) — no multiple
statements, no comments, no session controls, no admin verbs. Compose it with
any `detect-*` skill:

```bash
python skills/ingestion/source-snowflake-query/src/ingest.py \
  --query "$(cat packs/snowflake/queries/backfill_detection_window.sql)" \
  | jq -c '.payload' \
  | python skills/detection/detect-lateral-movement/src/detect.py \
  | python skills/output/sink-snowflake-jsonl/src/sink.py \
      --table security_db.ops.findings_sink \
      --apply
```

This is the moment Snowflake stops being a sink and starts being a **lake**:
ship a new detection rule and replay it against historical normalized OCSF
events without re-pulling from the vendor. The repo ships nine Snowflake-native
detectors (bulk egress, account-key creation, unauthorized grant, failed-MFA
burst, session-policy bypass, network-policy disable, replication-config
change, share creation, warehouse-resize burst) that run over the same lake.

## Step 4 — Close the loop with view / remediate

Replay findings out of the lake into operator-facing views:

```bash
# SARIF for audit handoff
python skills/ingestion/source-snowflake-query/src/ingest.py \
  --query "$(cat packs/snowflake/queries/replay_findings_last_day.sql)" \
  | jq -c '.payload' \
  | python skills/view/convert-ocsf-to-sarif/src/convert.py

# Mermaid attack-flow for incident review
python skills/ingestion/source-snowflake-query/src/ingest.py \
  --query "$(cat packs/snowflake/queries/replay_findings_last_day.sql)" \
  | jq -c '.payload' \
  | python skills/view/convert-ocsf-to-mermaid-attack-flow/src/convert.py
```

HITL-gated `remediate-*` skills write their audit chain into
`security_db.ops.audit_sink` through the same sink step, so the lake captures
**what was decided** as well as **what fired**. Keep approval and
incident-window controls outside the sink; the Snowflake runtime role should
only receive `INSERT` on the audit table.

## What it buys an AI agent

The Snowflake lake is what makes the skill set agent-native, not just
agent-callable:

1. **Stateless detectors, stateful lake.** The skills never carry per-tenant
   state. Stable UIDs make historical replay and duplicate-aware projections
   possible without adding detector state.
2. **MCP-callable.** Both `sink-snowflake-jsonl` and `source-snowflake-query`
   are auto-registered as MCP tools — Claude, Cursor, Codex, Cortex can pipe
   through them without bespoke wiring.
3. **Bounded SQL surface.** The source skill enforces a read-only allowlist
   before the agent's SQL ever touches the wire. There is no "the LLM wrote a
   DROP TABLE" failure mode.
4. **Governed, open data.** Horizon Catalog governs the same rows external
   engines can read as Iceberg, so the agent's findings are auditable and
   portable rather than trapped in one engine.

## Non-goals

- This doc does not turn the repo into a SIEM. The lake replaces the SIEM's
  **storage tier**; the operator UX stays SQL-native through dynamic tables and
  query templates feeding Snowsight or existing BI surfaces.
- The sink and source skills do not perform encryption-at-rest or TLS-in-flight
  on their own. Both are properties of the Snowflake account and the external
  volume the operator provisions.
- Row access policies are query-time filters. Use dedicated roles,
  least-privilege grants, and per-region accounts where the tenancy or
  data-residency boundary requires it.

## Related

- [`packs/snowflake/README.md`](../packs/snowflake/README.md) — pack contents and CLI run-through
- [`CLICKHOUSE_DATA_LAKE.md`](CLICKHOUSE_DATA_LAKE.md) — the self-hosted, low-latency lake lane
- [`SINK_CONTRACT.md`](SINK_CONTRACT.md) — what every sink must do, and what it must not
- [`AGENT_DATA_LAKE_FLOW.md`](AGENT_DATA_LAKE_FLOW.md) — the repo-supported lake flows
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — the 7-layer skill model behind the diagram
