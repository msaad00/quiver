# ClickHouse security data lake — hero use case

This is the canonical end-to-end story for running cloud-ai-security-skills on
top of a ClickHouse-backed security data lake. It is one of three lake
patterns the repo supports (see [`AGENT_DATA_LAKE_FLOW.md`](AGENT_DATA_LAKE_FLOW.md)),
and the most fully wired one: write-side, read-side, and replay all live in
this repo.

The pattern is **agentless, append-only, and replay-aware**. The skills mutate
no schema. The lake owns retention. Stable `event_uid` and `finding_uid`
values make replay windows duplicate-aware, but raw duplicate inserts remain
visible because the shipped tables are append-only `MergeTree` tables.

> Want the schema instead? Jump to
> [`packs/clickhouse`](../packs/clickhouse/README.md). Want the wire
> contract? See [`SINK_CONTRACT.md`](SINK_CONTRACT.md).

## TL;DR

```
   any cloud / SaaS / IdP / K8s / MCP signal
                         │
                         ▼
                ingest-*  (22 skills)        ──── L1 normalize to OCSF 1.8
                         │
                         ▼
                sink-clickhouse-jsonl --apply ──── L7 append-only insert
                         │
                         ▼
   ┌──────────────────── ClickHouse ─────────────────────────┐
   │  security.events_sink     (90 d  — hot)                 │
   │  security.findings_sink   (365 d — warm)                │
   │  security.evidence_sink   (7 yr  — compliance hold)     │
   │  security.audit_sink      (legal-hold retention)        │
   │  security.findings_by_rule_hourly  (rollup MV)          │
   │  security.events_by_class_daily    (rollup MV)          │
   │  security.remediations_by_outcome_daily (rollup MV)     │
   └─────────────────────────────────────────────────────────┘
                         │
                         ▼
                source-clickhouse-query        ──── read-only SQL gate
                         │
                         ▼
                detect-*  (71 skills)          ──── L3 deterministic rules
                view-*    (2 skills)           ──── L6 SARIF / Mermaid
                discover-control-evidence      ──── L2 posture / compliance
                         │
                         ▼
                sink-clickhouse-jsonl --apply  ──── append findings / evidence / audit rows
```

Every repo-owned box on that diagram is shipped in this branch. No new
application code is needed to stand the lake up — only the pack DDL,
credentials, and an operator-chosen ClickHouse cluster.

## Why ClickHouse for this lane

The repo ships more than one persistence lane because customers standardize on
different substrates. Use the ClickHouse lane when these constraints matter:

| Trait | ClickHouse position |
|---|---|
| Self-host **or** managed | Works with operator-owned ClickHouse or a managed endpoint. |
| Hot analytical reads | MergeTree tables, skip indexes, and rollups keep replay queries small and predictable. |
| Replay economics | Raw OCSF JSONL stays append-only while materialized views answer operator summary questions. |
| Sovereign deployment | Can run inside the customer's cloud, VPC, Kubernetes cluster, identity, and audit boundary. |
| SQL-native operator UX | Materialized views and query templates support ClickHouse-native or existing dashboard surfaces without changing the lake contract. |

Pick this lane for an **operator-owned, low-latency, replayable security
lake**. Pick another shipped sink/source lane when the customer's existing
warehouse or object-lake contract is the source of truth.

## Step 1 — Provision the lake (one shot)

Apply the DDL pack with an operator role. The downstream skills hold no DDL
rights:

```bash
cd packs/clickhouse

for f in ddl/*.sql materialized-views/*.sql; do
  clickhouse-client --multiquery < "$f"
done
```

This creates `security.events_sink`, `security.findings_sink`,
`security.evidence_sink`, `security.audit_sink`, the three rollup
materialized views, and the per-table row policy that isolates by
`cloud.account.uid`.

Grant the **runtime** role only:

```sql
GRANT SELECT, INSERT ON security.events_sink     TO agent_bom_runtime;
GRANT SELECT, INSERT ON security.findings_sink   TO agent_bom_runtime;
GRANT SELECT, INSERT ON security.evidence_sink   TO agent_bom_runtime;
GRANT SELECT, INSERT ON security.audit_sink      TO agent_bom_runtime;
GRANT SELECT          ON security.findings_by_rule_hourly       TO agent_bom_runtime;
GRANT SELECT          ON security.events_by_class_daily         TO agent_bom_runtime;
GRANT SELECT          ON security.remediations_by_outcome_daily TO agent_bom_runtime;
```

Note: `INSERT` only — no `CREATE`, `ALTER`, `DROP`, `OPTIMIZE`, or `TRUNCATE`.

## Step 2 — Wire ingest into the lake

Every shipped OCSF `ingest-*` skill emits JSONL on stdout. Pipe directly into
`sink-clickhouse-jsonl`:

```bash
aws cloudtrail lookup-events --max-results 1000 \
  | python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py \
  | python skills/output/sink-clickhouse-jsonl/src/sink.py \
      --table security.events_sink \
      --apply
```

The same shape works for every other ingest skill:

| Vendor | Ingest skill | Lake table |
|---|---|---|
| AWS CloudTrail | `ingest-cloudtrail-ocsf` | `security.events_sink` |
| AWS VPC Flow Logs | `ingest-vpc-flow-logs-ocsf` | `security.events_sink` |
| AWS GuardDuty | `ingest-guardduty-ocsf` | `security.findings_sink` |
| AWS Security Hub | `ingest-security-hub-ocsf` | `security.findings_sink` |
| GCP audit | `ingest-gcp-audit-ocsf` | `security.events_sink` |
| GCP SCC | `ingest-gcp-scc-ocsf` | `security.findings_sink` |
| Azure activity | `ingest-azure-activity-ocsf` | `security.events_sink` |
| Azure Defender | `ingest-azure-defender-for-cloud-ocsf` | `security.findings_sink` |
| Entra | `ingest-entra-directory-audit-ocsf` | `security.events_sink` |
| K8s audit | `ingest-k8s-audit-ocsf` | `security.events_sink` |
| Okta | `ingest-okta-system-log-ocsf` | `security.events_sink` |
| Workspace | `ingest-google-workspace-login-ocsf` | `security.events_sink` |
| MCP proxy | `ingest-mcp-proxy-ocsf` | `security.events_sink` |
| GitHub | `ingest-github-audit-log-ocsf` | `security.events_sink` |
| Slack | `ingest-slack-audit-ocsf` | `security.events_sink` |

## Step 3 — Detect from the lake (replay or live)

The read-side skill is `source-clickhouse-query`. It enforces a strict
read-only SQL allowlist (`SELECT`, `WITH`, `SHOW`, `DESCRIBE`) — no comments,
no session controls, no admin verbs. Compose it with any `detect-*` skill:

```bash
python skills/ingestion/source-clickhouse-query/src/ingest.py \
  --query "$(cat packs/clickhouse/queries/backfill_detection_window.sql)" \
  | jq -c '.payload | fromjson' \
  | python skills/detection/detect-lateral-movement/src/detect.py \
  | python skills/output/sink-clickhouse-jsonl/src/sink.py \
      --table security.findings_sink \
      --apply
```

This is the moment ClickHouse stops being a sink and starts being a **lake**:
you can ship a new detection rule and replay it against historical normalized
OCSF events without re-pulling from the vendor. For duplicate-prone backfills,
make the query UID-aware, for example by selecting the latest row per
`event_uid` before piping into the detector.

## Step 4 — Close the loop with view / remediate

Replay findings out of the lake into operator-facing views:

```bash
# SARIF for audit handoff
python skills/ingestion/source-clickhouse-query/src/ingest.py \
  --query "$(cat packs/clickhouse/queries/replay_findings_last_day.sql)" \
  | jq -c '.payload | fromjson' \
  | python skills/view/convert-ocsf-to-sarif/src/convert.py

# Mermaid attack-flow for incident review
python skills/ingestion/source-clickhouse-query/src/ingest.py \
  --query "$(cat packs/clickhouse/queries/replay_findings_last_day.sql)" \
  | jq -c '.payload | fromjson' \
  | python skills/view/convert-ocsf-to-mermaid-attack-flow/src/convert.py
```

HITL-gated `remediate-*` skills can write their audit chain into
`security.audit_sink` through the same sink step, so the lake captures **what
was decided** as well as **what fired**. Keep the approval and incident-window
controls outside the sink; the ClickHouse role should only receive `INSERT`
on the audit table.

## What it buys an AI agent

The ClickHouse lake is what makes the skill set agent-native, not just
agent-callable:

1. **Stateless detectors, stateful lake.** The skills never carry per-tenant
   state. Stable UIDs make historical replay and duplicate-aware projections
   possible without adding detector state.
2. **MCP-callable.** Both `sink-clickhouse-jsonl` and
   `source-clickhouse-query` are auto-registered as MCP tools — Claude,
   Cursor, Codex, Cortex can pipe through them without bespoke wiring.
3. **Bounded SQL surface.** The source skill enforces a read-only allowlist
   before the agent's SQL ever touches the wire. There is no "the LLM wrote
   a DROP TABLE" failure mode.
4. **Small replay surfaces.** The materialized views answer "top rules
   today", "ingest volume by class", and "remediation outcome counts" without
   rescanning raw JSONL rows, freeing the agent's context budget for actual
   judgment.

## Non-goals

- This doc does not turn the repo into a SIEM. The lake replaces the SIEM's
  **storage tier**, and the operator UX stays SQL-native: materialized views
  and query templates provide stable surfaces for ClickHouse-native consoles
  or existing dashboard tools.
- The sink and source skills do not perform encryption-at-rest or
  TLS-in-flight on their own. Both are properties of the ClickHouse cluster
  the operator provisions.
- Row policies are query-time filters. Use dedicated roles, least-privilege
  grants, and per-region clusters where the tenancy or data-residency boundary
  requires it.

## Related

- [`packs/clickhouse/README.md`](../packs/clickhouse/README.md) — pack contents and CLI run-through
- [`SINK_CONTRACT.md`](SINK_CONTRACT.md) — what every sink must do, and what it must not
- [`AGENT_DATA_LAKE_FLOW.md`](AGENT_DATA_LAKE_FLOW.md) — the three repo-supported lake flows
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — the 7-layer skill model behind the diagram
