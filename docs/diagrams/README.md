# Diagrams

Mermaid sources for the visuals the audit (2026-04-28 / 2026-05-09)
flagged as missing. Source-controlled here so a regeneration is one
command:

```bash
mmdc -i docs/diagrams/<name>.mmd -o docs/images/<name>.svg -t dark -b transparent
```

(`mmdc` ships with `@mermaid-js/mermaid-cli`.)

## Shipped diagrams

| File | Renders the | Where it's read |
|---|---|---|
| [`mcp-trust-boundary.mmd`](mcp-trust-boundary.mmd) | sequence of: agent → MCP wrapper → guards → skill subprocess → audit log; including the dry-run / HITL / `min_approvers` short-circuit branches | `docs/MCP_AUDIT_CONTRACT.md`, `docs/HARNESS.md` |
| [`agent-topology.mmd`](agent-topology.mmd) | local stdio clients (Claude Code/Desktop, Cursor, Windsurf, Codex, Cortex, Zed) vs remote / HTTP clients (Claude.ai web, runners, GitHub Actions); shared registry behind both surfaces | `docs/HARNESS.md`, `docs/integrations/README.md` |
| [`pipeline-blast-radius.mmd`](pipeline-blast-radius.mmd) | data flowing left-to-right with each layer colour-coded by capability — read-only ingest/discover/detect/evaluate, HITL-gated remediate, write-only sink — so the trust boundary is visible at a glance | `docs/ARCHITECTURE.md`, `README.md` |
| [`skill-hierarchy.mmd`](skill-hierarchy.mmd) | every shipped layer × every shipped skill, grouped by sub-domain (AWS / GCP / Azure / Identity / K8s / MCP / Web). Renders the full 131-skill surface in one picture | `docs/ARCHITECTURE.md`, `README.md` |
| [`surface-comparison.mmd`](surface-comparison.mmd) | the six shipped surfaces (CLI · CI · MCP · webhook · library · runners) with the eight trust controls and the shared registry that sits behind every one | `docs/HARNESS.md`, `README.md` |

## Hand-authored README SVGs

Some README hero visuals are hand-authored SVGs instead of Mermaid output
because they need fixed layout, logo marks, and exact text containment:

| File | Purpose |
|---|---|
| [`../images/hero-banner.svg`](../images/hero-banner.svg) | first-viewport repo positioning and shipped counts |
| [`../images/architecture-layers.svg`](../images/architecture-layers.svg) | seven skill layers with readable counts and sink labels |
| [`../images/agentic-soc-orchestrator.svg`](../images/agentic-soc-orchestrator.svg) | optional LangGraph/LangChain orchestration over deterministic skills |
| [`../images/clickhouse-data-lake.svg`](../images/clickhouse-data-lake.svg) | ClickHouse closed-loop lake hero |
| [`../images/snowflake-data-lake.svg`](../images/snowflake-data-lake.svg) | Snowflake closed-loop lake hero |
| [`../images/coverage-matrix-summary.svg`](../images/coverage-matrix-summary.svg) | compact closed-loop summary for README |
| [`../images/coverage-matrix.svg`](../images/coverage-matrix.svg) | full closed-loop coverage matrix (71 detection rows) |

## Authoring rules

- **Each diagram is its own file.** GitHub renders the markdown links
  natively in `*.md` callsites, and `mmdc` keeps SVG generation
  deterministic.
- **Class definitions stay in the diagram** so colours don't drift if
  the consuming markdown's theme changes.
- **No external image refs.** Every label is in the diagram source —
  consistent with the hero-banner rule that text never escapes its
  container.
- **Stable node IDs** (`audit_log`, `skill_proc`, `mcp_wrapper`) — so
  consumers can `grep` source and link section anchors.
