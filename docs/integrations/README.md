# Agent + IDE integrations

This directory holds per-client setup docs for loading
`cloud-ai-security-skills` into AI agents and IDE assistants over MCP.

Every integration **goes through the same `mcp-server/src/server.py` stdio
wrapper** — so the skill contract, audit trail, and HITL gates are identical
across clients. Only the config syntax changes.

## Choose your client

| Client | Doc | Transport | Config location |
|---|---|---|---|
| Claude Code (CLI) | (already shipped — see [`../../.mcp.json`](../../.mcp.json)) | stdio | repo root `.mcp.json` |
| Claude Desktop | [`claude-desktop.md`](claude-desktop.md) | stdio | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Claude.ai (web) | [`claude-ai-web.md`](claude-ai-web.md) | ❌ local MCP not supported | use Claude Code / Desktop instead |
| Codex (CLI + IDE) | [`codex.md`](codex.md) | stdio | `~/.codex/config.toml` |
| Cursor | [`cursor.md`](cursor.md) | stdio | `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` |
| Windsurf | [`windsurf.md`](windsurf.md) | stdio | `~/.codeium/windsurf/mcp_config.json` |
| Cortex Code CLI | [`cortex.md`](cortex.md) | stdio | project `.cortex/mcp.json` |
| Zed | [`zed.md`](zed.md) | stdio via context-server extension | `~/.config/zed/settings.json` |
| Continue / Cody / generic | [`ide-agents.md`](ide-agents.md) | stdio | per-tool, see doc |

## Guardrails (inherited from the MCP server, not per-client)

Every integration gets these automatically — no client-side config can turn
them off:

- **Audit:** one JSON audit record per resolved tool call
  ([`docs/MCP_AUDIT_CONTRACT.md`](../MCP_AUDIT_CONTRACT.md)). Every call carries
  a wrapper-generated `correlation_id` forwarded to the skill as
  `SKILL_CORRELATION_ID` so `stderr` events join back to the audited call.
- **Timeouts:** 60s default, per-skill override via `mcp_timeout_seconds`
  frontmatter, operator override via `CLOUD_SECURITY_MCP_TIMEOUT_SECONDS` env.
- **HITL:** remediation skills gated `approval_model: human_required` demand
  human approval regardless of which client invoked them. A naive agent loop
  cannot call `remediate-*` without going through the gate.
- **No arbitrary shell:** the wrapper resolves MCP tool calls to fixed local
  repo-owned entrypoints. There is no "run anything" tool to abuse.
- **Read-only default:** CSPM, detection, ingestion, discovery, view — all
  inherently read-only. Remediation is the only write path, and it's HITL.

## Least-privilege rule of thumb

Each integration doc shows the **minimum** MCP tool allowlist for a given
use case:

- **CSPM-only use:** grant only `cspm-*-cis-benchmark` tools — nothing else
- **Ingest + detect pipeline:** grant `ingest-*` + `detect-*`, never
  `remediate-*` unless the human operator intends destructive response
- **Security review triage:** grant `convert-ocsf-to-sarif` +
  `convert-ocsf-to-mermaid-attack-flow` on top of CSPM

Never grant `*:*` "for convenience." The tool list is small enough to
whitelist explicitly.

## See also

- [`../../mcp-server/README.md`](../../mcp-server/README.md) — server internals, timeout / audit semantics
- [`../../CLAUDE.md`](../../CLAUDE.md) — agent guardrails required before invoking any skill
- [`../../docs/HITL_POLICY.md`](../HITL_POLICY.md) — when human approval is required, across all clients
- [`../../examples/agents/`](../../examples/agents/) — runnable agent-SDK integration examples (Anthropic, OpenAI, LangGraph)
