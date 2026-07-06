# Codex (CLI + IDE extensions)

Setup for OpenAI Codex CLI and the Codex IDE extensions (VS Code, JetBrains)
against the repo's MCP server.

## CLI setup

Codex CLI reads MCP servers from `~/.codex/config.toml`:

```toml
[mcp_servers.cloud-ai-security-skills]
command = "python3"
args = ["/absolute/path/to/cloud-ai-security-skills/mcp-server/src/server.py"]
```

Verify:

```bash
codex mcp list
# cloud-ai-security-skills  (stdio, N tools)
```

Start a session with skills available:

```bash
codex chat --mcp cloud-ai-security-skills
```

## IDE extension setup

The VS Code / JetBrains Codex extensions read the same TOML. After editing
`~/.codex/config.toml`, reload the window (`Developer: Reload Window` in
VS Code, `Restart IDE` in JetBrains) to pick up the new MCP entry.

## Least-privilege example — ingest + detect only

```toml
[mcp_servers.cloud-ai-security-skills]
command = "python3"
args = ["/absolute/path/.../mcp-server/src/server.py"]
env = { CLOUD_SECURITY_MCP_ALLOWED_SKILLS = "ingest-cloudtrail-ocsf,ingest-vpc-flow-logs-ocsf,detect-lateral-movement,detect-privilege-escalation-k8s" }
```

Omits `iam-departures-aws` and `remediate-okta-session-kill` entirely — the
model cannot call what isn't in its tool registry.

## Codex-specific quirks

- Codex CLI caches the tool list per session — restart the `codex chat`
  process after editing `config.toml`.
- If `python3` is behind a pyenv shim, prefer the absolute interpreter path
  (e.g. `/Users/you/.pyenv/versions/3.11.9/bin/python3`) to avoid PATH
  surprises when Codex spawns the subprocess.

## HITL + audit behavior

Same bar as Claude Code: remediation tools stay human-gated, the
`correlation_id` lands in the audit record, timeouts use the wrapper defaults
unless the env override is set.
