# Agent Quickstart

Give any agent these 131 skills in under 60 seconds. Pick your client,
paste the snippet, restart. Replace `/abs/path/to/cloud-ai-security-skills`
with the absolute path to your local clone.

---

## Claude Code (CLI)

The repo-shipped [`.mcp.json`](../.mcp.json) registers the server
automatically when you open the repo. To add it to another project from
the CLI:

```bash
cd /your/other/repo
claude mcp add cloud-ai-security-skills python3 \
  /abs/path/to/cloud-ai-security-skills/mcp-server/src/server.py
```

Full setup: [`integrations/README.md`](integrations/README.md).

---

## Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) — full per-OS paths in [`integrations/claude-desktop.md`](integrations/claude-desktop.md):

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["/abs/path/to/cloud-ai-security-skills/mcp-server/src/server.py"]
    }
  }
}
```

Restart Claude Desktop (`⌘Q`, reopen).

---

## Cursor

Create `.cursor/mcp.json` in your repo — uses `${workspaceFolder}`, so it's
portable across clones:

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["${workspaceFolder}/mcp-server/src/server.py"]
    }
  }
}
```

Enable: **Cursor Settings → MCP → cloud-ai-security-skills → on**.

---

## Windsurf

Edit `~/.codeium/windsurf/mcp_config.json` (absolute path required —
Windsurf does not expand `~`):

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["/abs/path/to/cloud-ai-security-skills/mcp-server/src/server.py"]
    }
  }
}
```

Reload: **Settings → Cascade → MCP → Refresh**.

---

## Codex · Cortex · Zed

Same shape as the Claude Desktop block above, in each client's MCP config:

- Codex: [`integrations/codex.md`](integrations/codex.md)
- Cortex: [`integrations/cortex.md`](integrations/cortex.md)
- Zed: [`integrations/zed.md`](integrations/zed.md)

---

## Anthropic Agent SDK

Wrap the MCP server as a stdio tool for an Anthropic Agent — runnable
example with full HITL handling:

[`../examples/agents/anthropic_sdk_security_agent.py`](../examples/agents/anthropic_sdk_security_agent.py)

---

## OpenAI SDK

Same pattern, wired through the OpenAI Responses API tool surface:

[`../examples/agents/openai_sdk_security_agent.py`](../examples/agents/openai_sdk_security_agent.py)

---

## LangGraph

Multi-step graph (ingest → detect → triage → remediate) with HITL approval
nodes:

[`../examples/agents/langgraph_security_graph.py`](../examples/agents/langgraph_security_graph.py)

---

## Continue · Cody · generic MCP client

Any stdio-MCP client works with the same `python3 .../server.py` invocation.
See [`integrations/ide-agents.md`](integrations/ide-agents.md).
