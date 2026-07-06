# Windsurf

Setup for loading `cloud-ai-security-skills` into Windsurf (Codeium) over
stdio MCP.

## Config location

`~/.codeium/windsurf/mcp_config.json`

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["/absolute/path/to/cloud-ai-security-skills/mcp-server/src/server.py"]
    }
  }
}
```

Windsurf does not expand `~` in the config — use absolute paths.

## Enable in the UI

**Windsurf → Settings → Cascade → Model Context Protocol Servers →
Refresh.** Tools appear in the Cascade tool palette after the server
connects.

## Least-privilege example — Kubernetes-only review

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["/absolute/path/.../mcp-server/src/server.py"],
      "env": {
        "CLOUD_SECURITY_MCP_ALLOWED_SKILLS": "k8s-security-benchmark,ingest-k8s-audit-ocsf,detect-privilege-escalation-k8s,detect-sensitive-secret-read-k8s"
      }
    }
  }
}
```

## Quirks

- Windsurf wraps MCP tool calls with its own context-shaping layer — if a
  skill's structured output is truncated, check Cascade settings for tool-
  output token limits.
- Hit **Refresh** in Settings after editing `mcp_config.json`; Windsurf does
  not auto-reload.
- Cascade's agentic mode can chain many tool calls — the wrapper's per-call
  audit record is still one-per-invocation, so the audit trail remains clean.

## HITL + audit behavior

Same as every other MCP client: remediation gates stay in place, each call
carries a `correlation_id`, timeouts are server-enforced.
