# Cursor

Setup for loading `cloud-ai-security-skills` into Cursor over stdio MCP.

## Project-scoped config (recommended)

Create `.cursor/mcp.json` in the repo:

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

Cursor expands `${workspaceFolder}` to the current workspace root, so this
config is portable across clones.

## Global config

If you want these skills available in every Cursor workspace, add to
`~/.cursor/mcp.json`:

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

## Enable in the UI

Open **Cursor Settings → MCP → cloud-ai-security-skills → toggle on**.
The tools appear in Composer's tool picker after the server connects.

## Least-privilege example — posture review

For a repo that only ever reviews cloud posture (no ingestion, no
remediation):

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["${workspaceFolder}/mcp-server/src/server.py"],
      "env": {
        "CLOUD_SECURITY_MCP_ALLOWED_SKILLS": "cspm-aws-cis-benchmark,cspm-gcp-cis-benchmark,cspm-azure-cis-benchmark,convert-ocsf-to-sarif"
      }
    }
  }
}
```

## Quirks

- Cursor reloads MCP servers on window reload (`Developer: Reload Window`)
  — not on every Composer prompt.
- If the server errors on first call, check **Settings → MCP → View Logs**.
- `${workspaceFolder}` only works inside `.cursor/mcp.json`, not the global
  `~/.cursor/mcp.json`.

## HITL + audit behavior

Cursor is just another MCP client — the wrapper's audit trail and human-
approval gate for `remediate-*` skills apply unchanged. The model cannot
skip the HITL gate even if it's running in an agentic Composer loop.
