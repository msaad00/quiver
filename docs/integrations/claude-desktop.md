# Claude Desktop

Full setup for loading `cloud-ai-security-skills` into the Claude Desktop app
over stdio MCP.

## 1 · Locate the config file

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Create the file if it doesn't exist.

## 2 · Add the MCP server entry

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": [
        "/absolute/path/to/cloud-ai-security-skills/mcp-server/src/server.py"
      ]
    }
  }
}
```

Use the **absolute** path to the repo — Claude Desktop does not expand
`~` or relative paths.

## 3 · Restart Claude Desktop

Fully quit (⌘Q on macOS) and reopen. The repo's SKILL.md bundles are
auto-discovered by the wrapper on startup.

## 4 · Verify

In a new chat ask: *"list my available MCP tools from cloud-ai-security-skills"* —
you should see `cspm-aws-cis-benchmark`, `ingest-cloudtrail-ocsf`,
`detect-privilege-escalation-k8s`, etc.

If nothing appears, check
`~/Library/Logs/Claude/mcp-server-cloud-ai-security-skills.log`.

## Least-privilege example — CSPM-only

If you only want posture checks, constrain the allowlist so remediation and
ingestion tools aren't exposed to the model:

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["/absolute/path/.../mcp-server/src/server.py"],
      "env": {
        "CLOUD_SECURITY_MCP_ALLOWED_SKILLS": "cspm-aws-cis-benchmark,cspm-gcp-cis-benchmark,cspm-azure-cis-benchmark,k8s-security-benchmark"
      }
    }
  }
}
```

(Env-var-based allowlist is honored by the wrapper; see
[`../../mcp-server/src/server.py`](../../mcp-server/src/server.py). Unlisted
skills are not registered as tools.)

## Quirks

- **stdio only** — Claude Desktop does not speak HTTP MCP.
- **Python 3.11+** required; `python3` must resolve on the `PATH` Claude Desktop
  sees at launch. On macOS, Homebrew Python works; if `python3` is only in a
  venv, pass the absolute interpreter path.
- Config changes need a full app restart, not just a reload.

## HITL behavior

Remediation skills (`iam-departures-aws`, `remediate-okta-session-kill`)
remain `approval_model: human_required` when called from Claude Desktop —
the MCP wrapper enforces the same gate whether the caller is an IDE agent
or a chat UI. See [`../HITL_POLICY.md`](../HITL_POLICY.md).
