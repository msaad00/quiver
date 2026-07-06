# Continue, Cody, and other MCP-capable IDE agents

Generic stdio MCP bridge instructions for IDE assistants not covered by
their own doc in this directory.

Most modern IDE agents accept one of three config shapes — match yours
below.

## Shape 1 — JSON (`mcpServers` map)

Used by Cursor, Windsurf, Claude Desktop, most newer agents. Your tool
likely has a config file (check its docs) at a path like
`~/.<tool-name>/mcp.json`:

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

## Shape 2 — TOML (`[mcp_servers.<name>]` table)

Used by Codex CLI, some Rust-based tools:

```toml
[mcp_servers.cloud-ai-security-skills]
command = "python3"
args = ["/absolute/path/to/cloud-ai-security-skills/mcp-server/src/server.py"]
```

## Shape 3 — YAML (Continue `~/.continue/config.yaml`)

```yaml
mcpServers:
  - name: cloud-ai-security-skills
    command: python3
    args:
      - /absolute/path/to/cloud-ai-security-skills/mcp-server/src/server.py
```

## Tool-specific notes

### Continue (VS Code / JetBrains)

- Config: `~/.continue/config.yaml` (user) or `.continue/config.yaml` (project)
- Reload: `Continue: Reload Config` from the command palette
- Docs: https://docs.continue.dev

### Cody (Sourcegraph)

- Cody currently supports MCP through agent mode only (check the docs for
  your installed version)
- Config: `~/.cody/mcp.json` on recent builds; older builds may need a
  wrapper plugin
- Docs: https://sourcegraph.com/docs/cody

### Aider

- Aider wires MCP via `--mcp-server` CLI flag rather than a config file:
  ```bash
  aider --mcp-server "cloud-ai-security-skills:python3 /abs/path/mcp-server/src/server.py"
  ```

### Anything else

If your tool reads MCP from a config file, the server block is identical
across them — `command: python3`, `args: [<abs-path>/mcp-server/src/server.py]`.

## Can't find your tool above?

Run the server standalone to confirm it works, then paste it into whatever
config syntax your tool expects:

```bash
python3 /abs/path/mcp-server/src/server.py
# should block, waiting for stdio MCP handshake — Ctrl-C to exit
```

If that works, the stdio contract is fine and the remaining problem is
purely on the client-config side.

## Least-privilege applies universally

Every client supports an `env` map alongside `command`/`args`. Always use
it to restrict the tool set:

```json
"env": {
  "CLOUD_SECURITY_MCP_ALLOWED_SKILLS": "cspm-aws-cis-benchmark,detect-lateral-movement"
}
```

Omit `remediate-*` skills unless the operator is knowingly using the HITL-
gated destructive path.

## HITL + audit behavior

Guarantees are the same across every MCP client:
- human-approval gates for remediation are enforced server-side
- every tool call generates an audit record with a `correlation_id` that
  joins back to structured skill `stderr`
- timeouts are wrapper-enforced, per-skill tunable via SKILL.md frontmatter

See [`../MCP_AUDIT_CONTRACT.md`](../MCP_AUDIT_CONTRACT.md) for the record
schema.
