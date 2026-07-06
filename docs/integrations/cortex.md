# Cortex Code CLI (Snowflake)

Setup for loading `cloud-ai-security-skills` into Snowflake Cortex Code CLI
via MCP bridge.

> **Why this integration matters:** Cortex Code runs inside a Snowflake
> account boundary. Using these skills through Cortex means posture and
> detection queries can cross-reference warehouse tables (e.g. HR data
> driving `iam-departures-aws`) without data egress.

## Config location

Project-scoped: `.cortex/mcp.json`

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

## Snowflake auth flow

Skills that read warehouse data (e.g. `iam-departures-aws` reconciler,
`sink-snowflake-jsonl`) use the env vars set by Cortex Code in your shell:

```bash
export SNOWFLAKE_ACCOUNT="acct-id"
export SNOWFLAKE_USER="security_reviewer"
export SNOWFLAKE_PRIVATE_KEY_PATH="$HOME/.snowflake/rsa_key.p8"
export SNOWFLAKE_ROLE="SECURITY_REVIEWER_RO"
export SNOWFLAKE_WAREHOUSE="SECURITY_XS"
```

The reconciler uses **parameterized queries** (never string-concatenated SQL)
and honors role-based read scoping — if your role can't see HR data, the
skill fails closed rather than leaking the error to the chat surface.

## MCP bridge pattern

Cortex Code is an MCP client, not a host — it connects to the same stdio
wrapper as every other client. The difference is the surrounding shell
environment, not the transport. The wrapper does not talk to Snowflake
directly; individual skills do, using the env vars above.

## Least-privilege example — IAM departures read-only

For a Cortex session that should see the reconciler's read path only (no
destructive remediation):

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["${workspaceFolder}/mcp-server/src/server.py"],
      "env": {
        "CLOUD_SECURITY_MCP_ALLOWED_SKILLS": "iam-departures-aws",
        "IAM_DEPARTURES_DRY_RUN": "true"
      }
    }
  }
}
```

`IAM_DEPARTURES_DRY_RUN=true` forces the reconciler's `--dry-run` path, so
even if the model attempts a state-changing call, nothing writes to S3 /
DynamoDB / IAM.

## Quirks

- Cortex Code does not currently expose an MCP refresh UI — restart the CLI
  after editing `.cortex/mcp.json`.
- If running Cortex Code inside Snowpark Container Services, mount the repo
  as a read-only volume; the wrapper will auto-discover SKILLs at startup.

## HITL + audit behavior

Remediation gates apply. The audit record lands in the same log line format
regardless of which MCP client issued the call — useful when a Snowflake-
side SIEM ingests the MCP audit log for cross-source correlation.
