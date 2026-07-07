# Claude.ai (web)

**Local MCP is not available in the claude.ai web client.** The web client
cannot spawn a stdio process on your machine or reach a local HTTP endpoint —
this is by design, not a missing feature.

If you see a guide claiming otherwise, it's out of date or inaccurate.

## What to do instead

| Goal | Recommended path |
|---|---|
| Interactive chat + local skill calls | [Claude Desktop](claude-desktop.md) — supports stdio MCP |
| CLI / IDE usage | [Claude Code](../../.mcp.json) — already wired at repo root |
| Headless agent that uses these skills | Anthropic Agent SDK ([`../../examples/agents/anthropic_sdk_security_agent.py`](../../examples/agents/anthropic_sdk_security_agent.py)) |
| CI pipeline runs a skill | call the skill script directly — MCP not needed |

## Can I make claude.ai reach my local skills over HTTP?

Not supported today. You'd need:

1. A publicly reachable MCP HTTP endpoint (not what `mcp-server/src/server.py`
   provides — it's stdio only).
2. An authenticated tunnel that respects the repo's audit and HITL contract.
3. A way to bind the model's session to an operator identity for the audit
   trail.

Until the repo ships an explicit hosted MCP server with authn + audit (not on
the current roadmap), **use Claude Desktop or Claude Code** for local skill
access. For pure-cloud agent use cases, use the Anthropic Agent SDK with the
repo checked out on the agent host; that path is covered by
[`../../examples/agents/anthropic_sdk_security_agent.py`](../../examples/agents/anthropic_sdk_security_agent.py).

## Why this restriction exists

- **Audit integrity:** every MCP tool call must emit a `correlation_id`-linked
  audit record. Going through a public HTTP endpoint without operator auth
  would break the `(operator_identity, tool_call)` binding that
  [`../MCP_AUDIT_CONTRACT.md`](../MCP_AUDIT_CONTRACT.md) requires.
- **HITL enforcement:** remediation skills gate on human approval. A
  session running in the browser with no persistent operator identity can't
  participate in that gate.
- **Least privilege:** local clients inherit your cloud SDK credentials.
  A hosted MCP bridge would need a credential broker, which is out of scope.
