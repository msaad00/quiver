# Workflow · Incident response — Okta MFA fatigue

End-to-end response to an Okta MFA-fatigue attempt: detect, gather
evidence, kill the session. Three atomic skills, one HITL gate, one
audit chain.

## Trigger

OCSF Detection Finding 2004 emitted by `detect-okta-mfa-fatigue` with:

- `metadata.product.feature.name == "detect-okta-mfa-fatigue"`
- `attacks[].technique.uid == "T1110.001"` (Brute Force: Password Guessing)

## Required preset

[`presets/preset-incident-response.json`](../../presets/preset-incident-response.json)
— the only atomic skills authorized for this workflow are the three
below. Loading any broader preset is a contract violation.

```bash
export CLOUD_SECURITY_MCP_ALLOWED_SKILLS="$(jq -r '.allowed_skills | join(",")' presets/preset-incident-response.json)"
```

## Steps

### 1 · Detect (read-only)

```text
tool:    detect-okta-mfa-fatigue
input:   OCSF System Activity 1003 stream from ingest-okta-system-log-ocsf
output:  zero or more OCSF Detection Finding 2004 records on stdout
write?:  no
HITL?:   no
```

If the detector returns zero findings, **stop**. The workflow is a no-op.

### 2 · Gather control evidence (read-only)

```text
tool:    discover-control-evidence
input:   --finding <stdout from step 1>
output:  control-evidence JSON describing the user, MFA enrollment,
         recent login geo, recent device list, and any tickets already
         tracking the principal
write?:  no
HITL?:   no
```

Surfaces the context an approver needs to decide whether to fire step 3.
A workflow that skips this step asks the approver to act on a single
detection — explicitly out of scope for this playbook.

### 3 · Kill the session (write — HITL-gated)

```text
tool:    remediate-okta-session-kill
input:   --finding <stdout from step 1> --evidence <stdout from step 2>
mode:    --apply  (NOT --dry-run)
write?:  yes — Okta API session revoke
HITL?:   yes
required _approval_context:
  approver_email: <approver's Okta email>
  ticket_id:      <incident tracker ticket, e.g. SEC-1234>
  approval_timestamp: ISO-8601 UTC timestamp
min_approvers: 1   (matches HITL_POLICY.md row "Active account takeover containment")
```

The atomic skill refuses `--apply` without a complete
`_approval_context`. Approver email, ticket id, and timestamp all land
in the audit record so the chain is bound to a real ticket.

## Audit chain

Each of the three steps writes one `mcp_tool_call` audit record (see
[`docs/MCP_AUDIT_CONTRACT.md`](../../docs/MCP_AUDIT_CONTRACT.md)). Each
record carries its own wrapper-generated `correlation_id`. To replay the
incident:

```bash
jq -c '
  select(.event == "mcp_tool_call")
  | select(.tool == "detect-okta-mfa-fatigue"
        or .tool == "discover-control-evidence"
        or .tool == "remediate-okta-session-kill")
' /var/log/cloud-security-mcp/audit.jsonl
```

For tamper evidence on the chain itself, set
`CLOUD_SECURITY_AUDIT_HMAC_KEY` and verify with
`scripts/verify_audit_chain.py`.

## Failure modes

| Step | Failure | Workflow behaviour |
|---|---|---|
| 1 | detector returns zero findings | stop — no-op |
| 1 | detector exits non-zero | propagate; do not retry |
| 2 | evidence-gather returns empty | proceed only if the operator overrides; otherwise stop and re-request human review |
| 2 | evidence-gather exits non-zero | stop — never escalate to step 3 without context |
| 3 | session-kill exits non-zero | log audit record (already written); operator must reconcile manually; do not silently retry |
| 3 | post-apply re-verify shows session still active | open a ticket via the audit envelope; surface as a SEV2 |

No silent retries anywhere. A retry is a new workflow run, with a new
`correlation_id` triplet.

## Reference clients

- **Claude Code / Claude Desktop:** load the preset via the env var,
  point the client at the repo `.mcp.json`, and prompt the agent with
  the trigger finding.
- **Anthropic Agent SDK:** see
  [`../agents/anthropic_sdk_security_agent.py`](../agents/anthropic_sdk_security_agent.py)
  for a runnable Python harness.
- **LangGraph:** see
  [`../agents/langgraph_security_graph.py`](../agents/langgraph_security_graph.py).
- **Manual:** all three skills are `python` entrypoints — pipe stdin /
  stdout between them and supply the approval env vars to the third.

## When to extend

Add a fourth step (e.g. notify SOC channel, file a ticket) **as a new
workflow document** that calls this one as a prefix. Do not edit this
workflow to grow scope — that breaks the trigger ↔ steps ↔ preset
binding.
