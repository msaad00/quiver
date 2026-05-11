---
name: remediate-mcp-tool-quarantine
description: >-
  Quarantine an MCP tool flagged by detect-mcp-tool-drift (T1195.001 supply
  chain compromise) or detect-prompt-injection-mcp-proxy (MITRE ATLAS
  AML.T0051) by appending a structured entry to a JSONL quarantine file
  the operator's MCP client reads at startup or via hot-reload to exclude
  the tool from its discoverable surface. Every action is dry-run by
  default, deny-listed against MCP infrastructure prefixes (mcp_, system_,
  internal_), gated behind an incident ID plus two distinct approvers for
  --apply, and
  dual-audited (DynamoDB + KMS-encrypted S3). Re-verify reads the
  quarantine file and emits VERIFIED, DRIFT, or UNREACHABLE via the shared
  remediation_verifier contract — DRIFT also emits a paired OCSF Detection
  Finding so the gap flows back through the SIEM/SOAR pipeline. Use when
  the user mentions "quarantine an MCP tool," "block a poisoned MCP tool,"
  "respond to MCP tool drift," "remediate prompt injection in MCP proxy,"
  or "re-verify MCP tool quarantine." Do NOT use for cloud IAM revocation,
  Kubernetes containment, Okta session-kill, or any cloud-API write —
  those belong to their own remediation skills. Out of scope: revoking the
  MCP server itself, mutating remote tool definitions, or contacting the
  third-party MCP server author.
purpose: Quarantine an MCP tool flagged by detect-mcp-tool-drift (T1195.001 supply chain compromise) or detect-prompt-injection-mcp-proxy (MITRE ATLAS AML.T0051) by appending a structured entry to a JSONL quarantine file the o...
capability: write-storage
persistence: cloud_state
telemetry: stderr_jsonl
privilege_escalation: read_write
license: Apache-2.0
approval_model: human_required
execution_modes: jit, ci, mcp, persistent
side_effects: writes-storage, writes-audit
input_formats: ocsf, native
output_formats: native
concurrency_safety: operator_coordinated
network_egress: s3.amazonaws.com, dynamodb.amazonaws.com
caller_roles: security_engineer, incident_responder, platform_engineer
approver_roles: security_lead, incident_commander, platform_owner
min_approvers: 2
compatibility: >-
  Requires Python 3.11+. Dry-run and re-verify need only filesystem read
  access to the quarantine file. Apply additionally requires write access
  to the quarantine file plus audit write access to DynamoDB, S3, and KMS.
  No third-party MCP SDK required — this skill writes a structured JSONL
  file that the operator's MCP client filters its tool list against.
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/remediation/remediate-mcp-tool-quarantine
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
    - MITRE ATLAS
    - OWASP MCP Top 10
    - NIST CSF 2.0
    - SOC 2
  cloud:
    - mcp
---

# remediate-mcp-tool-quarantine

## What this closes

Pair skill for both shipped MCP detectors:

- [`detect-mcp-tool-drift`](../../detection/detect-mcp-tool-drift/) — T1195.001 Compromise Software Supply Chain (the rug-pull / tool-poisoning pattern where an MCP tool's behavior or schema mutates between calls)
- [`detect-prompt-injection-mcp-proxy`](../../detection/detect-prompt-injection-mcp-proxy/) — MITRE ATLAS AML.T0051 Prompt Injection (suspicious natural-language patterns in tool descriptions designed to override agent instructions)

Closes [#155](https://github.com/msaad00/cloud-ai-security-skills/issues/155) phase 2: 2 of 8 detection gaps in one skill, the AI-native loop. After this PR ships, **5 of 11 detections are closed-loop**.

## Why file-based quarantine

The MCP attack surface is in-process from the agent's POV — there's no cloud API to call to "block a tool." The cleanest, surface-neutral remediation is a **structured JSONL quarantine file** that the operator's MCP client reads at startup (or via hot-reload) to filter its tool surface:

- **MCP servers in this repo** can read it via `CLOUD_SECURITY_MCP_QUARANTINED_TOOLS_FILE` (operators wire this in their `.mcp.json`).
- **Third-party MCP clients** (Claude Code / Desktop, Codex, Cursor, Windsurf, etc.) can wire it via their per-client allow/deny config — the file is the protocol.

Each line of the file is one quarantine entry with `tool_name`, `session_uid`, `fingerprint`, `producer_skill`, `finding_uid`, `incident_id`, `approvers`, `approver_count`, and `quarantined_at`. The MCP client filters its discoverable tool list against this on startup.

The dual-audit (DynamoDB + KMS-encrypted S3) is preserved for organizational traceability — same shape as the other 4 remediation skills.

## Inputs

Reads OCSF 1.8 Detection Finding (class 2004) JSONL from stdin or a file argument. Required observables:

- `tool.name` — the MCP tool to quarantine (REQUIRED; missing emits `skipped_no_tool_pointer`)
- `session.uid` — the MCP session that surfaced the finding (audit context only)
- `tool.after_fingerprint`, `tool.before_fingerprint`, or `tool.description_sha256` — recorded for forensic context

Findings whose `metadata.product.feature.name` is not in `ACCEPTED_PRODUCERS` are logged and skipped.

## Outputs

JSONL records on stdout:

- `remediation_plan` — under dry-run (default); shows the exact quarantine entry that would be written
- `remediation_action` — under `--apply`; carries `audit.row_uid` + `audit.s3_evidence_uri`
- `remediation_verification` — under `--reverify`; reports VERIFIED / DRIFT / UNREACHABLE per the shared `_shared/remediation_verifier.py` contract
- **OCSF Detection Finding 2004** — additionally emitted on DRIFT so the gap flows back through the same SIEM/SOAR pipeline as every other finding

## Guardrails (enforced in code)

| Layer | Mechanism |
|---|---|
| Source check | `ACCEPTED_PRODUCERS = {"detect-mcp-tool-drift", "detect-prompt-injection-mcp-proxy"}` |
| Protected-tool deny-list | `mcp_*`, `system_*`, `internal_*` prefixes refuse quarantine — operators should revoke / patch infrastructure tools, not silently block them |
| Apply gate | `--apply` requires `MCP_QUARANTINE_INCIDENT_ID` plus two distinct approvers via `MCP_QUARANTINE_APPROVER_EMAILS`, `MCP_QUARANTINE_APPROVER_IDS`, or the legacy pair `MCP_QUARANTINE_APPROVER` + `MCP_QUARANTINE_SECOND_APPROVER` |
| Audit | Dual write (DynamoDB + KMS-encrypted S3) BEFORE and AFTER each quarantine append; failure paths still write the failure audit row |
| Re-verify | Reads the quarantine file; emits VERIFIED if tool is present, DRIFT (+ paired OCSF finding) if removed, UNREACHABLE if file unreadable — never silently downgrades |

## Run

```bash
# Dry-run plan (default)
python skills/remediation/remediate-mcp-tool-quarantine/src/handler.py findings.ocsf.jsonl

# Apply (after out-of-band approval)
export MCP_QUARANTINE_INCIDENT_ID=INC-2026-04-19-002
export MCP_QUARANTINE_APPROVER_EMAILS=alice@security,bob@security
export MCP_QUARANTINE_FILE=$HOME/.mcp-quarantine.jsonl
export MCP_QUARANTINE_AUDIT_DYNAMODB_TABLE=mcp-quarantine-audit
export MCP_QUARANTINE_AUDIT_BUCKET=acme-mcp-audit
export KMS_KEY_ARN=arn:aws:kms:us-east-1:111122223333:key/...
python skills/remediation/remediate-mcp-tool-quarantine/src/handler.py findings.ocsf.jsonl --apply

# Re-verify (read-only)
python skills/remediation/remediate-mcp-tool-quarantine/src/handler.py findings.ocsf.jsonl --reverify
```

## Non-goals

- Mutating remote tool definitions on the third-party MCP server (out of scope; this is operator-side only)
- Contacting the MCP server author or filing a vendor disclosure (manual workflow)
- Revoking the MCP server itself — use the operator's MCP client config for that
- Killing in-flight tool calls — the quarantine takes effect on next MCP client load / hot-reload

## See also

- [`remediate-container-escape-k8s`](../remediate-container-escape-k8s/) and [`remediate-k8s-rbac-revoke`](../remediate-k8s-rbac-revoke/) — sibling closed-loop remediation skills
- [`detect-mcp-tool-drift`](../../detection/detect-mcp-tool-drift/) and [`detect-prompt-injection-mcp-proxy`](../../detection/detect-prompt-injection-mcp-proxy/) — source detectors
- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — verification contract this skill emits via
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — repo-wide HITL bar
- [`SECURITY_BAR.md`](../../../SECURITY_BAR.md) — eleven-principle contract
