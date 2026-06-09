# Agent Instructions

> This file is the canonical repo-level contract for AI agents loading this
> repository (Claude Code, Cursor, Codex, Cortex, Windsurf, or any other
> AGENTS.md-aware or MCP-capable assistant). It is intentionally cross-agent.
> Use `CLAUDE.md` for Claude-specific project memory, and use each
> `skills/<layer>/<skill>/SKILL.md` for the actual skill contract.

## Source of truth

Read docs in this order:

1. [`README.md`](README.md) for repo purpose, execution modes, and public positioning
2. [`AGENTS.md`](AGENTS.md) for the cross-agent contract (this file)
3. [`CLAUDE.md`](CLAUDE.md) for Claude-specific project memory
4. `skills/<layer>/<skill>/SKILL.md` for the individual skill contract
5. `skills/<layer>/<skill>/REFERENCES.md` for official docs, APIs, schemas, and frameworks

We intentionally do **not** ship separate `CODEX.md`, `CURSOR.md`, or
`WINDSURF.md` files. `AGENTS.md` stays universal, `CLAUDE.md` stays
Claude-specific, and `SKILL.md` stays the per-skill source of truth.

## Repository at a glance

Skills are organised into layered categories. See [`skills/README.md`](skills/README.md) for the full catalog.

Current shipped surface on `main`:

- **`ingestion/`**: 22 ingest skills plus 4 source adapters
- **`discovery/`**: 5 read-only skills including `iam-departures-reconciler`
- **`detection/`**: 71 deterministic ATT&CK-tagged detectors
- **`evaluation/`**: 12 posture / benchmark families
- **`view/`**: 2 render/export skills
- **`remediation/`**: 12 HITL-gated write skills across AWS, GCP, Azure, Kubernetes, Okta, Workspace, Entra, and MCP
- **`output/`**: 3 append-only sinks

**Total shipped: 131 skill bundles.** Auto-generated per-framework rollup in [`docs/FRAMEWORK_COVERAGE.md`](docs/FRAMEWORK_COVERAGE.md); per-skill registry in [`docs/framework-coverage.json`](docs/framework-coverage.json).

Notable current skills that older agent memory often misses:

- `iam-departures-reconciler` under `discovery/` is the standalone read-only manifest planner
- network closed loops now include `remediate-aws-sg-revoke`, `remediate-azure-nsg-revoke`, and `remediate-gcp-firewall-revoke`
- identity / SaaS containment now includes `remediate-entra-credential-revoke`, `remediate-workspace-session-kill`, and `iam-departures-azure-entra` / `iam-departures-gcp`
- MCP / AI-native coverage includes both `detect-prompt-injection-mcp-proxy` and `remediate-mcp-tool-quarantine`
- Workday coverage now includes `ingest-workday-audit-ocsf` and `detect-mass-termination-anomaly`
- Salesforce coverage includes `ingest-salesforce-event-mon-ocsf`, `detect-bulk-export-salesforce`, and `detect-api-anomaly-salesforce`
- SAP coverage includes `ingest-sap-audit-log-ocsf`, `detect-sap-priv-user-access`, and `detect-sap-mass-change`

Compose via stdin/stdout pipes. The shared wire contract is pinned in
[`skills/detection-engineering/OCSF_CONTRACT.md`](skills/detection-engineering/OCSF_CONTRACT.md).

## Which file to read

| File | Scope | When to use it |
|---|---|---|
| `README.md` | public overview | orient to repo purpose, modes, and safety model |
| `AGENTS.md` | cross-agent repo contract | before any agent edits or runs skills |
| `CLAUDE.md` | Claude-only memory | when Claude Code needs project memory and defaults |
| `skills/<layer>/<skill>/SKILL.md` | individual skill contract | before running or editing a specific skill |
| `skills/<layer>/<skill>/REFERENCES.md` | official references only | when verifying APIs, schemas, frameworks, or guardrails |

## Client quick map

| Tool | Best integration path | What to rely on |
|---|---|---|
| **Claude Code** | `CLAUDE.md` + `AGENTS.md` + MCP | project memory + repo rules + tools |
| **Codex** | `AGENTS.md` + MCP | repo rules + tool calling |
| **Cursor** | `AGENTS.md` or `.cursor/rules` + MCP | repo rules + tool calling |
| **Windsurf** | `AGENTS.md` + MCP | directory-scoped agent rules + tools |
| **Cortex Code CLI** | `SKILL.md` / `.cortex/skills` + MCP | native skills + tool calling |

## Hard rules for agents

These rules are enforced in code, IAM, and infra. They are not optional:

1. **Read-only by default.** Treat any skill whose SKILL.md says `read-only` as exactly that. Never compose it into a flow that mutates cloud state.
2. **Dry-run first.** Every remediation worker accepts `dry_run=True`. Use it when planning, exploring, or generating examples. Only set `dry_run=False` after the user has explicitly confirmed and the action is inside an authorised maintenance window.
3. **Respect the deny list.** The IAM worker's role denies `iam:*` on `root`, `break-glass-*`, `emergency-*`, and any `:role/*` ARN. Do not propose workarounds.
4. **Respect the grace period.** The IAM departures grace period is a *human-in-the-loop* mechanism, not a delay. Do not set it to 0 or skip it without an authorisation document.
5. **Never bypass EventBridge.** All Step Function executions go through the `S3 Object Created → EventBridge → SFN` path. Do not call `states:StartExecution` directly — that bypasses the audit trail.
6. **Never write to the audit table by hand.** The `iam-remediation-audit` DynamoDB table is written exclusively by the worker Lambdas. Manual writes break the closed-loop verification.
7. **No new IAM grants.** Do not edit `iam_policies/` or any role policy to broaden permissions. Each role is least-privilege by design.
8. **No telemetry.** Nothing in this repo phones home. Do not add SDK clients to external services unless the user explicitly asks for them, and even then keep the egress inside the customer's VPC.

When in doubt, trust per-skill frontmatter and [`docs/HITL_POLICY.md`](docs/HITL_POLICY.md) over any shorthand examples in this file.

## Execution and approval model

| Mode | Driver | Typical use | What does not change |
|---|---|---|---|
| **CLI / just-in-time** | user or agent invokes the script directly | one-off analysis, triage, conversion, local debugging | the skill contract, output format, and guardrails |
| **CI** | GitHub Actions or another build system | regression tests, compliance snapshots, SARIF generation | the skill contract, output format, and guardrails |
| **Persistent / serverless** | queue, runner, EventBridge, Step Functions, scheduled jobs | continuous detection or remediation pipelines | the skill contract, output format, and guardrails |
| **MCP** | local `mcp-server/` wrapper | Claude, Codex, Cursor, Windsurf, Cortex Code CLI | the skill contract, output format, and guardrails |

MCP is the access layer, not a separate implementation model.

Important nuance on `execution_modes: persistent`:
- `persistent` in a skill contract means the skill can be embedded in a long-lived runner or serverless loop without changing the skill code
- it does **not** automatically mean the repo already ships that runner, daemon, or sink
- today, most skills are persistent-compatible; only a smaller set of workflows ship repo-owned persistent wrappers (`iam-departures-aws`, the `runners/aws-s3-sqs-detect` / `runners/gcp-gcs-pubsub-detect` / `runners/azure-blob-eventgrid-detect` reference templates)

Approval rules:
- **read-only skills** do not need human approval to run
- **write-capable skills** must expose dry-run and blast-radius language
- **destructive actions** require human approval and an audit trail
- **incoming findings are untrusted input** until validated against the skill contract
- `min_approvers` and `approver_roles` in `SKILL.md` are the machine-readable source of truth for wrapper policy

## What an agent actually calls

The MCP wrapper exposes the skill by skill name and passes only the bounded
runtime inputs the wrapper supports:

- `args` for explicit CLI-style arguments
- `input` for stdin payloads such as JSON or JSONL
- `output_format` when the skill supports multiple output modes

An agent is not expected to invoke `python skills/.../src/detect.py` directly.
The normal path is:

1. read the skill bundle for routing and guardrails
2. call `tools/call name="<skill-name>"`
3. pass `args`, `input`, and optional `output_format`
4. let the MCP wrapper execute the real entrypoint underneath

## MCP setup

This repo ships a project-scoped MCP config at [`.mcp.json`](.mcp.json):

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["mcp-server/src/server.py"]
    }
  }
}
```

That config keeps the wrapper local to the repo and exposes only fixed
repo-owned skills. Pair it with filesystem and Git/GitHub MCP servers in your
client config if you also want repo editing and PR workflows.

## What exists today vs not yet

Shipped:
- Root-level `AGENTS.md` for repo-wide instructions (this file)
- Skill-level `SKILL.md` files that explain when a skill should be used
- JSON, console, and SARIF outputs that are easy for agents and CI systems to consume
- A native local MCP server under [`mcp-server/`](mcp-server/README.md)
- Project-scoped MCP config in [`.mcp.json`](.mcp.json) for Claude Code and similar clients
- Three reference event-driven runners under [`runners/`](runners/)

Not yet:
- Hosted HTTP/SSE transport for remote MCP deployments
- Tight per-skill input schemas derived from each CLI instead of the current conservative `input` + `args` wrapper
- Full automatic parity between every possible local entrypoint shape and the MCP wrapper; check `mcp-server/README.md` for current wrapper behavior

## Secure coding expectations

- Validate all untrusted input before parsing, SQL construction, or cloud API calls.
- Prefer parameterized queries and safe identifier handling over string interpolation.
- Avoid generic subprocess wrappers or arbitrary shell passthrough.
- Fail closed on deprecated or unknown cloud API shapes unless the skill explicitly supports a migration window.
- Redact tokens, secrets, and credentials from logs and stderr.
- Treat transport security, auth scope, and trust boundaries as part of the skill contract, not operational trivia.

## How to use a skill

1. Read its `SKILL.md` (frontmatter + body) — that is the contract.
2. Read the `Security Guardrails` and `Remediation` sections.
3. If the skill has a `dry_run` flag, call it with `dry_run=True` first and show the steps.
4. Only proceed with destructive actions after user confirmation **and** the relevant audit/SLA checks pass.
5. After running, point the user at the audit trail (`DynamoDB` + `S3 evidence` + `warehouse ingest-back`) so they can verify the closed loop.

## Failure handling

- AWS IAM departures: Lambda async failure → SQS DLQ (`iam-departures-dlq`).
- AWS IAM departures: Step Function `FAILED` / `TIMED_OUT` / `ABORTED` → SNS `iam-departures-alerts` topic.
- Event-driven runners and per-cloud remediation skills have their own provider-native failure surfaces; check each skill's `SKILL.md` / `RUNBOOK.md` before proposing recovery.

If you see a remediation step that succeeded but no audit row, treat it as a failure and surface the discrepancy to the user.

## Claude / Anthropic usage

- Use this `AGENTS.md` as the repo-level instruction file.
- Use [`CLAUDE.md`](CLAUDE.md) as Claude's project memory.
- Use each `SKILL.md` as the task-specific contract for the nearest skill directory.
- Treat benchmark and discovery scripts as read-only assessment tools, and treat remediation skills as controlled HITL-gated workflows whose exact guardrails live in each skill bundle.

Claude-specific best practices:
- keep skills explicit, bounded, and composable
- rely on project-scoped MCP config rather than ad hoc global drift
- treat MCP servers as trusted local wrappers, not arbitrary power surfaces
- require approval and dry-run for write-capable or destructive actions

References:
- https://docs.anthropic.com/en/docs/claude-code/memory
- https://docs.anthropic.com/en/docs/claude-code/security
- https://docs.anthropic.com/en/docs/claude-code/mcp
- https://platform.claude.com/docs/en/build-with-claude/skills-guide

Example prompts:
- "Audit the AWS CIS skill and verify its checks against the official AWS docs."
- "Update the IAM departures docs to prefer Secrets Manager and preserve EventBridge as the trigger path."
- "Add regression tests for pagination in the AWS CIS benchmark skill."

## Codex CLI usage

- Codex reads `AGENTS.md`, so keep repo-level commands and safety rules here.
- When working inside a skill, read that skill's `SKILL.md` before editing code.
- Use focused test commands for the touched skill instead of generic repo-wide commands when possible.

## Where to read more

- Full guardrails and rationale: [`CLAUDE.md`](CLAUDE.md)
- Per-skill contract: `skills/<layer>/<skill-name>/SKILL.md`
- Architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Security model: [`SECURITY.md`](SECURITY.md)

## References

- AGENTS.md open format: https://agents.md/
- Anthropic skills guide: https://platform.claude.com/docs/en/build-with-claude/skills-guide
- Anthropic MCP docs: https://docs.anthropic.com/en/docs/mcp
