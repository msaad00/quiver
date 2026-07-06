# HITL Policy

The human-in-the-loop bar for every skill in this repo. Closes
[#259](https://github.com/msaad00/cloud-ai-security-skills/issues/259).

This file sets **when** human approval is required, **how many** approvers
are required, and **where** the gate sits. It applies to every skill —
new and existing. It is the policy doc that
[`scripts/validate_safe_skill_bar.py`](../scripts/validate_safe_skill_bar.py)
enforces and that the auto-generated per-skill matrix in
[`SECURITY_BAR.md`](../SECURITY_BAR.md) reflects
([#246](https://github.com/msaad00/cloud-ai-security-skills/issues/246)).

If you are adding a new skill, find the row that matches what it does and
set frontmatter to match. If no row matches cleanly, open an issue rather
than choosing the weakest row.

## The matrix

The five fields below are all declared in each skill's `SKILL.md`
frontmatter. The policy rubric is in the last three columns.

| Finding class / skill category | Reversibility | Blast radius | Required `approval_model` | `min_approvers` | Grace period | Notes |
|---|---|---|---|---:|---|---|
| **Read-only evaluation or discovery** (CSPM scan, `discover-*`, `detect-*` without a paired remediation) | n/a | n/a | `none` | 0 | n/a | By construction — no side effects. `side_effects: none` required. |
| **Active account takeover containment** (Okta MFA fatigue + success, credential stuffing + success; Workspace suspicious login + success) | Low — session kill reversible by re-auth | Single user | `human_required` with **declared incident window** + dry-run default | 1 | 0 min (time-sensitive) | `remediate-okta-session-kill` is the reference. Incident ID + approver env vars are mandatory before `--apply` fires. |
| **Kubernetes workload quarantine** (`remediate-container-escape-k8s`) | Low by default; higher when `--approve-pod-kill` or `--approve-node-drain` is selected | Single pod / workload in one namespace; node scope for the explicit drain path | `human_required` with **declared incident window** + dry-run default | 1 baseline; **2 for `--approve-node-drain`** | 0 but dry-run first | Protected namespaces (`kube-system`, `kube-public`, `istio-system`, `linkerd*`) are denied in code. `--approve-pod-kill` is explicit because it destroys in-memory state; `--approve-node-drain` requires `K8S_CONTAINER_ESCAPE_SECOND_APPROVER` and refuses when protected-namespace pods share the node. `--reverify` must prove the selected post-response state still holds. |
| **Stale identity cleanup** (IAM departures, idle access key purge) | Irreversible | Single user / SA | `human_required` | 1 | 7 days default | `iam-departures-aws` is the reference. Grace period is configurable per environment but never zero. Rehire filter and protected-principal deny list both enforced in code AND in IAM. |
| **Cross-account role creation or trust edit** (edit an `sts:AssumeRole` allow; add a new principal to an allow list) | Low — policy edit | Multi-account | `human_required` + `min_approvers: 2` | **2** | 0 but dry-run first | Privilege-escalation-adjacent. One compromised identity must not be able to unilaterally expand its reach. |
| **CIS posture misconfig fix** (`--auto-remediate` on open SG, public S3, unencrypted trail) | Low — service config | Account scope | `human_required` | 1 | 0 but dry-run first | Must honor an allow-list of break-glass resources and an explicit allowed-account binding so ambient credentials cannot drift into the wrong account. `#254` + `#242` track the auto-remediate rollout. |
| **K8s RBAC revocation** (`remediate-k8s-rbac-revoke`) | Low — RBAC edit | Namespace | `human_required` | 1 | 0 but dry-run first | Namespace deny-list (`kube-system`, `kube-public`, anything labeled `security.company.io/protected=true`) enforced in code. `--apply` also requires `K8S_CLUSTER_NAME` plus `K8S_RBAC_REVOKE_ALLOWED_CLUSTERS` so ambient kube context alone cannot pick the target cluster. |
| **MCP tool quarantine** (`remediate-mcp-tool-quarantine`) | Low — re-enable is cheap | Single tool | `human_required` + `min_approvers: 2` | **2** | 0 | Recursive-exploit defense: a compromised agent could try to disable its own watchdog. Two approvers = attacker must compromise two identities to succeed. `--apply` requires `MCP_QUARANTINE_INCIDENT_ID` plus two distinct approvers via `MCP_QUARANTINE_APPROVER_EMAILS`, `MCP_QUARANTINE_APPROVER_IDS`, or the legacy pair `MCP_QUARANTINE_APPROVER` + `MCP_QUARANTINE_SECOND_APPROVER`. |
| **GPU workload drain** (`remediate-gpu-workload-drain`) | Low — re-schedule | Single node | `human_required` | 1 | 0 but dry-run first | Documented in `#255`. |
| **Model weight or credential rotation** (`remediate-agent-credential-rotate`, `remediate-model-weights-lock`) | Mid — service disruption possible | Service scope | `human_required` | 1 | 0 but dry-run first | Test in staging first per skill. |
| **Write-sink / persistence** (`sink-s3-jsonl`, `sink-snowflake-jsonl`, `sink-clickhouse-jsonl`) | Low — append-only, immutable objects | Target bucket / table | `human_required` once at the pipeline level (not per-record) | 1 | n/a | Sinks are write-capable but not mutating. HITL is the operator who configured the pipeline, not a per-row approval. |

## Five load-bearing principles

1. **`approval_model: none` is reserved for read-only skills.**
   Any skill whose `side_effects` is non-empty — anything touching identity,
   cloud config, storage, or audit — MUST declare at least
   `dry_run_required`. `none` is not an acceptable choice for a writable
   skill, ever. The `validate_safe_skill_bar.py` lint enforces this.

2. **Containment can auto-apply only inside a _declared_ incident window.**
   The window is a separate Pydantic-validated record written to an audit
   table by an on-call human. A remediation skill reads it from env vars
   or a dedicated table before `--apply` fires. A skill that "just runs
   containment automatically because the detector fired" is rejected at
   review — the gate must land on a human.

3. **Privilege-escalation-adjacent actions require `min_approvers: 2`.**
   That set is: cross-account trust edits, MCP tool disable, audit-table
   mutations, deny-list mutations, role-to-role AssumeRole additions. A
   single compromised identity — human or agent — cannot unilaterally
   widen its reach if two independent approvers are required.

4. **The HITL gate sits OUTSIDE the agent loop.**
   When Claude / Codex / Cursor / any MCP client calls a HITL-gated skill,
   the skill responds with "approval required" and exits. Approval comes
   from a separate out-of-band signal — ticketing, SMS, a human CLI
   invocation — never from the agent's own context window. This defeats
   prompt injection against the approval path: an attacker who controls
   the model cannot spoof the approver record that the skill checks.
   `remediate-okta-session-kill` demonstrates this with
   `OKTA_SESSION_KILL_INCIDENT_ID` + `OKTA_SESSION_KILL_APPROVER` env vars
   that the MCP client cannot set on its own.

5. **Every dry-run that would touch a protected resource returns
   `would-violate-deny-list`, not `would-apply`.**
   The clearest diagnostic that the deny list is load-bearing is that the
   dry-run itself refuses to plan the action. If a dry-run against a
   protected principal shows `would-apply`, the deny list is broken.

## Enforcement — where the policy is load-bearing, not just documented

| Check | Where | Fails CI when |
|---|---|---|
| `approval_model != "none"` for writable skills | [`validate_safe_skill_bar.py::validate_write_skill_dry_run`](../scripts/validate_safe_skill_bar.py) | A new `remediate-*` ships with `approval_model: none` |
| `dry-run` documented in SKILL.md + exercised in tests | same | Writable skill lacks `dry-run` in SKILL.md or fails to test the dry-run path |
| `sts:AssumeRole` carries a boundary condition | `validate_assume_role_boundaries()` ([#263](https://github.com/msaad00/cloud-ai-security-skills/pull/263)) | Any IAM policy grants AssumeRole without `aws:PrincipalOrgID` / `aws:SourceAccount` / equivalent |
| Wildcard action/resource justified | `validate_wildcards()` | `Action: "*"` or `Resource: "*"` without a `WILDCARD_OK` comment nearby |
| Remediation `--apply` gated on incident + approver env vars | `validate_remediation_hitl_env_vars()` | A `remediate-*` skill src/ doesn't reference both an incident-style env var (`*INCIDENT*` / `*TICKET*` / `*CASE_ID*`) and an approver-style env var (`*APPROVER*` / `*APPROVED_BY*` / `*AUTHORIZED_BY*` / `*AUTHORIZER*`); opt out with `HITL_ENV_OK` + justification |
| Per-skill matrix in SECURITY_BAR.md stays in sync with frontmatter | [#246](https://github.com/msaad00/cloud-ai-security-skills/issues/246) auto-gen (planned) | CI regenerates the matrix and asserts the committed file matches |

## How to declare in frontmatter

Copy the row that matches, paste into `SKILL.md`:

```yaml
# Read-only skill (CSPM, detect-*, discover-*):
approval_model: none
side_effects: none
caller_roles: security_engineer
approver_roles: []
min_approvers: 0

# Containment (active account takeover):
approval_model: human_required
side_effects: writes-identity, writes-audit
caller_roles: security_engineer, incident_responder
approver_roles: security_lead, incident_commander
min_approvers: 1

# Stale identity cleanup (iam-departures-aws pattern):
approval_model: human_required
side_effects: writes-identity, writes-storage, writes-database, writes-audit
caller_roles: security_engineer
approver_roles: security_lead, cis_officer
min_approvers: 1

# Privilege-escalation-adjacent (role edits, MCP tool quarantine):
approval_model: human_required
side_effects: writes-identity, writes-audit
caller_roles: security_engineer
approver_roles: security_lead, cis_officer
min_approvers: 2

# Posture auto-remediate (CSPM --auto-remediate):
approval_model: human_required
side_effects: writes-cloud, writes-audit
caller_roles: security_engineer
approver_roles: security_lead
min_approvers: 1
```

`network_egress` is orthogonal to HITL — it lists the exact domains a skill
is allowed to reach. Scope it to the minimum set the skill actually uses.

`approver_roles` and `min_approvers` define the policy floor. Runtime wrappers
or surrounding approval systems may enforce approver identity and role
membership separately from the local CLI gate, so a skill should not claim
in-code approver-role validation unless its shipped handler or wrapper
actually performs that check.

## Related

- [`SECURITY_BAR.md`](../SECURITY_BAR.md) — the full eleven-principle contract
- [`CLAUDE.md`](../CLAUDE.md) — agent guardrails for the same surface
- [`AGENTS.md`](../AGENTS.md) — cross-agent repo contract
- [`scripts/validate_safe_skill_bar.py`](../scripts/validate_safe_skill_bar.py) — the lint that enforces this policy
- [#240](https://github.com/msaad00/cloud-ai-security-skills/issues/240), [#244](https://github.com/msaad00/cloud-ai-security-skills/issues/244), [#256](https://github.com/msaad00/cloud-ai-security-skills/issues/256) — landed pieces of the guardrail foundation
- [#246](https://github.com/msaad00/cloud-ai-security-skills/issues/246), [#257](https://github.com/msaad00/cloud-ai-security-skills/issues/257) — SECURITY_BAR auto-gen and drift framework (will consume this doc)
