---
name: detect-admin-role-grant-workspace
description: >-
  Detect Google Workspace protected admin role grants, especially Super Admin,
  that occur outside an operator-maintained break-glass granter allow-list.
  Reads OCSF 1.8 Account Change (3001) or native events emitted by
  `ingest-workspace-admin-ocsf` with `application_name=admin`, role assignment
  parameters, and assignee details; emits OCSF Detection Finding (2004) tagged
  with MITRE ATT&CK T1098.003. Use when the user mentions Workspace admin role
  grants, Super Admin escalation, or break-glass governance. Do NOT use on raw
  Admin SDK payloads before normalization, on non-Workspace role events, or as
  a remediation skill.
purpose: Detect protected Google Workspace admin role grants outside a break-glass granter allow-list.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native, ocsf
concurrency_safety: stateless
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-admin-role-grant-workspace
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - google-workspace
---

# detect-admin-role-grant-workspace

## Use when

- You normalized Google Workspace admin audit events with `ingest-workspace-admin-ocsf`
- You need to detect Super Admin grants outside a documented break-glass path
- You want a stateless privileged-role grant detector for Workspace governance

## Do NOT use

- On raw Admin SDK Reports API JSON before ingestion
- On role grants from Slack, Entra, Okta, Snowflake, or Databricks
- As remediation; role revocation belongs in a separate HITL-gated write skill

## Detection logic

One pass over OCSF Account Change events:

1. Require producer `ingest-workspace-admin-ocsf`.
2. Require `application_name=admin`.
3. Require a role-assignment event name or `role_name` / `role_id` plus assignee parameters.
4. Require a protected role. Default protected roles are `Super Admin` variants.
5. Ignore granters in `WORKSPACE_AUTHORIZED_ADMIN_ROLE_GRANTERS`.
6. If the allow-list is empty, fire in fail-open mode so every protected-role grant is reviewed.

Operators can extend protected roles with:

```bash
export WORKSPACE_PROTECTED_ADMIN_ROLES="Super Admin,Groups Admin"
```

## Output contract

Default output is OCSF Detection Finding (class `2004`) with:

- deterministic `metadata.uid`
- `finding_info.types[] = ["workspace-admin-role-grant", "OWASP-Top-10-A01"]`
- MITRE ATT&CK `T1098.003`
- `evidence.granter`, `evidence.grantee`, and `evidence.role`

Severity is `HIGH`.

## Usage

```bash
export WORKSPACE_AUTHORIZED_ADMIN_ROLE_GRANTERS="breakglass-admin@example.com"
cat workspace-admin.ocsf.jsonl | python src/detect.py > workspace-admin-role-findings.ocsf.jsonl
```

## Delivery note

Delivered as part of Google Workspace vendor story issue #32.
