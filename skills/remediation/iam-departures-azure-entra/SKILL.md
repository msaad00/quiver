---
name: iam-departures-azure-entra
description: >-
  Use when Azure Entra ID user departure manifest needs surgical IAM teardown
  for departed employees. Reconciles HR termination data against Microsoft
  Entra ID inside an Azure tenant, exports a manifest to Azure Blob Storage
  (CMK-encrypted via Key Vault), and triggers a Logic App / Durable Function
  that disables the user (`accountEnabled=false`), revokes all sign-in
  sessions, deletes OAuth2 permission grants, removes group + directoryRole +
  appRoleAssignment memberships, detaches Azure RBAC at management group +
  subscription + resource-group scope, removes assigned licenses, tags the
  user with audit metadata, then soft-deletes (default) or hard-deletes
  (opt-in flag) the user. Every action is grace-period-gated (7 days
  default), rehire-aware, deny-listed for `admin@*`, `breakglass-*`,
  `emergency-*`, `sync_*`, the tenant `Global Administrator` ObjectIds, and
  any extra ObjectIds in `IAM_DEPARTURES_AZURE_PROTECTED_OBJECT_IDS`.
  `--apply` requires `IAM_DEPARTURES_AZURE_INCIDENT_ID` +
  `IAM_DEPARTURES_AZURE_APPROVER` set out-of-band. Dual audit (Cosmos DB +
  CMK-encrypted Blob Storage) BEFORE and AFTER each step. Triggers:
  "Azure offboarding," "Entra IAM cleanup for departed employees," "Entra
  user departure manifest." Do NOT use for AWS IAM (use
  `iam-departures-aws`), GCP IAM (separate skill, see #239), Snowflake or
  Databricks user lifecycle, Entra service-principal credential containment
  (use `remediate-entra-credential-revoke`), Okta session revocation, or
  Workspace user deprovisioning. Do NOT bypass the grace period, write to
  the audit table by hand, disable the protected-object deny-list, or run
  the worker on a tenant `Global Administrator` ObjectId.
purpose: Use when Azure Entra ID user departure manifest needs surgical IAM teardown for departed employees.
capability: write-cloud
persistence: cloud_state
telemetry: stderr_jsonl
privilege_escalation: read_write
license: Apache-2.0
approval_model: human_required
execution_modes: jit, ci, mcp, persistent
side_effects: writes-identity, writes-storage, writes-database, writes-audit
input_formats: raw, native
output_formats: native
concurrency_safety: operator_coordinated
network_egress: graph.microsoft.com, login.microsoftonline.com, management.azure.com, vault.azure.net, documents.azure.com, blob.core.windows.net
caller_roles: security_engineer, incident_responder
approver_roles: security_lead, cis_officer
min_approvers: 1
compatibility: >-
  Requires Python 3.11+, msgraph-sdk, azure-identity, azure-mgmt-authorization,
  azure-cosmos, azure-storage-blob (lazy-imported only under --apply /
  --reverify). Entra: `User Administrator` directory role for
  user/group/license calls; `Privileged Role Administrator` for directoryRole
  removals; `Application Administrator` for OAuth2 + appRoleAssignment
  cleanup. Azure RBAC: `User Access Administrator` at the management-group
  scope for cross-subscription role-assignment teardown.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/remediation/iam-departures-azure-entra
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
    - NIST CSF 2.0
    - SOC 2 TSC
    - CIS Azure Foundations v2.1
  cloud:
    - azure
---

# IAM Departures Remediation — Azure Entra ID

Azure Entra ID counterpart to the flagship [`iam-departures-aws`](../iam-departures-aws/) pipeline. Closes [#238](https://github.com/msaad00/cloud-ai-security-skills/issues/238). Same skill contract, same rehire-safe + grace-period semantics, same dual-audit trail — but the orchestration uses Azure-native primitives (Function App, Logic App, EventGrid, Cosmos DB, Blob Storage with Key Vault CMK) instead of pretending one stack fits every cloud.

Read [REFERENCES.md](REFERENCES.md) for Microsoft Graph + Azure RBAC API specs and [examples.md](examples.md) for deployment + dry-run walkthroughs.

## When to Use

- An employee is terminated and their Azure Entra user should be cleaned up
- Bulk offboarding after a layoff or reorganization in an Azure-native shop
- Audit identifies stale Entra users tied to departed employees
- Compliance requires automated deprovisioning for Entra ID (SOC 2 CC6.3, CIS Azure 1.x, NIST PR.AC-1)
- Security team wants to eliminate T1078.004 (Valid Accounts: Cloud Accounts) risk in the Azure tenant

## Pipeline Overview

```
HR source ─► Reconciler (rehire + grace + SHA-256 diff)
            │
            ▼
   Blob Storage manifest (CMK via Key Vault)
            │
            ▼ EventGrid (BlobCreated, suffix .json)
            │
            ▼ Logic App (Durable orchestrator)
            │
            ▼ Function 1 — Parser (recheck manifest + Entra state)
            │
            ▼ Function 2 — Worker (11-step Entra IAM teardown)
            │
            ▼ Cosmos DB audit + Blob Storage evidence (CMK)
            │
            ▼ Ingest-back to source warehouse → drift check on next run
```

## Security Guardrails

- **Dry-run first**: parser and worker both default to dry-run; `--apply` requires the HITL env-var pair.
- **Protected ObjectIds**: tenant `Global Administrator`, `User Administrator`, `Privileged Role Administrator` ObjectIds, plus `admin@*`, `breakglass-*`, `emergency-*`, `sync_*` UPNs are protected by **both** the worker code (`protected_principals.py`) and the Azure RBAC role's deny condition. The list is mirrored in `infra/iam_policies/cross_subscription_role.json`.
- **Grace period**: 7-day default window before remediation (configurable via `IAM_DEPARTURES_AZURE_GRACE_PERIOD_DAYS`, never 0).
- **Rehire safety**: same eight scenarios as the AWS sibling. The reconciler/export path is the primary rehire-aware filter; the parser Function is the second gate.
- **Cross-subscription scoped**: the worker function's role is granted at the **management-group** scope (NOT subscription wildcard) so it cannot escape the tenant; `aws:PrincipalOrgID`-equivalent is the management-group hierarchy.
- **HITL gate**: `--apply` requires `IAM_DEPARTURES_AZURE_INCIDENT_ID` + `IAM_DEPARTURES_AZURE_APPROVER` both set out-of-band.
- **Encryption**: Blob Storage manifest + audit evidence encrypted with a customer-managed key in Azure Key Vault. Cosmos DB encryption at rest. Function App env vars stored in Key Vault references, never plaintext.
- **VNet isolation**: Function App runs inside a private VNet with Service Endpoints to Microsoft Graph, Azure Resource Manager, Cosmos DB, and Storage; no public internet egress.
- **Audit trail**: Every action dual-written to Cosmos DB + Blob Storage. Ingest-back to source warehouse for the next reconciler run.
- **Soft-delete by default**: Step 11 sets `accountEnabled=false` and writes the audit-tag extension property; the Microsoft Graph hard `DELETE /users/{id}` is opt-in via `--hard-delete` (independent of `--apply`).

## Do NOT use

- Do NOT use for AWS IAM (use [`iam-departures-aws`](../iam-departures-aws/)).
- Do NOT use for GCP IAM (separate skill, see [#239](https://github.com/msaad00/cloud-ai-security-skills/issues/239)).
- Do NOT use for Snowflake / Databricks user lifecycle (separate skills).
- Do NOT use for Entra **service-principal** credential containment (use [`remediate-entra-credential-revoke`](../remediate-entra-credential-revoke/)).
- Do NOT use for Okta session revocation (use [`remediate-okta-session-kill`](../remediate-okta-session-kill/)).
- Do NOT use for Workspace user deprovisioning (use [`remediate-workspace-session-kill`](../remediate-workspace-session-kill/)).
- Do NOT bypass the grace period by editing manifest timestamps or env-overriding to 0.
- Do NOT call the worker Function directly; enter through the documented EventGrid path so the audit row is bound to a manifest write.
- Do NOT write directly to the Cosmos DB audit table outside the shipped workflow.
- Do NOT pass a tenant `Global Administrator` ObjectId — the protected-principal deny list refuses it locally AND the cross-subscription Azure RBAC role denies it at the API boundary.
- Do NOT run `--hard-delete` without an explicit operator-approved soft-delete pass first.

## Rehire Safety

The pipeline handles 8 rehire scenarios. Key rules (mirror of the AWS sibling):

1. **Rehired + same Entra user in use** → SKIP (employee is active)
2. **Rehired + Entra user idle since rehire** → REMEDIATE (orphaned credential)
3. **Entra user already deleted** → SKIP (no-op)
4. **Within grace period** → SKIP (HR correction window, default 7 days)
5. **Terminated again after rehire** → REMEDIATE
6. **Sign-in blocked but not deleted** → SKIP if recently changed (still in grace), else REMEDIATE
7. **Rehire date present but UPN changed** → SKIP (this is a different identity)
8. **Manifest entry missing terminated_at** → SKIP (fail safe)

The parser Function is intentionally a second safety gate, not the first place rehire decisions are made.

## Entra IAM Teardown Order

Microsoft Graph + Azure RBAC require dependencies removed in a specific order before the user can be hard-deleted (and before soft-delete is auditable). The worker Function executes 11 steps in strict order:

1. **Disable user** — `PATCH /users/{id}` with `{"accountEnabled": false}` (immediately stops new auth + token issuance)
2. **Revoke all sign-in sessions** — `POST /users/{id}/revokeSignInSessions` (kills active refresh tokens)
3. **Delete all OAuth2 permission grants** — `DELETE /oauth2PermissionGrants/{id}` (per-grant, filtered by `principalId`)
4. **Remove from all Entra groups** — `DELETE /groups/{id}/members/{userId}/$ref` (per group)
5. **Remove from all directoryRole assignments** — `DELETE /directoryRoles/{id}/members/{userId}/$ref`
6. **Delete all appRoleAssignments** — `DELETE /users/{id}/appRoleAssignments/{id}` (per assignment)
7. **Detach Azure RBAC at subscription scope** — `DELETE /providers/Microsoft.Authorization/roleAssignments/{id}` filtered by `principalId == userId`
8. **Detach Azure RBAC at management group + resource-group scope** — same API, broader + narrower scopes
9. **Detach assigned licenses** — `POST /users/{id}/assignLicense` with `removeLicenses: [<sku-ids>]`
10. **Tag user with audit extension property** — `PATCH /users/{id}` setting `extension_audit_remediated_at`
11. **Final delete** — soft-delete by default (`accountEnabled=false` + tag retained); hard-delete (`DELETE /users/{id}`) is opt-in via `--hard-delete`

## Required Permissions

| Component | Identity | Key Permissions |
|-----------|----------|-----------------|
| Function 1 (Parser) | `iam-departures-azure-parser-msi` | `User.Read.All`, `Directory.Read.All`, Blob Storage `Reader` on the manifest container |
| Function 2 (Worker) | `iam-departures-azure-worker-msi` | `User.ReadWrite.All`, `Group.ReadWrite.All`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `User.ManageIdentities.All`; Azure RBAC `User Access Administrator` at the **management-group** scope |
| Logic App | `iam-departures-azure-logicapp-msi` | `Microsoft.Web/sites/functions/action` on both Functions |
| EventGrid Subscription | system topic | `Microsoft.EventGrid/eventSubscriptions/write` on the manifest storage account |
| Cosmos DB Audit | account-level RBAC | `Cosmos DB Built-in Data Contributor` for the worker MSI on the `audit` container only |
| Blob Audit | container-level RBAC | `Storage Blob Data Contributor` for the worker MSI on the `audit/` prefix only |
| Key Vault CMK | `iam-departures-azure-kv-msi` | `wrapKey`, `unwrapKey` on the storage CMK; `Get` for the Function App MSIs |

The cross-subscription role lives at **management-group scope** (NOT subscription wildcard) so it cannot escape the tenant. See [`infra/iam_policies/cross_subscription_role.json`](infra/iam_policies/cross_subscription_role.json).

## Run

```bash
# Dry-run (default)
python skills/remediation/iam-departures-azure-entra/src/function_parser/handler.py \
  examples/manifest.json

# Apply (after out-of-band approval) — soft-delete only
export IAM_DEPARTURES_AZURE_INCIDENT_ID=INC-2026-04-20-001
export IAM_DEPARTURES_AZURE_APPROVER=alice@security
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export IAM_DEPARTURES_AZURE_AUDIT_COSMOS_ACCOUNT=acme-iam-departures
export IAM_DEPARTURES_AZURE_AUDIT_COSMOS_DATABASE=audit
export IAM_DEPARTURES_AZURE_AUDIT_COSMOS_CONTAINER=actions
export IAM_DEPARTURES_AZURE_AUDIT_BLOB_ACCOUNT=acmeiamdeparturesaudit
export IAM_DEPARTURES_AZURE_AUDIT_BLOB_CONTAINER=audit
export IAM_DEPARTURES_AZURE_KEY_VAULT_KEY_ID=https://kv-acme-iam.vault.azure.net/keys/audit-cmk/...
python skills/remediation/iam-departures-azure-entra/src/function_worker/handler.py \
  examples/manifest.json --apply

# Apply with hard-delete (opt-in, second approval recommended)
python skills/remediation/iam-departures-azure-entra/src/function_worker/handler.py \
  examples/manifest.json --apply --hard-delete

# Re-verify (read-only)
python skills/remediation/iam-departures-azure-entra/src/function_worker/handler.py \
  examples/manifest.json --reverify
```

## Project Structure

```
skills/remediation/iam-departures-azure-entra/
├── SKILL.md                       # this file
├── REFERENCES.md                  # Microsoft Graph + Azure RBAC docs
├── examples.md                    # deployment walkthrough
├── examples/manifest.json         # sample HR manifest for the parser
├── src/
│   ├── function_parser/
│   │   ├── __init__.py
│   │   └── handler.py             # Function 1: validate + filter
│   └── function_worker/
│       ├── __init__.py
│       ├── handler.py             # Function 2: orchestrate the 11-step teardown
│       └── steps.py               # the 11 individual Microsoft Graph / RBAC steps
├── infra/
│   ├── arm_template.json          # full Azure stack
│   ├── eventgrid_subscription.json # BlobCreated → Logic App
│   ├── logic_app.json             # Durable orchestrator definition
│   ├── iam_policies/
│   │   ├── parser_function_role.json
│   │   ├── worker_function_role.json
│   │   └── cross_subscription_role.json
│   └── terraform/
│       ├── main.tf
│       └── terraform.tfvars.example
└── tests/                         # parser + worker + per-step tests
```

## MITRE ATT&CK Coverage

| Technique | ID | How This Skill Addresses It |
|-----------|-----|-----------------------------|
| Valid Accounts: Cloud | T1078.004 | Daily reconciliation detects + remediates departed-employee Entra users |
| Additional Cloud Creds | T1098.001 | All sign-in sessions revoked + OAuth2 grants deleted |
| Cloud Account Discovery | T1087.004 | Microsoft Graph `GET /users/{id}` validates user existence per remediation |
| Account Access Removal | T1531 | Full 11-step dependency cleanup |
| Unsecured Credentials | T1552 | Proactive cleanup within grace period |

## CIS Azure Foundations Cross-Reference

| CIS Control | Benchmark | What This Skill Remediates |
|-------------|-----------|----------------------------|
| 1.3 — Ensure that 'Users can register applications' is set to 'No' | CIS Azure v2.1 | Removes orphaned `Application.ReadWrite` consent grants |
| 1.4 — Ensure guest access is restricted | CIS Azure v2.1 | Includes guest/B2B users in the departure surface |
| 1.21 — Ensure custom subscription owner roles are not created | CIS Azure v2.1 | Detaches role assignments at subscription scope |
| 1.22 — Bypassing CA policies via "stay signed in" | CIS Azure v2.1 | `revokeSignInSessions` invalidates persistent refresh tokens |
| 5.3 — Disable/remove unused accounts | CIS Controls v8 | Full 11-step cleanup |
| 6.2 — Establish access revoking process | CIS Controls v8 | Event-driven pipeline, < 24h from termination once grace period clears |

## See also

- [`iam-departures-aws`](../iam-departures-aws/) — AWS sibling (the flagship)
- [`remediate-entra-credential-revoke`](../remediate-entra-credential-revoke/) — Entra service-principal containment (different surface; this skill targets users)
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — repo-wide HITL bar (this skill is the "Stale identity cleanup" Azure reference)
- [`SECURITY_BAR.md`](../../../SECURITY_BAR.md) — eleven-principle security contract
