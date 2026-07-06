---
name: remediate-entra-credential-revoke
description: >-
  Contain a Microsoft Entra credential-addition or app-role-grant escalation
  by disabling the targeted service principal (accountEnabled=false) and
  emitting a triage payload that lists the SP's current keyCredentials,
  passwordCredentials, appRoleAssignments, and oauth2PermissionGrants for
  operator selective revocation. Consumes OCSF 1.8 Detection Findings
  (class 2004) from detect-entra-credential-addition (T1098.001) or
  detect-entra-role-grant-escalation (T1098.003) via Microsoft Graph v1.0.
  Every action is dry-run by default, deny-listed against tenant-bootstrap
  and break-glass principals (display-name prefix + ENTRA_PROTECTED_OBJECT_IDS
  env list), gated behind an incident ID plus approver for --apply, bound to
  an explicit tenant allow-list via ENTRA_REVOKE_ALLOWED_TENANT_IDS, and
  dual-audited (DynamoDB + KMS-encrypted S3). Re-verify confirms the SP is
  still disabled and emits a paired OCSF Detection Finding via the shared
  remediation_verifier contract on DRIFT (the SP was re-enabled). Use when
  the user mentions "disable Entra service principal," "respond to Entra
  credential addition," "contain Entra role grant escalation," or "re-verify
  Entra SP containment." Do NOT use for full Entra user offboarding (that
  is HR-departure-shaped, see iam-departures-aws/src/lambda_worker/clouds/
  azure_entra.py for the cross-cloud HR worker), Okta containment, AWS IAM,
  or GCP. Out of scope: targeted credential keyId revocation (the detector
  does not carry the offending keyId; operator selects from the triage list)
  and tenant-wide policy changes.
purpose: Contain a Microsoft Entra credential-addition or app-role-grant escalation by disabling the targeted service principal (accountEnabled=false) and emitting a triage payload that lists the SP's current keyCredentials, p...
capability: write-identity
persistence: cloud_state
telemetry: stderr_jsonl
privilege_escalation: read_write
license: Apache-2.0
approval_model: human_required
execution_modes: jit, ci, mcp, persistent
side_effects: writes-identity, writes-storage, writes-audit
input_formats: ocsf, native
output_formats: native
concurrency_safety: operator_coordinated
network_egress: graph.microsoft.com, login.microsoftonline.com, s3.amazonaws.com, dynamodb.amazonaws.com
caller_roles: security_engineer, incident_responder
approver_roles: security_lead, incident_commander
min_approvers: 1
compatibility: >-
  Requires Python 3.11+, msgraph-sdk + azure-identity (lazy-imported only
  under --apply / --reverify), and boto3 for audit writes. Microsoft Graph
  permissions required: Application.ReadWrite.All + Directory.Read.All
  (Application). Entra ID role: Application Administrator (or Privileged
  Role Administrator if any target SPs hold privileged roles).
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/remediation/remediate-entra-credential-revoke
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
    - NIST CSF 2.0
    - SOC 2
    - CIS Azure v2.1
  cloud:
    - azure
    - entra
---

# remediate-entra-credential-revoke

## What this closes

Pair skill for both shipped Entra detectors:

- [`detect-entra-credential-addition`](../../detection/detect-entra-credential-addition/) — T1098.001 Additional Cloud Credentials (an attacker added a new key/password credential to a service principal or application)
- [`detect-entra-role-grant-escalation`](../../detection/detect-entra-role-grant-escalation/) — T1098.003 Additional Cloud Roles (an attacker escalated an SP's app-role assignments)

Closes [#155](https://github.com/msaad00/cloud-ai-security-skills/issues/155) phase 3 + the detection-side of [#238](https://github.com/msaad00/cloud-ai-security-skills/issues/238). After this lands, the closed-loop matrix flips both Entra detection rows from amber → green. Ratio goes 5/11 → **7/11**.

## Why disable + triage (not auto-revoke)

The two Entra detectors fire on Graph audit log entries. They know:
- WHICH service principal was modified (`target.uid`)
- WHEN (`time`)
- WHAT operation (`api.operation`, e.g. `Update application -- Certificates and secrets management`)

They do NOT know:
- The specific `keyCredentials[].keyId` of the new credential
- The specific `appRoleAssignments[].id` of the new assignment

Auto-revoke without that pointer would either over-block (revoke ALL credentials, breaking legitimate ones) or guess. **Disable-then-triage** gives the operator immediate containment AND the full state needed to make a correct revocation choice — preserving forensic context.

## Inputs

Reads OCSF 1.8 Detection Finding (class 2004) JSONL from stdin or a file argument. Required observables:

- `target.uid` — the service principal / application objectId (REQUIRED; missing emits `skipped_no_target_pointer`)
- `target.name` — display name (audit context + protected-name deny-list match)
- `target.type` — must be `ServicePrincipal` or `Application` (others emit `skipped_unsupported_target_type`)
- `actor.name`, `api.operation`, `rule` — audit context

## Outputs

JSONL records on stdout:

- `remediation_plan` — under dry-run (default); shows the disable PATCH + triage GET that would be performed
- `remediation_action` — under `--apply`; carries `audit.row_uid` + `audit.s3_evidence_uri` + the full triage payload (`key_credentials`, `password_credentials`, `app_role_assignments`, `oauth2_permission_grants`)
- `remediation_verification` — under `--reverify`; reports VERIFIED / DRIFT / UNREACHABLE per `_shared/remediation_verifier.py`
- **OCSF Detection Finding 2004** — additionally emitted on DRIFT (SP was re-enabled) so the gap flows back through the SIEM/SOAR pipeline

## Guardrails (enforced in code)

| Layer | Mechanism |
|---|---|
| Source check | `ACCEPTED_PRODUCERS = {"detect-entra-credential-addition", "detect-entra-role-grant-escalation"}` |
| Protected-name deny-list | display-name prefixes `break-glass`, `emergency`, `tenant-`, `directory-`, `ms-`, `microsoft-` refuse disable |
| Protected-objectId deny-list | comma-separated `ENTRA_PROTECTED_OBJECT_IDS` env var — match by exact objectId (use this for tenant-specific bootstrap SPs that don't follow the prefix convention) |
| Target-type filter | only `ServicePrincipal` and `Application` accepted; other Graph types are out of scope |
| Apply gate | `--apply` requires `ENTRA_REVOKE_INCIDENT_ID` + `ENTRA_REVOKE_APPROVER` env vars set out-of-band |
| Tenant boundary | `--apply` also requires `AZURE_TENANT_ID` and `ENTRA_REVOKE_ALLOWED_TENANT_IDS`; the active tenant must be listed explicitly before Graph writes proceed |
| Audit | Dual write (DynamoDB + KMS-encrypted S3) BEFORE and AFTER each Graph call; failure paths still write the failure audit row |
| Re-verify | Reads the SP via `GET /servicePrincipals/{id}`; emits VERIFIED if `accountEnabled=false`, DRIFT (+ paired OCSF finding) if re-enabled, UNREACHABLE if Graph throws — never silently downgrades |

## Run

```bash
# Dry-run plan (default) — no Graph egress
python skills/remediation/remediate-entra-credential-revoke/src/handler.py findings.ocsf.jsonl

# Apply (after out-of-band approval)
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export ENTRA_REVOKE_INCIDENT_ID=INC-2026-04-19-003
export ENTRA_REVOKE_APPROVER=alice@security
export ENTRA_REVOKE_ALLOWED_TENANT_IDS=...
export ENTRA_REVOKE_AUDIT_DYNAMODB_TABLE=entra-revoke-audit
export ENTRA_REVOKE_AUDIT_BUCKET=acme-entra-audit
export KMS_KEY_ARN=arn:aws:kms:us-east-1:111122223333:key/...
# Optional: pin tenant-specific bootstrap SPs that don't match the name-prefix deny-list
export ENTRA_PROTECTED_OBJECT_IDS=00000000-0000-0000-0000-000000000001,...
python skills/remediation/remediate-entra-credential-revoke/src/handler.py findings.ocsf.jsonl --apply

# Re-verify (read-only)
python skills/remediation/remediate-entra-credential-revoke/src/handler.py findings.ocsf.jsonl --reverify
```

## Microsoft Graph permissions required

Application permissions (consented at the tenant level):
- `Application.ReadWrite.All` — disable + read credentials/assignments
- `Directory.Read.All` — resolve target.uid → object metadata

Entra ID role: **Application Administrator** (or **Privileged Role Administrator** if any target SPs hold privileged roles).

## Non-goals

- Targeted credential `keyId` revocation — the detector does not carry the offending keyId. Operator selects from the triage list and revokes via Graph manually (or via a future `remediate-entra-keycredential-revoke` skill if a detector emits the keyId).
- Tenant-wide policy changes (Conditional Access, sign-in risk policies) — out of scope; this skill operates on one SP at a time.
- HR-departure offboarding (delete user across all systems) — that is shaped by `iam-departures-aws/src/lambda_worker/clouds/azure_entra.py`. Different workflow, different audit destination.

## See also

- [`remediate-okta-session-kill`](../remediate-okta-session-kill/), [`remediate-container-escape-k8s`](../remediate-container-escape-k8s/), [`remediate-k8s-rbac-revoke`](../remediate-k8s-rbac-revoke/), [`remediate-mcp-tool-quarantine`](../remediate-mcp-tool-quarantine/) — sibling closed-loop remediation skills
- [`detect-entra-credential-addition`](../../detection/detect-entra-credential-addition/) and [`detect-entra-role-grant-escalation`](../../detection/detect-entra-role-grant-escalation/) — source detectors
- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — verification contract this skill emits via
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — repo-wide HITL bar
