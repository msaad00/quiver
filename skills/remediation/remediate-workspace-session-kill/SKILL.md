---
name: remediate-workspace-session-kill
description: >-
  Contain a Google Workspace account takeover by signing the user out and
  forcing a password change at next login. Consumes an OCSF 1.8 Detection
  Finding (class 2004) emitted by detect-google-workspace-suspicious-login
  (T1110 Brute Force / T1078 Valid Accounts) and calls the Admin SDK
  Directory API to invalidate active session tokens (POST /users/{userKey}
  /signOut) and require re-authentication on next sign-in (PATCH
  /users/{userKey} with changePasswordAtNextLogin=true). Every action is
  dry-run by default, deny-listed against admin / service-account /
  break-glass / @google.com principals (extensible via
  WORKSPACE_SESSION_KILL_DENY_LIST_FILE), gated behind an incident ID plus
  approver plus an explicit allowed-domain boundary for --apply, and
  dual-audited (DynamoDB + KMS-encrypted S3).
  Re-verify reads the Admin SDK Reports API for any login_success since
  remediation; emits VERIFIED if absent, DRIFT (+ paired OCSF Detection
  Finding via the shared remediation_verifier contract) if the attacker
  came back in, UNREACHABLE if the Reports API throws. Use when the user
  mentions "kill Workspace session," "respond to Google Workspace
  suspicious login," "contain Workspace account takeover," "Workspace
  session kill," or "re-verify Workspace session containment." Do NOT
  use for Okta, Entra, AWS IAM, or GCP IAM sessions — those have their
  own per-IdP remediation skills. Do NOT bypass the deny-list, run with
  --apply without an explicit human-approved incident window, or edit
  the audit trail by hand. Out of scope: cross-Workspace federation
  (only operates on the target's home tenant), mobile-device wipe
  (separate API surface and authorization model), and group/role
  unwind (the suspicious-login finding doesn't carry that context).
purpose: Contain a Google Workspace account takeover by signing the user out and forcing a password change at next login.
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
network_egress: admin.googleapis.com, oauth2.googleapis.com, s3.amazonaws.com, dynamodb.amazonaws.com
caller_roles: security_engineer, incident_responder
approver_roles: security_lead, incident_commander
min_approvers: 1
compatibility: >-
  Requires Python 3.11+, google-api-python-client + google-auth (lazy-imported
  only under --apply / --reverify), and boto3 for audit writes. Workspace
  scopes required: admin.directory.user.security (signOut + password change)
  and admin.reports.audit.readonly (reverify). Service account with
  domain-wide delegation OR a delegated admin user with User Management role.
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/remediation/remediate-workspace-session-kill
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
    - NIST CSF 2.0
    - SOC 2
  cloud:
    - google-workspace
---

# remediate-workspace-session-kill

## What this closes

Pair skill for [`detect-google-workspace-suspicious-login`](../../detection/detect-google-workspace-suspicious-login/) — provider-marked suspicious Workspace login or repeated failures followed by success (MITRE ATT&CK T1110 Brute Force + T1078 Valid Accounts).

Closes [#155](https://github.com/msaad00/cloud-ai-security-skills/issues/155) phase 4 (tracking issue: [#312](https://github.com/msaad00/cloud-ai-security-skills/issues/312)). After this lands, the closed-loop coverage matrix flips the Workspace row red→green. Ratio goes 7/11 → **8/11**.

## Why sign-out + force-password-change (not user.suspend)

Suspending the user breaks legitimate work for the legitimate owner. **Sign-out + force-password-change** is the standard Workspace account-takeover containment:

- Kills the attacker's existing session tokens immediately (revokes web/mobile auth)
- Requires the legitimate user to re-authenticate before regaining access
- Recovery path is owned by the user (password reset via recovery phone/email or admin assist)

Same containment philosophy as `remediate-okta-session-kill`.

## Inputs

Reads OCSF 1.8 Detection Finding (class 2004) JSONL from stdin or a file argument. Required observables:

- `user.uid` — the Workspace userKey (REQUIRED; missing emits `skipped_no_user_pointer`)
- `user.name` — human-readable label for audit context
- `src.ip[]` — source IPs preserved in audit (forensic context)
- `session.uid[]` — session UIDs preserved in audit (forensic context)

Findings whose `metadata.product.feature.name` is not in `ACCEPTED_PRODUCERS` are logged and skipped.

## Outputs

JSONL records on stdout:

- `remediation_plan` — under dry-run (default); shows the two Admin SDK calls that would be made
- `remediation_action` — under `--apply`; carries `audit.row_uid` + `audit.s3_evidence_uri` per step
- `remediation_verification` — under `--reverify`; reports VERIFIED / DRIFT / UNREACHABLE per `_shared/remediation_verifier.py`
- **OCSF Detection Finding 2004** — additionally emitted on DRIFT (attacker came back in) so the gap flows back through the SIEM/SOAR pipeline

## Guardrails (enforced in code)

| Layer | Mechanism |
|---|---|
| Source check | `ACCEPTED_PRODUCERS = {"detect-google-workspace-suspicious-login"}` |
| Protected-principal deny-list | `@google.com`, `admin`, `administrator`, `service-account`, `svc-`, `break-glass`, `emergency`, `root` (substring match on `user_uid + " " + user_name`); extensible via `WORKSPACE_SESSION_KILL_DENY_LIST_FILE` JSON array |
| Apply gate | `--apply` requires `WORKSPACE_SESSION_KILL_INCIDENT_ID` + `WORKSPACE_SESSION_KILL_APPROVER` env vars set out-of-band |
| Tenant boundary | `--apply` requires `WORKSPACE_SESSION_KILL_ALLOWED_DOMAINS`; target `user.uid` domain must be in the allow-list, and the delegated admin email must belong to one of those domains when provided |
| Audit | Dual write (DynamoDB + KMS-encrypted S3) BEFORE and AFTER each Admin SDK call; failure paths still write the failure audit row |
| Re-verify | Reads Admin SDK Reports API for any `login_success` since `remediated_at`; emits VERIFIED if 0, DRIFT (+ paired OCSF finding) if any, UNREACHABLE if API throws — never silently downgrades |

## Run

```bash
# Dry-run plan (default) — no Admin SDK calls
python skills/remediation/remediate-workspace-session-kill/src/handler.py findings.ocsf.jsonl

# Apply (after out-of-band approval)
export WORKSPACE_DELEGATED_ADMIN_EMAIL=admin@yourdomain.com
export WORKSPACE_SESSION_KILL_ALLOWED_DOMAINS=yourdomain.com
export WORKSPACE_SA_KEY_JSON='{...}'  # JSON-encoded service-account key (fetch from secrets manager)
export WORKSPACE_SESSION_KILL_INCIDENT_ID=INC-2026-04-19-004
export WORKSPACE_SESSION_KILL_APPROVER=alice@security
export WORKSPACE_SESSION_KILL_AUDIT_DYNAMODB_TABLE=workspace-session-kill-audit
export WORKSPACE_SESSION_KILL_AUDIT_BUCKET=acme-workspace-audit
export KMS_KEY_ARN=arn:aws:kms:us-east-1:111122223333:key/...
python skills/remediation/remediate-workspace-session-kill/src/handler.py findings.ocsf.jsonl --apply

# Re-verify (read-only)
python skills/remediation/remediate-workspace-session-kill/src/handler.py findings.ocsf.jsonl --reverify
```

## Required Workspace permissions

- Admin SDK Directory scope: `https://www.googleapis.com/auth/admin.directory.user.security`
- Admin SDK Reports scope (reverify only): `https://www.googleapis.com/auth/admin.reports.audit.readonly`
- A service account with **domain-wide delegation** OR a delegated admin user with the **User Management** admin role

## Do NOT use

- For Okta, Entra, AWS IAM, or GCP IAM sessions — those have their own per-IdP remediation skills
- To bypass the deny-list, run with `--apply` without an explicit human-approved incident window and allowed-domain boundary, or edit the audit trail by hand
- For full HR-departure offboarding (delete user across all systems) — that is shaped by the IAM-departures workflow

## Non-goals

- User suspend/disable (the legitimate user owner still needs to log in to recover)
- Cross-Workspace federation (operates on the target's home tenant only)
- Mobile device wipe (separate Workspace API surface, distinct authorization model)
- Group/role unwind (the suspicious-login finding doesn't carry that context)
- OAuth token revocation for third-party apps (separate Token API; can be added if a future detector emits the token id)

## See also

- [`remediate-okta-session-kill`](../remediate-okta-session-kill/) — sibling shape (same dual-step containment philosophy, different IdP surface)
- [`remediate-entra-credential-revoke`](../remediate-entra-credential-revoke/), [`remediate-mcp-tool-quarantine`](../remediate-mcp-tool-quarantine/), [`remediate-k8s-rbac-revoke`](../remediate-k8s-rbac-revoke/), [`remediate-container-escape-k8s`](../remediate-container-escape-k8s/) — sibling closed-loop remediation skills
- [`detect-google-workspace-suspicious-login`](../../detection/detect-google-workspace-suspicious-login/) — source detector
- [`ingest-google-workspace-login-ocsf`](../../ingestion/ingest-google-workspace-login-ocsf/) — ingestion sibling, shared API surface
- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — verification contract
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — repo-wide HITL bar
