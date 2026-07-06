---
name: remediate-okta-session-kill
description: >-
  Contain an Okta account takeover by revoking all active sessions and
  OAuth refresh tokens for the affected user. Consumes an OCSF 1.8
  Detection Finding (class 2004) emitted by detect-okta-mfa-fatigue or
  detect-credential-stuffing-okta and calls the Okta Users API to revoke
  sessions, revoke OAuth tokens, and optionally force password reset.
  Every action is dry-run by default, deny-listed against break-glass /
  admin / service-account principals, and dual-audited (DynamoDB +
  KMS-encrypted S3 object). Use when the user mentions "kill Okta
  session," "revoke Okta tokens after MFA fatigue," "Okta session kill,"
  "contain Okta credential stuffing," or "Okta account takeover
  response." Do NOT use for Entra / Azure AD, Google Workspace, AWS IAM,
  or GCP sessions — those have their own per-IdP remediation skills. Do
  NOT bypass the deny-list, run with --apply without an explicit
  human-approved incident window, explicit Okta org allow-list, or edit
  the audit trail by hand.
purpose: Contain an Okta account takeover by revoking all active sessions and OAuth refresh tokens for the affected user.
capability: write-identity
persistence: cloud_state
telemetry: stderr_jsonl
privilege_escalation: read_write
license: Apache-2.0
approval_model: human_required
execution_modes: jit, persistent
side_effects: writes-identity, writes-storage, writes-audit
input_formats: ocsf, native
output_formats: native
concurrency_safety: operator_coordinated
network_egress: "*.okta.com, *.oktapreview.com"
caller_roles: security_engineer, incident_responder
approver_roles: security_lead, incident_commander
min_approvers: 1
compatibility: >-
  Requires Python 3.11+, httpx, and boto3 (for audit writes). Okta API
  access requires an API token with "Revoke Sessions and Tokens" scope
  (see REFERENCES.md). Dry-run mode requires no cloud credentials.
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/remediation/remediate-okta-session-kill
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
    - NIST CSF 2.0
    - SOC 2
  cloud:
    - okta
---

# remediate-okta-session-kill

## What this closes

Pair skill for:

- [`detect-okta-mfa-fatigue`](../../detection/detect-okta-mfa-fatigue/) — Okta Verify push-bombing (T1621)
- [`detect-credential-stuffing-okta`](../../detection/detect-credential-stuffing-okta/) — password spraying followed by success (T1110 / T1110.003)

Together those form the first shipped **detect → act → audit → re-verify** loop in the repo. A finding flows in (stdin OCSF 2004); this skill plans the containment (dry-run); an approver opts in with `--apply`; the Okta API calls run; the audit trail is dual-written. The same skill then runs in `--reverify` mode against the same finding to confirm the user has zero active sessions and zero OAuth refresh tokens — emitting a `remediation_verification` record (and, on DRIFT, a paired OCSF Detection Finding via the shared `_shared/remediation_verifier.py` contract) so the loop closes through the same SIEM/SOAR pipeline as every other finding.

## Attack pattern it responds to

Any Okta account takeover where the attacker has an active session or token. The standard containment is:

1. Revoke all active Okta sessions for the user → attacker is logged out
2. Revoke all OAuth refresh tokens → attacker cannot silently re-auth
3. (Optional) Expire password → force re-enrollment on next login

All three are reversible by the legitimate user authenticating and re-enrolling. Blast radius: the single target user account. No other user, no other service.

## Inputs

Reads one or more OCSF 1.8 Detection Finding (class 2004) records from stdin or a file argument. Only findings whose `metadata.product.feature.name` matches one of these producers are processed:

- `detect-okta-mfa-fatigue`
- `detect-credential-stuffing-okta`

Findings from any other producer are skipped with a `stderr` warning. This is a skill-mismatch guardrail — a prompt-injection attempt that feeds, say, an IAM-departures finding into this skill is refused by source-skill check.

From each finding, the skill extracts:

- `observables[name=user.uid]` — the Okta user to contain
- `observables[name=user.name]` — human-readable label for the audit record
- `observables[name=src.ip]` and `session.uid` — forensic context

## Guardrails (enforced in code, not just documented)

### 1. Deny-list for protected principals

Hard-coded to refuse any target matching:

- `*@okta.com` (Okta employee accounts)
- `*admin*`, `*administrator*` in email local-part (conservative — admins use the CLI)
- `service-account*`, `svc-*` (programmatic identities)
- `break-glass-*`, `emergency-*` (same deny pattern as iam-departures-aws)

Extensible via `OKTA_SESSION_KILL_DENY_LIST_FILE` env var pointing at a JSON array of additional patterns. The union is always applied.

### 2. Dry-run is the default

Without `--apply`, the skill prints the exact API calls it WOULD make (Okta user ID, endpoints, HTTP verbs) and emits a native `remediation_plan` record. Zero network egress to Okta. Exit 0.

### 3. `--apply` requires a declared incident window

The skill refuses to execute unless env var `OKTA_SESSION_KILL_INCIDENT_ID` is set to a non-empty string AND env var `OKTA_SESSION_KILL_APPROVER` is set (both checked before the first API call). The incident ID must be a valid UUID or an operator-assigned string; the approver identity is recorded in the audit trail, and enterprise wrappers should enforce membership in the `approver_roles` policy declared in frontmatter. Both values land in the audit record.

The intent: a skill invocation that lands in a SIEM alert or a naive agent loop STILL requires an operator to register an incident before writes happen. The gate sits outside the agent loop.

### 4. `--apply` requires an explicit org boundary

The current `OKTA_ORG_URL` must be present in `OKTA_SESSION_KILL_ALLOWED_ORG_URLS` before any write runs. This keeps the handler from acting against whichever Okta tenant ambient credentials happen to point at. The boundary is invocation-scoped, not target-scoped: one run talks to one Okta org.

### 5. Dual audit — before and after each API call

For every containment action (session revoke, token revoke, password expire) the skill writes:

- DynamoDB row at `<audit_table>` with hash key `(okta_user_id, action_at)`, status field updated from `planned` → `in_progress` → `success` / `failure`
- S3 evidence object at `s3://<bucket>/okta-session-kill/audit/<yyyy>/<mm>/<dd>/<user_id>/<action_at>.json` with KMS encryption

If either write fails, the skill raises BEFORE the Okta API call. No action without an audit trail.

### 6. Okta API token is fetched, not hardcoded

`OKTA_API_TOKEN_SECRETSMANAGER_ARN` points at an AWS Secrets Manager secret. The skill calls `secretsmanager:GetSecretValue` at invocation time and never persists the token to disk or stderr.

## Output contract

Emits a native `remediation_plan` (dry-run) or `remediation_action` (apply) JSON record to stdout per target:

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "remediation_action",
  "source_skill": "remediate-okta-session-kill",
  "target": {
    "provider": "Okta",
    "user_uid": "00u-target-1",
    "user_name": "alice@example.com"
  },
  "incident_id": "...",
  "approver": "...",
  "actions": [
    {"step": "revoke_sessions", "endpoint": "DELETE /api/v1/users/00u-target-1/sessions", "status": "success"},
    {"step": "revoke_oauth_tokens", "endpoint": "DELETE /api/v1/users/00u-target-1/oauth/tokens", "status": "success"}
  ],
  "audit": {
    "dynamodb_row_uid": "...",
    "s3_evidence_uri": "s3://..."
  },
  "status": "applied",
  "dry_run": false,
  "time_ms": 1776046500000
}
```

`dry_run: true` records have identical shape but `actions[].status: planned` and no `audit.*` population.

## Usage

```bash
# Dry-run (default) — prints the plan, makes zero Okta API calls
cat finding.ocsf.jsonl | python src/handler.py

# Apply — requires declared incident window
export OKTA_ORG_URL=https://example.okta.com
export OKTA_SESSION_KILL_ALLOWED_ORG_URLS=https://example.okta.com
export OKTA_API_TOKEN_SECRETSMANAGER_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:okta-api-token
export OKTA_SESSION_KILL_INCIDENT_ID=inc-2026-04-18-001
export OKTA_SESSION_KILL_APPROVER=alice@example.com
export IAM_AUDIT_DYNAMODB_TABLE=okta-session-kill-audit
export IAM_REMEDIATION_BUCKET=sec-okta-containment
export KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/...

cat finding.ocsf.jsonl | python src/handler.py --apply
```

## Do NOT use

- For Entra / Azure AD, Google Workspace, AWS IAM, or GCP session revocation — those have their own per-IdP skills (see #238, #239 for Entra and GCP)
- To bypass the deny-list of protected principals
- As a generic "log out user" button for ops workflows — this is an **incident response** skill with dual audit
- Without `OKTA_SESSION_KILL_INCIDENT_ID` set under `--apply`
- Without `OKTA_SESSION_KILL_ALLOWED_ORG_URLS` explicitly binding the invocation to the intended Okta org

## Closed-loop verification

After the containment lands, the next run of `detect-okta-mfa-fatigue` / `detect-credential-stuffing-okta` against the Okta System Log will either:

- Show a clean window for the target user (success) → emit `remediation_verified`
- Show continuing activity (the attacker re-authed) → emit `remediation_drift` finding

The drift-detection plumbing is tracked in #257. This skill only ensures the audit trail exists for that verifier to consume.

## Tests

- Dry-run emits a plan without any Okta HTTP call
- Apply requires `OKTA_SESSION_KILL_INCIDENT_ID` + approver + org allow-list — fails closed if any are missing
- Deny-list rejects admin / service-account / break-glass targets before any Okta API call
- Source-skill mismatch (finding from a non-Okta detector) is skipped with `stderr` warning
- Audit write precedes the Okta API call in the recorded order
- Mocked Okta client confirms the correct HTTP verbs and endpoints are called in the correct order
EOF
)
