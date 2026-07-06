---
name: remediate-gcp-firewall-revoke
description: >-
  Use when a GCP VPC firewall rule has been flagged as opening 0.0.0.0/0
  or ::/0 to risky admin / DB / cache ports and you need to contain it.
  Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by
  detect-gcp-open-firewall (T1190 Exploit Public-Facing Application) and
  surgically disables the offending firewall rule via Compute Engine
  `firewalls.patch` (default safe action: `disabled: true`) or, opt-in
  via `--mode delete`, removes it via `firewalls.delete`. Every action
  is dry-run by default, deny-listed against rule names matching
  `default-*`, rules whose `description` contains `intentionally-open`,
  and any rule name in GCP_FIREWALL_REVOKE_DENY_RULE_NAMES. Apply
  requires GCP_FIREWALL_REVOKE_INCIDENT_ID + GCP_FIREWALL_REVOKE_APPROVER
  plus an explicit allowed-project binding via
  GCP_FIREWALL_REVOKE_ALLOWED_PROJECT_IDS.
  Dual audit (DynamoDB + KMS-encrypted S3, same shared infra as the AWS
  pair, with `provider: "gcp"`). Reverify re-reads the rule via
  `firewalls.get` and emits VERIFIED if the rule is gone or remains
  disabled, DRIFT (+ paired OCSF Detection Finding via the shared
  remediation_verifier contract) if it re-appears or is re-enabled,
  UNREACHABLE if the Compute API throws. Do NOT use to mass-delete
  firewall rules, for AWS Security Groups (use remediate-aws-sg-revoke),
  for Azure Network Security Groups (separate skill planned), to bypass
  the deny-list, or to operate on rules outside the project the caller
  has authenticated to.
purpose: "Use when a GCP VPC firewall rule has been flagged as opening 0.0.0.0/0 or ::/0 to risky admin / DB / cache ports and you need to contain it. Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by detect-gcp-op..."
capability: write-cloud
persistence: cloud_state
telemetry: stderr_jsonl
privilege_escalation: read_write
license: Apache-2.0
approval_model: human_required
execution_modes: jit, ci, mcp, persistent
side_effects: writes-cloud, writes-storage, writes-audit
input_formats: ocsf, native
output_formats: native
concurrency_safety: operator_coordinated
network_egress: compute.googleapis.com, s3.amazonaws.com, dynamodb.amazonaws.com
caller_roles: security_engineer, incident_responder, platform_engineer
approver_roles: security_lead, incident_commander, platform_owner
min_approvers: 1
compatibility: >-
  Requires Python 3.11+, google-api-python-client (lazy-imported only
  under --apply / --reverify) and boto3 for the shared dual-audit sink.
  GCP permissions: compute.firewalls.get + compute.firewalls.patch (and
  compute.firewalls.delete only when --mode delete is used) on the
  target project. The skill runs under whatever GCP credentials the
  caller's environment provides; cross-project orchestration belongs in
  the runner layer.
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/remediation/remediate-gcp-firewall-revoke
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
    - NIST CSF 2.0
    - SOC 2
    - CIS GCP Foundations
  cloud:
    - gcp
---

# remediate-gcp-firewall-revoke

## What this closes

Pair skill for [`detect-gcp-open-firewall`](../../detection/detect-gcp-open-firewall/) (MITRE ATT&CK T1190 — Exploit Public-Facing Application).

This is the GCP counterpart to [`remediate-aws-sg-revoke`](../remediate-aws-sg-revoke/). Together with the detector, GCP firewall public exposure becomes a closed loop: detect → contain → audit → re-verify.

## Why disable-by-default (not delete)

GCP firewall rules are project-scoped, named, and frequently referenced by
infrastructure-as-code, attached service descriptions, and operator playbooks.
Deleting a rule by name is a destructive change that loses history and breaks
references. The default action is `firewalls.patch` with `disabled: true`,
which immediately stops the rule from granting traffic but preserves the
object for forensics and rollback. Use `--mode delete` only when the operator
explicitly accepts that loss of history.

## Inputs

OCSF 1.8 Detection Finding (class 2004) from `detect-gcp-open-firewall`. Required observables:

- `target.uid` — the firewall rule name (REQUIRED)
- `target.name` — same as `target.uid` for GCP
- `account.uid` — the GCP project id (REQUIRED for audit context)
- `permission.cidr[]`, `permission.port[]` — what the offending grant covers
- `actor.name`, `rule` — audit context

## Do NOT use

- To mass-delete firewall rules (this skill is finding-driven and one-rule-at-a-time)
- For AWS Security Groups (use `remediate-aws-sg-revoke`)
- For Azure Network Security Groups (separate skill planned)
- To bypass the deny-list, run `--apply` without an explicit human-approved incident window, or edit the audit trail by hand
- For audit/discovery — this skill writes; for inventory use `discover-environment`
- For rules outside the project the caller has authenticated to

## Guardrails (enforced in code)

| Layer | Mechanism |
|---|---|
| Source check | `ACCEPTED_PRODUCERS = {"detect-gcp-open-firewall"}` |
| Default-rule protection | rule names beginning with `default-` (the GCP project default firewalls) refuse revoke |
| Intentionally-open description | rules whose `description` contains `intentionally-open` refuse revoke; description is logged in the audit row |
| Operator allowlist | `GCP_FIREWALL_REVOKE_DENY_RULE_NAMES` env var (comma-separated rule names) refuses revoke |
| Apply gate | `--apply` requires `GCP_FIREWALL_REVOKE_INCIDENT_ID` + `GCP_FIREWALL_REVOKE_APPROVER` set out-of-band |
| Project boundary | `--apply` also requires `GCP_FIREWALL_REVOKE_ALLOWED_PROJECT_IDS`, and the finding's `account.uid` project must be listed there |
| Mode gate | `--mode patch` (default, sets `disabled: true`) is non-destructive; `--mode delete` is opt-in and dual-logged |
| Audit | Dual write (DynamoDB + KMS-encrypted S3) BEFORE and AFTER the patch/delete; failure paths still write the failure audit row |
| Re-verify | Re-reads the rule via `firewalls.get`; emits VERIFIED if absent or `disabled: true`, DRIFT (+ paired OCSF finding) if re-enabled or re-created, UNREACHABLE if API throws — never silently downgrades |

## Run

```bash
# Dry-run plan (default)
python skills/remediation/remediate-gcp-firewall-revoke/src/handler.py findings.ocsf.jsonl

# Apply (default mode = patch with disabled: true)
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
export GCP_FIREWALL_REVOKE_INCIDENT_ID=INC-2026-04-19-006
export GCP_FIREWALL_REVOKE_APPROVER=alice@security
export GCP_FIREWALL_REVOKE_ALLOWED_PROJECT_IDS=my-prod-project
export GCP_FIREWALL_REVOKE_AUDIT_DYNAMODB_TABLE=gcp-firewall-revoke-audit
export GCP_FIREWALL_REVOKE_AUDIT_BUCKET=acme-gcp-firewall-audit
export KMS_KEY_ARN=arn:aws:kms:us-east-1:111122223333:key/...
# Optional: pin rule names that should never be auto-revoked
export GCP_FIREWALL_REVOKE_DENY_RULE_NAMES=allow-ops-bastion,allow-internal-lb
python skills/remediation/remediate-gcp-firewall-revoke/src/handler.py findings.ocsf.jsonl --apply

# Apply with delete (opt-in, more destructive)
python skills/remediation/remediate-gcp-firewall-revoke/src/handler.py findings.ocsf.jsonl --apply --mode delete

# Re-verify (read-only)
python skills/remediation/remediate-gcp-firewall-revoke/src/handler.py findings.ocsf.jsonl --reverify
```

## Required GCP IAM

The execution principal needs these Compute Engine permissions on the target project:

- `compute.firewalls.get` — for re-verify and pre-check
- `compute.firewalls.patch` — for default `--mode patch` (set `disabled: true`)
- `compute.firewalls.delete` — only when `--mode delete` is used

These are all included in the predefined role `roles/compute.securityAdmin`. A
least-privilege custom role with just the three permissions above is the
recommended path.

## Non-goals

- Deleting all firewall rules in a project (one-rule-at-a-time, finding-driven)
- Tag-based discovery of rules to revoke (this skill is finding-driven)
- Cross-project auto-revoke (the skill now fails closed unless the target project is named explicitly in `GCP_FIREWALL_REVOKE_ALLOWED_PROJECT_IDS`)
- Posture-at-rest scanning (use `cspm-gcp-cis-benchmark`)

## See also

- [`detect-gcp-open-firewall`](../../detection/detect-gcp-open-firewall/) — paired source detector
- [`remediate-aws-sg-revoke`](../remediate-aws-sg-revoke/) — AWS counterpart
- [`remediate-okta-session-kill`](../remediate-okta-session-kill/), [`remediate-k8s-rbac-revoke`](../remediate-k8s-rbac-revoke/), [`remediate-entra-credential-revoke`](../remediate-entra-credential-revoke/) — sibling closed-loop remediation skills
- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — verification contract
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — repo-wide HITL bar
