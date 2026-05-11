---
name: remediate-azure-nsg-revoke
description: >-
  Use when the user mentions "revoke open Azure NSG rule," "close Azure
  NSG public exposure," "respond to detect-azure-open-nsg," or "re-verify
  Azure NSG revoke." Surgical revoke of an Azure Network Security Group
  inbound rule flagged as open to `*` / `Internet` / `0.0.0.0/0` / `::/0`
  by detect-azure-open-nsg (T1190 Exploit Public-Facing Application).
  Default mode is `delete` — calls
  `NetworkManagementClient.security_rules.begin_delete()` against the
  specific rule (the cleanest reversible op since NSG rule definitions
  are versioned by Azure Resource Manager). Opt-in `--mode patch`
  rewrites `access: Deny` for the same priority+source+destination tuple
  via `begin_create_or_update()`. Every action is dry-run by default,
  deny-listed against `default*`/`Default*` rule names, NSG names ending
  `-protected`, the parent NSG's `intentionally-open` tag, and any
  rule-fully-qualified-id in AZURE_NSG_REVOKE_DENY_RULE_IDS. Apply
  requires AZURE_NSG_REVOKE_INCIDENT_ID + AZURE_NSG_REVOKE_APPROVER
  plus an explicit allowed-subscription binding via
  AZURE_NSG_REVOKE_ALLOWED_SUBSCRIPTION_IDS.
  Dual audit (DynamoDB + KMS-encrypted S3). Reverify re-reads the rule
  via `security_rules.get()` and emits VERIFIED if the rule is gone (or
  patched to Deny), DRIFT (+ paired OCSF Detection Finding via the
  shared remediation_verifier contract) if the rule re-appears as
  Allow within the verification window, UNREACHABLE if the Azure API
  throws. Do NOT use to delete the entire NSG (deletes other legitimate
  rules), for AWS Security Groups (separate skill remediate-aws-sg-revoke),
  for GCP firewall (separate skill remediate-gcp-firewall-revoke), for
  Outbound NSG rules, or to bypass the deny-list.
purpose: Use when the user mentions "revoke open Azure NSG rule," "close Azure NSG public exposure," "respond to detect-azure-open-nsg," or "re-verify Azure NSG revoke." Surgical revoke of an Azure Network Security Group inbou...
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
network_egress: management.azure.com, login.microsoftonline.com, s3.amazonaws.com, dynamodb.amazonaws.com
caller_roles: security_engineer, incident_responder, platform_engineer
approver_roles: security_lead, incident_commander, platform_owner
min_approvers: 1
compatibility: >-
  Requires Python 3.11+, azure-identity + azure-mgmt-network (lazy-imported
  only under --apply / --reverify). Azure RBAC: `Network Contributor` on the
  parent NSG resource group for delete/patch; `Reader` is enough for
  --reverify. The skill runs under whatever Azure credentials
  DefaultAzureCredential resolves; cross-subscription orchestration belongs
  in the runner layer.
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/remediation/remediate-azure-nsg-revoke
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
    - NIST CSF 2.0
    - SOC 2
    - CIS Azure Foundations
  cloud:
    - azure
---

# remediate-azure-nsg-revoke

## What this closes

Pair skill for [`detect-azure-open-nsg`](../../detection/detect-azure-open-nsg/) (MITRE ATT&CK T1190 — Exploit Public-Facing Application).

This is the Azure counterpart to [`remediate-aws-sg-revoke`](../remediate-aws-sg-revoke/) and [`remediate-gcp-firewall-revoke`](../remediate-gcp-firewall-revoke/). Together with `detect-azure-open-nsg`, the Azure NSG closed loop becomes the third network-exposure response in the repo.

## Why surgical revoke (not "delete the NSG")

The parent NSG hosts other legitimate rules (HTTPS:443 on a public endpoint, intra-VNet rules, AzureLoadBalancer health probes, etc.). Deleting the NSG breaks them. The detector identifies the **specific offending rule** by its fully-qualified Azure Resource Manager id; we delete (or patch to `Deny`) only that one rule and leave the rest of the NSG intact.

## Modes

- `--mode delete` (default) — calls `network_client.security_rules.begin_delete()`. Cleanest reversible op since NSG rule definitions are versioned by Azure Resource Manager and easily re-created.
- `--mode patch` — opt-in. Calls `begin_create_or_update()` with the same priority+source+destination tuple but `access: Deny`, preserving the rule slot for forensic context.

## Inputs

OCSF 1.8 Detection Finding (class 2004) from `detect-azure-open-nsg`. Required observables:

- `target.uid` — the rule's fully-qualified Azure Resource Manager id (REQUIRED). Format: `/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/networkSecurityGroups/<nsg>/securityRules/<rule>`
- `target.name` — the rule name (used for deny-list match)
- `region`, `account.uid` (subscription id) — audit context
- `rule.source_prefix[]`, `rule.port[]` — what to revoke (REQUIRED for `--mode patch`; missing yields a skip in patch mode but `delete` only needs `target.uid`)
- `actor.name`, `rule` — audit context

## Do NOT use

- To delete the entire NSG (use the Azure portal or a separate destroy skill)
- For AWS Security Group changes (use `remediate-aws-sg-revoke`)
- For GCP firewall changes (use `remediate-gcp-firewall-revoke`)
- For Outbound NSG rules (different threat surface)
- To bypass the deny-list, run `--apply` without an explicit human-approved incident window, or edit the audit trail by hand
- For audit/discovery — this skill writes; for inventory use `discover-environment`

## Guardrails (enforced in code)

| Layer | Mechanism |
|---|---|
| Source check | `ACCEPTED_PRODUCERS = {"detect-azure-open-nsg"}` |
| Default-rule protection | Rule names matching `default*` / `Default*` (the platform-default NSG rules) refuse revoke |
| Protected-NSG name | NSG names matching `*-protected` refuse revoke |
| Intentionally-open tag | NSGs tagged `intentionally-open` refuse revoke; tag value is logged in the audit row |
| Operator allowlist | `AZURE_NSG_REVOKE_DENY_RULE_IDS` env var (comma-separated rule ids) refuses revoke |
| Apply gate | `--apply` requires `AZURE_NSG_REVOKE_INCIDENT_ID` + `AZURE_NSG_REVOKE_APPROVER` set out-of-band |
| Subscription boundary | `--apply` also requires `AZURE_NSG_REVOKE_ALLOWED_SUBSCRIPTION_IDS`, and the parsed subscription from `target.uid` must be listed there |
| Audit | Dual write (DynamoDB + KMS-encrypted S3) BEFORE and AFTER the action; failure paths still write the failure audit row |
| Re-verify | Re-reads the rule via `security_rules.get()`; emits VERIFIED if the rule is absent or patched to Deny, DRIFT (+ paired OCSF finding) if it re-appears as Allow, UNREACHABLE if the Azure API throws — never silently downgrades |

## Run

```bash
# Dry-run plan (default)
python skills/remediation/remediate-azure-nsg-revoke/src/handler.py findings.ocsf.jsonl

# Apply (after out-of-band approval)
export AZURE_NSG_REVOKE_INCIDENT_ID=INC-2026-04-20-001
export AZURE_NSG_REVOKE_APPROVER=alice@security
export AZURE_NSG_REVOKE_ALLOWED_SUBSCRIPTION_IDS=00000000-0000-0000-0000-000000000001
export AZURE_NSG_REVOKE_AUDIT_DYNAMODB_TABLE=azure-nsg-revoke-audit
export AZURE_NSG_REVOKE_AUDIT_BUCKET=acme-azure-nsg-audit
export KMS_KEY_ARN=arn:aws:kms:us-east-1:111122223333:key/...
# Optional: pin rules that should never be auto-revoked
export AZURE_NSG_REVOKE_DENY_RULE_IDS=/subscriptions/.../securityRules/r1,/subscriptions/.../securityRules/r2
python skills/remediation/remediate-azure-nsg-revoke/src/handler.py findings.ocsf.jsonl --apply

# Re-verify (read-only)
python skills/remediation/remediate-azure-nsg-revoke/src/handler.py findings.ocsf.jsonl --reverify

# Patch instead of delete
python skills/remediation/remediate-azure-nsg-revoke/src/handler.py findings.ocsf.jsonl --apply --mode patch
```

## Required Azure RBAC

The execution principal needs:

- `Network Contributor` on the parent NSG resource group (covers `Microsoft.Network/networkSecurityGroups/securityRules/delete` and `.../write`)
- `Reader` on the same scope is enough for `--reverify`

The dual-audit sink also needs the same AWS DynamoDB + S3 + KMS permissions used by the AWS / GCP siblings (the audit storage layer is unified, even though the cloud surface is Azure).

## Non-goals

- Deleting the NSG entirely
- Tag-based discovery of NSG rules to revoke (this skill is finding-driven)
- Cross-subscription auto-revoke (the skill now fails closed unless the target subscription is named explicitly in `AZURE_NSG_REVOKE_ALLOWED_SUBSCRIPTION_IDS`)
- Posture-at-rest scanning (use `cspm-azure-cis-benchmark`)

## See also

- [`detect-azure-open-nsg`](../../detection/detect-azure-open-nsg/) — paired source detector
- [`remediate-aws-sg-revoke`](../remediate-aws-sg-revoke/) — AWS sibling
- [`remediate-entra-credential-revoke`](../remediate-entra-credential-revoke/) — Azure identity-side sibling
- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — verification contract
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — repo-wide HITL bar
