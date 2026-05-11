---
name: remediate-aws-sg-revoke
description: >-
  Revoke an AWS Security Group ingress rule flagged as open to the internet.
  Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by
  detect-aws-open-security-group (T1190 Exploit Public-Facing Application)
  and calls EC2 RevokeSecurityGroupIngress to delete just the offending
  IpPermissions (the specific cidr+port combination, not the whole SG).
  Every action is dry-run by default, deny-listed against `default*` SG
  names, any SG carrying the `intentionally-open` tag, and any sg id in
  AWS_SG_REVOKE_PROTECTED_IDS. Apply requires AWS_SG_REVOKE_INCIDENT_ID +
  AWS_SG_REVOKE_APPROVER plus an explicit allowed-account binding via
  AWS_SG_REVOKE_ALLOWED_ACCOUNT_IDS. Dual audit (DynamoDB + KMS-encrypted S3). Reverify
  re-reads the SG via DescribeSecurityGroups and emits VERIFIED if no
  offending IpPermissions remain, DRIFT (+ paired OCSF Detection Finding
  via the shared remediation_verifier contract) if the rule came back,
  UNREACHABLE if the EC2 API throws. Use when the user mentions "revoke
  open security group," "close AWS SG public exposure," "respond to
  detect-aws-open-security-group," or "re-verify AWS SG revoke." Do NOT
  use to delete the whole SG (deletes other legitimate rules), for VPC
  Network ACL changes (different API surface), for GCP firewall or Azure
  NSG (separate skills per #307 phases B + C), or to bypass the deny-list.
purpose: Revoke an AWS Security Group ingress rule flagged as open to the internet.
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
network_egress: ec2.amazonaws.com, s3.amazonaws.com, dynamodb.amazonaws.com
caller_roles: security_engineer, incident_responder, platform_engineer
approver_roles: security_lead, incident_commander, platform_owner
min_approvers: 1
compatibility: >-
  Requires Python 3.11+, boto3 (lazy-imported only under --apply / --reverify).
  AWS permissions: ec2:DescribeSecurityGroups + ec2:RevokeSecurityGroupIngress
  on the target SG. The skill runs under whatever AWS profile / region the
  caller sets; cross-account orchestration belongs in the runner layer.
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/remediation/remediate-aws-sg-revoke
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
    - NIST CSF 2.0
    - SOC 2
    - CIS AWS Foundations
  cloud:
    - aws
---

# remediate-aws-sg-revoke

## What this closes

Pair skill for [`detect-aws-open-security-group`](../../detection/detect-aws-open-security-group/) (MITRE ATT&CK T1190 — Exploit Public-Facing Application).

This is **#307 phase A — remediation side**. Together with the detector this PR ships, the AWS open-SG closed loop becomes the first network-exposure response in the repo.

## Why surgical revoke (not "delete the SG")

The SG may host legitimate other rules (HTTPS:443 on a load balancer, VPC peering on private CIDRs, etc.). Deleting the SG breaks them. The detector identifies the **specific offending permission** (cidr + port observables); we revoke just those IpPermissions and leave the rest of the SG intact.

## Inputs

OCSF 1.8 Detection Finding (class 2004) from `detect-aws-open-security-group`. Required observables:

- `target.uid` — the security group id (REQUIRED)
- `target.name` — the SG name (used for deny-list match)
- `region`, `account.uid` — audit context
- `permission.cidr[]`, `permission.port[]` — what to revoke (REQUIRED for actual revocation; missing yields a skip)
- `actor.name`, `rule` — audit context

## Do NOT use

- To delete the whole SG (use the AWS console or a separate destroy skill)
- For VPC Network ACL changes (different API surface)
- For GCP firewall or Azure NSG (separate skills per #307 phases B + C)
- To bypass the deny-list, run `--apply` without an explicit human-approved incident window, or edit the audit trail by hand
- For audit/discovery — this skill writes; for inventory use `discover-environment`

## Guardrails (enforced in code)

| Layer | Mechanism |
|---|---|
| Source check | `ACCEPTED_PRODUCERS = {"detect-aws-open-security-group"}` |
| Default-SG protection | SG names starting with `default` (the AWS default SG per VPC) refuse revoke |
| Intentionally-open tag | SGs tagged `intentionally-open` (e.g. ALB on 443) refuse revoke; tag value is logged in the audit row |
| Operator allowlist | `AWS_SG_REVOKE_PROTECTED_IDS` env var (comma-separated sg ids) refuses revoke |
| Apply gate | `--apply` requires `AWS_SG_REVOKE_INCIDENT_ID` + `AWS_SG_REVOKE_APPROVER` set out-of-band |
| Account boundary | `--apply` also requires `AWS_SG_REVOKE_ALLOWED_ACCOUNT_IDS`, and the finding's `account.uid` must match both that allow-list and the caller's current STS account |
| Audit | Dual write (DynamoDB + KMS-encrypted S3) BEFORE and AFTER the revoke; failure paths still write the failure audit row |
| Re-verify | Re-reads the SG via `DescribeSecurityGroups`; emits VERIFIED if no offending permissions, DRIFT (+ paired OCSF finding) if re-added, UNREACHABLE if API throws — never silently downgrades |

## Run

```bash
# Dry-run plan (default)
python skills/remediation/remediate-aws-sg-revoke/src/handler.py findings.ocsf.jsonl

# Apply (after out-of-band approval)
export AWS_REGION=us-east-1
export AWS_PROFILE=incident-response
export AWS_SG_REVOKE_INCIDENT_ID=INC-2026-04-19-005
export AWS_SG_REVOKE_APPROVER=alice@security
export AWS_SG_REVOKE_ALLOWED_ACCOUNT_IDS=111122223333
export AWS_SG_REVOKE_AUDIT_DYNAMODB_TABLE=aws-sg-revoke-audit
export AWS_SG_REVOKE_AUDIT_BUCKET=acme-aws-sg-audit
export KMS_KEY_ARN=arn:aws:kms:us-east-1:111122223333:key/...
# Optional: pin SGs that should never be auto-revoked
export AWS_SG_REVOKE_PROTECTED_IDS=sg-0aaa,sg-0bbb
python skills/remediation/remediate-aws-sg-revoke/src/handler.py findings.ocsf.jsonl --apply

# Re-verify (read-only)
python skills/remediation/remediate-aws-sg-revoke/src/handler.py findings.ocsf.jsonl --reverify
```

## Required AWS IAM

The execution role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["ec2:DescribeSecurityGroups", "ec2:RevokeSecurityGroupIngress"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": "arn:aws:dynamodb:*:*:table/aws-sg-revoke-audit"},
    {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "arn:aws:s3:::acme-aws-sg-audit/*"},
    {"Effect": "Allow", "Action": ["kms:Encrypt", "kms:GenerateDataKey"], "Resource": "<your KMS key arn>"}
  ]
}
```

`*` on `ec2:` actions is justified because security groups have no resource-level permission boundary in AWS IAM (per the [AWS Resource Permissions docs](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html)). The deny-list (default-SG, intentionally-open tag, sg-id allowlist) provides the operational boundary.

## Non-goals

- Deleting the SG entirely
- Tag-based discovery of SGs to revoke (this skill is finding-driven)
- Cross-account auto-revoke (the skill now fails closed unless the target account is named explicitly and matches the caller's current STS account)
- Posture-at-rest scanning (use `cspm-aws-cis-benchmark`)

## See also

- [`detect-aws-open-security-group`](../../detection/detect-aws-open-security-group/) — paired source detector
- [`remediate-okta-session-kill`](../remediate-okta-session-kill/), [`remediate-k8s-rbac-revoke`](../remediate-k8s-rbac-revoke/), [`remediate-entra-credential-revoke`](../remediate-entra-credential-revoke/) — sibling closed-loop remediation skills
- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — verification contract
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — repo-wide HITL bar
- [#307](https://github.com/msaad00/cloud-ai-security-skills/issues/307) — network-exposure response umbrella (this is phase A)
