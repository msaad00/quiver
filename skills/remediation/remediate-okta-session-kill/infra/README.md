# Infrastructure stub — `remediate-okta-session-kill`

Reference deployment skeleton for Platform/SRE operators. Handler logic lives in
[`../src/handler.py`](../src/handler.py). This directory documents the worker
runtime, dual audit wiring, and least-privilege IAM shape.

## Topology

- **Runtime:** AWS Lambda (VPC egress to Okta)
- **Trigger:** SOAR / MCP wrapper invoking the skill entrypoint with `dry_run=True` first
- **Audit:** DynamoDB (or provider-native fast lookup) + KMS-encrypted object evidence
- **HITL:** `--apply` requires incident + approver env vars documented below

## Required environment variables

- `OKTA_SESSION_KILL_AUDIT_DYNAMODB_TABLE`
- `OKTA_SESSION_KILL_AUDIT_S3_BUCKET`
- `OKTA_SESSION_KILL_INCIDENT_ID`
- `OKTA_SESSION_KILL_APPROVER`
- `OKTA_DOMAIN`

## Worker permissions (summary)

- `okta.sessions.clear`

## Audit resources

| Store | Example name |
|---|---|
| Fast lookup | `okta-session-kill-audit` |
| Evidence object store | `okta-session-kill-evidence` |

## Deploy

1. Review `terraform/main.tf` variables against your security OU naming.
2. Attach `iam_policies/worker_execution_role.json` (or cloud-native equivalent).
3. Map env vars to the handler CLI — never bypass dry-run in automation.
4. Subscribe on-call to audit drift alerts; re-run `--reverify` after apply.

See also [`../SKILL.md`](../SKILL.md) and [`../REFERENCES.md`](../REFERENCES.md).
