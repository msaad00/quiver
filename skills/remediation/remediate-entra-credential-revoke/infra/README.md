# Infrastructure stub — `remediate-entra-credential-revoke`

Reference deployment skeleton for Platform/SRE operators. Handler logic lives in
[`../src/handler.py`](../src/handler.py). This directory documents the worker
runtime, dual audit wiring, and least-privilege IAM shape.

## Topology

- **Runtime:** Azure Function
- **Trigger:** SOAR / MCP wrapper invoking the skill entrypoint with `dry_run=True` first
- **Audit:** DynamoDB (or provider-native fast lookup) + KMS-encrypted object evidence
- **HITL:** `--apply` requires incident + approver env vars documented below

## Required environment variables

- `ENTRA_CREDENTIAL_REVOKE_AUDIT_COSMOS_CONTAINER`
- `ENTRA_CREDENTIAL_REVOKE_AUDIT_BLOB_CONTAINER`
- `ENTRA_CREDENTIAL_REVOKE_INCIDENT_ID`
- `ENTRA_CREDENTIAL_REVOKE_APPROVER`

## Worker permissions (summary)

- `Microsoft Graph: DELETE /users/{id}/authentication/passwordMethods`

## Audit resources

| Store | Example name |
|---|---|
| Fast lookup | `entra-credential-revoke-audit` |
| Evidence object store | `entra-credential-revoke-evidence` |

## Deploy

1. Review `terraform/main.tf` variables against your security OU naming.
2. Attach `iam_policies/worker_execution_role.json` (or cloud-native equivalent).
3. Map env vars to the handler CLI — never bypass dry-run in automation.
4. Subscribe on-call to audit drift alerts; re-run `--reverify` after apply.

See also [`../SKILL.md`](../SKILL.md) and [`../REFERENCES.md`](../REFERENCES.md).
