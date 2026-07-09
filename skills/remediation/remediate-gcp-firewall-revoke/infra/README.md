# Infrastructure stub — `remediate-gcp-firewall-revoke`

Reference deployment skeleton for Platform/SRE operators. Handler logic lives in
[`../src/handler.py`](../src/handler.py). This directory documents the worker
runtime, dual audit wiring, and least-privilege IAM shape.

## Topology

- **Runtime:** GCP Cloud Function (2nd gen)
- **Trigger:** SOAR / MCP wrapper invoking the skill entrypoint with `dry_run=True` first
- **Audit:** DynamoDB (or provider-native fast lookup) + KMS-encrypted object evidence
- **HITL:** `--apply` requires incident + approver env vars documented below

## Required environment variables

- `GCP_FIREWALL_REVOKE_AUDIT_FIRESTORE_COLLECTION`
- `GCP_FIREWALL_REVOKE_AUDIT_GCS_BUCKET`
- `GCP_FIREWALL_REVOKE_INCIDENT_ID`
- `GCP_FIREWALL_REVOKE_APPROVER`

## Worker permissions (summary)

- `compute.firewalls.update`
- `compute.firewalls.get`

## Audit resources

| Store | Example name |
|---|---|
| Fast lookup | `gcp-firewall-revoke-audit` |
| Evidence object store | `gcp-firewall-revoke-evidence` |

## Deploy

1. Review `terraform/main.tf` variables against your security OU naming.
2. Attach `iam_policies/worker_execution_role.json` (or cloud-native equivalent).
3. Map env vars to the handler CLI — never bypass dry-run in automation.
4. Subscribe on-call to audit drift alerts; re-run `--reverify` after apply.

See also [`../SKILL.md`](../SKILL.md) and [`../REFERENCES.md`](../REFERENCES.md).
