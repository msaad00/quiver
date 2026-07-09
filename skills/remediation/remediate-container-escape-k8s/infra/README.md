# Infrastructure stub — `remediate-container-escape-k8s`

Reference deployment skeleton for Platform/SRE operators. Handler logic lives in
[`../src/handler.py`](../src/handler.py). This directory documents the worker
runtime, dual audit wiring, and least-privilege IAM shape.

## Topology

- **Runtime:** Kubernetes Job (node drain + forensic collector)
- **Trigger:** SOAR / MCP wrapper invoking the skill entrypoint with `dry_run=True` first
- **Audit:** DynamoDB (or provider-native fast lookup) + KMS-encrypted object evidence
- **HITL:** `--apply` requires incident + approver env vars documented below

## Required environment variables

- `K8S_CONTAINER_ESCAPE_AUDIT_DYNAMODB_TABLE`
- `K8S_CONTAINER_ESCAPE_AUDIT_S3_BUCKET`
- `K8S_CONTAINER_ESCAPE_INCIDENT_ID`
- `K8S_CONTAINER_ESCAPE_APPROVER`
- `KUBECONFIG`

## Worker permissions (summary)

- `nodes cordon/drain`
- `pods/evictions create`

## Audit resources

| Store | Example name |
|---|---|
| Fast lookup | `k8s-container-escape-audit` |
| Evidence object store | `k8s-container-escape-evidence` |

## Deploy

1. Review `terraform/main.tf` variables against your security OU naming.
2. Attach `iam_policies/worker_execution_role.json` (or cloud-native equivalent).
3. Map env vars to the handler CLI — never bypass dry-run in automation.
4. Subscribe on-call to audit drift alerts; re-run `--reverify` after apply.

See also [`../SKILL.md`](../SKILL.md) and [`../REFERENCES.md`](../REFERENCES.md).
