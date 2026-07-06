---
name: remediate-k8s-rbac-revoke
description: >-
  Revoke a Kubernetes RoleBinding or ClusterRoleBinding flagged by an RBAC
  self-grant finding. Consumes an OCSF 1.8 Detection Finding (class 2004)
  emitted by detect-privilege-escalation-k8s and plans, applies, or
  re-verifies deletion of the offending binding identified by the detector's
  binding.type and binding.name observables. Every action is dry-run by
  default, deny-listed for protected namespaces (kube-system, kube-public,
  istio-system, linkerd*) and protected binding names (any binding whose name
  starts with system:), gated behind an incident ID plus approver plus an
  explicit cluster allow-list for --apply, and dual-audited (DynamoDB +
  KMS-encrypted S3). Use when the user mentions
  "revoke a Kubernetes RoleBinding," "remove a ClusterRoleBinding after
  privilege escalation," "respond to RBAC self-grant alert," or "re-verify a
  K8s RBAC revocation." Do NOT use for NetworkPolicy quarantine, pod
  deletion, node drain, or cloud-IAM revocation — those belong to their own
  remediation skills. Out of scope for this skill: discovering candidate
  bindings for an actor when the detector did not identify a specific
  binding (rules r1, r2, r4 of detect-privilege-escalation-k8s, and every
  finding from detect-sensitive-secret-read-k8s); those findings emit a
  skipped_no_binding_pointer record telling the operator to triage manually.
purpose: Revoke a Kubernetes RoleBinding or ClusterRoleBinding flagged by an RBAC self-grant finding.
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
network_egress: kubernetes.default.svc, s3.amazonaws.com, dynamodb.amazonaws.com
caller_roles: security_engineer, incident_responder, platform_engineer
approver_roles: security_lead, incident_commander, platform_owner
min_approvers: 1
compatibility: >-
  Requires Python 3.11+, kubernetes, and boto3. Dry-run and re-verify still
  require read access to RoleBindings and ClusterRoleBindings in the target
  namespace or cluster. Apply requires delete permission on
  rbac.authorization.k8s.io/v1 RoleBindings and ClusterRoleBindings plus
  audit write access to DynamoDB, S3, and KMS.
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/remediation/remediate-k8s-rbac-revoke
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
    - NIST CSF 2.0
    - SOC 2
  cloud:
    - kubernetes
---

# remediate-k8s-rbac-revoke

## What this closes

Pair skill for [`detect-privilege-escalation-k8s`](../../detection/detect-privilege-escalation-k8s/) — specifically rule **`r3-rbac-self-grant`** (T1098: Account Manipulation). That rule is the only one in the detection bundle that hands the responder an unambiguous binding to revoke; the others identify an actor and an effect (token grant, pod exec, secret enum) but not a single binding the operator can safely delete.

This is the second Kubernetes **detect → act → audit → re-verify** loop in the repo, after [`remediate-container-escape-k8s`](../remediate-container-escape-k8s/). It lifts the same dual-audit, dry-run-default, deny-list, and incident-ID-gated `--apply` harness.

## Scope honesty

| Source finding | Coverage |
|---|---|
| `detect-privilege-escalation-k8s` rule `r3-rbac-self-grant` | **Direct revocation** — detector emits `binding.type` + `binding.name`; we revoke that binding |
| `detect-privilege-escalation-k8s` rules `r1-secret-enum`, `r2-pod-exec`, `r4-token-self-grant` | **Skipped with pointer** — no specific binding in the finding; we emit `skipped_no_binding_pointer` and tell the operator to triage manually |
| `detect-sensitive-secret-read-k8s` (any rule) | **Skipped with pointer** — same reason; this skill does not consume that producer at all (`ACCEPTED_PRODUCERS` enforces it) |

A future PR can add a discovery mode (`--discover-bindings-for-actor=NAME`) that lists all RoleBindings + ClusterRoleBindings whose `subjects[]` reference an actor and emits a triage manifest. Discovery mode is intentionally out of scope here because it adds a large API surface (cluster-wide LIST + filter) and needs its own design pass on least-privilege scoping.

## Inputs

Reads one or more OCSF 1.8 Detection Finding (class 2004) JSONL records from stdin or a file path. Required observables:

- `actor.name` (used for audit context only)
- `binding.type` — must be `rolebindings` or `clusterrolebindings`
- `binding.name`
- `namespace` — required for `rolebindings`; ignored for `clusterrolebindings`
- `rule` (used for audit context only)

Findings missing `binding.type` or `binding.name` are emitted as skip records with `status: skipped_no_binding_pointer`.

## Outputs

JSONL records on stdout. Three record types:

- `remediation_plan` — under dry-run (default); shows the exact `DELETE` endpoint and the deny-list outcome
- `remediation_action` — under `--apply`; carries `audit.row_uid` + `audit.s3_evidence_uri` from the dual write
- `remediation_verification` — under `--reverify`; reports `verified` (binding gone) or `drift` (binding still present)

## Guardrails (enforced in code — not just docs)

| Layer | Mechanism |
|---|---|
| Source check | `ACCEPTED_PRODUCERS = {"detect-privilege-escalation-k8s"}` — any finding from a different producer is logged and skipped |
| Protected namespaces | Default deny-list: `kube-system`, `kube-public`, `istio-system`, `linkerd*` (see `DEFAULT_DENY_NAMESPACES`); applies to `rolebindings` only (ClusterRoleBindings are namespace-less) |
| Protected binding names | Any binding whose name starts with `system:` is denied (`DEFAULT_DENY_BINDING_PREFIXES`) — keeps `system:masters`, `system:basic-user`, `system:public-info-viewer`, etc. out of revocation scope |
| Apply gate | `--apply` requires `K8S_RBAC_REVOKE_INCIDENT_ID` + `K8S_RBAC_REVOKE_APPROVER` env vars — set out-of-band by the responder, not by the agent |
| Cluster boundary | `--apply` also requires `K8S_CLUSTER_NAME` and `K8S_RBAC_REVOKE_ALLOWED_CLUSTERS`; the active cluster must be allow-listed explicitly before a delete can run |
| Audit | Dual write (DynamoDB + KMS-encrypted S3) BEFORE and AFTER the delete; failure paths still write the failure audit row |
| Re-verify | `--reverify` confirms the binding is no longer present; emits `drift` if the binding came back |

## Run

```bash
# Dry-run plan (default)
python skills/remediation/remediate-k8s-rbac-revoke/src/handler.py findings.ocsf.jsonl

# Apply (after out-of-band approval)
export K8S_RBAC_REVOKE_INCIDENT_ID=INC-2026-04-19-001
export K8S_RBAC_REVOKE_APPROVER=alice@security
export K8S_CLUSTER_NAME=prod-eks-us-east-1
export K8S_RBAC_REVOKE_ALLOWED_CLUSTERS=prod-eks-us-east-1
export K8S_REMEDIATION_AUDIT_DYNAMODB_TABLE=k8s-remediation-audit
export K8S_REMEDIATION_AUDIT_BUCKET=acme-k8s-audit
export KMS_KEY_ARN=arn:aws:kms:us-east-1:111122223333:key/...
python skills/remediation/remediate-k8s-rbac-revoke/src/handler.py findings.ocsf.jsonl --apply

# Re-verify (read-only)
python skills/remediation/remediate-k8s-rbac-revoke/src/handler.py findings.ocsf.jsonl --reverify
```

## Non-goals

- Discover bindings for an arbitrary actor (planned, separate issue)
- Edit binding subjects in place (delete-only — partial edits introduce more failure modes)
- Recreate the binding after a window — this skill is a one-way revocation
- Cross-cluster propagation — operates on a single API server target
- Acting against whichever cluster ambient kubeconfig happens to point at — `--apply` now fails closed unless the active cluster name is allow-listed explicitly

## See also

- [`remediate-container-escape-k8s`](../remediate-container-escape-k8s/) — the other K8s remediation loop (NetworkPolicy quarantine)
- [`detect-privilege-escalation-k8s`](../../detection/detect-privilege-escalation-k8s/) — the source detector
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — repo-wide HITL bar
- [`SECURITY_BAR.md`](../../../SECURITY_BAR.md) — eleven-principle contract
