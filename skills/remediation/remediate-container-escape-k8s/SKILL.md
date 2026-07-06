---
name: remediate-container-escape-k8s
description: >-
  Contain a Kubernetes container-escape signal by planning, applying, or
  re-verifying a namespace-scoped deny-all NetworkPolicy for the targeted pod
  or workload selector. Consumes an OCSF 1.8 Detection Finding (class 2004)
  emitted by detect-container-escape-k8s and resolves the live selector from
  the Kubernetes API before emitting a native remediation plan or action
  record. Every action is dry-run by default, deny-listed for protected
  namespaces, gated behind an incident ID plus approver plus an explicit
  cluster allow-list for --apply, and dual-audited (DynamoDB +
  KMS-encrypted S3). The low-risk default remains
  reversible quarantine; explicit destructive follow-ups are also supported
  via `--approve-pod-kill` and `--approve-node-drain`, with the node-drain
  path requiring a second approver. Use when the user mentions "quarantine a
  suspicious Kubernetes pod," "contain container escape in Kubernetes,"
  "apply deny-all NetworkPolicy after escape finding," "re-verify K8s
  quarantine policy," "kill the compromised pod," "drain the affected node,"
  or "collect K8s container-escape forensics."
purpose: Contain a Kubernetes container-escape signal by planning, applying, or re-verifying a namespace-scoped deny-all NetworkPolicy for the targeted pod or workload selector.
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
  require read access to pods/workloads and NetworkPolicies in the target
  namespace so the selector can be resolved and checked. Apply requires create
  or replace permission for networking.k8s.io/v1 NetworkPolicies plus audit
  write access to DynamoDB, S3, and KMS.
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/remediation/remediate-container-escape-k8s
  version: 0.1.0
  frameworks:
    - MITRE ATT&CK v14
    - NIST CSF 2.0
    - SOC 2
  cloud:
    - kubernetes
---

# remediate-container-escape-k8s

## What this closes

Pair skill for [`detect-container-escape-k8s`](../../detection/detect-container-escape-k8s/).

This is the first Kubernetes **detect → act → audit → re-verify** loop in the
repo. A container-escape finding flows in from stdin or a file; this skill
resolves the live pod or workload selector from the cluster; dry-run prints the
exact deny-all `NetworkPolicy` manifest that would be applied; `--apply` writes
the policy after an out-of-band approval gate; `--reverify` proves the
quarantine policy is still present and still shaped as expected.

## Attack pattern it responds to

`detect-container-escape-k8s` emits findings for:

1. risky spec patches that enable `privileged`, `hostPID`, `hostNetwork`, or
   high-risk Linux capabilities (`T1611`)
2. risky `hostPath` injections to host-sensitive paths like `/proc` or
   `/var/lib/containerd` (`T1611`)
3. ephemeral container creation through `pods/ephemeralcontainers` or
   `kubectl debug` (`T1610`)

The least-destructive first response is to isolate the affected workload from
the network while preserving the pod for human investigation. This skill does
that with a namespace-scoped deny-all `NetworkPolicy` matched to the target
pod's labels or the workload selector. Once quarantine lands, the same skill
can also build a deterministic forensic bundle from host-mounted `/proc`,
runtime logs, and optional CSI `VolumeSnapshot` references.

## Inputs

Reads one or more OCSF 1.8 Detection Finding (class 2004) or repo-native
`detection_finding` records from stdin or a file argument. Only findings whose
`metadata.product.feature.name` is `detect-container-escape-k8s` are processed.

From each finding, the skill extracts:

- `observables[name=namespace]`
- `observables[name=resource.type]`
- `observables[name=resource.name]`
- `observables[name=pod.name]` when present
- `target` as a fallback encoded path like `deployments/payments/api` or
  `pods/payments/api-7d9b/ephemeralcontainers`

The skill then resolves the live selector from the cluster:

- pod finding → current pod labels
- workload finding → workload selector or pod-template labels

Dry-run therefore still performs read-only Kubernetes API calls.

## Guardrails (enforced in code, not just documented)

### 1. Source-skill lock

Only `detect-container-escape-k8s` findings are accepted. Any other producer is
skipped with a `stderr` warning. This blocks prompt-injection or operator error
from feeding an unrelated finding into a Kubernetes write path.

### 2. Protected namespace deny-list

The skill refuses to plan or apply quarantine for these protected namespaces:

- `kube-system`
- `kube-public`
- `istio-system`
- anything starting with `linkerd` or `linkerd-`

Dry-run returns `would-violate-deny-list`; apply returns
`skipped_deny_list`. The protected-namespace check fires before any policy
write or audit write.

### 3. Dry-run is the default

Without `--apply`, the skill emits a native `remediation_plan` record
containing the exact `NetworkPolicy` manifest, the resolved selector, and the
mutating Kubernetes endpoint it WOULD call. Zero cluster writes occur in this
mode.

### 4. `--apply` requires an incident gate and explicit cluster boundary

`--apply` is refused unless both env vars are set before any write:

- `K8S_CONTAINER_ESCAPE_INCIDENT_ID`
- `K8S_CONTAINER_ESCAPE_APPROVER`
- `K8S_CLUSTER_NAME`
- `K8S_CONTAINER_ESCAPE_ALLOWED_CLUSTERS`

The gate sits outside the agent loop. An alert or agent suggestion alone is not
sufficient to mutate cluster state.

The active cluster name must be listed explicitly in
`K8S_CONTAINER_ESCAPE_ALLOWED_CLUSTERS` before the skill will quarantine,
delete a pod, or drain a node. This keeps the handler from acting against
whichever kube context ambient credentials happen to resolve to.

Destructive follow-up paths tighten that bar further:

- `--approve-pod-kill` still requires the incident + approver pair
- `--approve-node-drain` requires the same pair **plus**
  `K8S_CONTAINER_ESCAPE_SECOND_APPROVER`, and the second approver must differ
  from the primary approver

### 5. Dual audit before and after the write

For the quarantine step the skill writes:

- a KMS-encrypted S3 evidence object under
  `s3://<bucket>/container-escape/audit/<yyyy>/<mm>/<dd>/<namespace>/<resource>/<timestamp>-apply_quarantine_network_policy.json`
- a DynamoDB audit row carrying the target, incident, approver, status, and
  evidence URI

The first audit write lands with `status: in_progress` BEFORE the Kubernetes
write. A second audit row lands with `status: success` or `status: failure`
after the API call returns.

### 6. `--reverify` proves the expected post-response state still holds

`--reverify` is read-only and follows the same action mode you selected:

- default quarantine path: fetches the expected `NetworkPolicy` by the
  deterministic policy name and checks that:

- the policy still exists
- `podSelector.matchLabels` still matches the resolved selector
- `policyTypes` still contains both `Ingress` and `Egress`
- both `ingress` and `egress` are empty arrays

- `--approve-pod-kill --reverify`: proves the target pod is still absent
- `--approve-node-drain --reverify`: proves the node remains cordoned and the
  target pod is still absent

The emitted record is `remediation_verification` with `status: verified` or
`status: drift`.

## Output contract

Dry-run emits a native `remediation_plan`; apply emits
`remediation_action`; re-verify emits `remediation_verification`.

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "remediation_plan",
  "source_skill": "remediate-container-escape-k8s",
  "target": {
    "provider": "Kubernetes",
    "namespace": "payments",
    "resource_type": "deployments",
    "resource_name": "api",
    "pod_name": ""
  },
  "policy_name": "ce-quarantine-api-7bacbd6e11",
  "selector": {
    "app": "api"
  },
  "manifest": {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy"
  },
  "actions": [
    {
      "step": "apply_quarantine_network_policy",
      "endpoint": "UPSERT /apis/networking.k8s.io/v1/namespaces/payments/networkpolicies/ce-quarantine-api-7bacbd6e11",
      "status": "planned",
      "detail": "dry-run: would apply quarantine NetworkPolicy"
    }
  ],
  "status": "planned",
  "dry_run": true,
  "finding_uid": "det-k8s-r2-hostpath-injection-9c5a6fa5-7bacbd6e"
}
```

Apply records add `incident_id`, `approver`, and `audit` metadata. Re-verify
records replace `actions` with a single `endpoint` field and a
`status: verified` or `status: drift`.

## Usage

```bash
# Dry-run (default) — resolves selector and prints the exact quarantine manifest
cat finding.ocsf.jsonl | python src/handler.py

# Apply quarantine — requires incident gate and audit destinations
export K8S_CONTAINER_ESCAPE_INCIDENT_ID=inc-2026-04-19-001
export K8S_CONTAINER_ESCAPE_APPROVER=alice@example.com
export K8S_CLUSTER_NAME=prod-eks-us-east-1
export K8S_CONTAINER_ESCAPE_ALLOWED_CLUSTERS=prod-eks-us-east-1
export K8S_REMEDIATION_AUDIT_DYNAMODB_TABLE=k8s-remediation-audit
export K8S_REMEDIATION_AUDIT_BUCKET=sec-k8s-remediation
export KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/...

cat finding.ocsf.jsonl | python src/handler.py --apply

# Re-verify — read-only check that the quarantine policy still exists
cat finding.ocsf.jsonl | python src/handler.py --reverify

# Explicit destructive pod delete
cat finding.ocsf.jsonl | python src/handler.py --approve-pod-kill
cat finding.ocsf.jsonl | python src/handler.py --apply --approve-pod-kill

# Explicit destructive node drain — requires a second approver
export K8S_CONTAINER_ESCAPE_SECOND_APPROVER=bob@example.com
cat finding.ocsf.jsonl | python src/handler.py --approve-node-drain
cat finding.ocsf.jsonl | python src/handler.py --apply --approve-node-drain
```

## Forensic evidence mode

`src/forensic_collector.py` is the post-quarantine evidence path. It runs in a
controlled follow-up worker or sidecar with read-only host mounts:

- `/host/proc` for PID discovery and `/proc/<pid>` capture
- `/host/var/log` for container runtime logs
- optional CSI `VolumeSnapshot` creation for PVC-backed pod volumes

Dry-run is still the default. Without `--upload`, the collector emits a native
`remediation_plan` record describing the exact bundle contents it WOULD write.
With `--upload`, it writes a deterministic `tar.gz` bundle to the same
KMS-encrypted audit bucket under
`container-escape/audit/<incident-id>/<timestamp>-<namespace>-<target>-forensics.tar.gz`.

```bash
# Dry-run forensic plan
cat finding.ocsf.jsonl | python src/forensic_collector.py \
  --proc-root /host/proc \
  --log-root /host/var/log

# Upload bundle + create VolumeSnapshot refs
export K8S_CONTAINER_ESCAPE_INCIDENT_ID=inc-2026-04-19-001
export K8S_CONTAINER_ESCAPE_APPROVER=alice@example.com
export K8S_REMEDIATION_AUDIT_BUCKET=sec-k8s-remediation
export KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/...

cat finding.ocsf.jsonl | python src/forensic_collector.py \
  --upload \
  --snapshot-volumes \
  --snapshot-class csi-snapshots
```

## Use when

- you need a reversible first-response containment for a suspicious Kubernetes
  workload after `detect-container-escape-k8s`
- you want a deny-all `NetworkPolicy` matched to the live selector, not a raw
  pod name
- you need an auditable quarantine step that can later be re-verified for drift
- you need a reproducible forensic bundle after quarantine, without killing the
  target pod first

## Do NOT use

- against protected namespaces like `kube-system` or `istio-system`
- as a generic "pause traffic" control for planned maintenance
- without setting `K8S_CONTAINER_ESCAPE_INCIDENT_ID` and
  `K8S_CONTAINER_ESCAPE_APPROVER` under `--apply`
- without setting `K8S_CLUSTER_NAME` and
  `K8S_CONTAINER_ESCAPE_ALLOWED_CLUSTERS` under `--apply`
- without setting `K8S_CONTAINER_ESCAPE_SECOND_APPROVER` for
  `--approve-node-drain --apply`

## Closed-loop verification

The remediation loop is:

1. `ingest-k8s-audit-ocsf`
2. `detect-container-escape-k8s`
3. `remediate-container-escape-k8s --apply`
4. `remediate-container-escape-k8s --reverify`

If the next re-verify run shows the expected quarantine, pod-delete, or
node-drain state missing or drifted, the skill emits `status: drift` and the
shared verifier contract produces the paired OCSF drift finding.

## Tests

- accepted-producer enforcement
- protected-namespace deny-list in dry-run and apply modes
- dry-run emits a plan with the resolved selector and deny-all manifest
- `--apply` gate requires incident ID and approver
- `--approve-node-drain` requires a distinct second approver
- audit write lands before the Kubernetes mutating call
- `--reverify` distinguishes verified from drifted policy state
- destructive pod-kill and node-drain modes re-verify their own post-action state
- end-to-end dry-run from the frozen container-escape findings golden
- forensic collector builds deterministic bundles from `/proc` + runtime logs
- forensic collector can plan or create `VolumeSnapshot` refs and upload a
  KMS-encrypted bundle to S3
