---
name: detect-privilege-escalation-k8s
description: >-
  Detect Kubernetes privilege-escalation patterns from normalized
  kube-apiserver audit events in OCSF or native mode. Fires on four
  high-signal behaviors: service-account secret enumeration plus read
  (T1552.007), service-account pod exec (T1611), non-admin role-binding
  creation (T1098), and token self-grant flows (T1550.001). Use when the
  user mentions Kubernetes threat detection, RBAC abuse, service-account
  compromise, container escape, or kube-apiserver audit analysis. Do NOT use
  on raw audit logs — pipe them through ingest-k8s-audit-ocsf first. Do NOT
  use for CloudTrail, GCP, or Azure detection. Do NOT use as a compliance
  check; this emits findings on observed behavior.
purpose: Detect Kubernetes privilege-escalation patterns from normalized kube-apiserver audit events in OCSF or native mode.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: canonical, native, ocsf
output_formats: native, ocsf
concurrency_safety: requires_consistent_sharding
---

# detect-privilege-escalation-k8s

## Attack patterns detected

This skill implements four independent detection rules, each producing a separate **OCSF 1.8 Detection Finding** (class `2004`) with MITRE ATT&CK populated inside `finding_info.attacks[]`.

### Rule 1: Service-account secret enumeration + read (T1552.007)

A service account that `list`s secrets and then `get`s an individual secret within a short window is a strong signal of a compromised pod rooting around for credentials. Legitimate workloads that need secrets mount them as files — they don't call the K8s API for them.

- **Trigger:** same `system:serviceaccount:*` actor performs `list` on `secrets` and later performs `get` on `secrets` in the same namespace within the window (default: 5 minutes)
- **MITRE:** T1552.007 — Unsecured Credentials: Container API
- **Severity:** High (4)
- **Observables:** `session.actor`, `session.namespace`, `secret.name` (from the `get` call), `time.window`

### Rule 2: Service-account pod exec (T1611)

A service account calling `create` on the `pods/exec` subresource is attempting to get a shell inside a running pod. No legitimate workload (as opposed to a human operator) does this.

- **Trigger:** `system:serviceaccount:*` actor performs `create` on `pods` with `subresource == "exec"`
- **MITRE:** T1611 — Escape to Host (precursor: getting an interactive shell inside a container)
- **Severity:** Critical (5)
- **Observables:** `actor`, `target.pod`, `namespace`

### Rule 3: RoleBinding / ClusterRoleBinding self-grant (T1098)

A non-admin principal creating a `rolebindings` or `clusterrolebindings` resource is attempting to grant itself (or another principal) permissions it did not already have. This is the canonical K8s privilege-escalation move after initial compromise.

- **Trigger:** actor whose username does **not** match `system:masters` group or the `kubernetes-admin` user performs `create` on `rolebindings` or `clusterrolebindings`
- **MITRE:** T1098 — Account Manipulation
- **Severity:** Critical (5)
- **Observables:** `actor`, `binding.kind`, `binding.name`, `binding.namespace`

### Rule 4: Service-account token self-grant (T1550.001)

A service account calling `create` on the `tokenrequests` or `tokenreviews` subresource of `serviceaccounts` is issuing itself (or another SA) a fresh API token. Combined with Rule 1 or 3, this is token-theft in progress.

- **Trigger:** `system:serviceaccount:*` actor performs `create` on `serviceaccounts` with `subresource in {"token", "tokenrequest"}`, OR `create` on `tokenreviews`
- **MITRE:** T1550.001 — Use Alternate Authentication Material: Application Access Tokens
- **Severity:** High (4)
- **Observables:** `actor`, `target.serviceaccount`, `namespace`

## Output contract

Each finding is a full OCSF 1.8 Detection Finding matching [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) by default. Deterministic `finding_info.uid` of the form `det-k8s-<rule>-<actor-hash>-<target-hash>` so re-running on the same input is idempotent.

`finding_info.attacks[]` always carries:
- `version: "v14"`
- `tactic: { name, uid }`
- `technique: { name, uid }`
- `sub_technique: { name, uid }` when applicable

## Window semantics

Rule 1 uses a time window because it requires two events to correlate. The window defaults to **5 minutes** and is a constant at the top of `detect.py`. Detection is **stateless across invocations** — if the same pattern spans two runs, you'll miss the correlation. A future version will persist window state to a small JSON file for streaming use.

## Usage

## Native output format

`--output-format native` emits one native detection-finding record per match with:

- `schema_mode`
- `canonical_schema_version`
- `record_type`
- `source_skill`
- `output_format`
- `finding_uid`
- `event_uid`
- `provider`
- `time_ms`
- `severity`
- `severity_id`
- `status`
- `status_id`
- `title`
- `description`
- `finding_types`
- `first_seen_time_ms`
- `last_seen_time_ms`
- `mitre_attacks`
- `actor_name`
- `target`
- `rule_name`
- `observables`
- `evidence_count`

## Usage

```bash
# Piped from the ingest skill (default OCSF output)
python ../ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python src/detect.py \
  > findings.ocsf.jsonl

# Native end-to-end path
python ../ingest-k8s-audit-ocsf/src/ingest.py --output-format native audit.log \
  | python src/detect.py --output-format native \
  > findings.native.jsonl

# Standalone OCSF file
python src/detect.py ../golden/k8s_audit_sample.ocsf.jsonl
```

## Tests

Golden fixture parity: the same OCSF fixture used by `ingest-k8s-audit-ocsf` ([`../golden/k8s_audit_sample.ocsf.jsonl`](../golden/k8s_audit_sample.ocsf.jsonl)) is piped through this detector. Expected findings are frozen in [`../golden/k8s_priv_esc_findings.ocsf.jsonl`](../golden/k8s_priv_esc_findings.ocsf.jsonl). Plus unit tests for each rule's trigger logic, windowing, deterministic-uid generation, and negative controls (admin user, allowed workload, stale events outside the window).
