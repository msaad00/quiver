---
name: detect-container-escape-k8s
description: >-
  Detect Kubernetes container-escape signals from normalized kube-apiserver
  audit events in native or OCSF mode. Fires on three high-signal behaviors:
  patches that introduce privileged / host-namespace / risky-capability
  settings, patches that introduce dangerous hostPath mounts, ephemeral-
  container creation on running pods, unexpected `kubectl exec`, and optional
  Falco / Tracee runtime signals fused on `container_id`. Use when the user
  mentions Kubernetes container escape, hostPath abuse, privileged pod
  patching, `kubectl debug`, suspicious `kubectl exec`, or Falco / Tracee
  runtime breakout signals. Do NOT use on raw audit logs — pipe them through
  ingest-k8s-audit-ocsf first for the audit stream.
purpose: Detect Kubernetes container-escape signals from normalized kube-apiserver audit events in native or OCSF mode.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: native, ocsf
output_formats: native, ocsf
concurrency_safety: stateless
---

# detect-container-escape-k8s

## Use when

- Kubernetes audit telemetry is already normalized by `ingest-k8s-audit-ocsf`
- you want deterministic findings for post-deploy escape-to-host changes
- you need native or OCSF findings for patch-driven container-escape signals

## Attack patterns detected

This skill now covers the original K8s-audit slice plus the follow-up
unexpected-exec and runtime-fusion scope from issue `#298`.

### Rule 1: Risky spec patch (T1611)

Fires when a `patch` request introduces one or more of:

- `privileged: true`
- `hostPID: true`
- `hostNetwork: true`
- `CAP_SYS_ADMIN`
- `CAP_SYS_PTRACE`

These settings materially weaken workload isolation and are explicitly aligned
to container escape behavior in MITRE ATT&CK and Kubernetes hardening guidance.

- **Trigger:** `patch` on a pod or pod-owning workload with a request payload that adds one or more risky settings
- **MITRE:** T1611 — Escape to Host
- **Severity:** Critical (5)
- **Observables:** actor, resource type/name, namespace, risky settings

### Rule 2: hostPath injection (T1611)

Fires when a `patch` request introduces a `hostPath` mount to one of:

- `/`
- `/proc`
- `/var/lib/docker`
- `/var/lib/containerd`

Kubernetes documents `hostPath` as a powerful escape hatch and warns that it
poses significant security risk. These paths are the classic host-access pivot.

- **Trigger:** `patch` on a pod or pod-owning workload with a request payload that adds a risky `hostPath`
- **MITRE:** T1611 — Escape to Host
- **Severity:** Critical (5)
- **Observables:** actor, resource type/name, namespace, host paths

### Rule 3: Ephemeral container creation (T1610)

Fires when a running pod is modified through the `pods/ephemeralcontainers`
subresource, the API path used by `kubectl debug` and related troubleshooting
flows.

- **Trigger:** `patch` or `update` on `pods` with `subresource == "ephemeralcontainers"` and an ephemeral container payload
- **MITRE:** T1610 — Deploy Container
- **Severity:** High (4)
- **Observables:** actor, pod, namespace, ephemeral container names

### Rule 4: Unexpected `kubectl exec` correlation (T1613)

Fires when a pod `exec` action targets a running workload but the exec actor is
not:

- the most recent deploy-or-patch actor for that pod inside the detector's
  30-minute lookback window, or
- a declared operator principal / group passed via
  `--known-operator-principal` or `K8S_CONTAINER_ESCAPE_KNOWN_OPERATORS`

If the detector does not have recent deploy history, it still fires when the
exec principal is a service account rather than a declared operator.

- **Trigger:** `create` or `connect` on `pods/exec`
- **MITRE:** T1613 — Container and Resource Discovery
- **Severity:** High (4)
- **Observables:** actor, actor type, pod, namespace, recent deploy actor

### Rule 5: Falco / Tracee runtime fusion (T1611)

Consumes optional Falco or Tracee JSONL records in the same input stream. When
runtime signals share a `container_id`, the detector fuses them into one
finding and raises severity when multiple engines or signal families align.

Supported signals:

- `Terminal shell in container`
- `Container Drift Detected` / `container_drift`
- `Write below root`
- `Sensitive file access below root`

- **Trigger:** Falco or Tracee runtime records with one of the supported
  signals; fusion happens automatically on `container_id`
- **MITRE:** T1611 — Escape to Host
- **Severity:** High (4) from one source; Critical (5) when multiple
  sources/signals align
- **Observables:** container ID, pod, namespace, runtime engines, fused signals

## Output contract

Each match emits a full OCSF 1.8 Detection Finding (class `2004`) by default.
Deterministic `finding_info.uid` uses the rule id plus stable actor/target
hashes so re-running on the same input is idempotent.

`finding_info.attacks[]` always carries:

- `version: "v14"`
- `tactic: { name, uid }`
- `technique: { name, uid }`

## What this detector still does NOT do

- automatic remediation or forensic collection
- arbitrary runtime-event parsing beyond the documented Falco / Tracee signals
- long-lived state outside the input batch window

Those remain separate concerns so the detector stays deterministic and batch-safe.

## Native output format

`--output-format native` emits one native detection-finding record per match
with:

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
# Piped from ingest-k8s-audit-ocsf (default OCSF output)
python ../ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python src/detect.py \
  > findings.ocsf.jsonl

# Native end-to-end path
python ../ingest-k8s-audit-ocsf/src/ingest.py --output-format native audit.log \
  | python src/detect.py --output-format native \
  > findings.native.jsonl

# Standalone OCSF file
python src/detect.py ../golden/k8s_container_escape_sample.ocsf.jsonl

# Allow a break-glass operator principal to exec without firing rule 4
python src/detect.py mixed-input.jsonl \
  --known-operator-principal alice@example.com \
  --known-operator-principal system:masters
```

## Tests

Golden fixture parity against
[`../golden/k8s_container_escape_sample.ocsf.jsonl`](../golden/k8s_container_escape_sample.ocsf.jsonl)
→
[`../golden/k8s_container_escape_findings.ocsf.jsonl`](../golden/k8s_container_escape_findings.ocsf.jsonl).
Follow-up golden parity covers mixed audit + runtime input at
[`../golden/k8s_container_escape_followup_input.jsonl`](../golden/k8s_container_escape_followup_input.jsonl)
→
[`../golden/k8s_container_escape_followup_findings.ocsf.jsonl`](../golden/k8s_container_escape_followup_findings.ocsf.jsonl).
Plus unit tests for risky-setting extraction, `hostPath` path filtering, JSON
Patch handling, ephemeral container name extraction, unexpected-exec
correlation, runtime fusion, native input, OCSF class pinning, and
deterministic finding UIDs.
