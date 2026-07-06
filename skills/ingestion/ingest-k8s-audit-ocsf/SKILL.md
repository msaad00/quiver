---
name: ingest-k8s-audit-ocsf
description: >-
  Convert raw Kubernetes audit logs (`audit.k8s.io/v1`) into normalized API
  activity records, with OCSF as the default wire format and native output as
  an option. Maps user, source IP, verb, objectRef, and response status with
  enough fidelity for K8s privilege-escalation and secret-access detectors.
  Use when the user mentions Kubernetes audit logs, kube-apiserver audit
  sinks, K8s detection engineering, or feeding K8s audit into a SIEM. Do NOT
  use for container runtime logs, kubelet logs, or CloudTrail / GCP audit /
  Azure Activity. Do NOT use as a detection skill; this only normalizes
  events.
purpose: Convert raw Kubernetes audit logs (`audit.k8s.io/v1`) into normalized API activity records, with OCSF as the default wire format and native output as an option. Maps user, source IP, verb, objectRef, and response stat...
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native, ocsf
concurrency_safety: stateless
---

# ingest-k8s-audit-ocsf

Thin, single-purpose ingestion skill: raw Kubernetes audit logs in → OCSF 1.8 API Activity JSONL out by default, with an optional native enriched event shape when `--output-format native` is selected. No detection logic, no K8s API calls, no side effects.

## Wire contract

Reads the `audit.k8s.io/v1` `Event` object that `kube-apiserver` writes to its audit sink:

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "abc-123",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/default/secrets",
  "verb": "list",
  "user": {
    "username": "system:serviceaccount:default:default",
    "groups": ["system:serviceaccounts", "system:authenticated"]
  },
  "sourceIPs": ["10.0.0.1"],
  "userAgent": "kubectl/v1.28",
  "objectRef": {
    "resource": "secrets",
    "namespace": "default",
    "apiVersion": "v1"
  },
  "responseStatus": {"metadata": {}, "code": 200},
  "requestReceivedTimestamp": "2026-04-10T05:00:00.000000Z",
  "stageTimestamp": "2026-04-10T05:00:00.100000Z",
  "annotations": {"authorization.k8s.io/decision": "allow"}
}
```

Writes OCSF 1.8 **API Activity** (`class_uid: 6003`, `category_uid: 6`) by default.
With `--output-format native`, writes the repo's native enriched API activity
shape instead of the OCSF envelope.

## Filtering by stage

K8s audit events are emitted at 4 stages: `RequestReceived`, `ResponseStarted`, `ResponseComplete`, `Panic`. The skill processes **only `ResponseComplete` and `Panic`** events — those are the ones with authoritative `responseStatus`. Earlier-stage events are skipped with a `stderr` debug line.

## Field mapping

The K8s verb → `activity_id` table, the `responseStatus.code` → `status_id` rules, the full K8s-field → OCSF-field map, the `unmapped.k8s.*` preservation rules, the service-account marker, and the native output field list live in [`references/field-map.md`](references/field-map.md). Keeping the detail there keeps this file under the progressive-disclosure target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)) while detectors and reviewers still get the exact mapping one click away.

## Usage

```bash
# Audit log file (as written by kube-apiserver)
python src/ingest.py /var/log/k8s-audit.log > k8s-audit.ocsf.jsonl

# Piped from a dynamic webhook sink
kubectl logs -n kube-system audit-webhook-receiver \
  | python src/ingest.py

# Native enriched output (same source truth, no OCSF envelope)
python src/ingest.py --output-format native /var/log/k8s-audit.log > k8s-audit.native.jsonl
```

## Tests

Golden fixture parity against [`../golden/k8s_audit_raw_sample.jsonl`](../golden/k8s_audit_raw_sample.jsonl) → [`../golden/k8s_audit_sample.ocsf.jsonl`](../golden/k8s_audit_sample.ocsf.jsonl).
