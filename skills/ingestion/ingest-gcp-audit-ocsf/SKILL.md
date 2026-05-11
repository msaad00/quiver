---
name: ingest-gcp-audit-ocsf
description: >-
  Convert raw GCP Cloud Audit Logs (Admin Activity, Data Access, System
  Event, or Policy Denied) into OCSF 1.8 API Activity events (class 6003).
  Reads the protoPayload format that GCP exports to Cloud Logging, BigQuery,
  Pub/Sub, or Cloud Storage. Supports `--output-format ocsf` and
  `--output-format native` from one canonical internal event shape. See
  `references/field-map.md` for the protoPayload → OCSF field mappings
  (principalEmail, callerIp, methodName, serviceName, status). Use when the
  user mentions GCP audit logs, GCP Cloud Logging ingestion, OCSF pipeline
  for GCP, or feeding GCP audit data into a SIEM. Do NOT use for AWS
  CloudTrail (use ingest-cloudtrail-ocsf), Azure Activity Logs (use
  ingest-azure-activity-ocsf), or Kubernetes audit logs (use
  ingest-k8s-audit-ocsf). Do NOT use as a detection skill — this only
  normalises events.
purpose: Convert raw GCP Cloud Audit Logs (Admin Activity, Data Access, System Event, or Policy Denied) into OCSF 1.8 API Activity events (class 6003). Reads the protoPayload format that GCP exports to Cloud Logging, BigQuery,...
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: ocsf, native
concurrency_safety: stateless
---

# ingest-gcp-audit-ocsf

Thin, single-purpose ingestion skill: raw GCP Cloud Audit Logs in -> canonical
API activity projection -> OCSF 1.8 API Activity JSONL or native enriched API
activity JSONL out. No detection logic, no GCP API calls, no side effects.

## Wire contract

GCP Cloud Audit Logs use the [`google.cloud.audit.AuditLog`](https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog) protobuf, exported to Cloud Logging and from there to BigQuery, Pub/Sub, or Cloud Storage. The skill reads the JSON serialisation:

```json
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {"principalEmail": "alice@example.com"},
    "requestMetadata": {
      "callerIp": "203.0.113.42",
      "callerSuppliedUserAgent": "google-cloud-sdk/470.0.0"
    },
    "serviceName": "iam.googleapis.com",
    "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
    "resourceName": "projects/-/serviceAccounts/sa@proj.iam.gserviceaccount.com",
    "status": {}
  },
  "insertId": "abc-def-123",
  "resource": {"type": "service_account", "labels": {"project_id": "my-project"}},
  "timestamp": "2026-04-10T05:00:00.000Z",
  "severity": "NOTICE",
  "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity"
}
```

The `protoPayload.@type` is the contract: only entries that are `google.cloud.audit.AuditLog` are processed; anything else is skipped with a `stderr` warning.

Writes OCSF 1.8 **API Activity** (`class_uid: 6003`, `category_uid: 6`) by
default.

## Native output format

`--output-format native` returns one JSON object per audit log entry with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "api_activity"`
- `event_uid`
- `provider`, `account_uid`, `region`
- `time_ms`
- `event_name`, `operation`, `service_name`
- `activity_id`, `activity_name`
- `status_id`, `status`, `status_detail`
- `actor`, `src`, `api`, `resources`, `cloud`, and `source`

The native shape keeps the same normalized semantics as the OCSF projection,
but omits OCSF envelope fields such as `class_uid`, `category_uid`, and
`metadata.product`.

## activity_id inference

GCP method names are dotted (`service.version.Verb`). The verb is the **last** segment. The skill applies the same prefix table as CloudTrail (Create / Read / Update / Delete / Other) but to the verb segment, not the full method name.

| Last segment prefix | OCSF activity | id |
|---|---|---:|
| `Create*`, `Insert*`, `Generate*` | Create | 1 |
| `Get*`, `List*`, `Search*`, `Lookup*`, `Test*`, `BatchGet*` | Read | 2 |
| `Update*`, `Patch*`, `Set*`, `Replace*`, `Add*` | Update | 3 |
| `Delete*`, `Remove*`, `Cancel*`, `Disable*` | Delete | 4 |
| anything else | Other | 99 |

## status_id

GCP audit log `protoPayload.status` is empty `{}` on success and populated with `{"code": 7, "message": "PERMISSION_DENIED"}` on failure. The skill sets:

- `status_id = 1` (Success) when `status` is missing, empty, or has `code == 0`
- `status_id = 2` (Failure) when `status.code` is non-zero
- `status_detail` is populated with the canonical gRPC error name + message

## Field mapping

| GCP field | OCSF field |
|---|---|
| `protoPayload.authenticationInfo.principalEmail` | `actor.user.name` |
| `protoPayload.authenticationInfo.principalSubject` | `actor.user.uid` |
| `protoPayload.requestMetadata.callerIp` | `src_endpoint.ip` |
| `protoPayload.requestMetadata.callerSuppliedUserAgent` | `src_endpoint.svc_name` |
| `protoPayload.serviceName` | `api.service.name` |
| `protoPayload.methodName` | `api.operation` |
| `insertId` | `api.request.uid` |
| `protoPayload.resourceName` | `resources[0].name` (with `type` from GCP `resource.type`) |
| `resource.labels.project_id` | `cloud.account.uid` |
| `resource.labels.location` (if present) | `cloud.region` |
| `timestamp` | `time` (ms epoch) |

`cloud.provider` is hard-coded to `"GCP"`.

## Usage

```bash
# Single file
python src/ingest.py gcp-audit.json > gcp-audit.ocsf.jsonl

# Same input, native enriched output
python src/ingest.py gcp-audit.json --output-format native > gcp-audit.native.jsonl

# Piped from gcloud logging
gcloud logging read 'logName=~"cloudaudit.googleapis.com"' --format=json --limit=1000 \
  | python src/ingest.py
```

## What's NOT mapped (yet)

- `protoPayload.request` and `protoPayload.response` — often huge, frequently sensitive
- `protoPayload.metadata` — free-form
- IAM policy delta in `protoPayload.serviceData` — would need its own follow-up skill
- Multi-resource batch operations — first resource only

Exception: for service-account key creation events, the ingester may copy only
the sanitized `protoPayload.response.name` resource identifier into
`resources[]` as `type: service_account_key`. It never copies
`privateKeyData` or the full response object.

## Tests

Golden fixture parity against [`../golden/gcp_audit_raw_sample.jsonl`](../golden/gcp_audit_raw_sample.jsonl) → [`../golden/gcp_audit_sample.ocsf.jsonl`](../golden/gcp_audit_sample.ocsf.jsonl).
