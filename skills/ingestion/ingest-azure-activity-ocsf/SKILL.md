---
name: ingest-azure-activity-ocsf
description: >-
  Convert raw Azure Activity Logs (Administrative, Service Health, Resource
  Health, Alert, Autoscale, Recommendation, Security, Policy) into OCSF 1.8
  API Activity events (class 6003). Reads the JSON shape Azure Monitor
  exports to Event Hubs, Storage, or Log Analytics. Supports
  `--output-format ocsf` and `--output-format native` from one canonical
  internal event shape. See `references/field-map.md` for the caller /
  callerIpAddress / operationName field mappings. Use when the user mentions
  Azure activity logs, Azure Monitor ingestion, OCSF pipeline for Azure, or
  feeding Azure audit data into a SIEM. Do NOT use for AWS CloudTrail (use
  ingest-cloudtrail-ocsf), GCP audit logs (use ingest-gcp-audit-ocsf), or
  Kubernetes audit logs (use ingest-k8s-audit-ocsf). Do NOT use for Azure
  diagnostic / metric logs — those are different pipelines. Do NOT use as a
  detection skill — this only normalises events.
purpose: Convert raw Azure Activity Logs (Administrative, Service Health, Resource Health, Alert, Autoscale, Recommendation, Security, Policy) into OCSF 1.8 API Activity events (class 6003). Reads the JSON shape Azure Monitor...
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

# ingest-azure-activity-ocsf

Thin, single-purpose ingestion skill: raw Azure Activity Logs in -> canonical
API activity projection -> OCSF 1.8 API Activity JSONL or native enriched API
activity JSONL out. No detection logic, no Azure API calls, no side effects.

## Wire contract

Azure Activity Logs are emitted by Azure Monitor in this shape (the JSON form delivered to Event Hubs, Storage Accounts, or Log Analytics):

```json
{
  "time": "2026-04-10T05:00:00.0000000Z",
  "resourceId": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.STORAGE/STORAGEACCOUNTS/STG",
  "operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
  "category": "Administrative",
  "resultType": "Success",
  "resultSignature": "Succeeded.OK",
  "durationMs": 1234,
  "callerIpAddress": "203.0.113.42",
  "correlationId": "abc-def-123",
  "identity": {
    "claims": {
      "appid": "11111111-2222-3333-4444-555555555555",
      "name": "alice@example.com",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "alice@example.com"
    }
  },
  "level": "Information",
  "properties": {
    "statusCode": "OK",
    "serviceRequestId": "service-req-789"
  }
}
```

Writes OCSF 1.8 **API Activity** (`class_uid: 6003`, `category_uid: 6`) by
default.

## Native output format

`--output-format native` returns one JSON object per activity log entry with:

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

Azure operation names follow `PROVIDER/RESOURCETYPE/ACTION` (e.g. `MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE`). The skill takes the **last** segment as the verb:

| Last segment | OCSF activity | id |
|---|---|---:|
| `WRITE`, `CREATE`, `REGENERATE` | Create | 1 |
| `READ`, `LIST`, `GET`, `LISTKEYS`, `LISTACCOUNTSAS` | Read | 2 |
| `ACTION`, `UPDATE`, `MOVE`, `RESTART` | Update | 3 |
| `DELETE`, `STOP`, `DEALLOCATE` | Delete | 4 |
| anything else | Other | 99 |

Note: Azure overloads `WRITE` for both create and update. We classify `WRITE` as Create on the principle that detections care most about *new* resources appearing — an Update detector can pivot on `properties.previousState` if we add it later.

## status_id

Azure populates `resultType` (Success / Failure / Started) and `properties.statusCode` (HTTP-style or Azure-specific). The skill prefers `resultType`:

- `resultType == "Success"` → `status_id = 1`
- `resultType == "Failure"` → `status_id = 2`
- otherwise inspect `properties.statusCode`: `2xx` → success, `4xx`/`5xx` → failure
- on failure, `status_detail` carries `resultSignature` (e.g. `Forbidden.AuthorizationFailed`)

## Field mapping

| Azure field | OCSF field |
|---|---|
| `identity.claims.upn` or `.name` or `.appid` | `actor.user.name` (first present wins) |
| `identity.claims.appid` | `actor.user.uid` (when present) |
| `caller` (legacy) | `actor.user.name` if no identity.claims |
| `callerIpAddress` | `src_endpoint.ip` |
| `operationName` | `api.operation` |
| derived service from operationName provider | `api.service.name` |
| `correlationId` | `api.request.uid` |
| `resourceId` | `resources[0].name` (with `type` from the provider segment) |
| `resourceId` subscription segment | `cloud.account.uid` |
| `resourceId` location is not in this field — populated when present in `properties` | `cloud.region` |
| `time` | `time` (ms epoch) |

`cloud.provider` is hard-coded to `"Azure"`.

## Usage

```bash
# Single file
python src/ingest.py azure-activity.json > azure-activity.ocsf.jsonl

# Same input, native enriched output
python src/ingest.py azure-activity.json --output-format native > azure-activity.native.jsonl

# Piped from az monitor
az monitor activity-log list --offset 1h --output json \
  | python src/ingest.py
```

## Tests

Golden fixture parity against [`../golden/azure_activity_raw_sample.jsonl`](../golden/azure_activity_raw_sample.jsonl) → [`../golden/azure_activity_sample.ocsf.jsonl`](../golden/azure_activity_sample.ocsf.jsonl).
