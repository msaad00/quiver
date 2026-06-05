# Normalization Reference

This is the repo's vendor-to-normalized-schema reference.

Use it when you need one place that answers:

- which raw source maps to which repo record type
- which OCSF class the source lands in by default
- which vendor or natural identifiers are preserved
- which repo-owned identifiers are deterministic
- where vendor detail survives under `unmapped.*`

This doc is intentionally practical. It does not replace individual
`SKILL.md` mapping sections. It gives operators, reviewers, and agents a single
starting point for the most important normalization decisions.

Use this together with:

- [`NATIVE_VS_OCSF.md`](./NATIVE_VS_OCSF.md)
- [`CANONICAL_SCHEMA.md`](./CANONICAL_SCHEMA.md)
- [`SCHEMA_COVERAGE.md`](./SCHEMA_COVERAGE.md)
- [`NORMALIZATION_EXAMPLES.md`](./NORMALIZATION_EXAMPLES.md)
- the relevant ingest skill's `SKILL.md`

## Mental model

The repo normalizes source payloads in this order:

`raw vendor payload -> canonical internal model -> native | ocsf | bridge`

Important rule:

- `raw` is the original vendor payload
- `native` is the repo-owned external wire format
- `ocsf` is the default interoperable stream format
- `bridge` is OCSF plus preserved repo or source detail

## Identifier rules

The repo does not invent random UUIDs for normalized events or findings.

| Identifier kind | Rule |
|---|---|
| Raw vendor ID | preserve the vendor or source natural ID when one exists |
| `event_uid` | deterministic and replay-stable |
| `finding_uid` | deterministic and replay-stable |
| OCSF `metadata.uid` | should carry the same stable event or finding identity as the normalized record |
| OCSF `api.request.uid` | use the best request, correlation, or audit identifier the source exposes |
| `session_uid` / `correlation_uid` | preserve a stable session or correlation handle when the source provides one |
| Random UUIDs | avoid for normalized outputs; use only when the source itself emitted one and it is the natural ID |

Short rule:

- if the source gives an immutable ID, preserve it
- if the source does not, derive a deterministic content or semantic key
- never make replay safety depend on a random runtime-generated UUID

## Source mapping summary

| Source skill | Raw source | Native `record_type` | Default OCSF class | Main natural IDs kept | Main repo-stable IDs / correlation |
|---|---|---|---|---|---|
| `ingest-cloudtrail-ocsf` | AWS CloudTrail | `api_activity` | API Activity `6003` | `eventID`, `recipientAccountId`, `eventName`, `eventSource` | `event_uid`, `metadata.uid`, `api.request.uid = eventID` |
| `ingest-aws-config-ocsf` | AWS Config configuration items and compliance changes | `aws_config_configuration_item`, `aws_config_compliance_finding` | API Activity `6003`, Compliance Finding `2003` | Config `configurationStateId`, `resourceType`, `resourceId`, Config rule name | deterministic `metadata.uid` from account, region, resource, rule, status, and recorded time; raw Config context preserved under `unmapped.aws_config` |
| `ingest-vpc-flow-logs-ocsf` | AWS VPC Flow Logs | `network_activity` | Network Activity `4001` | no single immutable vendor event ID in the raw format | deterministic `event_uid` from normalized flow tuple; account, ENI, instance, and timing context preserved |
| `ingest-guardduty-ocsf` | AWS GuardDuty finding JSON | `detection_finding` | Detection Finding `2004` | GuardDuty `Id`, `Arn` | `finding_uid = det-gd-<sha256(Id)>`; raw GuardDuty `Id` preserved in evidence |
| `ingest-gcp-audit-ocsf` | GCP Cloud Audit Logs | `api_activity` | API Activity `6003` | `insertId`, `methodName`, `serviceName`, `resourceName` | deterministic `event_uid`; `api.request.uid = insertId` |
| `ingest-vpc-flow-logs-gcp-ocsf` | GCP VPC Flow Logs | `network_activity` | Network Activity `4001` | raw flow tuple fields, project context | deterministic `event_uid`; project and boundary context preserved |
| `ingest-azure-activity-ocsf` | Azure Activity Log | `api_activity` | API Activity `6003` | `correlationId`, `resourceId`, `operationName` | deterministic `event_uid`; `api.request.uid = correlationId` |
| `ingest-nsg-flow-logs-azure-ocsf` | Azure NSG Flow Logs | `network_activity` | Network Activity `4001` | tuple fields, NSG rule, subscription context | deterministic `event_uid`; subscription and boundary context preserved |
| `ingest-k8s-audit-ocsf` | Kubernetes audit `Event` | `api_activity` | API Activity `6003` | `auditID`, `verb`, `objectRef.*` | deterministic `event_uid`; `api.request.uid = auditID` |
| `ingest-okta-system-log-ocsf` | Okta System Log | `authentication`, `account_change`, `user_access_management` | Authentication `3002`, Account Change `3001`, User Access Management `3005` | `uuid`, `published`, `transaction.id`, `authenticationContext.*` | deterministic `event_uid`; `metadata.uid` based on `uuid`; session and transaction data preserved |
| `ingest-entra-directory-audit-ocsf` | Microsoft Graph `directoryAudit` | `api_activity` | API Activity `6003` | `id`, `correlationId`, `activityDateTime` | deterministic `event_uid`; `metadata.uid` from `id` or stable fallback; `api.request.uid = correlationId` |
| `ingest-google-workspace-login-ocsf` | Google Workspace login audit | `authentication` or `account_change` | Authentication `3002`, Account Change `3001` | `id.time`, `id.uniqueQualifier`, `applicationName` | deterministic `event_uid`; `metadata.uid` from time + qualifier + event name |
| `ingest-mcp-proxy-ocsf` | MCP proxy JSON-RPC logs | `application_activity` | Application Activity `6002` with custom MCP profile | `session_id`, method, tool attributes | deterministic `event_uid`; stable tool fingerprint for drift detection |

## Vendor and class mapping detail

### AWS

#### CloudTrail

| Concern | Mapping |
|---|---|
| Raw source | CloudTrail event JSON or `{"Records":[...]}` wrapper |
| Native type | `api_activity` |
| OCSF class | API Activity `6003` |
| Main actor fields | `userIdentity.* -> actor.*` |
| Main request ID | `eventID -> api.request.uid` |
| Main service mapping | `eventSource -> api.service.name` |
| Main operation mapping | `eventName -> api.operation` |
| Resource mapping | selected top-level `requestParameters` keys -> `resources[]` |
| Stable ID rule | preserve `eventID` as the primary event identity |
| Known trade-off / caveat | nested `requestParameters`, `responseElements`, and `additionalEventData` are intentionally selective; see [`SCHEMA_COVERAGE.md`](./SCHEMA_COVERAGE.md) |

Abbreviated example:

```json
{
  "raw": {
    "eventID": "1d0f...",
    "eventName": "AssumeRole",
    "eventSource": "sts.amazonaws.com"
  },
  "native": {
    "record_type": "api_activity",
    "event_uid": "1d0f...",
    "operation": "AssumeRole",
    "service_name": "sts.amazonaws.com"
  },
  "ocsf": {
    "class_uid": 6003,
    "metadata": {"uid": "1d0f..."},
    "api": {"request": {"uid": "1d0f..."}, "operation": "AssumeRole"}
  }
}
```

#### VPC Flow Logs

| Concern | Mapping |
|---|---|
| Raw source | AWS VPC Flow Log tuple lines |
| Native type | `network_activity` |
| OCSF class | Network Activity `4001` |
| Main endpoints | `srcaddr`, `dstaddr`, `srcport`, `dstport` |
| Main status / activity | `action=ACCEPT|REJECT -> activity_id 6|7` |
| Main cloud context | `account-id`, `region`, `interface-id`, `instance-id`, `subnet-id`, `vpc-id` |
| Stable ID rule | derive deterministic `event_uid` from the normalized flow tuple because the raw format has no immutable vendor event ID |
| Known loss / caveat | no single vendor request ID; several extended fields are currently omitted or flattened |

#### GuardDuty

| Concern | Mapping |
|---|---|
| Raw source | GuardDuty finding JSON, `Findings[]`, or EventBridge `detail` wrapper |
| Native type | `detection_finding` |
| OCSF class | Detection Finding `2004` |
| Main natural ID | GuardDuty `Id` |
| Stable finding ID | `finding_uid = det-gd-<sha256(Id)>` |
| MITRE mapping | derived from GuardDuty `Type` into tactic and, when known, technique |
| Evidence preservation | original GuardDuty `Id` and `Arn` remain in the finding evidence |

### GCP

#### Cloud Audit Logs

| Concern | Mapping |
|---|---|
| Raw source | `google.cloud.audit.AuditLog` JSON |
| Native type | `api_activity` |
| OCSF class | API Activity `6003` |
| Main actor fields | `authenticationInfo.principalEmail` and `principalSubject` |
| Main request ID | `insertId -> api.request.uid` |
| Main service mapping | `serviceName -> api.service.name` |
| Main operation mapping | `methodName -> api.operation` |
| Main resource mapping | `resourceName`, `resource.type`, `resource.labels.project_id` |
| Stable ID rule | deterministic `event_uid`; preserve `insertId` as request correlation |

#### VPC Flow Logs

| Concern | Mapping |
|---|---|
| Raw source | GCP VPC flow rows |
| Native type | `network_activity` |
| OCSF class | Network Activity `4001` |
| Main cloud context | project, subnet, VM / interface, region where present |
| Stable ID rule | deterministic `event_uid` because the raw flow export is tuple-based rather than request-ID-based |

### Azure

#### Activity Log

| Concern | Mapping |
|---|---|
| Raw source | Azure Monitor Activity Log JSON |
| Native type | `api_activity` |
| OCSF class | API Activity `6003` |
| Main actor fields | `identity.claims.*` or legacy `caller` |
| Main request ID | `correlationId -> api.request.uid` |
| Main service mapping | provider segment of `operationName` |
| Main operation mapping | `operationName -> api.operation` |
| Main resource mapping | `resourceId -> resources[0]` and subscription context |
| Stable ID rule | deterministic `event_uid`; preserve `correlationId` as the request or operation handle |

#### NSG Flow Logs

| Concern | Mapping |
|---|---|
| Raw source | Network Watcher NSG flow tuples |
| Native type | `network_activity` |
| OCSF class | Network Activity `4001` |
| Main cloud context | subscription, NSG boundary, rule name, MAC, direction |
| Stable ID rule | deterministic `event_uid` derived from the normalized tuple and boundary context |

### Kubernetes

#### Audit events

| Concern | Mapping |
|---|---|
| Raw source | `audit.k8s.io/v1` `Event` |
| Native type | `api_activity` |
| OCSF class | API Activity `6003` |
| Main actor fields | `user.username`, `user.uid`, `user.groups[]` |
| Main request ID | `auditID -> api.request.uid` |
| Main operation mapping | `verb -> api.operation` |
| Main resource mapping | `objectRef.* -> resources[0]` |
| Stable ID rule | preserve `auditID` as the event and request identity when available |
| Vendor-specific note | service-account detail is preserved in repo-native fields such as `k8s.service_account_namespace`; raw `requestObject`, `responseObject`, and `objectRef` survive under `unmapped.k8s.*` |

### Identity vendors

#### Okta System Log

| Concern | Mapping |
|---|---|
| Raw source | Okta System Log API array, single event, or hook wrapper |
| Native type | `authentication`, `account_change`, `user_access_management` |
| OCSF class | Authentication `3002`, Account Change `3001`, User Access Management `3005` |
| Main natural ID | `uuid` |
| Session / transaction IDs | `authenticationContext.externalSessionId`, `transaction.id`, `rootSessionId` |
| Stable ID rule | preserve `uuid` as the primary event identity |
| Vendor detail | `transaction.id` and `rootSessionId` survive under `unmapped.okta.*` |

Abbreviated example:

```json
{
  "raw": {
    "uuid": "b9ab...",
    "eventType": "user.session.start",
    "transaction": {"id": "trn-123"}
  },
  "native": {
    "record_type": "authentication",
    "event_uid": "b9ab..."
  },
  "ocsf": {
    "class_uid": 3002,
    "metadata": {"uid": "b9ab..."},
    "unmapped": {"okta": {"transaction_id": "trn-123"}}
  }
}
```

#### Microsoft Entra `directoryAudit`

| Concern | Mapping |
|---|---|
| Raw source | Graph `directoryAudit` list, single object, or JSONL |
| Native type | `api_activity` |
| OCSF class | API Activity `6003` |
| Main natural ID | `id` |
| Main correlation ID | `correlationId -> api.request.uid` |
| Main time field | `activityDateTime` |
| Stable ID rule | use `id` when present, otherwise derive a deterministic fallback |
| Vendor detail | `additionalDetails` survives under `unmapped.entra` |

#### Google Workspace login audit

| Concern | Mapping |
|---|---|
| Raw source | Admin SDK Reports `applicationName=login` activities |
| Native type | `authentication` or `account_change` |
| OCSF class | Authentication `3002`, Account Change `3001` |
| Main natural IDs | `id.time`, `id.uniqueQualifier`, `applicationName` |
| Stable ID rule | deterministic `metadata.uid` and `event_uid` from the Workspace natural key plus event name |
| Vendor detail | raw login parameters survive under `unmapped.google_workspace_login` |

### MCP / agent runtime telemetry

#### MCP proxy logs

| Concern | Mapping |
|---|---|
| Raw source | MCP proxy JSON-RPC request/response logs |
| Native type | `application_activity` |
| OCSF class | Application Activity `6002` plus the repo's MCP custom profile |
| Main natural IDs | `session_id`, `method`, tool metadata |
| Stable ID rule | deterministic `event_uid`; stable tool fingerprint from tool name + description + schema + annotations |
| Vendor detail | MCP-specific fields remain under the custom profile rather than pretending they are generic cloud API fields |

## Resource and service anchors

This is the quick map for how the repo tends to normalize service and resource
identity across major vendors:

| Vendor | Service anchor | Resource anchor | Account / tenant anchor |
|---|---|---|---|
| AWS | `eventSource`, GuardDuty `Type`, VPC flow context | top-level CloudTrail resource identity, VPC / ENI / instance, GuardDuty resource type | `recipientAccountId` or source account field |
| GCP | `serviceName`, `methodName` | `resourceName`, `resource.type`, project labels | project ID |
| Azure | provider segment from `operationName` | `resourceId`, NSG rule / boundary context | subscription ID |
| Kubernetes | hard-coded `kubernetes` service + `verb` | `objectRef.resource`, `namespace`, `name`, `apiGroup` | cluster or deployment scope when supplied |
| Okta | `eventType` | target users, groups, apps, privileges | Okta org context when supplied |
| Entra | `activityDisplayName` / Graph audit family | `targetResources[]` primary IDs and types | tenant / directory context when supplied |
| Workspace | `applicationName=login` + event name | actor profile and login parameters | Workspace customer scope when supplied |

## Current OCSF note

OCSF keeps evolving. For example, the current schema browser exposes profiles
such as `ai_operation`.

That does **not** change the repo's current contract by itself:

- use OCSF where the class or profile fit is explicit and stable
- keep operational artifacts native-first
- update this reference as new repo mappings become explicit and test-backed

In other words, OCSF growth is a reason to revisit mappings, not a reason to
pretend every native or operational contract should move immediately.

## Scope and update rule

This page should expand over time.

Add or update an entry when a shipped source-normalization skill:

- gains a new supported vendor event family
- changes its OCSF class mapping
- changes its deterministic identifier rule
- adds or removes meaningful `unmapped.*` preservation

If this page and a skill's `SKILL.md` ever disagree, the skill contract and its
tests win until both are updated together.
