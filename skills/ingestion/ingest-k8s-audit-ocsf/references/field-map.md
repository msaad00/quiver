# ingest-k8s-audit-ocsf OCSF field map

Full Kubernetes-audit-field → OCSF-field mapping for `ingest-k8s-audit-ocsf`. Pulled out of `SKILL.md` to keep that file under the progressive-disclosure target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)).

## activity_id inference

K8s verbs are standard — no guessing needed:

| K8s verb | OCSF activity | id |
|---|---|---:|
| `create` | Create | 1 |
| `get`, `list`, `watch`, `proxy` | Read | 2 |
| `update`, `patch` | Update | 3 |
| `delete`, `deletecollection` | Delete | 4 |
| anything else (`connect`, `bind`, custom) | Other | 99 |

## status_id

`responseStatus.code` is an HTTP status code:

- `2xx` → `status_id = 1` (Success)
- `4xx` / `5xx` → `status_id = 2` (Failure)
- missing (audit level below `Metadata`) → `status_id = 0` (Unknown)

On failure, `status_detail` is populated with `responseStatus.message` (e.g. `"secrets \"db-password\" is forbidden: User ... cannot get resource"`) for fast triage and detection rule pivots.

## Field mapping

| K8s field | OCSF field |
|---|---|
| `user.username` | `actor.user.name` |
| `user.uid` | `actor.user.uid` |
| `user.groups` | `actor.user.groups[]` (each as `{name: ...}`) |
| `sourceIPs[0]` | `src_endpoint.ip` |
| `userAgent` | `src_endpoint.svc_name` |
| `verb` | `api.operation` |
| `"kubernetes"` | `api.service.name` (hard-coded) |
| `auditID` | `api.request.uid` |
| `objectRef.resource` / `namespace` / `name` / `apiGroup` | `resources[0]` |
| `requestReceivedTimestamp` | `time` (ms epoch) |
| `annotations["authorization.k8s.io/decision"]` | `metadata.labels` (`authz-allow` / `authz-deny`) |

`cloud.provider` is hard-coded to `"Kubernetes"` (even though K8s is not a cloud, OCSF uses the `cloud` object as the deployment-context holder).

### `unmapped.k8s.*` preservation

Fields without a clean first-class OCSF slot round-trip verbatim under
`unmapped.k8s.*` in both native and OCSF output:

- `requestObject` → `unmapped.k8s.request_object`
- `responseObject` → `unmapped.k8s.response_object`
- raw `objectRef` → `unmapped.k8s.object_ref`

This preserves spec-patch and response-body detail for downstream detectors
without overloading the normalized `resources[]` shape.

## Service-account marker

When `user.username` starts with `system:serviceaccount:<namespace>:<name>`, the skill sets `actor.user.type = "ServiceAccount"` and records `mcp.sa_namespace` under a non-standard k8s custom profile so detection skills can key off it without parsing the username string.

## Native output format

`--output-format native` emits one enriched event per accepted audit entry with:

- `schema_mode`
- `canonical_schema_version`
- `record_type`
- `event_uid`
- `provider`
- `account_uid`
- `region`
- `time_ms`
- `activity_id`
- `activity_name`
- `status_id`
- `status`
- `status_detail` when present
- `operation`
- `service_name`
- `actor`
- `src`
- `resources`
- `source`
- `k8s.service_account_namespace` when the actor is a service account
- `unmapped.k8s.*` when raw request / response / objectRef detail is present
