# ingest-cloudtrail-ocsf OCSF field map

Full CloudTrail-field → OCSF-field mapping for `ingest-cloudtrail-ocsf`. Pulled out of `SKILL.md` to keep that file under the progressive-disclosure target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)).

## Native output format

`--output-format native` returns one JSON object per event with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "api_activity"`
- `event_uid`
- `provider`, `account_uid`, `region`
- `time_ms`
- `activity_id`, `activity_name`
- `status_id`, `status`, `status_detail`
- `actor`, `api`, `src`, `cloud`, and `resources`

The native shape keeps the same normalized semantics as the OCSF projection,
but omits `class_uid`, `category_uid`, `type_uid`, and `metadata.product`.

## activity_id inference

CloudTrail doesn't tell you whether an event is a Create / Read / Update / Delete — you have to infer from the verb in `eventName`. The skill uses a deterministic prefix table:

| `eventName` prefix | OCSF activity | id |
|---|---|---:|
| `Create*`, `Run*`, `Start*`, `Issue*` | Create | 1 |
| `Get*`, `List*`, `Describe*`, `View*`, `Lookup*`, `Search*`, `Head*`, `Read*` | Read | 2 |
| `Update*`, `Modify*`, `Put*`, `Set*`, `Edit*`, `Attach*`, `Associate*`, `Add*`, `Enable*` | Update | 3 |
| `Delete*`, `Remove*`, `Terminate*`, `Stop*`, `Detach*`, `Disable*`, `Disassociate*` | Delete | 4 |
| anything else | Other | 99 |

## status_id

CloudTrail records a top-level `errorCode` field when an API call fails. The skill sets:

- `status_id = 1` (Success) when `errorCode` is absent
- `status_id = 2` (Failure) when `errorCode` is present
- `status_detail` is populated with the `errorMessage` for fast triage

## What's NOT mapped (yet)

CloudTrail carries fields the OCSF 1.8 API Activity class has homes for, but the
mapping is one-shot per skill. The first version focuses on the high-signal
fields any detection skill needs:

- `actor.user.name` (from `userIdentity.userName` or principal)
- `actor.session.uid` (from `userIdentity.accessKeyId`)
- `actor.session.created_time` (from `userIdentity.sessionContext.attributes.creationDate`)
- `src_endpoint.ip` and `src_endpoint.svc_name` (from `sourceIPAddress` and `userAgent`)
- `api.operation`, `api.service.name`, `api.request.uid` (from `eventName`, `eventSource`, `eventID`)
- `resources[]` (from `requestParameters` — only top-level keys, no recursion)
- `cloud.account.uid`, `cloud.region` (from `recipientAccountId`, `awsRegion`)
- `metadata.product.feature.name = "ingest-cloudtrail-ocsf"`

Fields **explicitly out of scope** for v0.1: `request.data` and `response.data` (often huge), `additionalEventData` (free-form), MFA context. Add these in a follow-up if a detector needs them.
