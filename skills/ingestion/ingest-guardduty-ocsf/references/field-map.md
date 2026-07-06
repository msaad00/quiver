# ingest-guardduty-ocsf OCSF field map

Full GuardDuty-finding → OCSF-field mapping for `ingest-guardduty-ocsf`. Pulled out of `SKILL.md` to keep that file under the progressive-disclosure target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)).

## Native output format

`--output-format native` returns one JSON object per GuardDuty finding with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "detection_finding"`
- `event_uid` and `finding_uid`
- `provider`, `account_uid`, `region`
- `time_ms`
- `severity_id`, `severity`, `status_id`, `status`
- `title`, `description`, `finding_types`
- `attacks`, `resources`, `cloud`, `source`, and `evidence`

The native shape keeps the same normalized semantics as the OCSF projection,
but omits `class_uid`, `category_uid`, `type_uid`, and `metadata.product`.

## GuardDuty Type → MITRE ATT&CK mapping

GuardDuty finding types follow the format:

```
<ThreatPurpose>:<ResourceTypeAffected>/<ThreatFamily>.<DetectionMechanism>[!Artifact]
```

The skill extracts the `ThreatPurpose` prefix and the `ThreatFamily` segment and looks them up in two deterministic tables:

| `ThreatPurpose` | MITRE tactic |
|---|---|
| `Backdoor` | TA0011 Command and Control |
| `CredentialAccess` | TA0006 Credential Access |
| `CryptoCurrency` | TA0040 Impact |
| `DefenseEvasion` / `Stealth` | TA0005 Defense Evasion |
| `Discovery` | TA0007 Discovery |
| `Execution` | TA0002 Execution |
| `Exfiltration` | TA0010 Exfiltration |
| `Impact` | TA0040 Impact |
| `InitialAccess` | TA0001 Initial Access |
| `Persistence` | TA0003 Persistence |
| `Policy` | TA0005 Defense Evasion |
| `PrivilegeEscalation` | TA0004 Privilege Escalation |
| `Recon` | TA0043 Reconnaissance |
| `Trojan` | TA0002 Execution |
| `UnauthorizedAccess` | TA0001 Initial Access |

A secondary exact-match table covers ~20 high-signal GuardDuty finding types with a specific MITRE technique (e.g. `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` → `T1552.005` Cloud Instance Metadata API + `T1078.004` Valid Accounts: Cloud Accounts). When no specific technique is known, the skill emits the tactic-only attack so downstream pivots still work.

## Severity mapping

GuardDuty severity is a float on a 1.0–8.9 scale. The skill maps it to `severity_id`:

| GuardDuty severity | OCSF `severity_id` | Label |
|---:|---:|---|
| 0.0 – 1.9 | 1 | Informational |
| 2.0 – 3.9 | 2 | Low |
| 4.0 – 5.9 | 3 | Medium |
| 6.0 – 7.9 | 4 | High |
| 8.0 – 8.9 | 5 | Critical |

The raw float is also preserved as an observable (`gd.severity`) so rules don't lose precision.

## Deterministic finding UID

`finding_info.uid` is derived as `det-gd-<first 8 chars of sha256(GuardDuty Id)>`, so re-ingesting the same finding always yields the same OCSF uid. The original GuardDuty Id is preserved on `evidence.raw_events[].uid`.

## What's NOT mapped (yet)

GuardDuty findings carry rich context that OCSF has field homes for; the first version focuses on fields any downstream converter or evaluator needs:

- `finding_info.uid`, `title`, `desc`, `types`
- `finding_info.attacks[]` (tactic + technique + sub_technique when known)
- `finding_info.first_seen_time` / `last_seen_time` (from `Service.EventFirstSeen/LastSeen`)
- `severity_id` (from the 1.0–8.9 scale)
- `cloud.account.uid` / `cloud.region` (from `AccountId` / `Region`)
- `resources[]` (from `Resource.ResourceType` plus the type-specific sub-object)
- A curated `observables[]` list (resource id, resource type, GuardDuty type, severity float)
- `evidence.raw_events[]` with the GuardDuty finding Id + ARN (pointer, not body)

Fields **explicitly out of scope** for v0.1: the full `Service.Action` sub-tree (varies by finding type), `Resource` sub-objects beyond the type tag, NetworkConnectionAction bytes/ports (add when a detector needs them).
