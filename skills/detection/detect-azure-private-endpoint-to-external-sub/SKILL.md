---
name: detect-azure-private-endpoint-to-external-sub
description: >-
  Detect Azure `Microsoft.Network/privateEndpoints/write` events where the
  private link target service lives in a subscription **outside** the
  operator-declared `AZURE_PRIVATE_ENDPOINT_AUTHORIZED_SUBS` allow-list.
  Reads OCSF 1.8 API Activity (class 6003) records produced by
  `ingest-azure-activity-ocsf` carrying `unmapped.azure.privateLinkServiceConnections`
  (an array; each entry has `privateLinkServiceId` whose first
  `/subscriptions/<guid>/` segment names the target subscription). Walks
  every connection — a private endpoint can target multiple link services
  — and emits an OCSF 1.8 Detection Finding (class 2004) tagged with
  MITRE ATT&CK T1071.001 (Application Layer Protocol — Web) and T1567
  (Exfiltration Over Web Service) per (resource_uid, target_subscription)
  tuple that crosses the boundary. Use when the user mentions "Azure
  private-endpoint pinned to another sub", "private link exfil to external
  tenant", "T1071 over private link", or "Microsoft.Network/privateEndpoints
  to unknown subscription". Do NOT use as a posture-at-rest private-link
  inventory, for Azure storage account network ACL changes (separate
  detector), or on raw Azure Activity JSON before OCSF normalization.
purpose: Detect Azure private endpoint creation that pins the link to a target service in an external subscription as a T1071.001 / T1567 exfiltration vector.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. Read-only — consumes OCSF 1.8 API Activity 6003
  records from stdin/file and emits OCSF 1.8 Detection Finding 2004 to
  stdout. No Azure SDK; pairs with `ingest-azure-activity-ocsf` upstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-azure-private-endpoint-to-external-sub
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud: azure
  capability: read-only
---

# detect-azure-private-endpoint-to-external-sub

## Attack pattern

Azure Private Link lets a workload reach a target service over the
Microsoft backbone instead of the public internet. The
`Microsoft.Network/privateEndpoints/write` operation creates the endpoint
and pins it to a target service via `privateLinkServiceConnections[].
privateLinkServiceId` — a resource id whose first
`/subscriptions/<guid>/` segment names the **subscription that owns
the target service**.

A persistent attacker with `Microsoft.Network/privateEndpoints/write`
permission inside the victim subscription can lay down a private
endpoint whose target service lives in a **subscription the attacker
controls** — typically a different tenant. Traffic that traverses that
endpoint never hits the public internet, never crosses an internet NSG,
and is fully encrypted by the Microsoft backbone. From the victim's
side, the exfil channel looks like a normal Azure-native private link.

This is the Application Layer Protocol — Web (`T1071.001`) and
Exfiltration Over Web Service (`T1567`) idiom executed over Azure's own
private link plumbing.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose producer
is `ingest-azure-activity-ocsf`:

1. Filter to `api.operation == "Microsoft.Network/privateEndpoints/write"`
   (case-insensitive).
2. Require `status_id == 1` (success).
3. Walk `unmapped.azure.privateLinkServiceConnections[]`. A private
   endpoint can pin multiple link services; each entry's
   `privateLinkServiceId` is parsed for its first `/subscriptions/<guid>/`
   segment.
4. **Fail-open allow-list**: if `AZURE_PRIVATE_ENDPOINT_AUTHORIZED_SUBS`
   is empty, fire on every cross-subscription connection (with
   `evidence.allowlist_mode = "fail-open"`). Operators must set the
   allow-list explicitly in prod; the warning is emitted to stderr,
   mirroring `detect-snowflake-unauthorized-grant`.
5. When the allow-list is set, fire only when the target subscription
   is **not** on it.

The detector is stateless — one finding per (resource_uid,
target_subscription) tuple, deduplicated on `metadata.uid` per source
event.

Operators tune the policy at runtime:

- `AZURE_PRIVATE_ENDPOINT_AUTHORIZED_SUBS` — comma-separated
  subscription GUIDs (default empty = fail-open).

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["azure-private-endpoint-to-external-sub", "boundary-cross-subscription"]`
- `finding_info.attacks[]` carries MITRE ATT&CK `T1071.001` and `T1567`
  (tactics `TA0011 Command and Control` and `TA0010 Exfiltration`)
- `observables[]` for source subscription, target subscription,
  private-link service id, private endpoint resource id, actor
- `evidence` carries `boundary`, `allowlist_mode`,
  `private_link_service_id`, `connection_name`

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
export AZURE_PRIVATE_ENDPOINT_AUTHORIZED_SUBS="11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222"
cat azure_activity.ocsf.jsonl \
  | python src/detect.py \
  > azure_private_endpoint_external_sub_findings.ocsf.jsonl
```

## Do NOT use

- On raw Azure Activity JSON before OCSF normalization (use
  `ingest-azure-activity-ocsf` first).
- As a posture-at-rest private-link inventory (this is event-based).
- For Azure storage account network ACL changes — that lives in a
  separate detector slot.
- As a remediation skill — private-endpoint revocation lives in the
  remediation layer.

## Tests

The test suite covers:

- positive: cross-subscription private-link service connection fires in fail-open
- positive: cross-subscription connection fires under enforced allow-list when not in set
- negative: same-subscription connection does NOT fire
- negative: cross-sub connection whose target is on the allow-list does NOT fire
- malformed: missing `privateLinkServiceConnections` → no fire, stderr warning
- schema-mode discriminator: native + ocsf output paths both validated
- multi-target endpoint: one privateEndpoint with two unauthorized link-service
  connections produces two findings, classification correct on each
- producer guard: events from non-azure-activity producer are ignored with stderr
- env-override: `AZURE_PRIVATE_ENDPOINT_AUTHORIZED_SUBS` honored, GUIDs
  lower-cased for comparison
- golden fixture: input / output round-trip

## Roadmap

Closing slice of the cloud exfiltration + defense-evasion expansion under
issue `#253`. Lands the Azure half of the second pair; `#479` shipped the
AWS S3 + GCP peering pair earlier, and the CloudTrail
event-selector-tampering detector ships in this same PR.
