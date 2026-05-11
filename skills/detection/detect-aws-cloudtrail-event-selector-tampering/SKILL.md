---
name: detect-aws-cloudtrail-event-selector-tampering
description: >-
  Detect AWS CloudTrail `PutEventSelectors` or `UpdateTrail` events that
  **structurally reduce audit scope** — `IncludeManagementEvents` flipped
  to false, `ReadWriteType` set to `None`, an empty `EventSelectors`
  array, or `IsMultiRegionTrail` collapsed from multi-region to
  single-region. Reads OCSF 1.8 API Activity (class 6003) records produced
  by `ingest-cloudtrail-ocsf` and emits an OCSF 1.8 Detection Finding
  (class 2004) tagged with MITRE ATT&CK T1562.001 (Disable or Modify
  Tools — defense evasion). Use when the user mentions "CloudTrail audit
  scope narrowed", "PutEventSelectors emptied", "ReadWriteType set to
  None", "IncludeManagementEvents disabled", or "multi-region trail
  collapsed". Do NOT use for full `StopLogging` / `DeleteTrail` (covered
  by `detect-cloudtrail-disabled`), for per-event-selector data-resource
  subtraction in isolation (requires upstream diff context — see honesty
  note below), or on raw CloudTrail JSON before OCSF normalization.
purpose: Detect AWS CloudTrail audit-scope tampering via PutEventSelectors / UpdateTrail as a T1562.001 defense-evasion vector.
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
  stdout. No AWS SDK; pairs with `ingest-cloudtrail-ocsf` upstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-aws-cloudtrail-event-selector-tampering
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud: aws
  capability: read-only
---

# detect-aws-cloudtrail-event-selector-tampering

## Attack pattern

CloudTrail is the foundational audit-log surface for AWS. `StopLogging`
and `DeleteTrail` (covered by `detect-cloudtrail-disabled`) are loud,
binary signals that something is wrong. Sophisticated attackers prefer
the quieter alternative: **narrow the trail's audit scope** without
turning it off, so the trail still exists, still appears healthy in
posture checks, but no longer captures the activity the attacker is
about to execute.

The CloudTrail APIs that do this:

- `PutEventSelectors` rewrites the trail's `EventSelectors[]` array. The
  attacker can drop management events (`IncludeManagementEvents: false`),
  pin `ReadWriteType` to `None` (no read OR write captured), or ship an
  empty array (the trail logs nothing).
- `UpdateTrail` can flip `IsMultiRegionTrail` from true to false,
  collapsing a global trail into a single region and blinding every
  other region.

The result is a trail that survives a posture audit but observes
nothing the attacker cares about. This is the canonical
`T1562.001 Disable or Modify Tools` idiom executed against CloudTrail
itself.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose producer
is `ingest-cloudtrail-ocsf`:

1. Filter to `api.operation in {"PutEventSelectors", "UpdateTrail"}`.
2. Require `status_id == 1` (success).
3. Walk the structural scope-reduction signals on the new selector
   payload (under `unmapped.cloudtrail.request_parameters`):
   - **`empty_event_selectors`** — `eventSelectors[]` ships as an empty
     array on `PutEventSelectors`. Highest-confidence signal: the trail
     still exists but captures nothing.
   - **`management_events_disabled`** — any selector has
     `IncludeManagementEvents == false`. Management events are the
     IAM / STS / KMS / Config control-plane records — disabling them
     hides the privileged-API arc.
   - **`read_write_type_none`** — any selector has
     `ReadWriteType == "None"`. The selector matches no events at all.
   - **`multi_region_collapsed`** — `UpdateTrail` flips
     `IsMultiRegionTrail` from `true` to `false`. Detected when the new
     value is `false` AND the request payload also carries
     `previousIsMultiRegionTrail: true` (or the upstream diff helper
     surfaces it under `unmapped.cloudtrail.event_selector_change`).
4. Fire one finding per (trail_uid, signal) pair seen on the event.
5. A softer **`audit_scope_reduced`** signal-type is emitted on
   `PutEventSelectors` events that carry at least one selector with
   data-resource entries (signalling a structural rewrite) but no
   per-selector data-resource subtraction can be confirmed because the
   diff context is not available. See **Honesty caveat** below.

The detector is stateless — findings are deduplicated on
`metadata.uid` per (trail, signal) tuple, so two trail edits with the
same `metadata.uid` do not double-fire.

## Honesty caveat — structural signals vs diff context

Subtracting a single `DataResources` entry from an existing selector
**looks identical to a no-op rewrite** in the audit log itself: the new
selector payload contains the *post-edit* shape, not a before/after
diff. To call out a precise subtraction the detector would need either
(a) an upstream ingester that captures a before-snapshot (CloudTrail
does not natively provide one), or (b) a side-channel diff under
`unmapped.cloudtrail.event_selector_change`.

This detector commits to the **structural signals it can prove from a
single OCSF event**:

- `IncludeManagementEvents == false` → management arc blinded
- `ReadWriteType == "None"` → selector matches nothing
- empty `eventSelectors[]` → trail logs nothing
- `IsMultiRegionTrail` collapsed from `true` to `false` → cross-region blind

And documents that per-event-selector data-resource subtraction
requires upstream diff context. When upstream surfaces the diff under
`unmapped.cloudtrail.event_selector_change.removed_data_resources[]`,
that path is consumed and emits the same finding shape under signal
type `data_resources_removed`.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["aws-cloudtrail-event-selector-tampering", "signal-<kind>"]`
- `finding_info.attacks[]` carries MITRE ATT&CK `T1562.001` (tactic
  `TA0005 Defense Evasion`)
- `observables[]` for trail uid, trail name, account, region, actor
- `evidence` carries the signal kind, the api operation, the new
  payload values that triggered the signal, and `signal_provenance`
  (`structural` or `diff_context`)

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
cat cloudtrail.ocsf.jsonl \
  | python src/detect.py \
  > aws_cloudtrail_event_selector_tampering_findings.ocsf.jsonl
```

There is no env-var allow-list — tampering with the audit trail is
never expected during normal operations. If a one-time legitimate
narrowing is in flight, the operator should suppress at the SIEM /
detection-output layer, not at the detector boundary.

## Do NOT use

- On raw CloudTrail JSON before OCSF normalization (use
  `ingest-cloudtrail-ocsf` first).
- For full trail disable / delete — that's `detect-cloudtrail-disabled`.
- For per-event-selector data-resource subtraction without upstream
  diff context (see Honesty caveat).
- As a remediation skill — trail re-enable / re-arm lives in the
  remediation layer.

## Tests

The test suite covers:

- positive: PutEventSelectors with empty selectors fires (signal
  `empty_event_selectors`)
- positive: PutEventSelectors with `IncludeManagementEvents == false`
  fires (signal `management_events_disabled`)
- positive: PutEventSelectors with `ReadWriteType == "None"` fires
- positive: UpdateTrail collapsing `IsMultiRegionTrail` from true to
  false fires
- positive: a single event emitting multiple structural signals yields
  one finding per signal
- negative: PutEventSelectors with normal selectors (management events
  enabled, ReadWriteType `All`) does NOT fire
- negative: failed (`status_id != 1`) call does NOT fire
- producer guard: non-cloudtrail producer events ignored with stderr
- malformed: missing `request_parameters` → no fire, stderr warning
- schema-mode discriminator: native + ocsf output paths both validated
- multi-event idempotence: duplicate `metadata.uid` does not inflate counts
- diff-context path: `unmapped.cloudtrail.event_selector_change.removed_data_resources`
  emits a `data_resources_removed` finding
- golden fixture: input / output round-trip

## Roadmap

Closing slice of the cloud exfiltration + defense-evasion expansion
under issue `#253`. Lands the AWS defense-evasion half of the second
pair (`#479` shipped the AWS S3 + GCP peering exfil pair earlier). With
this PR `#253` ships all four planned detectors.
