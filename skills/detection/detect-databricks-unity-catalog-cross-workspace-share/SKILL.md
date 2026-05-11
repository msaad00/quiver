---
name: detect-databricks-unity-catalog-cross-workspace-share
description: >-
  Detect Databricks Unity Catalog data being shared across workspaces or to
  external recipients via Delta Sharing. Reads OCSF 1.8 API Activity (class
  6003) records normalized from Databricks audit logs whose `api.operation`
  matches `unityCatalog.CreateRecipient`, `unityCatalog.UpdateRecipient`,
  `unityCatalog.CreateShare`, or `unityCatalog.UpdateShare`, and emits OCSF
  1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1537 Transfer
  Data to Cloud Account when the recipient is external (Delta Sharing
  `recipient.type == "EXTERNAL"`) or the recipient ID is not in the
  `DATABRICKS_AUTHORIZED_RECIPIENTS` allow-list. The allow-list is fail-open
  by default with a stderr warning so the detector ships safe defaults that
  fire on every external share until the operator scopes it. Use when you
  suspect a Databricks principal is wiring Delta Sharing recipients to off-
  workspace consumers or sharing Unity Catalog objects outside the
  documented data-sharing inventory. Do NOT use on raw Databricks audit
  JSON before OCSF normalization, as a posture-at-rest catalog inventory,
  or as a generic cross-cloud share detector for non-Databricks platforms.
purpose: Detect Databricks Unity Catalog cross-workspace or external Delta Sharing.
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
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-databricks-unity-catalog-cross-workspace-share
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - databricks
---

# detect-databricks-unity-catalog-cross-workspace-share

## Attack pattern

Databricks Unity Catalog uses Delta Sharing to grant external recipients
read access to catalog objects. A compromised workspace admin or a
service principal with `CREATE RECIPIENT` / `CREATE SHARE` privilege
can wire a Delta Sharing recipient to an account outside the
documented data-sharing inventory and immediately publish catalog
objects to it — bypassing every workspace-level network policy because
the consumer never logs into the producing workspace.

On the wire this surfaces as a Databricks audit-log entry with
`serviceName == "unityCatalog"` and `actionName` in
{`CreateRecipient`, `UpdateRecipient`, `CreateShare`, `UpdateShare`}.
Once normalized through the upstream `ingest-databricks-audit-ocsf`
pipeline (roadmap, see #436) the same record materializes as OCSF 1.8
API Activity (class `6003`) with the action surfaced under
`api.operation` and the recipient / share block surfaced under
`unmapped.databricks.{recipient, share}`.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events from a
Databricks producer:

1. Match `api.operation` in the recognized Unity Catalog recipient /
   share family (case-insensitive).
2. Require `status_id == 1` (success) — failed share / recipient
   create attempts are not a data-movement anchor on their own.
3. For recipient events: fire when `recipient.type == "EXTERNAL"` AND
   the recipient ID is not in `DATABRICKS_AUTHORIZED_RECIPIENTS`.
4. For share events: fire when the target recipient ID is outside the
   allow-list (the upstream `share.recipients[]` block carries the
   bound recipient IDs).
5. Fire **once per matching event** — every recipient bind / share
   publication is its own data-movement anchor.

When `DATABRICKS_AUTHORIZED_RECIPIENTS` is empty the detector emits an
`allowlist_fail_open` stderr telemetry event and surfaces every
external Delta Sharing recipient — the safer default for first-run
operators.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding
projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["databricks-uc-cross-workspace-share",
  "OWASP-Top-10-A04"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1537`
  (Transfer Data to Cloud Account), tactic `TA0010 Exfiltration`
- `observables[]` carrying the actor, workspace ID, recipient ID,
  recipient type, share name, and bound recipients
- `evidence` carrying the raw event uid, the recipient / share names,
  the recipient type, and the allow-list mode

Severity is `HIGH` (severity_id `4`) because Delta Sharing publishes
data outside the producing workspace's audit and network controls.

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
cat databricks_audit.ocsf.jsonl \
  | python src/detect.py \
  > databricks_uc_share_findings.ocsf.jsonl

# Native projection out:
cat databricks_audit.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > databricks_uc_share_findings.native.jsonl
```

## Do NOT use

- On raw Databricks audit JSON before OCSF normalization
- As a posture-at-rest catalog inventory or share-age check
- On non-Databricks API Activity 6003 events
- As a generic cross-cloud data-share detector (Snowflake shares are
  handled by `detect-snowflake-share-creation`)

## Tests

The test suite covers:

- positive: an external recipient create fires exactly one finding
  with the expected MITRE T1537 mapping
- positive: a share create whose recipient is outside the allow-list
  fires
- negative: a recipient on the `DATABRICKS_AUTHORIZED_RECIPIENTS`
  allow-list does NOT fire
- negative: an internal (non-EXTERNAL) recipient create does NOT fire
- negative: a failed create (`status_id != 1`) does NOT fire
- edge: an empty allow-list emits an `allowlist_fail_open` stderr
  telemetry event and fires on every external recipient
- edge: a malformed JSON line is skipped with a stderr telemetry
  event, not crashed on
- edge: a non-Databricks producer is ignored

## Roadmap

Second Databricks vendor-depth detector for issue #436 (after
`detect-databricks-token-creation`). Five Databricks detectors close
out the Databricks column under #436.
