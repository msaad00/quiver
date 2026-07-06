---
name: detect-databricks-workspace-admin-grant
description: >-
  Detect a user being granted Databricks `workspace_admin` or `account_admin`
  privilege outside the documented change window. Reads OCSF 1.8 API
  Activity (class 6003) records normalized from Databricks audit logs whose
  `api.operation` is `accounts.setAdmin` or `iam.addUserToGroup` (where the
  group is `admins` or `account_admins`), and emits OCSF 1.8 Detection
  Finding (class 2004) tagged with MITRE ATT&CK T1098.003 (Additional Cloud
  Roles) when the granter is not in `DATABRICKS_AUTHORIZED_GRANTERS`
  (fail-open default) OR the event UTC hour is outside
  `DATABRICKS_GRANT_WINDOW_HOURS_UTC` (default `08-18`). Use when you
  suspect a Databricks principal is escalating themselves or someone else
  to workspace/account admin outside the break-glass process. Do NOT use
  on raw Databricks audit JSON before OCSF normalization, as a
  posture-at-rest admin inventory, or as a generic role-grant detector for
  non-Databricks platforms.
purpose: Detect Databricks workspace / account admin grants outside the change window.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-databricks-workspace-admin-grant
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - databricks
---

# detect-databricks-workspace-admin-grant

## Attack pattern

Databricks workspace admin and account admin grants are the
control-plane equivalent of AWS `iam:AttachUserPolicy` for the
`AdministratorAccess` managed policy. Once a principal carries that
role they can configure SCIM, attach init scripts, mint PATs, edit
Unity Catalog recipients, and walk the entire workspace audit feed.
A grant outside the documented change window is the canonical
escalation anchor — it is also the breadcrumb that survives every
post-incident wipe because the audit-log row remains.

On the wire this surfaces as a Databricks audit-log entry with
`actionName == "accounts.setAdmin"` (account-level admin grant) or
`actionName == "iam.addUserToGroup"` where the target group is
`admins` (workspace) or `account_admins` (account). Once normalized
via `ingest-databricks-audit-ocsf` the same record arrives as OCSF
1.8 API Activity (class `6003`).

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events from a
Databricks producer:

1. Match `api.operation` in the recognized admin-grant anchor set
   (case-insensitive).
2. Require `status_id == 1` (success).
3. For `iam.addUserToGroup` events, require the target group name
   under `unmapped.databricks.group_name` to be in {`admins`,
   `account_admins`}.
4. Fire if either:
   - The granter (`actor.user.uid` / email) is not in
     `DATABRICKS_AUTHORIZED_GRANTERS` (fail-open default — empty
     allow-list fires on every admin grant); OR
   - The event UTC hour is outside the
     `DATABRICKS_GRANT_WINDOW_HOURS_UTC` range (default `08-18` — fires
     on grants outside the business-hours change window).

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding
projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["databricks-workspace-admin-grant",
  "OWASP-Top-10-A01"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1098.003`
  (Additional Cloud Roles), tactic `TA0003 Persistence`
- `observables[]` carrying the granter, grantee, group name,
  workspace ID, and event UTC hour
- `evidence` carrying the raw event uid, granter, grantee, group,
  allow-list mode, and window mode

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
cat databricks_audit.ocsf.jsonl \
  | python src/detect.py \
  > databricks_admin_grant_findings.ocsf.jsonl
```

Tune the allow-list with `DATABRICKS_AUTHORIZED_GRANTERS=alice,bob` and
the change-window hours with `DATABRICKS_GRANT_WINDOW_HOURS_UTC=08-18`.
Mirrors the Snowflake / Slack unauthorized-grant detector pattern.

## Do NOT use

- On raw Databricks audit JSON before OCSF normalization
- As a posture-at-rest admin inventory or role-membership snapshot
- As a generic IAM role-grant detector (cloud-specific detectors live
  under `detect-aws-*`, `detect-gcp-*`, `detect-entra-role-grant-escalation`)

## Tests

The test suite covers:

- positive: an `accounts.setAdmin` by an unauthorized granter fires
- positive: an `iam.addUserToGroup` adding to the `admins` group
  outside the change window fires
- negative: an authorized granter inside the change window does NOT
  fire
- negative: a `failed (status_id != 1)` admin grant does NOT fire
- negative: `iam.addUserToGroup` adding to a non-admin group does NOT
  fire
- edge: an empty allow-list emits `allowlist_fail_open` stderr
  telemetry
- edge: a malformed `DATABRICKS_GRANT_WINDOW_HOURS_UTC` falls back to
  the default with a stderr warning
- edge: a non-Databricks producer is ignored

## Roadmap

Fifth Databricks vendor-depth detector for issue #436.
