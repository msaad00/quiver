---
name: detect-databricks-cluster-init-script-abuse
description: >-
  Detect Databricks cluster init scripts being attached or modified to point
  at remote (off-DBFS) URLs or unsafe S3 paths. Reads OCSF 1.8 API Activity
  (class 6003) records normalized from Databricks audit logs whose
  `api.operation` is `clusters.create` or `clusters.edit` and whose
  `unmapped.databricks.cluster_config.init_scripts[].destination` falls
  outside the operator-tuned `DATABRICKS_INIT_SCRIPT_ALLOWED_PATHS` regex
  (default `^(dbfs:/databricks/init/|s3://databricks-workspace-[a-z0-9-]+-internal/)`)
  or matches the `\b(curl|wget|http|https|nc|netcat)\b` shell-command
  pattern. Emits OCSF 1.8 Detection Finding (class 2004) tagged with MITRE
  ATT&CK T1059.004 (Unix Shell) and T1546 (Boot or Logon Initialization
  Scripts). Init scripts run on every cluster node at boot under the
  Databricks-managed service identity, so a remote-fetched script is a
  workspace-wide RCE primitive. Use when you suspect a Databricks user is
  wiring an attacker-controlled bootstrap into a workspace cluster. Do NOT
  use on raw Databricks audit JSON before OCSF normalization, as a
  posture-at-rest cluster inventory, or as a generic shell-script linter.
purpose: Detect Databricks cluster init scripts pointing at unsafe remote paths.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-databricks-cluster-init-script-abuse
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - databricks
---

# detect-databricks-cluster-init-script-abuse

## Attack pattern

Databricks cluster init scripts execute on every cluster node at boot
under the Databricks-managed service identity. They are the
workspace-equivalent of cloud-init: anything they run gets the
workspace credentials, the mounted S3 / DBFS paths, and the
inter-cluster network. A compromised user with `CAN_MANAGE` on a
cluster (or workspace admin) can attach an init script that points at
an attacker-controlled URL, a writable S3 bucket they own, or a script
whose path itself encodes a `curl | sh` exfiltration command.

On the wire this surfaces as a Databricks audit-log entry with
`actionName == "clusters.create"` or `"clusters.edit"` carrying
`requestParams.cluster.init_scripts[]` with a `destination` field
(DBFS, S3, GCS, ADLS, or workspace storage URI). Once normalized via
`ingest-databricks-audit-ocsf` the same record arrives as OCSF 1.8 API
Activity (class `6003`) with the cluster config under
`unmapped.databricks.cluster_config.init_scripts[]`.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events from a
Databricks producer:

1. Match `api.operation` in {`clusters.create`, `clusters.edit`}
   (case-insensitive).
2. Require `status_id == 1` (success).
3. For each `init_scripts[].destination`:
   - Fire if the destination does NOT match
     `DATABRICKS_INIT_SCRIPT_ALLOWED_PATHS` (regex; default
     `^(dbfs:/databricks/init/|s3://databricks-workspace-[a-z0-9-]+-internal/)`)
   - OR fire if the destination matches the
     `\b(curl|wget|http|https|nc|netcat)\b` shell-command pattern
     (case-insensitive)
4. Emit one finding per (cluster_id, destination) tuple.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding
projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["databricks-cluster-init-script-abuse",
  "OWASP-Top-10-A08"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1059.004`
  (Unix Shell) and `T1546` (Boot or Logon Initialization Scripts)
- `observables[]` carrying the actor, workspace ID, cluster ID,
  destination, and the violation reason
- `evidence` carrying the cluster name, raw event uid, all flagged
  destinations, and the matched violation patterns

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
cat databricks_audit.ocsf.jsonl \
  | python src/detect.py \
  > databricks_init_script_findings.ocsf.jsonl
```

Tune the allow-list regex with `DATABRICKS_INIT_SCRIPT_ALLOWED_PATHS`.
The default allows the workspace-internal DBFS path and the
Databricks-managed internal S3 bucket pattern.

## Do NOT use

- On raw Databricks audit JSON before OCSF normalization
- As a posture-at-rest cluster inventory or init-script lint
- As a generic init / cloud-init detector for non-Databricks platforms

## Tests

The test suite covers:

- positive: a `clusters.create` with an S3 destination outside the
  allowed regex fires
- positive: a `clusters.edit` whose destination string contains `curl`
  fires
- negative: a DBFS-internal init script (allowed) does NOT fire
- negative: a failed event (`status_id != 1`) does NOT fire
- edge: a malformed JSON line is skipped with a stderr telemetry event
- edge: multiple destinations in one cluster fire once per (cluster,
  destination) tuple
- edge: a non-Databricks producer is ignored
- edge: an invalid `DATABRICKS_INIT_SCRIPT_ALLOWED_PATHS` regex falls
  back to the default with a stderr warning

## Roadmap

Fourth Databricks vendor-depth detector for issue #436.
