---
name: detect-databricks-secret-scope-read-burst
description: >-
  Detect abnormally high read volume against a Databricks secret scope.
  Reads OCSF 1.8 API Activity (class 6003) records normalized from Databricks
  audit logs whose `api.operation` is `secrets.getSecret`, and emits OCSF 1.8
  Detection Finding (class 2004) tagged with MITRE ATT&CK T1552.001
  (Credentials In Files) when a single `actor.user.uid` reads
  ≥ `DATABRICKS_SECRET_READ_THRESHOLD` (default 30) distinct secrets from the
  same scope within `DATABRICKS_SECRET_READ_WINDOW_MIN` (default 10) minutes.
  The detector tracks distinct-secret count per (user, scope) tuple, not raw
  call count, so a CI pipeline that polls one secret 60 times stays under
  threshold but a fan-out enumeration crosses it. Use when you suspect a
  Databricks principal is enumerating a secret scope as a pre-exfil step.
  Do NOT use on raw Databricks audit JSON before OCSF normalization, as a
  posture-at-rest secret-scope inventory, or as a generic credential-access
  detector for non-Databricks platforms.
purpose: Detect Databricks secret-scope read bursts (pre-exfil credential enumeration).
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
concurrency_safety: requires_consistent_sharding
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-databricks-secret-scope-read-burst
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - databricks
---

# detect-databricks-secret-scope-read-burst

## Attack pattern

Databricks secret scopes back the workspace credential vault that holds
JDBC strings, OAuth tokens, service-account JSONs, and registry
credentials referenced from notebooks and jobs. The standard access
pattern is a job reading one or two secrets at startup; a fan-out
enumeration where one principal pulls dozens of distinct secrets from
the same scope inside a few minutes is the canonical pre-exfil
signature — the attacker is harvesting the whole vault before
moving on.

On the wire this surfaces as repeated Databricks audit-log entries
with `actionName == "secrets.getSecret"` carrying
`requestParams.scope` and `requestParams.key`. Once normalized via
`ingest-databricks-audit-ocsf` the same record arrives as OCSF 1.8
API Activity (class `6003`) with the scope / key surfaced under
`unmapped.databricks.secret_scope` and
`unmapped.databricks.secret_key`.

## Detection logic

Aggregating pass over OCSF 1.8 API Activity (class `6003`) events from
a Databricks producer:

1. Match `api.operation == "secrets.getSecret"` (case-insensitive).
2. Require `status_id == 1` (success).
3. Require a non-empty `actor.user.uid`, scope, and key.
4. Group events by (actor_uid, scope). Inside a sliding window of
   `DATABRICKS_SECRET_READ_WINDOW_MIN` minutes, count **distinct**
   secret keys.
5. Fire when distinct-key count crosses
   `DATABRICKS_SECRET_READ_THRESHOLD`. Cooldown for one window
   afterwards (per tuple) to avoid storming.

The distinct-key check is what separates this skill from a naive
rate detector: a job that polls a single secret on every retry never
trips, but an enumeration touching 30+ keys does.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding
projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["databricks-secret-scope-read-burst",
  "OWASP-Top-10-A07"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1552.001`
  (Credentials In Files), tactic `TA0006 Credential Access`
- `observables[]` carrying the actor, workspace ID, scope name,
  distinct-key count, and the keys themselves
- `evidence` carrying the raw event uids, the keys, the window range,
  and the threshold + window configuration

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
cat databricks_audit.ocsf.jsonl \
  | python src/detect.py \
  > databricks_secret_burst_findings.ocsf.jsonl
```

Tune via:
- `DATABRICKS_SECRET_READ_THRESHOLD` (default `30`)
- `DATABRICKS_SECRET_READ_WINDOW_MIN` (default `10`)

## Do NOT use

- On raw Databricks audit JSON before OCSF normalization
- As a posture-at-rest secret-scope inventory
- As a credential-access detector for non-Databricks platforms (AWS
  Secrets Manager, GCP Secret Manager, Azure Key Vault have dedicated
  detectors)

## Tests

The test suite covers:

- positive: 30+ distinct keys read in window fires once
- negative: 30 reads of the SAME key does NOT fire (distinct-key
  threshold enforced)
- negative: 30 distinct reads spread across two scopes does NOT fire
- negative: a failed `secrets.getSecret` (`status_id != 1`) does NOT
  count toward the threshold
- edge: cool-down — a second burst by the same principal in the same
  scope inside one window does NOT re-fire
- edge: malformed JSON line is skipped with a stderr telemetry event
- edge: non-Databricks producer is ignored
- edge: a custom threshold via `DATABRICKS_SECRET_READ_THRESHOLD=5`
  fires at exactly 5 distinct keys

## Roadmap

Sixth and final Databricks vendor-depth detector for issue #436;
this PR closes the Databricks column.
