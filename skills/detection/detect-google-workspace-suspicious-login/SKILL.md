---
name: detect-google-workspace-suspicious-login
description: >-
  Detect suspicious Google Workspace login bursts from OCSF 1.8 Authentication
  (3002) events or the native authentication projection produced by
  ingest-google-workspace-login-ocsf. The first
  slice stays narrow and verified: it fires when Google Workspace already marks
  a login event as suspicious, or when the same user shows a short burst of
  repeated login failures followed by a successful login from the same source
  IP inside a 10-minute window. Emits OCSF 1.8 Detection Finding (class 2004)
  with MITRE ATT&CK T1110 Brute Force and T1078 Valid Accounts. Use when the
  user mentions suspicious Workspace logins, repeated failed sign-ins followed
  by success, or Google Workspace login anomaly detection. Do NOT use on raw
  Workspace Admin SDK payloads — normalize them through
  ingest-google-workspace-login-ocsf first. Do NOT use as a generic MFA
  detector or for non-Workspace identity sources.
purpose: Detect suspicious Google Workspace login bursts from OCSF 1.8 Authentication (3002) events or the native authentication projection produced by ingest-google-workspace-login-ocsf. The first slice stays narrow and verif...
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: canonical, native, ocsf
output_formats: native, ocsf
concurrency_safety: requires_consistent_sharding
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-google-workspace-suspicious-login
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud:
    - google-workspace
---

# detect-google-workspace-suspicious-login

## Attack pattern

This skill covers one narrow Workspace identity pattern with two verified entry
paths:

- Google Workspace already marks the login event as suspicious via the
  `is_suspicious` login audit parameter
- a short burst of repeated `login_failure` events followed by one
  `login_success` for the same user and source IP inside a 10-minute window

That second path is intentionally conservative. It does not attempt impossible
travel, geovelocity, or every login anomaly in the catalog.

## Detection logic

One pass over Google Workspace authentication events from
`ingest-google-workspace-login-ocsf`, whether they arrive as OCSF Authentication
records or the native authentication projection:

1. Keep only Workspace auth events from the Workspace ingester
2. Group by `user.uid` and `src_endpoint.ip`
3. Sort by `time`
4. Fire when either:
   - the event is a `login_success` or `login_failure` with
     `unmapped.google_workspace_login.parameters.is_suspicious == true`
   - or at least `3` `login_failure` events are followed by one
     `login_success` inside `10` minutes for the same user/IP pair

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["google-workspace-suspicious-login"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK:
  - `T1110` Brute Force
  - `T1078` Valid Accounts
- `evidence.raw_event_uids` and `evidence.failure_count`
- `observables[]` carrying the impacted user, source IP, and session IDs

## Usage

```bash
python ../ingest-google-workspace-login-ocsf/src/ingest.py workspace-login.json \
  | python src/detect.py \
  > workspace-suspicious-login-findings.ocsf.jsonl

python ../ingest-google-workspace-login-ocsf/src/ingest.py workspace-login.json --output-format native \
  | python src/detect.py --output-format native \
  > workspace-suspicious-login-findings.native.jsonl
```

## Do NOT use

- On raw Workspace Admin SDK payloads before normalization
- As a generic failed-login detector for every SaaS source
- For Okta, Entra, CloudTrail, or Google Cloud Audit Logs
- As an impossible-travel or MFA-fatigue rule

## Tests

The test suite covers:

- suspicious-flag path
- repeated failure then success path
- out-of-order input
- exact window-boundary behavior
- duplicate event suppression by `metadata.uid`
- a frozen golden fixture for detector parity

## Native output format

When `--output-format native` is selected, the skill emits:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "detection_finding"`
- `finding_uid` and `event_uid`
- `provider`
- `time_ms`
- `user_uid` / `user_name`
- `src_ip`
- `mitre_attacks`
- `evidence`
