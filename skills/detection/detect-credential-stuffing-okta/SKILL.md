---
name: detect-credential-stuffing-okta
description: >-
  Detect credential-stuffing and password-spraying bursts against Okta user
  accounts from OCSF 1.8 Authentication (3002) events or the native
  authentication projection produced by ingest-okta-system-log-ocsf. Tracks
  one user at a time, looks for a burst of failed sign-ins followed by a
  successful sign-in inside a short window, and emits an OCSF 1.8 Detection
  Finding (class 2004) tagged with MITRE ATT&CK T1110 Brute Force and
  T1110.003 Password Spraying. Use when the user mentions credential
  stuffing, Okta credential stuffing, brute-force login bursts, password
  spraying followed by success, or automated login spam. Do NOT use on raw
  Okta System Log JSON — normalize through ingest-okta-system-log-ocsf
  first. Do NOT use as a generic MFA-fatigue detector (use
  detect-okta-mfa-fatigue). Do NOT use on Entra, Workspace, or CloudTrail
  — those have their own detectors.
purpose: Detect credential-stuffing and password-spraying bursts against Okta user accounts from OCSF 1.8 Authentication (3002) events or the native authentication projection produced by ingest-okta-system-log-ocsf. Tracks one...
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-credential-stuffing-okta
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud:
    - okta
---

# detect-credential-stuffing-okta

## Attack pattern

Credential stuffing is the pattern where an attacker replays leaked
username/password pairs across Okta until one works. Password spraying is
the adjacent pattern where a small number of common passwords are tried
across many users. In Okta System Log terms, both look like:

- a burst of `user.session.start` / `user.authentication.auth` /
  `user.authentication.sso` / `user.authentication.auth_via_mfa` events
  with `outcome.result: FAILURE` (OCSF `status_id = 2`) against one user
- followed by a successful sign-in (OCSF `status_id = 1`) inside the same
  window
- often from multiple distinct source IPs, indicating a botnet or proxy
  rotation

This detector is deliberately narrow: it fires on the **"many failures
then a success"** signature for a single user. Pure brute-force without
a success doesn't fire (it's a different signal — see the roadmap for
`detect-brute-force-okta`).

## Detection logic

One pass over Okta authentication events from `ingest-okta-system-log-ocsf`,
whether they arrive as OCSF Authentication records or the native
authentication projection:

1. Group by `user.uid`
2. Sort by `time`
3. Maintain a 5-minute burst window (rolling)
4. Fire once per burst when all of the following are true at the moment a
   success arrives:
   - at least `5` failed sign-in events in the window preceding the success
   - failures came from at least `2` distinct source IPs (tunable to `1`
     for targeted stuffing against a single account)
   - the success event is inside the same window

Operators can tune the logic at runtime without forking the skill:

- `DETECT_OKTA_STUFFING_WINDOW_MS` (default `300000` — 5 minutes)
- `DETECT_OKTA_STUFFING_MIN_FAILURES` (default `5`)
- `DETECT_OKTA_STUFFING_MIN_UNIQUE_IPS` (default `2`)

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["okta-credential-stuffing", "brute-force"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1110` and
  `T1110.003`
- `evidence.failure_events`, `evidence.success_event_uid`,
  `evidence.source_ips`, `evidence.raw_event_uids`
- `observables[]` carrying the impacted user, source IPs, and session IDs

## Usage

```bash
python ../ingest-okta-system-log-ocsf/src/ingest.py okta-system-log.json \
  | python src/detect.py \
  > okta-stuffing-findings.ocsf.jsonl

python ../ingest-okta-system-log-ocsf/src/ingest.py okta-system-log.json --output-format native \
  | python src/detect.py --output-format native \
  > okta-stuffing-findings.native.jsonl
```

## Do NOT use

- On raw Okta JSON before normalization
- As an MFA-fatigue detector (use `detect-okta-mfa-fatigue`)
- On Entra, Workspace, or CloudTrail — those have their own detectors
- To flag pure brute-force that never succeeds — that's a different signal

## Closed loop

The natural remediation for a confirmed stuffing finding is **kill the
session + require MFA re-enrollment**. That's handled by
`remediate-okta-session-kill` (tracked in issue #240). Together they
form the first shipped detect → act → audit → re-verify loop for Okta.

## Tests

The test suite covers:

- out-of-order OCSF and native auth input
- exact window-boundary behavior (success outside the window does NOT fire)
- duplicate event suppression by `metadata.uid`
- the "many failures but no success" suppression case
- distinct-IP threshold suppression (lowering to 1 enables single-IP
  targeted stuffing detection)
- a frozen golden fixture for detector output parity
