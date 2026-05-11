---
name: detect-github-pat-creation
description: >-
  Detect creation of GitHub personal access tokens (PATs) at the
  organization scope. Reads OCSF 1.8 API Activity (class 6003) records
  carrying `metadata.product.feature.name ==
  "ingest-github-audit-log-ocsf"`, `api.operation IN
  ("personal_access_token.create", "personal_access_token.access_granted")`,
  an `actor.user.uid` (or `name`), and `unmapped.github.*` token detail,
  and emits one OCSF 1.8 Detection Finding (class 2004) per successful PAT
  issuance, tagged with MITRE ATT&CK T1098.001 (Additional Cloud
  Credentials). Once a PAT exists it can be used for headless
  REST/GraphQL access without an interactive login. Use when the user
  mentions "GitHub PAT created", "fine-grained personal access token
  issued", "T1098.001 in GitHub", or "additional cloud credentials in
  GitHub". Do NOT use on raw GitHub audit-log JSON before OCSF
  normalization, as a posture-at-rest token inventory or age check, or as
  a generic credential-issuance detector for non-GitHub platforms.
purpose: Detect creation of GitHub personal access tokens (PATs) at the organization scope.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-github-pat-creation
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP LLM Top 10
  cloud:
    - github
---

# detect-github-pat-creation

## Attack pattern

A GitHub personal access token (PAT) is an additional cloud credential.
Once issued, a PAT lets a principal call the GitHub REST/GraphQL API
without going through an interactive SSO/OIDC login. Fine-grained PATs
may carry org-wide read or write scope; classic PATs may carry
`repo`/`workflow`/`admin:org` scope. A single token-creation event by a
compromised user, a stale offboarded principal, or a machine user
operating outside its declared automation window can sit on the wire
indefinitely.

The shape on the wire is a GitHub audit-log entry where
`action == "personal_access_token.create"` (classic PAT) or
`action == "personal_access_token.access_granted"` (fine-grained PAT
approved into the org) carrying the requesting principal's `actor` /
`actor_id`, the org, the `programmatic_access_type`, and the
`hashed_token` / `token_id`. Once normalized through the upstream
`ingest-github-audit-log-ocsf` pipeline the same record materializes as
OCSF 1.8 API Activity (class `6003`) with the action surfaced under
`api.operation` and the GitHub metadata surfaced under
`unmapped.github.*`.

This detector does NOT model token *use* (every API call carries the
token); it models token *issuance*, which is the persistence anchor.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` is `ingest-github-audit-log-ocsf`:

1. Match `api.operation` against
   `{personal_access_token.create, personal_access_token.access_granted}`
   (case-insensitive).
2. Require `status_id == 1` (success).
3. Require a non-empty `actor.user.uid` or `actor.user.name`.
4. Fire **once per matching event** (no windowing, no dedupe across
   principals — each token issuance is its own persistence anchor).

When the operation is in the `personal_access_token.*` family but the
action name is not in the recognized map (e.g. a future GitHub API verb
the detector hasn't seen yet), the skill emits an `unmapped_event_type`
stderr telemetry record and does not fire — same pattern the Okta
ingest pipeline uses post-#458, so operators can grep the unmapped feed
and propose new mappings without losing visibility.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding
projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["github-pat-creation",
  "OWASP-LLM-Top-10-LLM02"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1098`
  (Account Manipulation) plus sub-technique `T1098.001` (Additional
  Cloud Credentials), tactic `TA0003 Persistence`
- `observables[]` carrying the actor (uid + name), the GitHub org, the
  API operation, the `programmatic_access_type`, the optional token id
  and scopes, and the src IP when the upstream surfaces them
- `evidence` carrying the raw event uid, the org, the API operation,
  the token id, the kind of PAT, and the requested scopes

Severity is `HIGH` (severity_id `4`) because a GitHub PAT can carry
broad scope and only expires when the issuing user sets an explicit
TTL or the org admin revokes it.

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
cat github_audit.ocsf.jsonl \
  | python src/detect.py \
  > github_pat_creation_findings.ocsf.jsonl

# Same input, native finding projection out:
cat github_audit.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > github_pat_creation_findings.native.jsonl
```

## Do NOT use

- On raw GitHub audit-log JSON before OCSF normalization
- As a posture-at-rest token inventory or age / lifetime check
- As a token-use detector — this skill models issuance, not consumption
- On non-GitHub API Activity 6003 events (we filter on
  `metadata.product.feature.name == "ingest-github-audit-log-ocsf"`)

## Tests

The test suite covers:

- positive: a successful `personal_access_token.access_granted` fires
  exactly one finding with the expected MITRE T1098.001 mapping
- positive: classic `personal_access_token.create` also fires
- negative: a read-only `personal_access_token.request_denied` does NOT
  fire
- negative: a failed PAT create (`status_id != 1`) does NOT fire
- negative: a non-GitHub producer is ignored
- edge: a malformed JSON line is skipped with a stderr telemetry event,
  not crashed on
- edge: a multi-token burst (same principal, several tokens within
  seconds) fires once per token
- edge: a future GitHub PAT verb that is not in the recognized map
  emits an `unmapped_event_type` stderr telemetry event and does not
  fire

## Closes

This detector is one of the three detection deliverables of issue
[`#31`](https://github.com/msaad00/cloud-ai-security-skills/issues/31).
