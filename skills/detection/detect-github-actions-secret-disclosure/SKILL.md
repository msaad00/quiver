---
name: detect-github-actions-secret-disclosure
description: >-
  Detect GitHub Actions workflow runs that log a secret value to stdout
  in an encoded form GitHub's redactor missed. Reads OCSF 1.8 API
  Activity (class 6003) records emitted by an upstream GitHub Actions
  log feed (assumed to share the
  `ingest-github-audit-log-ocsf` producer envelope) carrying
  `unmapped.github.workflow_log_excerpt`. Fires when the excerpt
  contains BOTH GitHub's redaction marker `***` (proves a secret was
  present in the run) AND at least one high-entropy substring (≥ 32
  chars, base64-ish, hex-ish, or JWT-shaped) that survived the
  redactor — meaning the secret was logged in an encoded form the
  redactor couldn't match against the secret store. The workflow run
  must have completed successfully (otherwise the secret was prevented
  from going downstream). Maps to MITRE ATT&CK T1552.004 (Private Keys
  / Credentials in Logs). Severity CRITICAL. Use when the user
  mentions "GitHub Actions secret leak", "workflow log discloses
  encoded secret", "T1552.004 in GitHub Actions", or "CI exfil via
  encoded log line". Do NOT use as a generic high-entropy log scanner
  or on workflow logs without the `***` marker, and do NOT use on
  non-GitHub API Activity 6003 events.
purpose: Detect GitHub Actions workflow runs that log a secret value to stdout in an encoded form the redactor missed.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-github-actions-secret-disclosure
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP LLM Top 10
  cloud:
    - github
---

# detect-github-actions-secret-disclosure

## Attack pattern

The classic CI exfil vector. A workflow that consumes a secret in any
form GitHub's runtime can recognize (`$MY_SECRET`, `${{ secrets.X }}`)
gets stdout-redacted automatically — every literal occurrence of the
secret value in the log is replaced with `***`. The interesting
failure mode is when the secret is *transformed* before being logged:

- `echo -n "$MY_SECRET" | base64`
- `echo "$MY_SECRET" | xxd -p`
- `gh auth status --show-token | jq -r .token | base64`

The base64 / hex / JWT-encoded form does not match the redactor's
literal-value table, so it goes to the log uncensored. Anyone who can
read the workflow log can decode it back to the secret.

GitHub does not emit the workflow log content in the audit log — this
detector assumes an upstream ingester that fetches the per-run job log
via the `GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs` REST
API and wraps it under `unmapped.github.workflow_log_excerpt`.

## Detection logic

For each OCSF 1.8 API Activity (class `6003`) event whose
`metadata.product.feature.name` is `ingest-github-audit-log-ocsf`:

1. Require `unmapped.github.workflow_log_excerpt` to be non-empty.
2. Require the excerpt to contain `***` (proof a secret was present).
3. Require at least one high-entropy substring (≥ 32 chars) matching:
   - JWT shape (`eyJ...eyJ...`),
   - base64-ish (`[A-Za-z0-9+/=_-]{32,}` with Shannon entropy
     ≥ 3.5 bits/byte),
   - or pure hex (`[0-9a-fA-F]{32,}` with entropy ≥ 3.5 bits/byte).
4. Require the workflow run to have completed successfully
   (`unmapped.github.workflow_status == "completed"` /
   `"success"` / `"succeeded"`, or — when the upstream did not surface
   workflow_status — `status_id == 1`).
5. Fire **once per matching event**.

The finding carries length-truncated *previews* of the high-entropy
substrings (`<first8>...<last4>`) so the operator can correlate
against the raw log without the full secret travelling on the wire.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding
projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["github-actions-secret-disclosure",
  "OWASP-LLM-Top-10-LLM02"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1552`
  (Unsecured Credentials) plus sub-technique `T1552.004` (Private
  Keys), tactic `TA0006 Credential Access`
- `observables[]` carrying the actor, the repo, the workflow id, the
  API operation, and the src IP
- `evidence` carrying the raw event uid, the repo, the workflow id,
  the number of high-entropy substrings observed, and length-truncated
  previews

Severity is `CRITICAL` (severity_id `5`).

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
cat github_actions_logs.ocsf.jsonl \
  | python src/detect.py \
  > github_actions_secret_disclosure_findings.ocsf.jsonl

# Same input, native finding projection out:
cat github_actions_logs.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > github_actions_secret_disclosure_findings.native.jsonl
```

## Do NOT use

- On raw GitHub workflow logs before OCSF normalization
- As a generic high-entropy log scanner (we require both the `***`
  marker AND a surviving high-entropy substring AND a successful run)
- On non-GitHub API Activity 6003 events

## Tests

The test suite covers:

- positive: redacted `***` + a base64-encoded high-entropy substring +
  successful run fires CRITICAL
- positive: redacted `***` + a JWT-shaped substring + successful run
  fires CRITICAL
- positive: redacted `***` + a hex-encoded substring + successful run
  fires CRITICAL
- negative: log excerpt with `***` but no surviving high-entropy
  substring does NOT fire (the redactor caught it)
- negative: high-entropy substring with no `***` marker does NOT fire
  (no secret was in the run)
- negative: failed / cancelled workflow run does NOT fire (the secret
  was prevented from leaving the runner)
- negative: low-entropy candidate (`aaaa...` repeated) does NOT
  fire — entropy gate filters it out
- edge: duplicate metadata uid does not inflate finding count
- edge: malformed JSON line is skipped with stderr telemetry
- edge: non-GitHub producer is ignored

## Closes

This detector is one of the three detection deliverables of issue
[`#31`](https://github.com/msaad00/cloud-ai-security-skills/issues/31).
