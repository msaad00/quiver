---
name: detect-github-org-secret-exposure
description: >-
  Detect GitHub Actions / Codespaces / Dependabot org-level secret scope
  widening. Reads OCSF 1.8 API Activity (class 6003) records carrying
  `metadata.product.feature.name == "ingest-github-audit-log-ocsf"`,
  `api.operation IN ("actions.org_secret_create",
  "actions.org_secret_update", "dependabot_secrets.update",
  "codespaces.org_secret_update", "dependabot_secrets.create",
  "codespaces.org_secret_create")`, and an `unmapped.github.visibility`
  field. Fires when `visibility` flips from `selected` (named repos) to
  `all` (every repo in the org) — HIGH severity — or when
  `selected_repositories` expands by more than
  `GITHUB_ORG_SECRET_REPO_DELTA` repos (default 5) in a single event
  without flipping to `all` — MEDIUM severity. Maps to MITRE ATT&CK
  T1078.004 (Cloud Accounts — over-permissioning of a shared
  credential). Use when the user mentions "GitHub Actions org secret
  exposed", "Codespaces secret visibility widened", or "Dependabot secret
  scope reduction". Do NOT use as a posture-at-rest secret inventory or
  on non-GitHub API Activity 6003 events.
purpose: Detect GitHub org-level secret scope widening (visibility flip or large selected_repositories expansion).
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-github-org-secret-exposure
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP LLM Top 10
  cloud:
    - github
---

# detect-github-org-secret-exposure

## Attack pattern

GitHub Actions / Codespaces / Dependabot org-level secrets carry the
shared credentials that workflows in the org use for cloud auth, image
registry pulls, package publishes, and SaaS API tokens. The two scope
controls are:

- **`visibility`** — `all` (every repo in the org), `private` (every
  non-public repo), or `selected` (only the repos in
  `selected_repositories`)
- **`selected_repositories`** — when `visibility == "selected"`, the
  explicit allow-list of repos that can read the secret

Both controls are tamper-evident: changing either emits a fresh
audit-log row carrying both the new value and the previous value.

The exposure path is widening: an attacker who has gained admin scope
on the org silently flips `visibility` from `selected` to `all`, or
adds a large set of repos (often including a public fork) to
`selected_repositories`, then triggers a workflow run in the newly
in-scope repo to read the secret.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` is `ingest-github-audit-log-ocsf`:

1. Match `api.operation` against the org-secret operation set
   (`actions.org_secret_*`, `codespaces.org_secret_*`,
   `dependabot_secrets.*`).
2. Require `status_id == 1` (success).
3. Compare `visibility` against `before_visibility`:
   - If `visibility == "all"` AND `before_visibility != "all"` → fire
     **HIGH** (reason: `visibility_flip_to_all`).
4. Otherwise compare `selected_repositories` vs
   `before_selected_repositories`:
   - If `len(selected) - len(before_selected) >
     GITHUB_ORG_SECRET_REPO_DELTA` (default `5`) AND `visibility !=
     "all"` → fire **MEDIUM** (reason:
     `selected_repositories_expanded`).
5. Fire **once per matching event**.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding
projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["github-org-secret-exposure",
  "OWASP-LLM-Top-10-LLM02"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1078`
  (Valid Accounts) plus sub-technique `T1078.004` (Cloud Accounts),
  tactic `TA0001 Initial Access`
- `observables[]` carrying the actor, the org, the secret name, the
  API operation, the new and previous visibility, and the src IP
- `evidence` carrying the raw event uid, the org, the secret name,
  the reason code, the visibility delta, the repo-count delta, and
  the configured threshold

Severity is `HIGH` for visibility flips to `all`; `MEDIUM` for repo
count deltas above the threshold.

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
cat github_audit.ocsf.jsonl \
  | python src/detect.py \
  > github_org_secret_exposure_findings.ocsf.jsonl

# Same input, native finding projection out:
cat github_audit.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > github_org_secret_exposure_findings.native.jsonl

# Tune the repo-count delta threshold:
GITHUB_ORG_SECRET_REPO_DELTA=10 python src/detect.py < github_audit.ocsf.jsonl
```

## Do NOT use

- On raw GitHub audit-log JSON before OCSF normalization
- As a posture-at-rest secret inventory or rotation check
- On non-GitHub API Activity 6003 events (we filter on
  `metadata.product.feature.name == "ingest-github-audit-log-ocsf"`)

## Tests

The test suite covers:

- positive: visibility flip from `selected` to `all` fires HIGH
- positive: `selected_repositories` expansion past threshold fires
  MEDIUM
- negative: shrinking `selected_repositories` (scope reduction) does
  NOT fire
- negative: failed org-secret update (`status_id != 1`) does NOT fire
- negative: non-GitHub producer is ignored
- edge: threshold override via `GITHUB_ORG_SECRET_REPO_DELTA` env var
- edge: duplicate metadata uid does not inflate finding count
- edge: malformed JSON line is skipped with stderr telemetry

## Closes

This detector is one of the three detection deliverables of issue
[`#31`](https://github.com/msaad00/cloud-ai-security-skills/issues/31).
