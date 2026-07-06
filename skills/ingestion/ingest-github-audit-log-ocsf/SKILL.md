---
name: ingest-github-audit-log-ocsf
description: >-
  Convert verified GitHub Organization Audit Log rows into OCSF 1.8 or native
  records. Most actions normalize to API Activity (6003); IAM-shaped actions
  (`org.add_member`, `org.update_member`, `org.remove_member`,
  `team.add_member`, `team.remove_member`) route to User Access Management
  (3005); authentication actions (`account.login`, `account.failed_login`)
  route to Authentication (3002). Preserves GitHub natural IDs such as
  `_document_id`, `@timestamp`, `request_id`, repo, team, secret name,
  workflow id, hashed token, and visibility deltas under `unmapped.github.*`
  for SIEM-friendly dedupe and downstream detector consumption. Use when the
  user mentions GitHub audit log ingestion, GitHub Enterprise audit
  normalization, org-level GitHub event hooks, or feeding GitHub identity
  and API events into an OCSF pipeline. Do NOT use for raw Okta, Entra,
  Google Workspace, or AWS IAM logs. Do NOT use as a detector or policy
  engine — this skill only normalizes verified GitHub audit log payloads.
purpose: Convert verified GitHub Organization Audit Log rows into OCSF 1.8 or native records. The default route is API Activity 6003; IAM-shaped actions route to User Access Management 3005; authentication actions route to Authentication 3002.
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. No GitHub SDK required when audit-log payloads are
  already exported through the REST API (`/orgs/{org}/audit-log`), the
  log-streaming destination, or an event hook. Read-only — validates raw
  GitHub event shape and emits OCSF or native JSONL. Never calls write APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-github-audit-log-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: github
  capability: read-only
---

# ingest-github-audit-log-ocsf

Convert raw GitHub Organization Audit Log rows into OCSF 1.8 or native
events with deterministic IDs and verified field mappings.

## Use when

- You have GitHub Organization Audit Log exports from `/orgs/{org}/audit-log`,
  the audit log streaming destination (S3 / GCS / Azure Blob / Splunk / Datadog
  / Amazon Event Bridge), or archived JSON and need OCSF output
- You want to normalize GitHub identity, repo, secret, and workflow telemetry
  for SIEM, lake, MCP, or downstream detection use
- You need a portable event stream that preserves GitHub `_document_id`,
  `@timestamp`, `actor`, and `request_id` identifiers
- You want org-member and team-membership updates represented as OCSF user
  access events instead of vendor-only audit records

## Do NOT use

- On Okta, Entra, Workspace, CloudTrail, or Kubernetes audit logs
- To collect live GitHub logs by itself — upstream collection and auth stay
  outside this skill
- To infer ATT&CK techniques or create findings directly
- To rewrite or mutate GitHub objects (orgs, repos, teams, secrets,
  workflows, tokens)

## Input contract

Accepts one of four raw GitHub Organization Audit Log shapes:

1. **REST API array** (`/orgs/{org}/audit-log`)

```json
[
  {
    "_document_id": "abc123",
    "@timestamp": 1735689600000,
    "action": "personal_access_token.access_granted",
    "actor": "alice",
    "actor_id": 1001,
    "org": "acme"
  }
]
```

2. **Single event** — bare JSON object

3. **NDJSON** — one JSON object per line (the streamed audit log format)

4. **Wrapper** — `{ "audit_log": [...] }`

The classification map covers the action families called out in GitHub's
docs:

- **API Activity 6003 (default route)** — `actions.*`, `codespaces.*`,
  `dependabot_secrets.*`, `personal_access_token.*`, `repo.*`, `team.*`,
  `git.*`, `workflows.*`, `members.invite`/`members.uninvite`,
  `org.create`/`org.delete`/`org.update_default_repository_permission`
- **User Access Management 3005** — `org.add_member`,
  `org.update_member`, `org.remove_member`, `team.add_member`,
  `team.remove_member`
- **Authentication 3002** — `account.login`, `account.failed_login`

Unsupported action names are skipped, never silently dropped. Each
occurrence emits an `unmapped_event_type` warning to `stderr` with the
offending `event_type` and event uid. At end of run, an
`unmapped_event_type_summary` info record reports total skipped, distinct
actions, and the top 10 unmapped actions with counts — so blind spots in
the classification map surface immediately in CI logs and log-search
dashboards.

## Output contract

Emits OCSF 1.8 JSONL by default, with `--output-format native` available
for the repo-owned canonical projection.

OCSF output uses these verified class mappings:

- **API Activity (6003)** for everything that does not match an explicit
  IAM or authentication action — repo, workflow, secret, PAT,
  organization-admin, team, and git-protocol actions
- **User Access Management (3005)** for org and team membership churn
- **Authentication (3002)** for `account.login` / `account.failed_login`

Each output record includes:

- deterministic `metadata.uid` based on GitHub `_document_id`, falling back
  to `id` or a stable SHA-256 hash of (timestamp, action, actor, repo,
  request_id)
- UTC epoch-millisecond `time` from `@timestamp` or `created_at`
- the GitHub action surfaced under `api.operation`
- repo / team / org surfaced under `resources[]`
- the actor IP, user agent, and country surfaced under `src_endpoint`
- vendor-specific detail (visibility flips, `selected_repositories` lists,
  secret name + type, workflow id + log excerpt, PAT scopes,
  `programmatic_access_type`, `hashed_token`, `request_id`) preserved
  under `unmapped.github.*` so downstream detectors can reach for the
  GitHub-specific signal without re-parsing the raw audit row

## Usage

```bash
# REST API export file
python src/ingest.py github-audit.json > github.ocsf.jsonl

# streaming-destination NDJSON from stdin
cat audit-stream.ndjson | python src/ingest.py > github.ocsf.jsonl

# explicit output path
python src/ingest.py github-audit.json --output github.ocsf.jsonl

# native projection for non-OCSF consumers
python src/ingest.py github-audit.json --output-format native > github.native.jsonl
```

## Security guardrails

- Read-only only. No GitHub writes. No subprocesses.
- Keeps vendor-native IDs (`_document_id`, `request_id`) for dedupe and
  correlation instead of inventing new random IDs.
- Uses verified raw fields from official GitHub docs only; unsupported
  action names are skipped rather than guessed.
- Normalizes into OCSF only where the class fit is explicit. Unmapped
  vendor-specific detail stays under `unmapped.github.*` for downstream
  detector access.

## Native output format

When `--output-format native` is selected, the skill emits:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type` — `api_activity` / `authentication` /
  `user_access_management`
- `event_uid`
- `provider: "GitHub"`
- `activity_id`, `event_type`, `severity`, `severity_id`, `status`,
  `status_id`, `time_ms`, `actor`, `src_endpoint`, `api`, `resources`,
  `http_request` where the source row supports them
- `unmapped.github.*` vendor-specific detail

## Closes

This skill is the ingest deliverable of issue
[`#31`](https://github.com/msaad00/cloud-ai-security-skills/issues/31) —
GitHub vendor story.

## See also

- [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) — shared OCSF wire contract
  and version pinning
- [`../ingest-okta-system-log-ocsf/SKILL.md`](../ingest-okta-system-log-ocsf/SKILL.md)
  — canonical multi-class IAM ingester template this skill mirrors
- [`../../detection/detect-github-pat-creation/SKILL.md`](../../detection/detect-github-pat-creation/SKILL.md)
  — downstream PAT-creation detector
- [`../../detection/detect-github-org-secret-exposure/SKILL.md`](../../detection/detect-github-org-secret-exposure/SKILL.md)
  — downstream org-secret-scope reduction detector
- [`../../detection/detect-github-actions-secret-disclosure/SKILL.md`](../../detection/detect-github-actions-secret-disclosure/SKILL.md)
  — downstream Actions workflow log disclosure detector
