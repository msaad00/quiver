# Skill Contract

This document defines the minimum contract for a shipped skill in `cloud-ai-security-skills`.

The goal is to keep skills:

- easy for humans to review
- safe for agents to call
- grounded in official references
- deterministic enough to test and trust

## Required layout

Every shipped skill under `skills/<category>/<skill-name>/` must include:

- `SKILL.md`
- `src/`
- `tests/`
- `REFERENCES.md`

Optional:

- `infra/`
- `examples/`
- `RUNBOOK.md`

## Required metadata

`SKILL.md` must include YAML frontmatter with:

- `name`
- `description`
- `purpose`
- `capability`
- `persistence`
- `telemetry`
- `privilege_escalation`
- `license`
- `approval_model`
- `execution_modes`
- `side_effects`
- `input_formats`
- `output_formats`

Optional:
- `network_egress`
- `concurrency_safety`
- `caller_roles`
- `approver_roles`
- `min_approvers`
- `mcp_timeout_seconds`

## Trust-heuristic fields

The five trust-heuristic fields feed `agent-bom skills scan` so the
purpose-and-capability and persistence-and-privilege axes resolve to
`pass` / `info` instead of `warn`. They live immediately after
`description` so a human reviewer sees the trust posture before the
operational metadata.

- `purpose` — one-sentence purpose statement. Distinct from
  `description`, which carries the full routing prose. Derive from the
  first sentence of `description`.
- `capability` — the layer verb the skill performs. Allowed values:
  - `ingest` — skills under `skills/ingestion/`
  - `detect` — skills under `skills/detection/`
  - `discover` — skills under `skills/discovery/`
  - `evaluate` — skills under `skills/evaluation/`
  - `view` — skills under `skills/view/`
  - `output` — skills under `skills/output/`
  - `remediate` — skills under `skills/remediation/`
  - legacy values `read-only`, `write-cloud`, `write-identity`,
    `write-sink`, `write-storage` remain valid where already declared
    and continue to drive the MCP tool registry's read-only hint.
- `persistence` — declares what the skill persists:
  - `none` — read-only skills with `side_effects: none`
  - `audit_log` — skills that emit findings via a `writes-audit` scope
  - `cloud_state` — skills under `skills/remediation/` (mutate cloud
    resources)
- `telemetry` — declares what runtime telemetry is emitted. Every
  shipped skill uses `stderr_jsonl` because runtime logs route through
  `skills/_shared/logging.py`.
- `privilege_escalation` — declares the cloud privilege the skill
  needs:
  - `none` — ingest/detect/view/output (no live cloud calls)
  - `read` — discover/evaluate (cloud read APIs)
  - `read_write` — remediation (cloud write APIs)

`scripts/add_skill_trust_frontmatter.py` derives all five values from
existing frontmatter and the skill's path, never from guesses; running
`python scripts/add_skill_trust_frontmatter.py --check` is a CI gate
that refuses drift.

Rules:

- `name` must match `^[a-z0-9-]+$`
- `name` must be 64 characters or fewer
- `description` must clearly state when the skill should be used
- `description` must clearly state what the skill must not be used for
- `approval_model` must be one of:
  - `none`
  - `dry_run_required`
  - `human_required`
- `execution_modes` must be a comma-separated subset of:
  - `jit`
  - `ci`
  - `mcp`
  - `persistent`
- `execution_modes: persistent` means the skill can be embedded unchanged in a long-lived runner, queue consumer, scheduler, or serverless loop.
- `persistent` does **not** imply that this repo already ships a dedicated runner, daemon, Lambda wrapper, or sink for that skill.
- if a skill is the exception and does ship a repo-owned persistent entrypoint, document that explicitly in `SKILL.md`
- `side_effects` must be a comma-separated subset of:
  - `none`
  - `writes-cloud`
  - `writes-identity`
  - `writes-storage`
  - `writes-database`
  - `writes-audit`
- `side_effects: none` must appear by itself, never combined with write scopes
- read-only skills must set:
  - `approval_model: none`
  - `side_effects: none`
- write-capable skills must set:
  - `approval_model: human_required`
  - one or more explicit write scopes in `side_effects`
- `input_formats` must be a comma-separated subset of:
  - `raw`
  - `canonical`
  - `native`
  - `ocsf`
- `output_formats` must be a comma-separated subset of:
  - `raw`
  - `native`
  - `ocsf`
  - `bridge`
- every skill must declare the formats it supports today, even if only one mode is implemented
- `concurrency_safety` must be one of:
  - `stateless`
  - `requires_consistent_sharding`
  - `operator_coordinated`
- `stateless` means the skill has no repo-local mutable state and can be parallelized safely on independent inputs
- `requires_consistent_sharding` means the skill is safe to parallelize only when batching or sharding preserves the logical correlation window
- `operator_coordinated` means concurrency is possible, but the caller should coordinate around remote quotas, writes, approvals, or append semantics
- `network_egress`, when present, must be a comma-separated list of hostnames or wildcard hostnames such as:
  - `api.workday.com`
  - `*.snowflakecomputing.com`
  - `*.databricks.com`
  - `*.clickhouse.cloud`
- `caller_roles`, when present, should name the human or agent roles allowed to invoke the skill
- `approver_roles`, when present, should name the roles allowed to approve write-capable actions
- `min_approvers`, when present, must be an integer greater than or equal to 1
- `mcp_timeout_seconds`, when present, must be an integer between 1 and 900 and names the per-call subprocess timeout the MCP wrapper should apply to this skill. It is opt-in; skills that do not declare it inherit the global default (60 seconds) or whatever the operator sets via the `CLOUD_SECURITY_MCP_TIMEOUT_SECONDS` env var. The env var wins over the per-skill value so on-call can widen or tighten the window without editing `SKILL.md`
<<<<<<< HEAD
- write-capable skills should declare `approver_roles` and `min_approvers` when enterprise wrappers need machine-readable approval policy; the repo MCP wrapper uses them to require `_approval_context` and enforce approver count
- `approver_roles` is policy metadata, not proof that every local CLI path validates role membership itself; a `SKILL.md` body should only claim in-code role enforcement when the shipped handler or wrapper actually performs that check
=======
- write-capable skills should declare `approver_roles` and `min_approvers` when enterprise wrappers need machine-readable approval policy; the repo MCP wrapper uses them to require `_approval_context` and enforce approver count
>>>>>>> origin/main
- write-capable skills should preserve caller, approver, and request or session identifiers in their audit trail when the runtime provides them

## Required language

Each `SKILL.md` must contain both:

- `Use when`
- `Do NOT use`

This keeps routing explicit and guardrails visible for Claude, Codex, Cursor, Windsurf, Cortex Code CLI, and other MCP-aware agents.

Write-capable skills should also include a body-level `## Do NOT do` section for
operator anti-patterns that must never be bypassed.

## Required references

`REFERENCES.md` must point to the official documentation, schema, API, benchmark, or framework the skill relies on.

Blogs, opinion posts, and vendor marketing pages may be helpful during authoring,
but they are not authoritative references for shipped skills.

Examples:

- AWS / Azure / GCP official docs
- Kubernetes docs
- OCSF schema docs
- MITRE ATT&CK / MITRE ATLAS
- SARIF spec

## Required behavior

- read-only by default unless the skill is explicitly a remediation/write path
- no hidden side effects
- deterministic output where practical
- explicit input/output shape
- defensive parsing on untrusted input
- explicit human-in-the-loop and runtime-mode declaration in frontmatter so agents know when they must stop for approval
- preserve caller, approver, and execution identity context when the surrounding runtime provides it

## How Code Blocks Work

Code blocks in `SKILL.md` are documentation examples, not executable code.

The relationship is:

- YAML frontmatter:
  - machine-readable metadata for validators, MCP tool registration, and wrappers
- `SKILL.md` body:
  - human-and-agent-readable guidance such as usage examples, composition paths, prerequisites, and schema notes
- `src/<entry>.py`:
  - the actual executable implementation

This means:

- shell examples show how to invoke a skill directly
- composition examples show how skills chain together
- SQL or infrastructure examples show prerequisites the skill expects
- wrappers and MCP ignore `SKILL.md` code blocks at execution time and call the real Python entrypoint instead

## Required validation and error handling

- validate every untrusted input boundary before calling a cloud API or parser
- fail closed on unknown or malformed data
- write machine-usable results to `stdout` and human debugging detail to `stderr`
- return non-zero exit codes on contract-breaking failures
- surface partial-data / skipped-record behavior explicitly rather than silently dropping it
- follow the repo-wide exit-code meanings in [`ERROR_CODES.md`](ERROR_CODES.md) when the skill documents or adopts codes beyond `0` and `1`

## API drift and deprecation handling

- cite only official docs, schemas, APIs, or benchmarks in `REFERENCES.md`
- prefer stable SDKs and documented API versions over ad hoc REST calls
- pin dependencies at the repo level and update them in grouped batches
- add or update tests whenever a provider changes response shape, enum values, or required fields
- treat deprecated APIs as a compatibility event: document the replacement, add coverage for both shapes during migration, then remove the old path intentionally

## Required tests

- at least one test module under `tests/`
- golden fixtures where they make sense
- malformed input or failure-path coverage for parsers and converters
- regression coverage for provider-specific parsing quirks or deprecated/alternate response shapes

## CI enforcement

CI currently validates:

- required files exist
- `name` format is valid
- `Use when` and `Do NOT use` are present
- `approval_model`, `execution_modes`, and `side_effects` are present and valid
- `input_formats` and `output_formats` are present and valid
- `concurrency_safety` is present, valid, and in canonical frontmatter order
- read-only skills do not use subprocess/shell execution
- write-capable skills document and test dry-run behavior
- write-capable skills explicitly require human approval
- wildcard IAM / RBAC policy entries carry an explicit `WILDCARD_OK` justification

The contract will expand over time, but new CI rules should only be added when the current tree already satisfies them.

## Throttling, errors, and logs

Every shipped skill follows a single shared contract for retries,
errors, and structured logs. The three modules under
[`skills/_shared/`](../skills/_shared/) are the source of truth:

| Concern | Module | Helper |
|---|---|---|
| Rate-limit / 5xx retries with bounded backoff | `skills/_shared/retry.py` | `@retry_on_throttle()` decorator + `retry_call()` functional API |
| Structured error envelope | `skills/_shared/errors.py` | `SkillError` hierarchy + `emit_error()` |
| Structured logs (one-line JSON on stderr) | `skills/_shared/logging.py` | `get_logger(__name__, skill=..., layer=...)` |

### Retry rules — read before you tune

The retry helper is **bounded by construction**:

- Hard attempt cap: default 5, never below 1 or above 10.
- Hard wall-clock budget: default 60s from the first call, ceiling 600s.
- Bounded backoff: `min(base × 2^attempt, cap)` with full-jitter; cap defaults to 16s.
- Permanent errors short-circuit — no budget burn.
- A retry helper never calls another retry helper for the same function.
  Tested explicitly so we cannot reintroduce the `attempts^2` loop.

If a skill needs different limits, it sets the SKILL.md frontmatter
fields `retry_max_attempts` / `retry_total_budget_seconds` and reads
them in code via `RetryPolicy(...)` — the schema validator pins the
ranges so a misconfigured skill cannot silently disable the cap.

### Error envelope

The `SkillError` hierarchy partitions every failure into one of five
buckets a SIEM can route on:

```
SkillError
├── ConfigError       (1)   missing env / bad SKILL.md / bad CLI args
├── AuthError         (2)   401 / 403 / no creds / bad role
├── PermanentError    (1)   4xx that retries cannot fix
├── TransientError    (75)  rate-limited / 5xx / network blip
└── ContractError     (1)   caller violated the skill contract
```

Numbers in parentheses are the exit code `emit_error()` returns to the
shell. `75` is `EX_TEMPFAIL` so a host runner / wrapper can retry; the
others are permanent failures that should propagate.

### Logging shape

```json
{
  "timestamp": "2026-05-09T23:45:00.123Z",
  "level": "warning",
  "logger": "skills.detection.detect_okta_mfa_fatigue.src.detect",
  "skill": "detect-okta-mfa-fatigue",
  "layer": "detection",
  "correlation_id": "f3c4-…",
  "message": "rate-limited by Okta — retrying"
}
```

Every shipped skill stamps `skill`, `layer`, and the
`SKILL_CORRELATION_ID` env var (set by the MCP wrapper, the webhook
receiver, and the runners) so audit replays join on a single key.
Operators tail the wrapper's stderr through `jq`; SIEMs ingest the
same shape.
