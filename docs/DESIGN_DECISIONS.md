# Design Decisions

This file explains the major product and architecture decisions behind
`cloud-ai-security-skills`: what the repo is, why it is shaped this way, and
what features enterprise security teams can rely on today.

Use this doc when you want the rationale. Use [`ARCHITECTURE.md`](./ARCHITECTURE.md)
when you want the design contract. Use [`NATIVE_VS_OCSF.md`](./NATIVE_VS_OCSF.md)
when you want the schema-mode decision tree.

## What ships today

Current repo surface on `main`:

- shipped skills across ingestion, discovery, detection, evaluation, view, and
  remediation
- `3` read-only source adapters:
  - `source-snowflake-query`
  - `source-databricks-query`
  - `source-s3-select`
- `3` write-capable sinks:
  - `sink-snowflake-jsonl`
  - `sink-clickhouse-jsonl`
  - `sink-s3-jsonl`
- `2` query-pack families under `packs/`:
  - `lateral-movement`
  - `privilege-escalation-k8s`
- `3` reference persistent runners:
  - AWS `aws-s3-sqs-detect`
  - GCP `gcp-gcs-pubsub-detect`
  - Azure `azure-blob-eventgrid-detect`
- signed CycloneDX SBOM generation in CI and on releases
- MCP exposure through the same `SKILL.md + src/ + tests/` contract

## Product position

This repo is not a SIEM, not a multi-tenant SaaS runtime, and not a monolithic
security platform.

It is a library of:

- security skills
- reference runners
- reference sinks
- query packs
- trust and contract docs

The goal is to let enterprise teams run the same detection, evaluation,
inventory, and response logic:

- from the CLI
- in CI
- behind MCP / agent workflows
- inside serverless wrappers
- inside customer-owned warehouses and lakes

without forking the logic per runtime.

## Decisions

### 1. Keep the skill contract small and strict

Every shipped skill is a standalone bundle:

- `SKILL.md`
- `src/`
- `tests/`
- `REFERENCES.md`

The contract is:

- stdin + args in
- stdout out
- stderr for warnings / telemetry
- non-zero exit on contract-breaking failure

Why:

- MCP wrapping stays straightforward
- CI execution stays reproducible
- agent tooling does not need special integration paths
- reviewers can audit a skill locally without booting extra infrastructure

### 2. Keep side effects at the edges

Pure skills are the default. Side effects are allowed only in a narrow set of
places:

- `source-*` reads external systems
- `remediate-*` writes to cloud / identity systems
- `sink-*` writes to storage
- `runners/` own the long-lived loop and checkpoint behavior

Why:

- read-only analysis stays easy to trust
- risky behavior is isolated and auditable
- blast radius stays obvious in code review

### 3. OCSF by default for streams, native-first for operational artifacts

The repo operates across four schema modes:

- `raw`
- `native`
- `canonical`
- `ocsf`
- `bridge`

In practice:

- `native` is the repo-owned external wire format
- `canonical` is the stable internal normalization layer
- `ocsf` is the interoperable external mode
- `bridge` preserves repo or source detail alongside OCSF transport

Why:

- event and finding streams benefit from a standard wire format, so OCSF is the
  default there
- operational artifacts such as evaluation results, discovery/evidence output,
  sink summaries, and remediation plans are repo-owned contracts and stay
  native-first
- some source domains fit OCSF well, others need `bridge` or `unmapped` detail
- forcing everything into OCSF increases loss and confusion
- enterprise teams need both interoperability and source fidelity

This is why the repo is neither “OCSF-only” nor “two equal random options.”
The actual posture is:

- OCSF-default for event and finding streams
- native-first for operational artifacts

### 4. Keep canonical internal, stable, and boring

The repo normalizes different source families into a stable internal model
before projecting outward.

Why:

- cross-cloud joins need stable internal keys
- metrics, inventories, evidence, and state stores should not depend on a
  lossy wire format
- changing external transport should not require rethinking the whole repo

### 5. Use repo-native mode for operational contracts

`native` is the repo’s stable external format for:

- native findings
- evaluation results
- discovery and evidence artifacts
- sink summaries
- remediation plans and audit artifacts

Why:

- these artifacts are part of the repo’s own product contract
- they often need fields OCSF does not model well
- enterprise operators need deterministic, explicit repo-owned output

### 6. Use SQL packs where the warehouse is the runtime

The repo now ships a `packs/` layer because not every useful execution path
should move data through Python.

Use a query pack when:

- the data already lives in a warehouse
- you want zero egress
- the analytic is better run in SQL

Why:

- warehouse-native execution is often the right operational answer for large
  enterprises
- this keeps Python skills clean while still supporting in-lake detection

### 7. Prefer additive platform layers over skill forks

The repo adds:

- `source-*` adapters
- `sink-*` adapters
- `packs/*`
- `runners/*`

instead of forking every detector per storage engine or cloud.

Why:

- `detect-lateral-movement` should stay a detection, not become a storage SDK
- per-warehouse skill forks drift quickly
- orthogonal layers compose better than runtime-specific clones

### 8. Keep writes human-gated and dry-run first

Write-capable skills carry an explicit HITL envelope:

- `approval_model: human_required`
- explicit caller and approver roles
- `--dry-run` default for sinks and remediation paths

Why:

- enterprise security teams need reviewable intent
- production response should be reversible and explainable
- “agent-safe” is not credible without a visible approval model

### 9. Make persistence idempotent and replay-safe

Every persistence edge should converge safely on replay:

- deterministic identifiers
- append-only or merge-safe semantics
- dedupe at the edge where needed

Why:

- queue retries and reruns are normal
- operators should not fear replay
- production-grade systems need convergence, not one-shot assumptions

### 10. Prefer official vendors first, canonical OSS second

Dependency policy is:

1. official vendor SDKs first
2. repo-owned code second
3. canonical OSS only when needed

Why:

- provenance and maintenance matter in security tooling
- enterprise reviewers ask where a dependency comes from and why it exists

## Feature map

| Need | Shipped surface |
|---|---|
| Normalize raw telemetry | `ingest-*` |
| Detect attacks on event streams | `detect-*` |
| Evaluate posture or benchmarks | `evaluation/*` |
| Inventory cloud / AI assets | `discover-*` |
| Persist findings or evidence | `sink-*` |
| Run continuously | `runners/*` |
| Run in a warehouse | `packs/*` |
| Drive from agents | `mcp-server/` |

## What enterprise teams can rely on

Today the repo is credible for:

- read-only analysis
- benchmark and posture evaluation
- agent-driven investigations
- CI-driven policy and evidence pipelines
- serverless continuous ingest -> detect -> notify patterns
- customer-controlled sink persistence
- warehouse-native detection where a pack exists

What still requires more breadth, not a rethink:

- more query packs
- more sink vendors
- more response families beyond IAM departures
- stricter internal typing on every skill family

## What this repo is not trying to do

- replace a SIEM
- own a hosted control plane
- hide cloud-specific detail behind a fake universal schema
- make every artifact OCSF whether it fits or not
- turn every skill into a storage connector

The design goal is narrower and more useful:

build trustworthy, composable security skills and edge layers that enterprise
teams can run in their own environments with clear contracts, explicit trust
boundaries, and minimal surprises.
