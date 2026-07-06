# Changelog

All notable changes to `cloud-ai-security-skills` should be recorded here.

This changelog is intentionally **repo-level**, not per-skill semver. The repo
is released as one trust boundary: one CI bar, one MCP wrapper, one validation
model, one security posture. Individual skills track maturity and contract
metadata inside their own docs.

The format is loosely based on Keep a Changelog.

## [Unreleased]

### Revert Quiver repo slug and finish name cleanup

- Renamed the GitHub repository back to **`msaad00/cloud-ai-security-skills`**
  (redirects from `msaad00/quiver` still work). Updated clone URLs, CI badges,
  MCP server name, default OCSF `metadata.product.vendor_name`, golden fixtures,
  release SBOM asset names, and integration docs to match.
- Display name remains **Cloud AI Security Skills** (`cloud-ai-security-skills`
  in OCSF product metadata and `pyproject.toml`). Dropped vague "agent-safe"
  positioning from the GitHub About blurb and README tagline.
- Replaced the crowded hero banner with a minimal layout: title, one-line value
  prop, four stats, and eight **Simple Icons** (CC0) vendor marks — including
  the real Snowflake and ClickHouse paths, not placeholder glyphs.
- Slimmed the README: shorter quickstart, collapsed lake hero walls into doc
  links, and added a clear **LangGraph vs LangChain vs skills** table.
- Removed Quiver logo/social-preview assets from the default README path.

### Snowflake security data lake — hero use case end-to-end

`packs/snowflake/` turns Snowflake into a closed-loop security data lake, the
warehouse-native counterpart to the ClickHouse hero pack. It is the DDL
contract behind the existing `sink-snowflake-jsonl` (write) and
`source-snowflake-query` (read) skills — no new application code is needed to
stand the lake up.

- DDL: `events_sink` / `findings_sink` / `evidence_sink` / `audit_sink` with
  VARIANT payloads, clustering keys, Time Travel, and suspended retention
  tasks; a `tenant_role_map` + row access policy isolate tenants by
  `payload:cloud.account.uid`.
- Rollups as **dynamic tables** (incremental, auto-refreshing): findings by
  rule/hour, events by OCSF class/day, remediation outcomes/day.
- Optional **Snowflake-managed Apache Iceberg** variant
  (`ddl/07_iceberg_open_format.sql`) keeps the lake in open Parquet, readable
  and writable by external engines through the Horizon Catalog — no engine
  lock-in.
- Replay query templates plus the [`docs/SNOWFLAKE_DATA_LAKE.md`](docs/SNOWFLAKE_DATA_LAKE.md)
  hero walk-through and a closed-loop architecture diagram. ARCHITECTURE.md
  PR AC is marked shipped.

### Databricks vendor-depth detection — closes Databricks column under #436

Five new Databricks detectors complete the 6/6 plan for the Databricks
column in #436 (the first, `detect-databricks-token-creation`, shipped in
v0.11.0). Together they cover MITRE ATT&CK T1098.003, T1059.004 + T1546,
T1537, T1552.001 and MITRE ATLAS AML.T0040 across the Databricks
control plane:

- `detect-databricks-unity-catalog-cross-workspace-share` — T1537. Fires
  on `unityCatalog.{Create,Update}{Recipient,Share}` events when the
  recipient is external or outside `DATABRICKS_AUTHORIZED_RECIPIENTS`
  (fail-open default).
- `detect-databricks-mlflow-model-exfil` — ATLAS AML.T0040 + ATT&CK
  T1567. Fires on `mlflow.downloadArtifact` /
  `mlflow.getModelVersionDownloadUri` or cross-workspace
  `transitionModelVersionStage`; one finding per (model, actor) tuple per
  24h via `DATABRICKS_MLFLOW_DEDUPE_WINDOW_MIN`.
- `detect-databricks-cluster-init-script-abuse` — T1059.004 + T1546.
  Fires on `clusters.{create,edit}` whose `init_scripts[].destination`
  falls outside `DATABRICKS_INIT_SCRIPT_ALLOWED_PATHS` or matches the
  unsafe shell-command pattern.
- `detect-databricks-workspace-admin-grant` — T1098.003. Fires on
  `accounts.setAdmin` or `iam.addUserToGroup` (`admins` /
  `account_admins`) when the granter is not in
  `DATABRICKS_AUTHORIZED_GRANTERS` or the event UTC hour is outside
  `DATABRICKS_GRANT_WINDOW_HOURS_UTC` (default `08-18`).
- `detect-databricks-secret-scope-read-burst` — T1552.001. Fires when
  one principal reads ≥ `DATABRICKS_SECRET_READ_THRESHOLD` distinct
  secrets from the same scope within
  `DATABRICKS_SECRET_READ_WINDOW_MIN` minutes (defaults 30 / 10).

Skill counts move from 112 → 117 total and 59 → 64 detection. #436
remains open for the five remaining ClickHouse detectors.

### ClickHouse hero data-lake story — closes the lake loop

The ClickHouse story is now bidirectional. The existing
`sink-clickhouse-jsonl` (write side) is paired with a new
`source-clickhouse-query` skill on the read side, mirroring the Snowflake
and Databricks query adapters. Both skills together let any `detect-*`,
`view-*`, or `discover-control-evidence` skill **replay from the lake**
without re-ingesting from the vendor.

- `skills/ingestion/source-clickhouse-query/` — read-only SQL allowlist
  (`SELECT` / `WITH` / `SHOW` / `DESCRIBE`); rejects comments, multiple
  statements, session controls, admin verbs; auto-registered as an MCP
  tool by the existing registry walker.
- `packs/clickhouse/` — DDL + materialized views + read-side query
  templates that turn ClickHouse into the substrate the architecture doc
  has been calling for under PR AA. Tables: `security.events_sink`
  (90-day TTL hot tier), `security.findings_sink` (365-day TTL),
  `security.evidence_sink` (7-year compliance hold), `security.audit_sink`
  (legal-hold retention). Materialized views: findings-by-rule hourly,
  events-by-class daily, remediations-by-outcome daily. Row policies
  isolate by `cloud.account.uid`.
- `docs/CLICKHOUSE_DATA_LAKE.md` — end-to-end hero use case walking
  through ingest → lake → detect → replay → close-loop.
- `docs/images/clickhouse-data-lake.svg` +
  `docs/diagrams/clickhouse-data-lake.mmd` — architecture diagram of the
  closed loop.
- README gets a hero subsection pointing at all of the above.

Skill counts move from 117 → 118 total and 3 → 4 source.

## [0.11.0] — 2026-05-11 — Vendor breadth + AI-native depth + trust posture

Skills count on `main`: **112** (15 ingest + 3 sources, 5 discover, 59 detect,
11 evaluate, 12 remediate, 2 view, 3 output). The last six weeks closed
**nine open roadmap issues** (#31, #33, #198, #199, #253, #255, #403, #404,
#405, #406, #415, #419, #420, #435 partial, #436 partial) across vendor
breadth (GitHub + Slack), AI-native depth (MITRE ATLAS + OWASP LLM/MCP Top
10 to 40%), cloud ATT&CK (exfil + defense-evasion to 50%), runtime
reliability (CI runner-e2e harness), trust posture (security-grade A,
five SKILL.md frontmatter fields enforced by agent-bom), and positioning
(`WHY.md`, `INGEST_COVERAGE.md`, three-flavours framing).

### AI-native depth closed (closes #255 — MITRE ATLAS + OWASP LLM/MCP to 40%)

Six new MCP detectors closing #255 fully (8/8 planned). PR #480 shipped
the first three (`detect-mcp-model-artifact-tampering` — ATLAS
AML.T0010 + OWASP LLM03; `detect-mcp-model-token-flood` — OWASP LLM04 +
LLM10; `detect-mcp-plugin-supply-chain` — OWASP LLM05 + OWASP MCP Top
10, schema-walker for nested `oneOf`/`anyOf`/`allOf`/`properties`/
`items`/`$ref`/`default`/`description`). PR #481 shipped the closing
three (`detect-mcp-unbounded-tool-output` — OWASP LLM10 + ATLAS
AML.T0034; `detect-mcp-adversarial-input-corpus` — ATLAS AML.T0043 with
a 33-fingerprint catalog at `src/fingerprints.json` citing OWASP LLM
example bank + NIST AI 600-1 + public jailbreak corpora;
`detect-mcp-shadow-tool-injection` — OWASP MCP Top 10 / T1195.001
out-of-band-baseline twin to `detect-mcp-tool-drift`).

### Cloud ATT&CK exfil + defense-evasion column closed (closes #253)

Final 2 of 4 planned ATT&CK detectors land, closing #253. PR #479
shipped the first pair (`detect-aws-s3-cross-region-replication` —
T1537/T1567 — and `detect-gcp-outbound-peering-anomaly` — T1071.001/
T1041). This PR ships the remaining pair.

- **`detect-azure-private-endpoint-to-external-sub`** — T1071.001 /
  T1567 HIGH. Fires when an Azure `Microsoft.Network/privateEndpoints/
  write` event carries a `privateLinkServiceConnections[]` entry whose
  `privateLinkServiceId` first `/subscriptions/<guid>/` segment names
  a subscription **outside** `AZURE_PRIVATE_ENDPOINT_AUTHORIZED_SUBS`.
  Walks every connection (a private endpoint can pin multiple link
  services) and emits one finding per (resource_uid,
  target_subscription) tuple. Fail-open with stderr warning when the
  allow-list is empty, mirroring `detect-snowflake-unauthorized-grant`.
- **`detect-aws-cloudtrail-event-selector-tampering`** — T1562.001
  HIGH. Fires on `PutEventSelectors` or `UpdateTrail` events that
  structurally narrow the trail's audit scope: `IncludeManagementEvents`
  flipped to false, `ReadWriteType` set to `None`, an empty
  `EventSelectors[]` array, or `IsMultiRegionTrail` collapsed from true
  to false. Documents the honest boundary: per-event-selector
  data-resource subtraction requires upstream diff context (a single
  audit event does not carry a before-snapshot), and the detector
  consumes `unmapped.cloudtrail.event_selector_change.removed_data_resources`
  under signal `data_resources_removed` when upstream surfaces the
  diff.

**Counts bumped: detection 54 → 56, repo total 107 → 109. ATT&CK
coverage on #253 closed at 4/4 detectors.**

### Vendor depth — SaaS column kickoff (closes #31, closes #33)

The first two SaaS vendor stories land together: GitHub (#31) and Slack
(#33). Both follow the Okta multi-class IAM ingester pattern — one ingester
normalizing into multiple OCSF wire classes depending on the source event
family — and each ships with three detectors covering the persistence,
scope-widening, and exfil arcs.

#### GitHub (closes #31)

- **`ingest-github-audit-log-ocsf`** — Organization Audit Log → OCSF.
  Most actions route to API Activity 6003; IAM-shaped (`org.*_member`,
  `team.*_member`) route to User Access Management 3005; auth actions
  (`account.login`, `account.failed_login`) route to Authentication 3002.
  Preserves `request_id`, visibility deltas, `selected_repositories`,
  secret name + type, workflow log excerpt, PAT scopes, and `hashed_token`
  under `unmapped.github.*`. `unmapped_event_type` stderr telemetry +
  end-of-run summary, same contract as the Okta ingester post-#458.
- **`detect-github-pat-creation`** — T1098.001. Fires HIGH on successful
  `personal_access_token.create` / `.access_granted`.
- **`detect-github-org-secret-exposure`** — T1078.004. Fires HIGH when
  org Actions / Codespaces / Dependabot secret `visibility` flips to
  `all`, MEDIUM when `selected_repositories` expands past
  `GITHUB_ORG_SECRET_REPO_DELTA` (default 5).
- **`detect-github-actions-secret-disclosure`** — T1552.004 CRITICAL.
  Fires when a successful workflow log contains BOTH GitHub's `***`
  redaction marker AND a high-entropy substring (≥ 32 chars,
  base64/hex/JWT) the redactor missed — classic CI exfil-via-encoding
  vector. Length-truncated previews ship; full secret never on the wire.

#### Slack (closes #33)

- **`ingest-slack-audit-ocsf`** — Audit Logs API (`/audit/v1/logs`,
  Enterprise Grid) → OCSF. Authentication 3002 for session events, User
  Access Management 3005 for membership and role-change, API Activity
  6003 for app / file / channel-create. Preserves natural IDs
  (`context.location`, `context.session_id`, `details.workspace_type`,
  `details.scopes`, `details.app`) under `unmapped.slack.*`. Same
  `_classify_event` + `unmapped_event_type_summary` aggregator.
- **`detect-slack-external-channel-add`** — T1078.004 HIGH. External
  workspace guest added to a sensitive channel matching
  `SLACK_SENSITIVE_CHANNEL_PATTERNS`.
- **`detect-slack-oauth-app-install-broad-scope`** — T1098.005 HIGH.
  Third-party app install grants `chat:write` plus a read scope (or any
  `*:write` wildcard) and the app id is not in
  `SLACK_PREAPPROVED_APP_IDS`.
- **`detect-slack-admin-elevation`** — T1098.003 HIGH. Workspace
  Admin / Owner role grant where the granter is not in
  `SLACK_AUTHORIZED_GRANTERS` (fail-open by default) or the event hour
  falls outside `SLACK_GRANT_WINDOW_HOURS_UTC` (default `08-18`).

Both GitHub and Slack rows move from the `docs/INGEST_COVERAGE.md`
Roadmap table into the Shipped table. **Combined counts: ingest 15 → 17,
detect 43 → 49, total 94 → 102.**

### Trust posture + visibility

- **Composite security grade A (99/100)** (#475) — `pytest 9.0.3` bump
  closes CVE-2025-71176; `pip>=26.1` floor closes CVE-2026-6357 + CVE-2026-3219;
  `pip-audit` 3 → 0. Five new `SKILL.md` frontmatter fields enforced
  by `add_skill_trust_frontmatter.py --check` and the `skill-contract`
  CI gate: `purpose`, `capability`, `persistence`, `telemetry`,
  `privilege_escalation` — all 112 skills carry them.
- **`docs/SECURITY_GRADES.md`** (#473) — auto-generated by
  `scripts/regen_security_grades.py`. Four scanner rows (Bandit /
  in-repo validators / pip-audit / agent-bom credentials) → composite
  grade. Weekly GitHub Action regenerates and `--check`s for drift.
- **`docs/WHY.md`** (#473, #474) — three-flavours positioning: agent
  writes Python at runtime / agent writes skills you commit / your
  team writes 90 from scratch — each with a separate answer.
- **`docs/INGEST_COVERAGE.md`** (#471) — canonical vendor × source
  × OCSF class matrix. 18 mappings shipped (AWS / GCP / Azure /
  Entra / K8s / Okta / Workspace / MCP / GitHub / Slack).
- **CI runner-e2e harness** (#467, closes #198, #199) — three runner
  templates (`webhook-receiver`, `mcp-sse`, `cloud-runner-aws-s3-sqs`)
  exercised end-to-end against ephemeral local backends. p50/p95
  numbers tracked in `docs/RUNTIME_PROFILES.md`, regenerated on the
  scheduled CI run.
- **MCP SSE / streamable-HTTP transport + Helm/Docker rollout** (#463,
  #466, closes #415) — slice 1 added the bearer-auth SSE listener
  with HMAC-chain audit parity; slice 2 added the cloud-runner Helm
  chart + bearer-key rotation contract with overlap windows.

### Vendor depth — Snowflake column completed (#436 partial)

- **`detect-snowflake-failed-mfa-burst`** — credential stuffing / MFA bombing
  against Snowflake's login surface. Reads OCSF Authentication 3002 events
  normalized from `account_usage.login_history`, fires when failed-MFA events
  for one principal cross `SNOWFLAKE_MFA_FAIL_THRESHOLD` (default 8) inside
  `SNOWFLAKE_MFA_FAIL_WINDOW_MIN` (default 10) (T1110 / T1621, severity HIGH).
- **`detect-snowflake-session-policy-bypass`** — persistence via session-policy
  idle-timeout widening. Fires on `ALTER SESSION POLICY` /
  `CREATE SESSION POLICY` events that raise `SESSION_IDLE_TIMEOUT_MINS` or
  `SESSION_UI_IDLE_TIMEOUT_MINS` above `SNOWFLAKE_SESSION_POLICY_MAX_IDLE_MINS`
  (default 30) (T1098.003, severity HIGH).
- **`detect-snowflake-network-policy-disable`** — cloud-firewall impairment.
  Fires on `ALTER ACCOUNT SET NETWORK_POLICY = NULL` or any network-policy
  modification that adds `0.0.0.0/0` / `::/0` to the allowed IP list
  (T1562.007, severity HIGH).
- **`detect-snowflake-replication-config-change`** — account / database
  replication used as exfiltration. Fires on `ALTER ACCOUNT SET REPLICATION`,
  `ALTER DATABASE ... ENABLE REPLICATION TO ACCOUNTS`, and the failover-group
  variants when any target account is outside
  `SNOWFLAKE_AUTHORIZED_REPLICATION_TARGETS`; default allowlist empty fails
  open with a stderr warning so operators see the missing config (T1537,
  severity HIGH).
- **Snowflake column under #436 fully landed (6/6).** Counts bumped: detection
  39 → 43, repo total 90 → 94. Remaining 11 detectors (5 Databricks, 5
  ClickHouse, 1 ClickHouse vendor-depth slot) stay open.

## [0.10.0] — 2026-05-10 — Vendor depth, AI governance, runtime reliability

Skills count on `main`: **90** (15 ingest, 5 discover, 39 detect, 11 evaluate,
12 remediate, 2 view, 3 output, 3 sources). First vendor-depth detection
slice on Snowflake / ClickHouse / Databricks, four NIST AI RMF 1.0 evaluators,
runner reliability bundle closes, authenticated MCP SSE / streamable-HTTP
transport with a rotation contract, and the audit-honesty trio lands.

### Vendor depth — Snowflake / Databricks / ClickHouse (#436 partial)

- **`detect-snowflake-bulk-data-egress`** (#462) — warehouse egress slice.
  Groups OCSF API Activity by `actor.user.uid` over a 60-min window, fires on
  combined `bytes_scanned` / `rows_unloaded` / `stage_name` thresholds (T1567).
- **`detect-snowflake-share-creation` / `-account-key-creation` /
  `-warehouse-resize-burst` / `-unauthorized-grant`** (#468) — T1537 / T1098.001
  / T1496 / T1098.003 covering data shares, RSA auth, compute-scale anomaly,
  and privileged-role grants.
- **`detect-clickhouse-bulk-export`** (#464) — `system.query_log` filter on
  `INTO OUTFILE` / `INSERT INTO FUNCTION s3(` / `URL(`, fires on cumulative
  `read_bytes` crossing the byte threshold (T1567). **`detect-databricks-token-creation`**
  (#465) — fires on successful `tokens/create` (T1098.001), emits
  `unmapped_event_type` stderr telemetry for ops not yet in the map.
- **7 of 18 #436 detectors shipped; 11 remain** (4 Snowflake, 5 Databricks,
  5 ClickHouse).

### AI governance (#435 partial)

- **`evaluate-nist-ai-rmf-govern` / `-map` / `-measure` / `-manage`** (#469)
  — one evaluator per NIST AI RMF 1.0 core function, 10 curated subcategories
  each (**40 total**), emitted as OCSF Compliance Finding 2003 per
  subcategory. Each SKILL.md carries the caveat that this is a
  manifest-completeness audit, not the qualitative org-level assessment NIST
  AI RMF requires. **8 of 12+ #435 evaluators shipped.**

### Runtime reliability (#198, #199 closed)

- **CI-driven runner e2e harness + auto-generated runtime profiles** (#467)
  exercising the three runner templates; writes the p50/p95 table into
  `docs/RUNTIME_PROFILES.md` on every scheduled run. First numbers (N=20):
  `mcp-sse` jsonrpc-ping 23.86/49.16 ms, `webhook-receiver` cloudtrail-ingest
  75.83/77.58 ms, `cloud-runner-aws-s3-sqs` ingest 32.24/33.96 ms — regression
  sentinels, not customer-scale throughput.

### MCP transport surface (#415 closed)

- **SSE + streamable-HTTP transport with bearer auth** (#463, slice 1) —
  authenticated listener alongside the stdio wrapper; preserves existing
  trust controls and HMAC-chained audit. **Helm/Docker deployment + bearer-key
  rotation contract** (#466, slice 2).

### Audit honesty (#406, #403, #404 closed)

- **Azure subscription parser refactor, Okta unmapped-event counter,
  golden-fixture provenance doc** (#458) — closes the ambient-subscription
  footgun (#406), surfaces Okta event types not in the recognized map (#403),
  and documents fixture collection + review (#404).

### Quality / infrastructure

- **Per-detector precision/recall scorer** (#460, closes #419) and
  **captured-fixture corpus with provenance gate** (#459, closes #420) —
  quantitative detector scoring replaces the "looked good on a fixture" proxy.
- **CSPM evaluation depth +542 tests** (#461, closes #405), **banner overflow
  + skill-index doc** (#454), **mypy upper bound bumped to <3** (#457).

### Changed

- Detection 32 → 39; evaluation 7 → 11; total 79 → 90. Benchmark checks
  91 → 131 (91 CIS + 40 NIST AI RMF subcategories).

## [0.9.0] — 2026-05-10 — Agentic posture: trust contract, coverage depth, sandboxing

Skills count on `main`: **79** (15 ingest, 5 discover, 32 detect, 7 evaluate,
12 remediate, 2 view, 3 output, 3 sources). Three new web-app detectors land
the first OWASP Top 10 coverage; CIS depth hits the 50%-per-platform target on
all three clouds; the sandboxing umbrella closes; the cross-cutting reliability
contract is shipped + exercised on 19 of 32 detectors.

### Coverage milestones

- **CIS AWS Foundations v3**: 20 → 29 controls = **50%** (#445, closes #432)
- **CIS Azure Foundations v2.1**: 8 → 32 controls = **53%** (#448, closes #433)
- **CIS GCP Foundations v3**: 10 → 30 controls = **50%** (#449, closes #434)
- **OWASP Top 10**: 0 → 30% (#446, closes #431) — A01 broken access control · A03 injection · A07 auth failures
- **#254** umbrella per-platform CIS target: hit across all three clouds

### Added

- **Cross-cutting reliability contract** (#437, closes #429). `skills/_shared/{retry,errors,logging}.py`. Bounded exponential-backoff retry with hard floors / ceilings, `SkillError` hierarchy + `emit_error()` envelope, JSON-formatted structured logger that propagates `SKILL_CORRELATION_ID`. Migrated onto 19 detectors (#443, #444, #451).
- **Sandboxing umbrella closed** (#427).
  - Layer 1 — container hardening (#438): non-root UID 65532, read-only rootfs, `--cap-drop=ALL`, `no-new-privileges`, default seccomp. Helm chart + hardened Dockerfile for both webhook receiver and MCP server.
  - Layer 2 — opt-in OS sandbox (#447): `bwrap` (Linux) / `sandbox-exec` (macOS), per-skill profile derived from SKILL.md `network_egress`. Off by default; `CLOUD_SECURITY_MCP_SANDBOX=on`.
  - Layer 3 — RLIMIT enforcement (#428): `RLIMIT_AS` 1 GB · `RLIMIT_FSIZE` 100 MB · `RLIMIT_CPU` mirrors wrapper timeout. Always-on for every skill subprocess.
- **Durable HMAC-chained audit** (#410, closes #396). One JSONL record per resolved tool call; `prev_hash` + `chain_hash` keyed by `CLOUD_SECURITY_AUDIT_HMAC_KEY`; tamper-evident. New `scripts/verify_audit_chain.py`.
- **MCP wrapper hardening** (#424, closes #413 #414). `additionalProperties: false` on context objects; structured tool annotations replace the description blob (`category`, `capability`, `approvalModel`, `executionModes`, `sideEffects`, `inputFormats`, `outputFormats`, `networkEgress`, `callerRoles`, `approverRoles`, `minApprovers`).
- **Webhook receiver runner** (#426, closes #425). FastAPI app, default-deny routing, per-skill HMAC + bearer auth, sink fan-out to S3 / Snowflake / ClickHouse. Hardened image + Helm chart.
- **Python SDK shim** (#439). `skills/_shared/library.py` lets external Python apps call shipped skills as functions with the same trust controls.
- **Persistent worker pool** (#452, closes #416). Opt-in via `CLOUD_SECURITY_MCP_WORKER_POOL=on`; one warm interpreter per skill; idle TTL + output-overflow kill. ~10× cold-start savings on CSPM benchmark walks.
- **Skill composition contract** (#422). `docs/SKILL_COMPOSITION.md` + four shipped presets (`presets/preset-*.json`) + reference workflow under `examples/workflows/`.
- **Harness doc** (#439). `docs/HARNESS.md` indexes the five customization surfaces, pins the scope boundary, and traces every Anthropic-published recommendation to the in-repo file that satisfies it.
- **Three Mermaid diagrams** (#442, closes #418). `docs/diagrams/`: MCP trust boundary · multi-agent topology · pipeline blast radius.
- **Auto-generated coverage snapshot** (#430). `docs/COVERAGE_SNAPSHOT.md` regenerable from `framework-coverage.json`; CI gate refuses drift.
- **Per-framework control coverage** (#441). Depth metric (covered control IDs / framework total), not skill count proxy.
- **76 → 79 MCP-callable skills** (#411). Top-level `handler.py` shims for the three `iam-departures-*` remediation skills closed the README's "76 shipped" overclaim.

### CI / DX

- **Tier-2 jobs parallelised** (#450). `lint` / `skill-contract` / `type-check` no longer chain serially. Critical-path PRs ~6-8 min → ~3-4 min.
- **Batched doc-regen check** with a unified self-heal hint. Top-level `Makefile` with `make docs-regen` / `docs-check` / `validate` / `test` / `ruff`.
- **Structural validator** (#412) — fails closed on stale or half-built skill subtrees.
- **Behavioral skill-runtime validator** (#409) — every shipped skill imports cleanly. Coverage floors 80% global + per-layer.
- **Preset CI gate** (#422) — `scripts/validate_presets.py` refuses any preset referencing a skill that does not ship.

### README

- Tightened to leading-OSS shape (#440, Langfuse / ClickHouse pattern). 339 → 150 lines. Quickstart promoted above architecture; Trust Posture replaces three prose paragraphs with one eight-row table.
- Hero banner refresh (#421, #423) — new wordmark "agentic security skills for cloud and AI", framework pills extended to MITRE ATT&CK / ATLAS / OWASP Top 10 / OWASP LLM Top 10.

## [0.8.1] — 2026-04-24 — Freeze hardening and release sweep fix

Skills count on `main`: **73** (15 ingest, 5 discover, 26 detect, 7 evaluate,
12 remediate, 2 view, 3 output, 3 sources).

### Hardened

- **Kubernetes RBAC revoke now has an explicit cluster boundary** —
  [`remediate-k8s-rbac-revoke`](skills/remediation/remediate-k8s-rbac-revoke/)
  no longer trusts ambient kube context under `--apply`. Operators must set
  `K8S_CLUSTER_NAME`, and that active cluster must be named explicitly in
  `K8S_RBAC_REVOKE_ALLOWED_CLUSTERS` before a binding delete can run. Dry-run
  and reverify remain read-only.
- **Kubernetes container-escape quarantine now has an explicit cluster boundary** —
  [`remediate-container-escape-k8s`](skills/remediation/remediate-container-escape-k8s/)
  now requires `K8S_CLUSTER_NAME` plus
  `K8S_CONTAINER_ESCAPE_ALLOWED_CLUSTERS` before any `--apply` quarantine,
  pod-kill, or node-drain can proceed. The write path fails closed with
  `skipped_cluster_boundary` when the active cluster is outside the allow-list.

### Changed

- **Repo freeze guidance now says the quiet part out loud** — top-level docs
  now describe writable skills as being pinned to explicit environment
  boundaries such as account, project, tenant, org, or cluster allow-lists
  before `--apply`, not just HITL-gated in the abstract.
- **The release sweep is mechanically clean again** — `scripts/run_mypy.sh`
  now skips empty `src/` directories instead of failing on skill paths that no
  longer contain Python entrypoints.

## [0.8.0] — 2026-04-24 — Cross-cloud ATT&CK depth and repo truth sync

Skills count: **65** (15 ingest, 5 discover, 18 detect, 7 evaluate, 12 remediate,
2 view, 3 output, 3 sources).

### Added

- **Cross-cloud logging-impairment ATT&CK slices** — the repo now ships
  narrow, high-confidence T1562.001 defense-evasion detectors across the three
  major clouds:
  [`detect-cloudtrail-disabled`](skills/detection/detect-cloudtrail-disabled/),
  [`detect-gcp-audit-logs-disabled`](skills/detection/detect-gcp-audit-logs-disabled/),
  and
  [`detect-azure-activity-logs-disabled`](skills/detection/detect-azure-activity-logs-disabled/).
  This closes the first honest AWS / GCP / Azure logging-impairment trio in the
  detection layer without overstating broader policy-drift coverage that is not
  yet shipped.
- **AI-native MCP credential-leak detection** —
  [`detect-agent-credential-leak-mcp`](skills/detection/detect-agent-credential-leak-mcp/)
  scans native MCP `tools/call` response bodies for high-confidence leaked
  credential material (AWS access keys, GitHub tokens, OpenAI keys, Slack
  tokens) and emits masked findings only — never raw secrets.
- **Balanced CSPM depth expansion across AWS, GCP, and Azure** — the benchmark
  surface now covers **91 checks** total after adding AWS CloudTrail KMS /
  data-events / GuardDuty / Security Hub coverage, GCP audit logging / default
  VPC / Private Google Access coverage, and Azure CMK / Network Watcher
  coverage.
- **First guarded CSPM auto-remediation slice** —
  [`cspm-aws-cis-benchmark`](skills/evaluation/cspm-aws-cis-benchmark/) now
  supports `--auto-remediate` for a narrow AWS-first control set with dry-run
  planning, dual audit, protected-resource deny-lists, and explicit `--apply`
  confirmation.

### Hardened

- **Explicit target-boundary enforcement on write-capable remediators** — AWS,
  GCP, Azure, and Entra remediation paths now require explicit account /
  project / subscription / tenant allow-lists before `--apply` can mutate
  anything. Ambient cloud context is no longer trusted by itself.
- **MCP approval enforcement now matches the documented HITL contract** — the
  MCP wrapper exposes approval context in its schema, enforces `min_approvers`,
  and keeps remediation `handler.py` skills dry-run-safe instead of silently
  depending on undocumented wrapper fields.
- **Session and CSPM apply boundaries are zero-trust by default** — AWS CSPM
  auto-remediation, session revocation, network revoke, and Entra credential
  revoke now fail closed when the caller identity is outside the explicitly
  allowed boundary for that skill.

### Changed

- **Repo truth surfaces are aligned again** — README, roadmap, framework
  mappings, changelog, version metadata, and the core diagrams now all agree on
  the current shipped state: **65 skills, 18 detectors, 91 checks**.
- **Count-drift validation is stricter** — the repo count validator now checks
  the count-bearing SVG and progress-table surfaces that previously drifted
  during rapid PR sequences.

## [0.7.0] — 2026-04-23 — Release alignment and coverage hardening

Skills count: **61** (15 ingest, 5 discover, 14 detect, 7 evaluate, 12 remediate,
2 view, 3 output, 3 sources).

### Added

- **Correlation of worker actions with CloudTrail** — STS
  `AssumeRole` in the IAM departures worker Lambda now embeds the
  first 8 characters of the Lambda `aws_request_id` in the
  `RoleSessionName`, so CloudTrail `AssumeRole` events, DynamoDB audit
  rows, and S3 audit objects can be cross-referenced during incident
  response.
- **Retries on transient HR-source failures** —
  `skills/discovery/iam-departures-reconciler/src/reconciler/sources.py`
  `fetch_departures` in all four sources (Snowflake, Databricks,
  ClickHouse, Workday) now wraps its query in a shared `_with_retry`
  helper: 3 attempts by default, exponential backoff starting at
  1.5 s. Tunable via the `HR_SOURCE_FETCH_ATTEMPTS` and
  `HR_SOURCE_FETCH_BASE_DELAY` env vars. Previously a single transient
  connection or query hiccup would drop a whole reconciler run,
  extending the departure-remediation window by up to a full scheduler
  interval.
- **Lambda reserved concurrency on Parser and Worker** — both the
  CloudFormation template and the Terraform module now declare
  `ReservedConcurrentExecutions` on the two IAM-departures Lambdas.
  Parser=1 (single-shot per manifest), Worker=10 to match the
  `step_function.asl.json` Map `MaxConcurrency`. Prevents the Map
  fan-out from starving other functions in the account, and prevents
  unrelated burst traffic from starving the remediation pipeline.
- **Standalone IAM departures planner skill** —
  [`skills/discovery/iam-departures-reconciler`](skills/discovery/iam-departures-reconciler/)
  now owns the shared read-only manifest-planning boundary. Rehire,
  grace-window, hash, and canonical-manifest logic are no longer mixed
  into the AWS write-path bundle.
- **Provider-scoped control evidence depth** —
  [`discover-cloud-control-evidence`](skills/discovery/discover-cloud-control-evidence/)
  now carries clearer provider-native evidence depth for logging,
  segmentation, encryption, and key-management surfaces instead of
  flattening them into one cross-cloud coverage story.

### Fixed

- **Worker Lambda audit writes no longer silently swallowed** —
  `skills/remediation/iam-departures-aws/src/lambda_worker/handler.py`
  previously caught every exception in the DynamoDB and S3 audit writes
  with `except Exception: logger.exception(...)` and still returned
  `status=remediated`. If both stores failed (KMS disabled, bucket
  rotation mid-flight, DynamoDB throttle), the IAM user was deleted
  with no durable audit record and the Step Function reported success.
  Introduces `AuditWriteError`, tracked per-store write outcomes, and a
  new `remediated_audit_failed` worker response status so Step Function
  DLQ / alerting fires on audit gaps instead of masking them. Dual-write
  redundancy is preserved: a single-store failure no longer raises as
  long as the other store succeeded.
- **Workday OAuth error handling cannot leak response bodies** —
  `WorkdayAPISource._get_token` previously called
  `resp.raise_for_status()`, which surfaces an `httpx.HTTPStatusError`
  whose repr may include tenant URLs. On failure the `health_check`
  caller logged via `logger.exception`, which writes the traceback and
  the exception's repr. Replaced with an explicit check: network
  errors raise `RuntimeError(f"... unreachable ({ExcType})")` and HTTP
  errors raise `RuntimeError(f"... returned HTTP {status_code}")`.
  Response bodies and inner exception messages are never re-raised or
  logged. `health_check` now logs only the exception type name.
- **`detect-lateral-movement` runtime metadata now matches the
  documented provider scope** — the machine-readable coverage metadata
  no longer advertises generic identity coverage where the shipped
  detector is explicitly scoped to AWS role sessions, GCP IAM
  Credentials and service-account keys, and Azure control-plane / Entra
  pivots.
- **`discover-environment` provider tests no longer fail lightweight CI
  lanes on missing `moto`** — AWS-specific provider coverage now skips
  cleanly when `moto` is absent instead of failing import-time
  collection in jobs that intentionally install only the cloud SDK set.

### Changed

- **ATT&CK provider-scope language is now explicit in the docs** — the
  AWS slice of `detect-lateral-movement` is pinned to shipped
  role-session anchors, and the GCP slice is pinned to service-account
  and IAM Credentials anchors, so roadmap depth is tracked without
  overstating current provider coverage.
- **Coverage depth across shipped evaluation and discovery skills is
  materially higher** — new test suites now cover the runner, CLI, and
  error branches for the AWS, GCP, and Azure CIS benchmark skills plus
  the provider-specific discovery paths in `discover-environment`.
- **README release state and shipped-surface visuals are aligned to
  current `main`** — the repo badge, release metadata, skill counts,
  coverage captions, and the core SVG diagrams now agree on the current
  61-skill surface and render without footer text collisions.

## [0.6.0] — 2026-04-18 — Closed-loop hardening

First release that claims both **SIEM-ready producer** AND **closed-loop
remediation**, with the guardrails to back the claims.

Skills count: **46** (15 ingest, 4 discover, 10 detect, 7 evaluate, 2 remediate,
2 view, 3 output, 3 sources).

### Added

- **First end-to-end detect → act → audit → re-verify loop shipped** —
  [`detect-credential-stuffing-okta`](skills/detection/detect-credential-stuffing-okta/)
  (T1110 / T1110.003, [#260](https://github.com/msaad00/cloud-ai-security-skills/pull/260))
  paired with [`remediate-okta-session-kill`](skills/remediation/remediate-okta-session-kill/)
  ([#264](https://github.com/msaad00/cloud-ai-security-skills/pull/264)).
  Covers both detection families — the new credential-stuffing detector and
  the existing MFA-fatigue detector — with a single HITL-gated containment
  skill (revoke sessions + OAuth refresh tokens) that honors a hard deny-list
  of protected principals, requires a declared incident window before
  `--apply` fires, and dual-audits every step (DynamoDB + KMS-encrypted S3)
  before AND after the Okta API call.
- **OCSF 1.8 schema validator at the wire** ([#243](https://github.com/msaad00/cloud-ai-security-skills/issues/243),
  [#267](https://github.com/msaad00/cloud-ai-security-skills/pull/267)) —
  [`skills/_shared/ocsf_validator.py`](skills/_shared/ocsf_validator.py) plus
  a CI hook ([`scripts/validate_golden_ocsf.py`](scripts/validate_golden_ocsf.py))
  that replays every golden fixture through the validator on every PR.
  Catches required-field drift, cross-field invariant violations
  (`type_uid == class_uid * 100 + activity_id`, `category_uid` matches
  class), enum-range bugs, metadata pinning drift, and the "forgot to multiply
  epoch seconds by 1000" bug class. Two pre-existing drifts caught and
  fixed on first run.
- **SKILL.md frontmatter ↔ src/ runtime contract check** ([#257 part A](https://github.com/msaad00/cloud-ai-security-skills/pull/268)) —
  `validate_safe_skill_bar.py` now verifies that a writable skill's `src/`
  actually implements the dry-run + audit guardrails its frontmatter promises,
  and that a read-only skill's `src/` never invokes a cloud-SDK write method.
  Catches the silent-HITL-bypass bug class at lint time.
- **Generalized remediation re-verify contract** ([#257 part B](https://github.com/msaad00/cloud-ai-security-skills/pull/269)) —
  [`skills/_shared/remediation_verifier.py`](skills/_shared/remediation_verifier.py)
  + [`docs/REMEDIATION_VERIFICATION.md`](docs/REMEDIATION_VERIFICATION.md).
  Three outcomes: VERIFIED / DRIFT / UNREACHABLE. A DRIFT outcome emits both a
  native audit record AND an OCSF 2004 Detection Finding with
  `finding_types: ["remediation-drift"]` so the SIEM alerting that already
  exists for the original attack pattern picks up drift automatically.
- **HITL policy matrix codified** ([#259](https://github.com/msaad00/cloud-ai-security-skills/issues/259),
  [#265](https://github.com/msaad00/cloud-ai-security-skills/pull/265)) —
  [`docs/HITL_POLICY.md`](docs/HITL_POLICY.md) lists the `approval_model` per
  finding class × reversibility × blast radius. Privilege-escalation-adjacent
  actions (cross-account trust edits, MCP tool quarantine, audit-table
  mutations) require `min_approvers: 2`. The HITL gate is documented to sit
  OUTSIDE the agent loop so prompt injection cannot spoof approval.
- **OCSF applicability framing** ([#261](https://github.com/msaad00/cloud-ai-security-skills/issues/261),
  [#266](https://github.com/msaad00/cloud-ai-security-skills/pull/266)) — docs
  now state the honest stance: OCSF is the SIEM interop wire format for
  **ingest** and **detect**; **native / CycloneDX / bridge** are correct for
  **discover**, **remediate**, and **sinks**. ARCHITECTURE.md, README.md,
  skills/README.md, and CLAUDE.md all carry the per-layer applicability table.
- first AI-native detector family slice: `detect-prompt-injection-mcp-proxy`
  for suspicious prompt-injection and instruction-smuggling language in MCP
  tool descriptions

### Hardened

- **Dropped redundant `iam:*` allows on iam-departures-aws parser + worker
  roles** ([#244](https://github.com/msaad00/cloud-ai-security-skills/issues/244),
  [#262](https://github.com/msaad00/cloud-ai-security-skills/pull/262)).
  Both Lambdas call IAM exclusively through the cross-account assumed role;
  direct allows on their own execution roles were never used. Removed and
  replaced with a defense-in-depth `Deny iam:* Resource: *` so any future edit
  reintroducing a direct grant is still caught by the Deny. Same change
  applied across JSON + CloudFormation + Terraform.
- **CI lint — every `sts:AssumeRole` Allow must carry an org/account/tag
  boundary condition** ([#256 part 1](https://github.com/msaad00/cloud-ai-security-skills/issues/256),
  [#263](https://github.com/msaad00/cloud-ai-security-skills/pull/263)).
  `validate_safe_skill_bar.py` fails the build on any AssumeRole Allow without
  `aws:PrincipalOrgID` / `aws:SourceAccount` / `aws:PrincipalTag` / `aws:SourceOrgID`
  (or an explicit `ASSUME_ROLE_CONDITION_OK` justification, symmetric to
  `WILDCARD_OK`). Trust-policy service-principal statements are exempt.

### Added (earlier)

- first AI-native detector family slice: `detect-prompt-injection-mcp-proxy`
  for suspicious prompt-injection and instruction-smuggling language in MCP
  tool descriptions

### Added

- [`scripts/benchmark_runtime_profiles.py`](scripts/benchmark_runtime_profiles.py) plus a checked-in runtime snapshot at [`docs/benchmarks/runtime-profiles-2026-04-16.json`](docs/benchmarks/runtime-profiles-2026-04-16.json) so the representative sizing tables in [`docs/RUNTIME_PROFILES.md`](docs/RUNTIME_PROFILES.md) can be regenerated from code instead of drifting as prose.
- a `Runtime Benchmarks` workflow plus [`scripts/check_runtime_profile_regressions.py`](scripts/check_runtime_profile_regressions.py) so the benchmark harness can run on demand, nightly, and on pull requests that touch benchmarked code, dependency, or baseline-snapshot surfaces, comparing scaling behavior against the checked-in baseline instead of relying on timestamp-sensitive JSON diffs.

### Changed

- tightened mypy from the shared/runtime surfaces into one additional shipped detector bucket. `detect-entra-role-grant-escalation`, `detect-google-workspace-suspicious-login`, and `detect-mcp-tool-drift` now run with `--disallow-untyped-defs --disallow-incomplete-defs --warn-return-any` in `scripts/run_mypy.sh`, while the rest of the skill catalog stays on gradual per-directory checking.
- batched downstream publish in the shipped runner detect paths so AWS uses SNS `publish_batch`, GCP keeps Pub/Sub publish futures outstanding until the batch is queued and then waits once, and Azure sends Service Bus findings in grouped batches instead of one API call per finding. The runner READMEs now also include exact first-event walkthrough skeletons and evidence capture checklists, while still stating honestly that real-cloud proof capture remains pending.
- tightened the read-only query gate for `source-snowflake-query` and `source-databricks-query`. They still are not full SQL parsers, but they now reject SQL comments, dynamic identifier helpers, `SYSTEM$` calls, and common control/write keywords in addition to rejecting multiple statements and non-read-only statement families.
- CI now checks `uv.lock` freshness with `uv lock --check`, and the checked-in lockfile was refreshed to match the current `pyproject.toml` so local `uv` workflows fail on real dependency drift instead of stale metadata.
- added three defense-in-depth parity fixes from the post-v0.5.0 audit: the GCP runner now writes `expires_at` dedupe documents and enables Firestore TTL, the Azure runner now carries an `expires_at` replay window and treats expired dedupe rows as replaceable, and MCP tool calls now generate a `correlation_id` that is recorded in the wrapper audit event, returned in `structuredContent`, and forwarded into skill stderr telemetry via `SKILL_CORRELATION_ID`. The IAM departures parser and worker roles now explicitly deny `states:StartExecution` in the standalone policy JSON and the deployable CloudFormation/Terraform definitions so the documented "never bypass EventBridge" rule is enforced in infrastructure as well as prose.
- optimized `detect-lateral-movement` to index candidate flows instead of repeatedly rescanning the full flow set per anchor, and added a duplicate-heavy regression test so the faster path preserves the same findings while keeping the benchmarked 10x case in line with the documented runtime envelope.
- calibrated two "zero trust" overclaims. [`docs/ROADMAP.md`](docs/ROADMAP.md) now lists "least privilege" with the credential-preference expansion from [`docs/CREDENTIAL_PROVENANCE.md`](docs/CREDENTIAL_PROVENANCE.md) and splits HITL + dual audit into the read-only-by-default bullet, rather than bundling all three under "zero trust". [`skills/remediation/iam-departures-aws/SKILL.md`](skills/remediation/iam-departures-aws/SKILL.md) renames its "Zero trust" Security Principles bullet to "Scoped cross-account trust" and describes the actual mechanism ( `aws:PrincipalOrgID` condition gates role assumption from outside the organization) instead of labeling one IAM condition as a full zero-trust posture.
- enabled DynamoDB TTL on the AWS persistent runner dedupe table so the `runners/aws-s3-sqs-detect/` reference pattern no longer grows without bound. Flipped `TimeToLiveSpecification.Enabled` from `false` to `true` in [`runners/aws-s3-sqs-detect/template.yaml`](runners/aws-s3-sqs-detect/template.yaml), added a `DedupeTtlDays` CloudFormation parameter (default 30, range 1-365), and updated [`runners/aws-s3-sqs-detect/src/detect_handler.py`](runners/aws-s3-sqs-detect/src/detect_handler.py) to set an `expires_at` Unix-epoch attribute on every new dedupe row using the `DEDUPE_TTL_DAYS` env var. Added matching handler tests in [`tests/integration/test_runner_template.py`](tests/integration/test_runner_template.py) for default, configured, out-of-range, and non-integer TTL values. Pre-TTL rows are not backfilled and will remain until overwritten or removed manually; this is documented in [`runners/aws-s3-sqs-detect/README.md`](runners/aws-s3-sqs-detect/README.md).
- renamed `docs/LOSSY_MAPPINGS.md` to [`docs/SCHEMA_COVERAGE.md`](docs/SCHEMA_COVERAGE.md) and rephrased internal headers from "Lost at raw -> normalized" to "Dropped at raw -> normalized" so the file name and table framing describe coverage honestly instead of implying that every projection loses value. All inbound links in [`README.md`](README.md), [`docs/NATIVE_VS_OCSF.md`](docs/NATIVE_VS_OCSF.md), [`docs/NORMALIZATION_REFERENCE.md`](docs/NORMALIZATION_REFERENCE.md), [`docs/NORMALIZATION_EXAMPLES.md`](docs/NORMALIZATION_EXAMPLES.md), and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) were updated in the same change.
- collapsed the root [`ARCHITECTURE.md`](ARCHITECTURE.md) from 219 lines to a short index that aligns with the six-skill-layer story (ingest, discover, evaluate, detect, remediate, view) used by [`README.md`](README.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/images/repo-architecture.svg`](docs/images/repo-architecture.svg). The file no longer opens with "Five layers" or claims L5 View has "(none yet)" shipped skills; the per-layer inventory now reflects real shipped counts (15 ingest, 4 discover, 8 detect, 7 evaluate, 1 remediate, 2 view) and OCSF is called out as the shared wire-format contract rather than a numbered layer. Deeper design invariants continue to live in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- redrew [`docs/images/repo-architecture.svg`](docs/images/repo-architecture.svg) around three action bands — Intake (Ingest and Discover in parallel), Analyze (Detect and Evaluate in parallel), and Act (View and Remediate in parallel) — so the visual stops implying a linear L1 → L6 pipeline and instead matches the fan-out reality where Discover runs alongside Ingest, Evaluate runs alongside Detect, and View runs alongside Remediate. Dropped the unnumbered L7 / L8 / L9 edge labels; the edge-persistence, query-packs, and runtime-surfaces row now uses verb-first names without numbering. Lane copy now cites concrete shipped counts (15 ingesters, 4 discover skills, 8 detectors, 7 benchmarks, 1 remediation, 2 views) so readers see scope at a glance. Alt text and `<desc>` updated in [`README.md`](README.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/DIAGRAMS.md`](docs/DIAGRAMS.md).
- merged `docs/DEBUGGING.md` into [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) so operators have one troubleshooting surface with a "Fast checklist", a "Common symptoms" section (the former DEBUGGING content: native-mode failures, empty detector output, large-batch guidance, MCP invocation symptoms, cloud SDK import failures, schema drift), and an "FAQ" section (the former TROUBLESHOOTING content: `-ocsf` suffix meaning, native rollout, canonical output, persistent execution mode, read-only contract, approval gates, disappearance semantics, storage guidance). Inbound links in [`README.md`](README.md), [`docs/ERROR_CODES.md`](docs/ERROR_CODES.md), [`docs/USE_CASES.md`](docs/USE_CASES.md), and [`docs/STDERR_TELEMETRY_CONTRACT.md`](docs/STDERR_TELEMETRY_CONTRACT.md) were updated in the same change.

### Planned for v0.5.1

- add parser-hardening follow-up tests on the highest-volume ingestion paths so malformed mixed-shape input keeps failing closed without breaking valid records in the same batch
- improve visual accessibility and readability with diagram descriptions, clearer captions, and continued overlap cleanup in rendered SVGs
- continue post-release quality work such as mutation/property-based parser testing where it adds measurable confidence without changing shipped contracts

## 0.5.0 - 2026-04-15

### Added

- [`docs/NATIVE_VS_OCSF.md`](docs/NATIVE_VS_OCSF.md) and [`docs/STATE_AND_TIMELINE_MODEL.md`](docs/STATE_AND_TIMELINE_MODEL.md) to make `native`, `canonical`, `ocsf`, and `bridge` modes explicit and to pin historical-state, tombstone, and timeline expectations across just-in-time and persistent runs.
- [`docs/DEBUGGING.md`](docs/DEBUGGING.md) and [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) for operator-facing format, CI, and runtime troubleshooting.
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/DATA_HANDLING.md`](docs/DATA_HANDLING.md), [`docs/COMPLIANCE_MAPPINGS.md`](docs/COMPLIANCE_MAPPINGS.md), [`docs/SCHEMA_VERSIONING.md`](docs/SCHEMA_VERSIONING.md), [`docs/LOSSY_MAPPINGS.md`](docs/LOSSY_MAPPINGS.md), [`docs/ERROR_CODES.md`](docs/ERROR_CODES.md), [`docs/STDERR_TELEMETRY_CONTRACT.md`](docs/STDERR_TELEMETRY_CONTRACT.md), [`docs/MCP_AUDIT_CONTRACT.md`](docs/MCP_AUDIT_CONTRACT.md), and [`docs/RUNTIME_PROFILES.md`](docs/RUNTIME_PROFILES.md) to make the trust, schema, operator, procurement, and sizing story auditable from docs alone.
- `ingest-okta-system-log-ocsf` as the first external identity-vendor ingestion skill, mapping verified Okta System Log session, user lifecycle, and membership events into OCSF Authentication (3002), Account Change (3001), and User Access Management (3005).
- `detect-okta-mfa-fatigue` as the first Okta-native detection skill, emitting OCSF Detection Finding (2004) for repeated Okta Verify push challenge and denial bursts aligned to MITRE ATT&CK T1621.
- `ingest-entra-directory-audit-ocsf` as the Microsoft Entra / Graph identity-audit ingestion skill, mapping verified `directoryAudit` application, service-principal, app-role-assignment, and federated-credential events into OCSF API Activity (6003).
- `ingest-google-workspace-login-ocsf` as the Google Workspace identity-audit ingestion skill, mapping verified Admin SDK Reports login audit events into OCSF Authentication (3002) and Account Change (3001) while preserving Workspace natural IDs and event parameters.
- `detect-google-workspace-suspicious-login` as the first Google Workspace-native detection skill, emitting OCSF Detection Finding (2004) for provider-marked suspicious logins and repeated Workspace login failures followed by success, aligned to MITRE ATT&CK T1110 and T1078.
- `detect-entra-role-grant-escalation` as the narrow Entra follow-up detector for successful app-role assignments to service principals, aligned to MITRE ATT&CK `T1098.003` Additional Cloud Roles.
- a phased native/OCSF pilot for `ingest-cloudtrail-ocsf` and `detect-lateral-movement`, including explicit `--output-format {ocsf,native}` support, native/canonical-friendly test coverage, and MCP output-format selection for supported skills.
- repo-wide skill frontmatter for `approval_model`, `execution_modes`, and `side_effects`, plus CI enforcement and MCP tool-surface hints so human-in-the-loop expectations are explicit instead of inferred.
- optional `caller_roles`, `approver_roles`, and `min_approvers` contract metadata plus MCP caller-context propagation into write-capable skills, so remediation audit trails can record who invoked, who approved, and which request or session triggered the action.
- stderr-based MCP invocation audit events covering tool name, caller-context presence, approval-context presence, hashed arguments, duration, and exit status without logging raw stdin payloads.
- a shared opt-in `stderr` telemetry helper plus pilot JSON telemetry in `ingest-cloudtrail-ocsf` and `detect-lateral-movement`, enabled by `SKILL_LOG_FORMAT=json` or `AGENT_TELEMETRY=1` while preserving existing plain-text warnings by default.
- extended the structured `stderr` telemetry pilot to `ingest-k8s-audit-ocsf` and `detect-privilege-escalation-k8s`, so the Kubernetes ingest/detect path now has the same opt-in machine-readable runtime hints as the CloudTrail/lateral-movement path.
- extended the same opt-in structured `stderr` telemetry pilot to `ingest-okta-system-log-ocsf` and `detect-okta-mfa-fatigue`, covering the Okta identity ingest/detect path without changing stdout data contracts.
- extended the same opt-in structured `stderr` telemetry pilot to `ingest-google-workspace-login-ocsf` and `detect-google-workspace-suspicious-login`, covering the Google Workspace identity ingest/detect path without changing stdout data contracts.
- tightened the README and skill catalog entry path around use cases, skill selection, plug-in surfaces, and clearer layer guidance, plus added `docs/USE_CASES.md` as the practical crosswalk for sources, assets, frameworks, and starting skills.
- clarified in the README and use-case guide that repo-owned remediation audit lands in DynamoDB + S3 today, while generic sink skills now ship for Snowflake, ClickHouse, and S3; additional destinations such as Security Lake and BigQuery remain supported patterns rather than built-ins.
- a new start-here visual and updated IAM departures data-flow visual so operators can see sources, layer choice, outputs, runtime surfaces, and the shipped-vs-optional sink boundary without reading the full architecture docs first.
- a runtime-surfaces visual showing that CLI, CI, MCP, and persistent wrappers all call the same `SKILL.md + src/ + tests/` contract instead of creating parallel implementations.
- expanded the vendor icon asset set with Okta plus Microsoft Entra and Google Workspace stand-ins so the visual system can represent shipped identity sources alongside cloud and data-platform vendors.
- broadened the contract validator to fail on skill-like directories missing `SKILL.md`, and expanded the Bandit CI lane from a few hand-picked paths to `skills/`, `mcp-server/`, and `scripts/`.
- added a repo-aware `mypy` runner and CI lane that type-checks each skill `src/` directory in isolation plus `mcp-server/src/` and `scripts/`, so the repeated `ingest.py` / `detect.py` layout no longer blocks meaningful type enforcement.
- `scripts/validate_test_coverage.py` plus a dedicated CI coverage lane that now enforces real repo-level thresholds: `overall >= 70%`, `detection >= 80%`, and `evaluation >= 60%`.
- `runners/aws-s3-sqs-detect`, a repo-owned AWS reference runner template for `S3 -> ingest Lambda -> SQS -> detect Lambda -> DynamoDB dedupe -> SNS`, so persistent execution is no longer docs-only outside the IAM departures workflow.
- `runners/gcp-gcs-pubsub-detect` and `runners/azure-blob-eventgrid-detect` as the matching GCP and Azure reference runners, so the persistent execution story now has a shipped template on all three major clouds.
- `source-snowflake-query`, `source-databricks-query`, and `source-s3-select` as read-only source adapters for warehouse and object-store based pipelines.
- `sink-snowflake-jsonl`, `sink-clickhouse-jsonl`, and `sink-s3-jsonl` as write-capable persistence edges with dry-run-first contracts, explicit approval metadata, and auditable native result summaries.
- `packs/lateral-movement/` and `packs/privilege-escalation-k8s/` as the first shipped query-pack families proving warehouse-native detection can stay aligned with the Python skill intent.
- `docs/RELEASE_CHECKLIST.md` plus explicit repo-level semver bump rules, and aligned local pre-commit Bandit scope with the same `skills/`, `mcp-server/`, and `scripts/` surface enforced in CI.
- `docs/CREDENTIAL_PROVENANCE.md` plus README / security-doc updates to make the repo's secret-minimizing credential posture explicit, document the remaining password/client-secret compatibility paths, and explain why direct Workday `httpx` access remains a narrow documented exception instead of a hidden supply-chain surprise.
- `docs/CANONICAL_SCHEMA.md` and `docs/DATA_FLOW.md` to pin the repo-owned canonical model and the raw → canonical → native / ocsf / bridge flow.
- `docs/SUPPLY_CHAIN.md` plus a new CI CycloneDX SBOM artifact, making the dependency-provenance, lockfile-ceiling, and runtime-surface story explicit for operators and auditors.
- a release workflow that attaches the signed CycloneDX SBOM artifact set directly to GitHub Releases instead of leaving it only as a CI artifact.

### Changed

- trimmed the handful of overlong `SKILL.md` frontmatter descriptions so tool-selection metadata stays concise for Claude, Codex, Cursor, Windsurf, Cortex, and MCP clients.
- added optional `network_egress` skill metadata, exposed it through the MCP tool registry, and documented it in the skill/runtime contracts for sandbox-aware wrappers.
- added an explicit `## Do NOT do` anti-pattern section to `iam-departures-aws` and surfaced network egress allowlist hints for the write-capable workflow.
- tightened the security and transparency language so dependency policy now explicitly prefers official vendor SDKs, treats `httpx` in the direct Workday API path as a documented exception, and points operators at the SBOM artifact instead of only the lockfile.
- Expanded the coverage registry and framework mapping docs to track Okta, Entra / Graph, and Google Workspace as first-class OCSF identity-ingestion sources and detections.
- Expanded `ingest-okta-system-log-ocsf` to cover the verified Okta Verify push and denial event families needed for narrow MFA fatigue detection.
- Reframed the repo contract so OCSF remains a first-class interoperability option, but not a mandatory storage or execution model; the stable internal contract is now explicitly source truth -> canonical model -> `native` / `ocsf` / `bridge` output.
- Made the OCSF metadata validator format-aware so native-mode support does not weaken the OCSF path contract.
- Extended the native/OCSF pilot to `ingest-vpc-flow-logs-ocsf`, so AWS flow logs can now emit either OCSF Network Activity or the repo's canonical native network-flow shape while preserving a compatible end-to-end lateral-movement path.
- Extended the native/OCSF pilot to `ingest-k8s-audit-ocsf` and `detect-sensitive-secret-read-k8s`, so Kubernetes audit ingestion and one Kubernetes detector now support the same dual-mode rollout pattern as the earlier CloudTrail / VPC / lateral-movement pilots.
- Extended the native/OCSF pilot to `detect-privilege-escalation-k8s`, so the main windowed Kubernetes privilege-escalation detector now accepts native or OCSF input and can emit native or OCSF findings.
- Extended the native/OCSF pilot to `ingest-mcp-proxy-ocsf` and `detect-mcp-tool-drift`, so the MCP application-activity ingestion and tool-drift detection path now supports native or OCSF input/output without changing the core drift logic.
- Extended the native/OCSF pilot to `ingest-google-workspace-login-ocsf` and `detect-google-workspace-suspicious-login`, so the Workspace login ingestion and suspicious-login detection path now supports native or OCSF input/output without changing the underlying detection semantics.
- Extended the native/OCSF pilot to `ingest-entra-directory-audit-ocsf` and `detect-entra-credential-addition`, so Entra directory-audit ingestion and credential-addition detection now support native or OCSF input/output without changing the underlying detection semantics.
- Extended the native/OCSF pilot to `ingest-okta-system-log-ocsf` and `detect-okta-mfa-fatigue`, so the Okta System Log ingestion and MFA-fatigue detection path now supports native or OCSF input/output without changing the underlying detection semantics.
- Finished the native/OCSF rollout across the shipped ingest and detect layers, so event and finding pipelines are now fully dual-mode wherever the repo intends interoperability parity.
- Made the README honest about current schema-mode rollout, required `input_formats` / `output_formats` for every shipped skill, and documented the native output fields on the currently dual-mode skills.
- Added a runnable README hello-world path, clarified that the `DATA_FLOW.md` rollout list is now driven by README + `SKILL.md` frontmatter, and documented bounded-batch guidance for `detect-lateral-movement`.
- Tightened the public contract so the repo is positioned as OCSF-default for streams and native-first for operational artifacts, with explicit lossy-mapping and schema-versioning policy instead of vague "optional OCSF" wording.
- Added `concurrency_safety` to every shipped skill plus validator enforcement for canonical frontmatter field order, making parallel-execution expectations explicit instead of tribal knowledge.
- Clarified the install and trust model in the README so the repo is presented as a tagged source release with pinned dependency groups and signed SBOMs, not as a generic opaque package install.

- `docs/COVERAGE_MODEL.md`, `docs/framework-coverage.json`, and `docs/ROADMAP.md` to make framework, provider, asset, and execution coverage measurable and auditable.
- `scripts/validate_framework_coverage.py` so CI can reject undocumented or drifting coverage claims.
- explicit cross-cloud ATT&CK identity coverage metadata for `detect-lateral-movement`, covering AWS role pivots, GCP service-account pivots, and Azure role / managed-identity pivot anchors.
- explicit MITRE ATLAS and NIST AI RMF declarations for `gpu-cluster-security`, including machine-readable benchmark metadata for wrappers and coverage tests.
- `docs/RUNTIME_ISOLATION.md` to document sandboxing, credential scope, transport protections, integrity controls, and approval rules across CLI, CI, MCP, and persistent/serverless runs.
- Added deterministic `metadata.uid` to OCSF emitters and discovery bridge events for replay-safe SIEM dedupe.
- Added [`docs/SIEM_INDEX_GUIDE.md`](docs/SIEM_INDEX_GUIDE.md) covering index fields, timestamps, dedupe keys, and just-in-time vs persistent ingestion guidance.
- Added Azure Entra / Microsoft Graph credential-pivot coverage to `detect-lateral-movement`, including application and service-principal password-key changes, app-role grants, and federated identity credential creation.
- Added explicit NIST AI RMF traceability to `model-serving-security` and `discover-cloud-control-evidence`, including machine-readable benchmark metadata and an opt-in `ai-rmf` evidence mode.

### Changed
- Promoted the IAM departures cross-cloud workflow visual in `README.md` and made the CI badge explicitly track the `main` branch.
- Rebranded the public repo/docs surface to `cloud-ai-security-skills`, updated the MCP server name and project-scoped `.mcp.json`, and added a concise agent quick-start matrix for Claude Code, Codex, Cursor, Windsurf, and Cortex Code CLI.
- Normalized emitted OCSF and SARIF product/vendor identity to `cloud-ai-security-skills` while explicitly keeping older repo-local bridge/profile identifiers stable for compatibility.

## 0.4.0 - 2026-04-13

### Added
- Repo-wide `CHANGELOG.md` to make material architecture, security, and skill changes discoverable without reading every PR.
- [`docs/FRAMEWORK_MAPPINGS.md`](docs/FRAMEWORK_MAPPINGS.md) to consolidate ATT&CK, ATLAS, CIS, NIST, OWASP, SOC 2, ISO, and PCI coverage across the repo.
- First `discovery/` layer AI BOM skill, `discover-ai-bom`, which turns AI asset inventory snapshots into a deterministic CycloneDX-aligned BOM.
- First discovery-layer technical evidence skill, `discover-control-evidence`, which turns discovery artifacts into deterministic PCI / SOC 2 evidence JSON.
- `discover-cloud-control-evidence`, which turns AWS, GCP, and Azure inventory snapshots into deterministic PCI / SOC 2 technical evidence JSON.
- `discover-cloud-control-evidence --output-format ocsf-live-evidence`, which emits an OCSF Discovery / Live Evidence Info `[5040]` bridge event while preserving the native evidence document under `unmapped`.
- `discover-environment --output-format ocsf-cloud-resources-inventory`, which emits an OCSF Discovery / Cloud Resources Inventory Info `[5023]` bridge event while preserving the native environment graph under `unmapped`.
- deeper AI provider inventory and evidence coverage across AWS Bedrock / SageMaker, Google Vertex AI, Azure ML, and Azure AI Foundry in the discovery layer.
- deeper AI evaluation coverage in `model-serving-security`, including provider-shaped endpoint configs for SageMaker, Bedrock, Vertex AI, Azure ML, and Azure AI Foundry.

### Changed
- Removed the redirect-only `skills/ai-infra-security/` and `skills/compliance-cis-mitre/` stubs after the layered skill reshape settled.
- Reframed `skills/detection-engineering/` as a shared OCSF contract and golden-fixture namespace rather than a temporary transition root.
- Collapsed the largest CI matrices into grouped test lanes and added workflow concurrency so superseded PR runs cancel instead of flooding the queue.
- Added repo-level dependency/import consistency validation and aligned missing cloud SDK declarations in `pyproject.toml`.
- Moved `discover-environment` into the canonical `skills/discovery/` layer and wired discovery into the grouped `test-ai-infra` lane.

### Documentation
- Clarified the repo-level release model: one repo version, lightweight per-skill contract metadata, no full per-skill semver yet.

## 0.3.0

### Added
- Thin local MCP wrapper under `mcp-server/` for project-scoped skill discovery and execution.
- Safe-skill CI bar and repo-level skill contract enforcement.
- Architecture visuals and refreshed public positioning docs.
- GCP parity skills:
  - `ingest-vpc-flow-logs-gcp-ocsf`
  - `ingest-gcp-scc-ocsf`
- Azure parity skills:
  - `ingest-nsg-flow-logs-azure-ocsf`
  - `ingest-azure-defender-for-cloud-ocsf`

### Changed
- Reorganized the repo into layered skill categories:
  - `ingestion/`
  - `detection/`
  - `evaluation/`
  - `view/`
  - `remediation/`
- Renamed and generalized `detect-lateral-movement-aws` to `detect-lateral-movement`.
- Expanded docs around execution modes, approval boundaries, Claude/agent usage, and the repo safety model.

### Security
- Fixed prior SQL-injection and unsafe identifier-handling issues in Snowflake and reconciler flows.
- Tightened event validation and dry-run enforcement for write-capable skills.
- Added centralized validator coverage for skill contract and safety checks.

### Testing
- Grew test coverage and parity validation substantially across skills, integration flows, and MCP discovery.

## 0.2.0

### Added
- Layered skill catalog with stronger CI, dependency hygiene, and repo baseline hardening.
- New ingestion, detection, evaluation, and AI-infra skills beyond the original CSPM/remediation set.

### Changed
- README, AGENTS, and architecture docs shifted from narrow CSPM wording to broader cloud + AI security skills framing.

## 0.1.0

### Added
- Initial cloud-security skills collection:
  - cloud posture / CIS evaluation
  - IAM departures remediation
  - OCSF-based ingestion and conversion foundations
