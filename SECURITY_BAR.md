# Security Bar

The contract every skill in this repo satisfies. Eleven principles, each
testable, each enforced at the skill level.

If you are reviewing a PR that adds a new skill, this is the checklist.
If you are an AI agent loading a skill, these are the guarantees you can
rely on. If you are a security team adopting one of these skills, this
is the row you can take to your auditor.

## The ten principles

| # | Principle | What it means in practice | How we verify it |
|---|---|---|---|
| 1 | **Read-only by default** | Posture and detection skills NEVER call write APIs. Remediation skills isolate the write path behind explicit IAM grants and require dry-run as the default. | Source review (no boto3 / google-cloud / azure-sdk write calls outside `remediation/`). Each `SKILL.md` declares the mode in its `Do NOT use…` clause. |
| 2 | **Agentless** | No daemons, no in-cluster sidecars, no continuously running processes. Skills are short-lived Python scripts that read what is already there (logs, configs, exported state). | No skill ships a Dockerfile, systemd unit, or DaemonSet. Each skill is invocable as `python src/<entry>.py <input>` and exits cleanly. |
| 3 | **Least privilege** | Each skill documents the EXACT IAM / RBAC permissions it needs in `REFERENCES.md`. The set is minimised to what the skill cannot operate without — never a broad `*Reader` role unless that is the only option the cloud provider offers. **Every `sts:AssumeRole` Allow carries a boundary condition** — `aws:PrincipalOrgID` / `aws:SourceAccount` / `aws:PrincipalTag` / `aws:SourceOrgID`. Wildcard actions and resources carry an explicit `WILDCARD_OK` justification. | Per-skill `REFERENCES.md` carries an explicit "required permissions" section. CSPM skills use the smallest read-only managed policy the provider publishes. The K8s detector reads audit logs, not the live API. `scripts/validate_safe_skill_bar.py` runs in CI and fails the build on any wildcard without a `WILDCARD_OK` marker or any `sts:AssumeRole` Allow without a boundary condition (opt-out requires an explicit `ASSUME_ROLE_CONDITION_OK` justification). |
| 4 | **Closed loop** | Every workflow has a verification step: detection → finding → action → audit row → re-verify. Drift is itself a detection. | Each skill's `SKILL.md` documents the verification path. Detection-engineering skills are golden-fixture tested so a refactor that loses coverage fails the build. Remediation skills dual-write to DynamoDB + S3 + warehouse. |
| 5 | **OCSF on the wire (detection-engineering)** | All ingest and detect skills speak OCSF 1.8 JSONL. No bespoke shapes, no per-cloud finding formats. MITRE ATT&CK lives inside `finding_info.attacks[]`. | `OCSF_CONTRACT.md` is the source of truth. Every detection-engineering skill has a frozen golden fixture; deep-equality tests fail if a refactor changes the wire shape. |
| 6 | **No telemetry, no undeclared egress** | No skill phones home. No "anonymous usage" reporting. External API access is limited to official vendor SDKs or documented, justified exceptions where the vendor exposes an API but no usable Python SDK exists. Findings stay local unless the operator explicitly forwards them. | Source review (`grep -r "requests\|httpx\|urllib"` returns only the cloud SDK clients each skill needs plus the documented Workday `httpx` path). No analytics imports. CI runs `bandit` against `skills/`, `mcp-server/`, and `scripts/`. |
| 7 | **Defense in depth** | A single failed control never owns the whole story. Posture + detection + remediation + audit + verification all run in parallel and back each other up. A bypass of one layer is caught by the next. | Every destructive workflow has at least three layers (e.g. iam-departures: grace period + deny list + rehire filter + audit + ingest-back verification). Detection-engineering has fixture-tested negative controls so a refactor that loses coverage fails CI. |
| 8 | **Secure by design (not bolt-on)** | Security is a first-class input to the skill's architecture, not a checklist applied at the end. Read-only is the default, write paths are opt-in, every IAM grant is scoped, every input is parsed defensively, every output is validated against a schema. | Source review during PR. Each `SKILL.md` carries a `Do NOT use…` clause that names the abuse cases the skill explicitly refuses. Each `REFERENCES.md` carries the exact IAM policy. |
| 9 | **Secure code** | Defensive parsing on every input boundary (JSON parse failures are skipped with stderr warnings, never crash the pipeline). No `eval`, no `exec`, no `pickle.loads` on untrusted data. Subprocess calls use list args and a fixed allow-list, never `shell=True` with interpolation. SQL via parameterised queries only. | `bandit` runs in CI against `skills/`, `mcp-server/`, and `scripts/`. Source review on PR. The reconciler's HR sources use parameterised SQL via the official Snowflake / Databricks / ClickHouse Python connectors — no string concatenation. |
| 10 | **Secure secrets, tokens, and env vars** | No hardcoded credentials anywhere. The preferred order is workload identity and short-lived creds first, vendor tokens second, and manager-injected passwords or client secrets only where a vendor path still requires them. Secrets come from environment variables, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, or Kubernetes Secrets — never from source files or commit history. Logs scrub credentials before emitting. | CI runs a hardcoded-secret grep against `skills/*/*/src/` (`AKIA[A-Z0-9]{16}`, `sk-[a-zA-Z0-9]{20,}`, `ghp_[a-zA-Z0-9]{36}`). `bandit` flags `B105` (hardcoded password). Secret-bearing exceptions are documented in `docs/CREDENTIAL_PROVENANCE.md` and the remediation skill contract. |
| 11 | **Human in the loop, no rogue skill behaviour** | A skill never escalates its own privileges, never adds itself to allow-lists, never asks the agent to bypass a guardrail, never silently widens its permission set across runs, never invokes a sibling skill it wasn't explicitly composed with. Destructive actions require an explicit human-approved trigger (HR termination event for IAM cleanup, operator confirmation for the worker Lambda's first run). Skills refuse instructions that conflict with their `Do NOT use…` clause. | Every destructive skill carries a HITL gate documented in `SKILL.md` (grace period for IAM departures, dry-run-default for cross-cloud workers). Per-skill IAM is the smallest set the skill can possibly use; no skill role grants `iam:CreateRole` / `iam:PutRolePolicy` / `iam:AttachRolePolicy` (which would let it expand its own permissions). Skills run as standalone subprocesses — they cannot import or call sibling skills directly per the Anthropic spec, so a compromised skill cannot recruit others. The `AGENTS.md` "what an agent should NEVER do" list is the agent-side mirror of this principle, which tools downstream of an agent (Claude Code, Cursor, Codex) read on every session. |

## Per-skill matrix

<!-- AUTO-GENERATED MATRIX START — do not edit by hand; run scripts/generate_security_bar_matrix.py -->
| Skill | Layer | Read-only | Agentless | Least privilege | Closed loop | OCSF wire | No telemetry |
|---|---|:-:|:-:|---|---|---|:-:|
| `ingest-azure-activity-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-azure-defender-for-cloud-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-cloudtrail-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-entra-directory-audit-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-gcp-audit-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-gcp-scc-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-google-workspace-login-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-guardduty-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-k8s-audit-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-mcp-proxy-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-nsg-flow-logs-azure-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-okta-system-log-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-security-hub-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-vpc-flow-logs-gcp-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `ingest-vpc-flow-logs-ocsf` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `source-databricks-query` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `source-s3-select` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `source-snowflake-query` | ingestion | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `discover-ai-bom` | discovery | ✅ | ✅ | ✅ | ✅ deterministic | n/a | ✅ |
| `discover-cloud-control-evidence` | discovery | ✅ | ✅ | ✅ | ✅ deterministic | n/a | ✅ |
| `discover-control-evidence` | discovery | ✅ | ✅ | ✅ | ✅ deterministic | n/a | ✅ |
| `discover-environment` | discovery | ✅ | ✅ | ✅ | ✅ deterministic | n/a | ✅ |
| `iam-departures-reconciler` | discovery | ✅ | ✅ | ✅ | ✅ deterministic | n/a | ✅ |
| `detect-agent-credential-leak-mcp` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-aws-access-key-creation` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-aws-enumeration-burst` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-aws-login-profile-creation` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-aws-model-artifact-download` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-aws-open-security-group` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-azure-activity-logs-disabled` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-azure-open-nsg` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-clickhouse-bulk-export` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-cloudtrail-disabled` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-container-escape-k8s` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-credential-stuffing-okta` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-databricks-token-creation` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-entra-credential-addition` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-entra-role-grant-escalation` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-gcp-audit-logs-disabled` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-gcp-model-artifact-download` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-gcp-open-firewall` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-gcp-service-account-key-creation` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-gcp-service-account-token-minting` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-google-workspace-suspicious-login` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-lateral-movement` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-mcp-tool-drift` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-okta-mfa-fatigue` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-privilege-escalation-k8s` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-prompt-injection-mcp-proxy` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-s3-cross-account-copy` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-sensitive-secret-read-k8s` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-snowflake-account-key-creation` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-snowflake-bulk-data-egress` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-snowflake-share-creation` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-snowflake-unauthorized-grant` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-snowflake-warehouse-resize-burst` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-system-prompt-extraction` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-tool-output-exfiltration-instructions` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-tool-output-policy-bypass` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-web-auth-failures` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-web-broken-access-control` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `detect-web-injection` | detection | ✅ | ✅ | ✅ | ✅ golden fixture | ✅ 1.8 | ✅ |
| `container-security` | evaluation | ✅ | ✅ | ✅ | ✅ deterministic | ✅ 1.8 opt-in | ✅ |
| `cspm-aws-cis-benchmark` | evaluation | ⚠️ write-capable | ✅ | ✅ | ✅ deterministic | ✅ 1.8 opt-in | ✅ |
| `cspm-azure-cis-benchmark` | evaluation | ✅ | ✅ | ✅ | ✅ deterministic | ✅ 1.8 opt-in | ✅ |
| `cspm-gcp-cis-benchmark` | evaluation | ✅ | ✅ | ✅ | ✅ deterministic | ✅ 1.8 opt-in | ✅ |
| `gpu-cluster-security` | evaluation | ✅ | ✅ | ✅ | ✅ deterministic | ✅ 1.8 opt-in | ✅ |
| `k8s-security-benchmark` | evaluation | ✅ | ✅ | ✅ | ✅ deterministic | ✅ 1.8 opt-in | ✅ |
| `model-serving-security` | evaluation | ✅ | ✅ | ✅ | ✅ deterministic | ✅ 1.8 opt-in | ✅ |
| `iam-departures-aws` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `iam-departures-azure-entra` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `iam-departures-gcp` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `remediate-aws-sg-revoke` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `remediate-azure-nsg-revoke` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `remediate-container-escape-k8s` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `remediate-entra-credential-revoke` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `remediate-gcp-firewall-revoke` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `remediate-k8s-rbac-revoke` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `remediate-mcp-tool-quarantine` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `remediate-okta-session-kill` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `remediate-workspace-session-kill` | remediation | ⚠️ write via HITL | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `convert-ocsf-to-mermaid-attack-flow` | view | ✅ | ✅ | ✅ | ✅ deterministic | n/a | ✅ |
| `convert-ocsf-to-sarif` | view | ✅ | ✅ | ✅ | ✅ deterministic | n/a | ✅ |
| `sink-clickhouse-jsonl` | output | ⚠️ append-only sink | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `sink-s3-jsonl` | output | ⚠️ append-only sink | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |
| `sink-snowflake-jsonl` | output | ⚠️ append-only sink | ✅ | ✅ | ✅ audit + re-verify | n/a | ✅ |

_86 skills · generated from SKILL.md frontmatter + layer conventions. Run `python scripts/generate_security_bar_matrix.py` to refresh after adding a skill; CI enforces parity via `--check`._
<!-- AUTO-GENERATED MATRIX END -->

## How to add a skill that satisfies the bar

1. Read the matching `REFERENCES.md` for the closest sibling skill — it tells you which official docs / schemas / IAM policies you need to wire.
2. Copy the directory layout: `SKILL.md` (with frontmatter + `Do NOT…` clause), `src/<entry>.py`, `tests/test_<entry>.py`, optional `examples/`.
3. For OCSF-speaking skills, also ship a golden fixture pair under `skills/detection-engineering/golden/` and a deep-equality test against it.
4. Document the exact IAM / RBAC permissions in your new `REFERENCES.md`.
5. Run `ruff check`, `ruff format --check`, and `pytest skills/<your-skill>/tests/`.
6. Add a row to the per-skill matrix above.
7. Open a PR. CI will run the matching test job from `.github/workflows/ci.yml` (one job per skill).
