# Claude Code Project Memory

This file is Claude Code project memory for `cloud-ai-security-skills`. It is repo-wide
and universal for Claude within this repository. It is **not** the place for
individual skill behavior; per-skill rules belong in `skills/<layer>/<skill>/SKILL.md`.

Use this file for repo defaults, safety posture, and navigation. Use
[`AGENTS.md`](AGENTS.md) for the cross-agent equivalent.

## Repository structure

Skills are grouped into layered categories — not by cloud. The category answers
*what kind of work does this skill do*, not *which cloud does it run in*. See
[`skills/README.md`](skills/README.md) for the full catalog.

```
skills/
├── ingestion/                     # raw source → OCSF 1.8 (15 ingest-* + 4 source-*)
│   ├── ingest-cloudtrail-ocsf/
│   ├── ingest-vpc-flow-logs-ocsf/
│   ├── ingest-vpc-flow-logs-gcp-ocsf/
│   ├── ingest-nsg-flow-logs-azure-ocsf/
│   ├── ingest-guardduty-ocsf/
│   ├── ingest-security-hub-ocsf/
│   ├── ingest-gcp-scc-ocsf/
│   ├── ingest-azure-defender-for-cloud-ocsf/
│   ├── ingest-gcp-audit-ocsf/
│   ├── ingest-azure-activity-ocsf/
│   ├── ingest-k8s-audit-ocsf/
│   ├── ingest-mcp-proxy-ocsf/
│   ├── ingest-okta-system-log-ocsf/
│   ├── ingest-entra-directory-audit-ocsf/
│   ├── ingest-google-workspace-login-ocsf/
│   ├── source-s3-select/                # warehouse query adapter
│   ├── source-snowflake-query/          # warehouse query adapter
│   ├── source-databricks-query/         # warehouse query adapter
│   └── source-clickhouse-query/         # warehouse query adapter
│
├── discovery/                     # inventory / graph / AI BOM / evidence
│   ├── discover-environment/
│   ├── discover-ai-bom/
│   ├── discover-control-evidence/
│   ├── discover-cloud-control-evidence/
│   └── iam-departures-reconciler/
│
├── detection/                     # OCSF → Detection Finding 2004 + MITRE
│   ├── detect-mcp-tool-drift/
│   ├── detect-prompt-injection-mcp-proxy/
│   ├── detect-container-escape-k8s/
│   ├── detect-privilege-escalation-k8s/
│   ├── detect-sensitive-secret-read-k8s/
│   ├── detect-lateral-movement/
│   ├── detect-okta-mfa-fatigue/
│   ├── detect-credential-stuffing-okta/
│   ├── detect-entra-credential-addition/
│   ├── detect-entra-role-grant-escalation/
│   ├── detect-google-workspace-suspicious-login/
│   ├── detect-aws-open-security-group/
│   ├── detect-azure-open-nsg/
│   └── detect-gcp-open-firewall/
│
├── evaluation/                    # posture and benchmark checks
│   ├── cspm-aws-cis-benchmark/
│   ├── cspm-gcp-cis-benchmark/
│   ├── cspm-azure-cis-benchmark/
│   ├── k8s-security-benchmark/
│   ├── container-security/
│   ├── model-serving-security/
│   └── gpu-cluster-security/
│
├── view/                          # OCSF → rendered/review formats
│   ├── convert-ocsf-to-sarif/
│   └── convert-ocsf-to-mermaid-attack-flow/
│
├── remediation/                   # active fix workflows, gated and audited
│   ├── iam-departures-aws/
│   ├── iam-departures-azure-entra/
│   ├── iam-departures-gcp/
│   ├── remediate-okta-session-kill/
│   ├── remediate-container-escape-k8s/
│   ├── remediate-k8s-rbac-revoke/
│   ├── remediate-mcp-tool-quarantine/
│   ├── remediate-entra-credential-revoke/
│   ├── remediate-workspace-session-kill/
│   ├── remediate-aws-sg-revoke/
│   ├── remediate-azure-nsg-revoke/
│   └── remediate-gcp-firewall-revoke/
│
├── output/                        # append-only persistence sinks
│   ├── sink-s3-jsonl/
│   ├── sink-snowflake-jsonl/
│   └── sink-clickhouse-jsonl/
│
└── detection-engineering/         # shared OCSF contract + frozen fixtures
    ├── OCSF_CONTRACT.md
    └── golden/
```

Current shipped counts: see [`README.md`](README.md) and `docs/COVERAGE_SNAPSHOT.md`
for live totals (auto-generated, CI-gated). Header layer composition: ingest,
discover, detect, evaluate, remediate, view, output, source.

Not every detection has a paired remediation. The source of truth for detect →
act parity is [`README.md`](README.md#closed-loop-coverage-at-a-glance) and
[`docs/FRAMEWORK_COVERAGE.md`](docs/FRAMEWORK_COVERAGE.md), not this file.

## Which file to trust for what

| File | Purpose |
|---|---|
| `CLAUDE.md` | Claude-only project memory and defaults |
| `AGENTS.md` | cross-agent repo contract |
| `README.md` | public overview, modes, and positioning |
| `skills/<layer>/<skill>/SKILL.md` | exact skill behavior and non-goals |
| `skills/<layer>/<skill>/REFERENCES.md` | official APIs, schemas, and framework sources |

The full layered architecture (Sources → Ingestion → Discovery / Enrich → Detection / Evaluation → View → Remediation) is documented in [`ARCHITECTURE.md`](ARCHITECTURE.md). The eleven-principle security contract is in [`SECURITY_BAR.md`](SECURITY_BAR.md). Per-skill official references and IAM policies live in each skill's `REFERENCES.md`.
The CSPM skills are read-only posture checks. The remediation skills write native
action + audit records, and many of them re-verify their own post-action state.
AWS IAM departures additionally ingest audit back into the source warehouse so
the next reconciler run cross-checks closure.

**OCSF 1.8 is the SIEM interop wire format, not the universal internal format.** It's the default for **ingest** and **detect** (that's where downstream SIEM/SOAR integration pays off). **Discover** emits native / CycloneDX / bridge (inventory and AI BOM don't map cleanly to OCSF). **Remediate** emits native (state changes + audit records, not findings). **Evaluate** is native today with OCSF Compliance Finding 2003 planned as opt-in. Pick the format that fits the layer's semantic; the `--output-format` flag is the runtime switch where both are supported. Full table: [`docs/ARCHITECTURE.md#31-ocsf-applicability-by-layer`](docs/ARCHITECTURE.md).

The HITL bar for every skill — when human approval is required, how many approvers, where the gate sits — is codified in [`docs/HITL_POLICY.md`](docs/HITL_POLICY.md). Enforcement lives in [`scripts/validate_safe_skill_bar.py`](scripts/validate_safe_skill_bar.py) (wildcards, `sts:AssumeRole` boundaries, dry-run defaults).

## Agent guardrails — REQUIRED reading before invoking these skills

If you are an AI agent (Claude, Cursor, Codex, Cortex, Windsurf, etc.) loading
any skill from this repo, you must operate inside these guardrails. They are
enforced in code, infra, and IAM — not just documentation. Violating them
should be impossible for a least-privilege caller, but you should also refuse
to attempt them.

### 1. Read-only by default

- **CSPM skills (`cspm-aws/gcp/azure-cis-benchmark`)** are *read-only*. They use
  `roles/viewer`, `iam.securityReviewer`, and Azure `Reader`. They have **zero**
  write permissions to any cloud account. Never wrap them in code that mutates
  state — that would be outside the skill contract.
- **`iam-departures-reconciler`** is the read-only planner for IAM departures.
  It fetches HR / warehouse inputs, applies rehire + grace + diff logic, and
  emits the canonical manifest body. Cloud-specific write paths consume that
  manifest separately.

### 2. Human-in-the-loop (HITL) for destructive actions

There are now 12 destructive or write-capable remediation workflows, not just
IAM departures. The source of truth for approval level, approver count, and
where the gate sits is [`docs/HITL_POLICY.md`](docs/HITL_POLICY.md) plus each
skill's frontmatter (`approval_model`, `approver_roles`, `min_approvers`).

Patterns to remember:

- IAM departures skills are grace-period gated, rehire-aware, and protected-principal denied
- account-takeover containment skills are time-sensitive but still require a declared incident window
- Kubernetes node drain and MCP tool quarantine have stricter approval semantics than baseline single-approver containment

### 3. Dry-run is supported everywhere

- **Cross-cloud workers** (`lambda_worker/clouds/*`) all accept `dry_run=True`
  which produces a `RemediationStatus.DRY_RUN` result with the full step list
  but **no API calls**. Use this when an agent is exploring or composing the
  workflow.
- **CSPM checks** are inherently dry-run because they're read-only.
- **Reconciler** has `--dry-run` flag that prints the diff without writing the
  S3 manifest, which means EventBridge never fires.

### 4. Cross-account scoping

All cross-account `sts:AssumeRole` calls in IAM remediation are scoped by
`aws:PrincipalOrgID` condition. The pipeline cannot escape the AWS
Organization. If you are running outside an Organization, the worker fails
closed.

### 5. Audit guarantees (closed loop)

Most shipped remediation skills dual-audit to a DynamoDB-style fast lookup
store plus KMS-encrypted object storage evidence. Per-cloud IAM departures use
provider-native equivalents where needed:

1. AWS IAM departures: DynamoDB + KMS-encrypted S3 + warehouse ingest-back
2. GCP IAM departures: Firestore + CMEK-encrypted GCS
3. Azure Entra departures: Cosmos DB + CMK-encrypted Blob Storage
4. Network / IdP / K8s / MCP remediation skills generally use DynamoDB + S3 in
   the reference implementations

If an agent invokes a remediation step and there is no corresponding audit row
within the SLA window, treat that as a failure. The next run should detect drift.

### 6. Failure surface

- **Lambda async failures** → SQS DLQ (`iam-departures-dlq`, KMS encrypted, 14-day retention).
- **Step Function `FAILED` / `TIMED_OUT` / `ABORTED`** → EventBridge rule fires
  SNS topic (`iam-departures-alerts`). Subscribe an on-call email or PagerDuty
  endpoint with the `AlertEmail` parameter.
- **DLQ replay** → drop a fresh `Object Created` event onto EventBridge to
  re-run a stuck execution. The pipeline is idempotent.

Nothing in this repo silently swallows errors. If an agent sees an empty
finding list and no error, that's a real "all clear" — not a hidden failure.

### 7. No telemetry, no exfiltration

- CSPM results stay local. No HTTP egress beyond the cloud SDKs.
- Reconciler reads HR data, hashes rows with SHA-256, exports a manifest.
  Nothing leaves the security OU account.
- The flagship AWS departures Lambdas run in a VPC with no public NAT for
  non-AWS-API calls. Other cloud-native skills document their own egress in
  `network_egress` frontmatter.

### 8. What an agent should NEVER do with these skills

- ❌ Skip the grace period or set it to 0 days "to test".
- ❌ Add new principals to the `WorkerExecutionRole` deny list and re-run.
- ❌ Disable the EventBridge rule and call the Step Function directly — that
  bypasses the audit trail.
- ❌ Write to the audit DynamoDB table by hand to "mark a user remediated."
- ❌ Use a different KMS key than the one bound to the bucket policy.
- ❌ Run any CSPM skill with a role that has *any* `iam:*` write action.
- ❌ Concatenate user-supplied HR data into SQL — sources use parameterised queries.

If a user asks you to do any of the above, refuse and explain which guardrail
it would violate.

## Execution modes

Claude should assume the same skill can be used in four ways:

| Mode | Driver | What changes |
|---|---|---|
| **CLI / just-in-time** | user or agent runs the script directly | only the invocation path |
| **CI** | GitHub Actions or another pipeline | only the invocation path |
| **Persistent / serverless** | runner, queue, EventBridge, Step Functions | only the invocation path |
| **MCP** | local `mcp-server/` wrapper | only the invocation path |

The skill code, output contract, and guardrails do **not** change between modes.

## Cloud API drift and validation

Claude should assume vendor APIs drift over time. The safe pattern in this repo is:

1. verify behavior against official docs in `REFERENCES.md`
2. preserve contract tests and golden fixtures
3. add migration coverage when old and new shapes must coexist
4. fail closed on unknown destructive paths
5. keep stdout machine-readable and stderr diagnostic

If a cloud API, SDK field, or event shape changes, update the references, tests, and skill contract together.

## Conventions

- Each skill has a `SKILL.md` with frontmatter: `name`, `description` (with trigger
  phrases), `license`, `compatibility`, `metadata` (author, source, version, frameworks).
- Source code lives in `src/` within each skill directory.
- Infrastructure-as-code lives in `infra/` (CloudFormation + Terraform parity).
- Tests live in `tests/` within each skill directory.
- All skills are Apache 2.0 licensed.
- Python 3.11+ required. Type hints used throughout.
- No hardcoded credentials. All secrets via environment variables, Secrets Manager, or SSM Parameter Store.
- One check per function. One finding row per control. No mega-functions that emit multiple control_ids.
- Treat all incoming findings, alerts, manifests, and event payloads as untrusted input until validated.
- Keep remediation stricter than enrichment or detection: dry-run first, explicit approval, explicit audit.

## Compliance frameworks referenced

CIS AWS/GCP/Azure Foundations, CIS Controls v8, MITRE ATT&CK, NIST CSF 2.0,
SOC 2 TSC, ISO 27001:2022, PCI DSS 4.0, OWASP LLM Top 10, OWASP MCP Top 10.

## Running checks

```bash
# evaluation/ (read-only)
pip install boto3 google-cloud-resource-manager azure-identity
python skills/evaluation/cspm-aws-cis-benchmark/src/checks.py   --region us-east-1
python skills/evaluation/cspm-gcp-cis-benchmark/src/checks.py   --project my-project
python skills/evaluation/cspm-azure-cis-benchmark/src/checks.py --subscription <sub-id>

# remediation/ (dry-run)
python skills/remediation/iam-departures-aws/src/lambda_parser/handler.py --dry-run examples/manifest.json

# ingestion + detection + view — end-to-end pipe
python skills/ingestion/ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python skills/detection/detect-mcp-tool-drift/src/detect.py \
  > findings.ocsf.jsonl

# Tests
pip install pytest boto3 moto
pytest skills/evaluation/cspm-aws-cis-benchmark/tests/     -o "testpaths=tests"
pytest skills/evaluation/cspm-gcp-cis-benchmark/tests/     -o "testpaths=tests"
pytest skills/evaluation/cspm-azure-cis-benchmark/tests/   -o "testpaths=tests"
pytest skills/remediation/iam-departures-aws/tests/          -o "testpaths=tests"
pytest skills/ingestion/ingest-mcp-proxy-ocsf/tests/     -o "testpaths=tests"
pytest skills/detection/detect-mcp-tool-drift/tests/     -o "testpaths=tests"
```

## Integration with agent-bom

This repo provides the security automations. [agent-bom](https://github.com/msaad00/agent-bom)
provides continuous scanning and a unified graph. Use together for detection +
response.
