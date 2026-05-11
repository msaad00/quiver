# Why this repo exists

You can ask Claude to write a regex that detects SQL injection in a log line.
You'll get one in 30 seconds. **That's not the job this repo competes for.**

This page answers the harder version of the question: *why use these 90 skills
instead of having an LLM (or a junior engineer) write 90 of your own?*

## The short answer

The detection rules are the easy part. The **trust contract around them** is
the hard part — and the trust contract is not LLM-generable.

A locked OCSF 1.8 wire shape; an HMAC-chained audit log with a tamper-evident
verifier; HITL approval gates that enforce `min_approvers` before any
subprocess fires; three layers of sandbox; per-detector precision/recall
scoring against a labelled corpus; the same skill bundle running unchanged in
CLI, CI, MCP, webhook, and cloud-runner surfaces — none of that fits in an
LLM prompt. **That's what this repo gives you.**

The skills are portable. The trust contract is the moat.

## What an LLM gives you

A Python file. Maybe a regex. Maybe a SQL query. It:

- emits some ad-hoc dict shape (yours, this morning's edition)
- runs once and exits
- writes nothing to an audit log
- has no concept of "two-person approval before this fires"
- has no calibration against red-team data
- has no test, no fixture, no snapshot
- runs as your user with full local credentials
- maps to MITRE ATT&CK roughly ("this looks like T1098 I think")

For an ad-hoc analysis on one cloud, that's enough. For anything more — a
detection pipeline, a compliance trail, an agent acting on production
infrastructure — it isn't.

## What this repo gives you that doesn't fit in a prompt

### 1. Locked OCSF 1.8 wire contract — composable by construction
Every detector emits the same OCSF Detection Finding 2004 envelope. Every
ingester emits OCSF 1.8 wire classes — see
[`docs/INGEST_COVERAGE.md`](INGEST_COVERAGE.md) for the vendor × class matrix.
Chain 30 skills via stdin/stdout:

```bash
python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-aws-access-key-creation/src/detect.py \
  | python skills/view/convert-ocsf-to-sarif/src/convert.py \
  > findings.sarif
```

That pipe works because every link in the chain speaks the same wire format.
LLM-generated rules give you 30 ad-hoc dict shapes that never compose.

### 2. HMAC-chained audit log, tamper-evident verifier
Every tool call writes one JSONL record. Each record carries
`prev_hash` + `chain_hash = HMAC-SHA-256(key, prev_hash || event_json)`. An
incident responder can replay the whole chain end-to-end and detect single
silent insertions. See [`docs/MCP_AUDIT_CONTRACT.md`](MCP_AUDIT_CONTRACT.md).
DIY equivalent: `print(finding)`.

### 3. HITL gates with `min_approvers` enforced before subprocess fires
Twelve write-capable skills (remediation paths) refuse to mutate state
without an `_approval_context` carrying at least `min_approvers` signatures.
The check happens in the MCP wrapper, before `subprocess.run` is called.
An LLM-generated `delete-iam-key` script has no concept of two-person
approval — and is one prompt-injection away from running.

### 4. Three layers of sandbox
- **RLIMIT** — always-on. `RLIMIT_AS` 1 GB, `RLIMIT_FSIZE` 100 MB, `RLIMIT_CPU` mirrors wrapper timeout. Caps every subprocess.
- **Container hardening** — Docker + Helm chart: non-root UID 65532, read-only rootfs, `--cap-drop=ALL`, `no-new-privileges`, default seccomp.
- **OS sandbox** (opt-in) — `bwrap` on Linux, `sandbox-exec` on macOS. Per-skill profile derived from `SKILL.md network_egress`.

DIY = your user, your shell, your local credentials.

### 5. Allowlist intersection — three-way
On every tool call:

```
effective_allowlist = operator_env ∩ caller_context ∩ workflow_preset
```

A caller can't widen what the operator allowed. A workflow can't bypass
the operator's allowlist. The webhook receiver fails closed if no preset is
configured.

### 6. Per-detector precision/recall scoring (v0.10.0)
[`skills/detection-engineering/scoring/`](../skills/detection-engineering/scoring/)
runs each detector subprocess against a labelled synthetic corpus, computes
TP / FP / FN / precision / recall / F1, and posts a sticky markdown table on
every PR touching `skills/detection/`. You **measure** detection quality.
DIY rules don't get scored — you guess.

### 7. Captured-fixture corpus + licence-checked provenance (v0.10.0)
[`skills/detection-engineering/captured/`](../skills/detection-engineering/captured/)
holds real attack traces, today sourced from Atomic Red Team (Apache-2.0).
Every file declares origin, licence, capture window, MITRE ATT&CK pattern,
and consuming detector. A CI gate refuses unlisted files and non-permissive
licences. See [`captured/README.md`](../skills/detection-engineering/captured/README.md).

### 8. One bundle, five surfaces — zero per-surface drift
Same `SKILL.md` + `src/` + `tests/` runs unchanged under:

| Surface | How it invokes |
|---|---|
| CLI | `python skills/[layer]/[name]/src/[entry].py` |
| CI | GitHub Actions runs the same entrypoint |
| MCP | Stdio wrapper (Claude Code / Desktop / Cursor / Codex / Cortex / Windsurf / Zed) or SSE/HTTP listener |
| Webhook | FastAPI receiver routes signed requests to the same `src/` |
| Runner | S3-SQS / GCS-PubSub / Blob-EventGrid event-driven; same `src/` |

DIY = write the rule three times.

### 9. Framework mapping locked in code, CI-gated
Every `SKILL.md` carries the framework mapping in its frontmatter (MITRE
ATT&CK technique ID, ATLAS, OWASP, NIST AI RMF, CIS). The auto-generated
[`docs/FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md) and
[`docs/COVERAGE_SNAPSHOT.md`](COVERAGE_SNAPSHOT.md) are produced from those
frontmatters; CI refuses drift. LLM rule = "this is sort of T1098 I think."

### 10. Cross-cutting reliability contract
[`skills/_shared/`](../skills/_shared/) gives every skill bounded retry
(`retry.py`), structured errors (`errors.py`), JSON-on-stderr logging with
correlation IDs (`logging.py`), and runtime telemetry (`runtime_telemetry.py`).
Nineteen detectors use it today. LLM rule = silent failure.

### 11. Calibration you cannot prompt-generate
What counts as a *lateral-movement chain* across an AWS+GCP+Azure principal
graph? What's the burst threshold for Okta MFA fatigue without
false-positive storming? What `bytes_scanned` threshold separates Snowflake
bulk-egress from a legitimate analyst's `COPY INTO`?

Those answers come from real telemetry, red-team corpora, and customer
review. They're not pattern-matchable from a prompt. See per-skill
`SKILL.md` "Honest scope" sections — every threshold is documented + tunable.

## Raw-data → OCSF: this is code, not vibes

Concrete trace of a single signal through the repo:

```
Okta /api/v1/logs JSON
        │
        ▼  (ingest-okta-system-log-ocsf)
        │  validates 'eventType' against three classification maps:
        │    _AUTH_EVENT_MAP        → OCSF Authentication       3002
        │    _ACCOUNT_CHANGE_EVENT_MAP → OCSF Account Change    3001
        │    _USER_ACCESS_EVENT_MAP  → OCSF User Access Mgmt    3005
        │  unmapped types: stderr 'unmapped_event_type' record + counter
        │
        ▼
OCSF 1.8 envelope { class_uid, activity_id, metadata.uid, user, actor,
                    src_endpoint, observables, unmapped.okta.* }
        │
        ▼  (detect-okta-mfa-fatigue)
        │  groups by actor.user.uid in a sliding window, fires when N
        │  factor_verify_push events exceed the threshold within window
        │
        ▼
OCSF Detection Finding 2004 { finding_info.attacks=[T1621], severity_id=4,
                              metadata.uid (deterministic), observables[] }
        │
        ▼  (convert-ocsf-to-sarif)
        │  emits SARIF 2.1.0 for IDE / PR-review consumption
        │
        ▼
findings.sarif → security tab in GitHub / VS Code / etc.
```

Every transform is a real Python file with a SKILL.md, a synthetic golden
fixture, a snapshot test, and an entry in
[`docs/INGEST_COVERAGE.md`](INGEST_COVERAGE.md). No LLM in the loop.
Reproducible, auditable, MCP-callable.

## The cost framing — roll your own to parity

| Component | Engineering cost (estimate) |
|---|---|
| 15 OCSF ingest skills @ ~6 h each (schema, fixture, snapshot test, mapping) | ~90 h |
| Shared retry / errors / logging contract + migration onto detectors | ~40 h |
| HMAC-chained audit + verifier + key-rotation | ~60 h |
| HITL wrapper + allowlist intersection + min_approvers | ~80 h |
| Three sandbox layers + RLIMIT enforcement | ~40 h |
| Five-surface harness (MCP stdio + SSE + CLI + CI + webhook + runner) | ~80 h |
| Per-detector precision/recall scorer + corpus | ~50 h |
| Captured-fixture corpus + licence-clean provenance gate | ~30 h |
| Framework-mapping drift gates (MITRE / ATLAS / OWASP / NIST / CIS / OCSF) | ~30 h |

**Subtotal: ~500 hours = ~12 engineer-weeks** to reach feature parity —
before the first detector is written. The repo represents three quarters
of engineering already done, and the calibration loop (precision/recall,
captured corpus, audit chain) is the part nobody else hands you.

## Where this repo is honestly the wrong tool

Stay-honest list. Don't adopt this if:

- **You only need one-off analysis on one cloud.** An LLM-generated regex on one CloudTrail file will do. The trust contract is overhead you don't need.
- **You already have a SIEM with shipped detection content and don't need MCP / agent-callable detection.** The OCSF + audit-chain story is a duplication, not an add.
- **You only need posture (CSPM)** without HITL remediation or detection. A CSPM SaaS is cheaper. (We're 50% CIS coverage on three clouds + 10 NIST AI RMF subcategories per function; that's a piece, not the whole pie.)
- **You're building proprietary closed-source detection and licence terms matter.** This repo is Apache-2.0; check downstream compatibility.
- **You need ML-based / behavioural anomaly detection at scale.** Every detector in this repo is deterministic. ML detection is a roadmap item ([#253](https://github.com/msaad00/cloud-ai-security-skills/issues/253)), not what we ship today.

## The positioning sentence

> **Production-grade detection content, OCSF on the wire, HITL-audited,
> sandboxed, runs the same in CLI / CI / MCP / webhook / cloud runner. The
> skills are LLM-portable but the trust contract is not — that's the part
> you can't generate.**

## Further reading

- Trust contract: [`docs/MCP_AUDIT_CONTRACT.md`](MCP_AUDIT_CONTRACT.md), [`docs/MCP_TRANSPORT.md`](MCP_TRANSPORT.md), [`docs/SKILL_CONTRACT.md`](SKILL_CONTRACT.md)
- Harness surfaces: [`docs/HARNESS.md`](HARNESS.md), [`docs/SKILL_COMPOSITION.md`](SKILL_COMPOSITION.md)
- Coverage today: [`docs/COVERAGE_SNAPSHOT.md`](COVERAGE_SNAPSHOT.md), [`docs/SKILL_INDEX.md`](SKILL_INDEX.md), [`docs/INGEST_COVERAGE.md`](INGEST_COVERAGE.md)
- Security grades: [`docs/SECURITY_GRADES.md`](SECURITY_GRADES.md) — scanner output, regenerated weekly
