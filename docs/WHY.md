# Why this repo exists

**This repo is built for LLMs and agents to use.** MCP wrapper, Agent SDK
hook, Python library shim, CLI pipes, webhook receiver, cloud runners — every
surface exists so a Claude agent / Cursor session / GitHub Actions step / cron
job can call one of these 90 skills the same way it would call any other tool.

So the question isn't *"LLM versus this repo."* It's:

> *Your agent needs skills to invoke. Should it use these 90 — or should it
> generate ad-hoc Python on the fly, or have you commit LLM-written skills,
> or have your team write the same 90 from scratch?*

All four options keep the LLM in the loop. The difference is **what runs
inside the trust boundary the agent crosses** when it fires a tool — and
who pays the engineering bill to put it there.

## The short answer

Skill content is the easy part. The **trust contract around the skill**, the
**calibration that makes the detector accurate**, and the **cross-cutting
maintenance** are the hard parts — and none of them are LLM-generable.

When your agent fires `remediate-aws-sg-revoke` because a tool description
said so (legitimately, or because a poisoned MCP server slipped a
prompt-injected instruction through a `tools/list` response), what stops the
security-group rule from actually getting revoked without human review? **The
guards in this repo, not the LLM:**

- **HITL approval context** required before subprocess spawn — `min_approvers` enforced in the wrapper, not the model.
- **Operator allowlist** intersected with caller context intersected with workflow preset — the model cannot widen what the operator allowed.
- **Three sandbox layers** around the subprocess — always-on RLIMIT, hardened container, opt-in OS sandbox (`bwrap` / `sandbox-exec`).
- **HMAC-chained audit log** — every call leaves a tamper-evident record an incident responder can replay.
- **Default-deny, dry-run-first** on every write-capable skill.

A function the LLM generated at runtime has **none** of those. It runs as
your user, with your full credentials, and the first time you see the
resulting damage is in `git log` (if you're lucky) or in your cloud bill.

The skills are LLM-portable. The trust contract is the moat.

## Three flavours of "skip this repo" — three different answers

There are three serious versions of *"why use these 90, why not roll our own?"*
The argument is different for each.

### A. *"My agent will just write the Python at runtime."*

Covered above. Answer: the agent can't write the trust contract around the
code (HITL gates, allowlist, sandbox, audit chain, default-deny) because the
contract has to live **outside** the function the agent generates — and the
agent has no privileged surface to install one. Runtime-generated code runs
as your user with your creds and zero observability. The first time a
prompt-injected `tools/list` response convinces the agent to fire a delete
operation, you find out via your cloud bill.

### B. *"I'll ask my agent to write skills, review the diff, commit them."*

Better posture (humans in the loop), but the LLM still can't generate the
parts that matter:

- **Calibration values are not in the training data.** What threshold of
  `bytes_scanned` separates Snowflake bulk egress from a legitimate
  analyst's `COPY INTO`? How many MFA push events in what window before
  Okta MFA fatigue fires without false-positive storms? Those come from
  real telemetry + red-team corpora — not from prompting. An LLM will
  pick a plausible-sounding number ("threshold = 1000") and you'll learn
  later it was the wrong number.
- **Framework mappings drift silently.** MITRE ATT&CK technique IDs,
  OWASP A-numbers, OCSF activity IDs — the LLM will hallucinate close
  matches ("this is T1098 I think"). Our `framework-coverage.json` +
  CI gate refuse drift; LLM-generated metadata doesn't have a gate
  behind it.
- **OCSF wire-class choice is non-obvious.** Should a Snowflake
  `GRANT_ROLE` event normalize to OCSF API Activity 6003 or User Access
  Management 3005? The right answer depends on the OCSF 1.8 catalog
  semantics — read the spec wrong and your downstream detector misses
  the event. We've made that choice once, snapshot-tested it; LLM-
  generated skills make it 90 times, inconsistently.
- **Vendor-schema fidelity is research.** The Entra Directory Audit
  schema, the Okta System Log event-type taxonomy, the Snowflake
  `query_history` columns that come and go between Snowflake releases —
  fidelity here comes from reading vendor docs deeply and watching them
  change over time. The LLM saw a snapshot of those docs at training
  time. Six months from now its mapping is stale and silently wrong.
- **Cross-skill composition needs context the LLM doesn't have.**
  `detect-snowflake-bulk-data-egress` reads `unmapped.snowflake.bytes_scanned`
  because that's what `source-snowflake-query` emits, because that's
  what Snowflake's `RESULT_SCAN(LAST_QUERY_ID())` returns under that
  exact name. Get any link in that chain wrong and the detector silently
  fires on nothing. The LLM has to be spoon-fed every adjacent
  contract; we've already done that work and locked it in snapshot tests.
- **No precision/recall feedback loop.** You committed the LLM's skill.
  Is it any good? Without a labelled corpus + scorer, you find out
  in production — or you don't. v0.10.0's
  [`scoring/`](../skills/detection-engineering/scoring/) is the loop.

### C. *"My team will write all 90 skills from scratch."*

This works — at cost. The repo's
[cost-framing table](#the-cost-framing--roll-your-own-to-parity) below
estimates **~500 engineer-hours / ~12 weeks** to reach feature parity
with v0.10.0 before the first detector is written. That's the harness
cost. Detector content is on top of that — six hours per detector × 39
detectors = another **~240 hours**, plus the calibration work, plus the
captured-fixture corpus, plus the framework-mapping research. Realistic
all-in: a small team for a quarter to land what the repo ships today.

Then comes the **maintenance tax**:

- **Every OCSF version bump** (1.7 → 1.8 → 1.9) touches every ingester
  and every detector. We rev once; a fork revs N times.
- **Every MITRE ATT&CK release** (v14 → v15) changes technique IDs and
  retires some. The repo's framework-coverage gate forces an update.
  Your fork has to do that work on its own.
- **Every vendor schema change** (Snowflake adds a column, Okta retires
  an event type, Entra renames a field) is a contract change. We see
  it once across the OSS commons; a fork sees it per-team.
- **The six-surface harness** (CLI + CI + MCP + webhook + library + cloud-runner)
  has to evolve together. Slip one surface and the contract drifts.
  Same `SKILL.md` runs all six here; a fork that picks two has to
  port back when it needs the third.

The OSS commons is the real argument against a fork: shared maintenance
amortizes across every adopter. Your team's engineering time gets spent
on what's unique to your environment (custom detectors, internal
playbooks, your compliance overlay) instead of re-implementing the
audit-chain HMAC verifier for the fourth time.

### When forking still makes sense

- You need detection content under a proprietary licence and Apache-2.0
  is the wrong fit.
- Your environment requires a single-cloud-deep stack and a generic
  multi-cloud harness is overhead you don't want.
- Your platform team is large enough that the maintenance tax pays for
  itself in flexibility.

Otherwise, the answer is: contribute upstream, not fork. The CONTRIBUTING
flow is documented; a single new ingester or detector lands in days,
not quarters.

## What this repo gives the agent that ad-hoc code doesn't

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

### 8. One bundle, six surfaces — zero per-surface drift
Same `SKILL.md` + `src/` + `tests/` runs unchanged under:

| Surface | How it invokes |
|---|---|
| CLI | `python skills/[layer]/[name]/src/[entry].py` |
| CI | GitHub Actions runs the same entrypoint |
| MCP | Stdio wrapper (Claude Code / Desktop / Cursor / Codex / Cortex / Windsurf / Zed) or SSE/HTTP listener |
| Webhook | Receiver routes signed POST payloads through the same registry |
| Library | Python apps call the shared skill runner in-process |
| Persistent runners | Queue / object / event loops reuse the same skill entrypoint |

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
| Six-surface harness (CLI + CI + MCP + webhook + library + runner) | ~80 h |
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

> **Production-grade security skills for LLMs and agents to invoke — OCSF on
> the wire, HITL-audited, sandboxed, MCP-callable, runs the same in CLI /
> CI / MCP / webhook / cloud runner. The skills are LLM-portable but the
> trust contract that wraps them, the calibration that makes them accurate,
> and the cross-cutting maintenance are not — that's the part your agent
> can't generate at runtime and your team shouldn't reimplement in-house.**

## Further reading

- Trust contract: [`docs/MCP_AUDIT_CONTRACT.md`](MCP_AUDIT_CONTRACT.md), [`docs/MCP_TRANSPORT.md`](MCP_TRANSPORT.md), [`docs/SKILL_CONTRACT.md`](SKILL_CONTRACT.md)
- Harness surfaces: [`docs/HARNESS.md`](HARNESS.md), [`docs/SKILL_COMPOSITION.md`](SKILL_COMPOSITION.md)
- Coverage today: [`docs/COVERAGE_SNAPSHOT.md`](COVERAGE_SNAPSHOT.md), [`docs/SKILL_INDEX.md`](SKILL_INDEX.md), [`docs/INGEST_COVERAGE.md`](INGEST_COVERAGE.md)
- Security grades: [`docs/SECURITY_GRADES.md`](SECURITY_GRADES.md) — scanner output, regenerated weekly
