<!-- AUTO-GENERATED — do not hand-edit. Source: runtime-profile-results.jsonl, regenerator: scripts/build_runtime_profiles_doc.py. -->

# Runtime Profiles — Runner Templates

This document is regenerated from `runtime-profile-results.jsonl` every time the harness runs. It is intentionally light on prose: the point is to detect **regressions** between CI runs, not to advertise raw numbers.

Closes:
- [#198](https://github.com/msaad00/cloud-ai-security-skills/issues/198) — deploy and verify all three runner templates end to end (CI surface).
- [#199](https://github.com/msaad00/cloud-ai-security-skills/issues/199) — benchmark runtime profiles at representative scale (CI cadence).

## What this is

Every record below comes from `scripts/runner_e2e.sh`, which spins each runner template up against an ephemeral local backend, sends **N synthetic events matched to that runner's real contract**, and asserts both **audit-log capture** and **sink arrival** before reporting timings.

Sample size defaults to **N = 20** per scenario. These are CI-runner numbers on a free-tier executor. Do **not** quote these p50/p95s as customer-scale numbers — they exist to flag a regression, not to advertise throughput.

## Measured runs

| Runner | Scenario | Samples | p50 | p95 | Mean | Sink arrival | Audit chain | Captured |
|---|---|---:|---:|---:|---:|---:|:---:|---|
| `cloud-runner-aws-s3-sqs` | `s3-eventbridge-ingest` | 20 | 32.24 ms | 33.96 ms | 32.38 ms | 20 | n/a | 2026-05-10T19:17:44Z |
| `mcp-sse` | `jsonrpc-ping-and-tools-list` | 20 | 23.86 ms | 49.16 ms | 24.18 ms | 20 | yes | 2026-05-10T19:17:43Z |
| `webhook-receiver` | `ingest-cloudtrail-ocsf` | 20 | 75.83 ms | 77.58 ms | 76.17 ms | 0 | n/a | 2026-05-10T19:17:42Z |

### Per-scenario assertions

Each `ok` record above means **all** of the following held for the run:

- the runner accepted every one of the N requests with no failures;
- the audit assertion for that runner passed (the receiver writes a single-line JSONL audit; the SSE runner writes an HMAC-chained log and `scripts/verify_audit_chain.py` returned exit 0; the AWS runner has no in-process audit chain — its audit gap is documented below);
- the **sink-arrival assertion** for that runner held (webhook receiver currently does not fan out — gap below; SSE response payload shape was verified for every reply; AWS scenario asserts exact SQS message count = N).

## Honest gaps

Scenarios in this section have **no automated coverage in this PR**. The doc lists them so readers can see the coverage boundary without having to grep the harness source.

- `cloud-runner-azure-blob-eventgrid` — `blob-eventgrid-ingest`: no in-tree local mock for Event Grid + Service Bus; track real-cloud deploy proof in issue #198 instead of fabricating numbers
- `cloud-runner-gcp-gcs-pubsub` — `gcs-finalize-ingest`: no in-tree local mock for Pub/Sub queueing; track real-cloud deploy proof in issue #198 instead of fabricating numbers

### Sub-gaps inside ok-status scenarios

Even `ok` scenarios have bounded coverage — the harness records the boundary on each row's `audit_chain_status` and `sink_status` so this doc never claims more than was tested.

- `cloud-runner-aws-s3-sqs` / `s3-eventbridge-ingest` — audit_chain_status: `gap_aws_runner_audit_writes_via_cloudwatch_only`
- `webhook-receiver` / `ingest-cloudtrail-ocsf` — sink_status: `gap_sink_fanout_needs_per_sink_flags`

## How to run

Locally:

```bash
uv sync --group dev --group webhook --group mcp-sse --group http-runtime
bash scripts/runner_e2e.sh
python scripts/build_runtime_profiles_doc.py
```

In CI the workflow `.github/workflows/runner-e2e.yml` runs the harness on every PR that touches `runners/**`, `mcp-server/**`, `skills/_shared/**`, the harness itself, or the workflow file, plus once a day at 02:00 UTC. The workflow also runs `build_runtime_profiles_doc.py --check` so a PR that updates the harness but not the doc fails immediately.

## Tooling notes

- `helm lint` / `docker build` for the runner templates run in `.github/workflows/runner-templates.yml`, not this harness. The harness assumes the templates render — it does not re-validate them.
- GCP and Azure cloud-runner end-to-end coverage is still gap (see above). The real-cloud deploy proof requested by #198 stays the responsibility of an operator running the templates against a real account; this harness only covers what can be exercised locally.

