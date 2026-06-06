---
name: detect-mass-termination-anomaly
description: >-
  Detect sudden spikes in Workday termination events that may indicate a
  compromised HR account, unauthorized bulk offboarding, or an unapproved
  workforce action. Reads OCSF 1.8 Account Change (3001) or native events
  emitted by `ingest-workday-audit-ocsf`, groups distinct workers into
  time windows, skips explicitly approved batch IDs, and emits OCSF Detection
  Finding (2004) tagged with MITRE ATT&CK T1098. Use when the user mentions
  Workday terminations, HR offboarding spikes, or insider-risk review. Do NOT
  use on raw Workday reports before normalization, on non-Workday IAM events,
  or as remediation.
purpose: Detect Workday mass-termination spikes in normalized HR lifecycle events.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-mass-termination-anomaly
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - workday
---

# detect-mass-termination-anomaly

## Use when

- You normalized Workday audit/report events with `ingest-workday-audit-ocsf`
- You need to detect termination spikes before downstream IAM remediation runs
- You want a stateless HR lifecycle detector for insider-risk and account-governance review

## Do NOT use

- On raw Workday REST/RaaS payloads before ingestion
- On Entra, Okta, Google Workspace, Slack, or cloud IAM lifecycle events
- As remediation; termination reversal or IAM disablement belongs in a HITL-gated write skill

## Detection logic

One pass over OCSF Account Change events:

1. Require producer `ingest-workday-audit-ocsf`.
2. Require `unmapped.workday.event_family=termination`.
3. Bucket events into `WORKDAY_TERMINATION_WINDOW_MINUTES` windows. Default is `60`.
4. Require at least `WORKDAY_TERMINATION_COUNT_THRESHOLD` distinct workers. Default is `10`.
5. Ignore events whose batch ID is present in `WORKDAY_APPROVED_TERMINATION_BATCH_IDS`.

Operators can tune thresholds with:

```bash
export WORKDAY_TERMINATION_WINDOW_MINUTES=30
export WORKDAY_TERMINATION_COUNT_THRESHOLD=5
export WORKDAY_APPROVED_TERMINATION_BATCH_IDS="planned-layoff-2026-06-06"
```

## Output contract

Default output is OCSF Detection Finding (class `2004`) with:

- deterministic `metadata.uid`
- `finding_info.types[] = ["workday-mass-termination-anomaly", "OWASP-Top-10-A01"]`
- MITRE ATT&CK `T1098`
- window start/end, threshold, workers, supervisory orgs, batch IDs, and raw event IDs in evidence

Severity is `HIGH`.

## Usage

```bash
cat workday-audit.ocsf.jsonl | python src/detect.py > workday-termination-findings.ocsf.jsonl
```

## Roadmap

Part of Workday vendor story issue #34.
