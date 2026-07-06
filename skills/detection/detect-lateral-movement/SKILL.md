---
name: detect-lateral-movement
description: >-
  Detect cloud lateral movement by joining normalized audit and flow telemetry
  in native or OCSF mode. Correlates a recent privileged identity pivot with
  accepted east-west traffic to an internal destination and emits a detection
  finding aligned to MITRE ATT&CK T1021 and T1078.004. Use when the user
  mentions lateral movement, east-west pivot, cloud identity abuse followed
  by internal traffic, or wants to detect attackers moving between cloud
  resources after initial access. Do NOT use on raw logs — pipe audit and
  network telemetry through their respective ingestion skills first. Do NOT
  use for pre-compromise detection. Do NOT use as an exfiltration detector.
purpose: Detect cloud lateral movement by joining normalized audit and flow telemetry in native or OCSF mode.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: canonical, native, ocsf
output_formats: ocsf, native
concurrency_safety: requires_consistent_sharding
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-lateral-movement
  version: 0.2.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud:
    - aws
    - azure
    - gcp
---

# detect-lateral-movement

## Attack pattern

The canonical cloud lateral-movement sequence after initial access:

1. Attacker compromises an IAM principal (stolen access key, compromised EC2 instance profile, phished human)
2. Attacker pivots identity with a privileged cloud API operation:
   - AWS `AssumeRole*`
   - GCP service-account impersonation / key generation
   - Azure role assignment / access elevation / managed-identity assignment
   - Azure Entra / Microsoft Graph application or service-principal credential changes
3. From a compute resource inside the cloud network, attacker initiates east-west traffic to an internal service the original principal never accessed
4. Data transfer starts

Audit logs alone see step 2. Flow logs alone see steps 3–4. **Neither source alone tells you the story** — the API call may look routine and the flow may look like ordinary internal traffic. The join is where the detection lives.

This skill correlates them.

## Detection logic

One pass over a merged normalized stream of API activity + network activity. The skill accepts OCSF input and the repo's native/canonical event shapes from supported upstream skills. For each identity-pivot anchor in the API stream:

1. Record the `(cloud.provider, cloud.account.uid, actor.session.uid, time)` as an anchor
2. Within a correlation window (default: 15 minutes), scan the Network Activity stream for flows where:
   - `cloud.provider` matches the anchor provider
   - `cloud.account.uid` matches the anchor account when both are present
   - `activity_id == 6` (Traffic ACCEPT — only successful flows count)
   - `dst_endpoint.ip` is **RFC1918 internal** (east-west, not egress to the internet)
   - `traffic.bytes >= 1024` (filter out scan probes — real data transfer threshold)
3. Emit one finding per distinct `(provider, session_uid, dst_endpoint.ip, dst_endpoint.port)` tuple

**Stateless per-run, deterministic UIDs.** Findings are keyed on `(session_uid, dst_ip, dst_port)` so re-running on the same merged stream produces byte-identical output.

## Cross-cloud identity coverage today

This detector already covers the highest-signal identity pivot anchors that are
observable in the repo's shipped audit ingestors:

| Provider | Covered principal types | Covered anchor operations today |
|---|---|---|
| AWS | IAM roles, federated role sessions | `AssumeRole`, `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity` |
| GCP | Service accounts | IAM Credentials API token generation, ID token generation, JWT/blob signing, service-account key creation |
| Azure | Applications, service principals, managed identities | Azure Activity role assignments / elevate access / managed-identity attach, plus Entra / Graph password-key adds, app-role grants, and federated identity credential creation |

This keeps the detector explicit and measurable for ATT&CK `T1021` and
`T1078.004` without pretending it already covers every provider-native identity
event family.

## Current limits

- Azure Entra / Microsoft Graph coverage here is limited to high-signal
  application and service-principal credential changes plus app-role grants. It
  is **not** a complete Entra administrative drift detector.
- AWS IAM user and access-key identity pivots are roadmap work, not current
  detector anchors. Today the AWS slice is explicitly limited to role-session
  pivots observed through STS.
- GCP service-account pivots are currently anchored to IAM Credentials and
  service-account key events. Workload-identity federation abuse beyond those
  signals remains a separate roadmap item.

### AWS roadmap slice

The next explicit AWS ATT&CK expansion for this detector is:

- IAM user access-key creation and proliferation sequences
- temporary-credential pivots such as `GetFederationToken` when the surrounding
  signal is strong enough to support `T1078.004`
- policy-change anchors that materially widen identity reach, such as
  trust-policy or role-policy drift associated with a subsequent east-west move

That work is intentionally tracked as a separate gap so the current detector
does not over-claim AWS identity coverage beyond role-session pivots.

### GCP roadmap slice

The next explicit GCP ATT&CK expansion for this detector is:

- repeated IAM Credentials impersonation patterns beyond the current single
  anchor join
- service-account key proliferation sequences where key creation or reuse
  widens identity reach
- workload-identity federation abuse once the authoritative signal quality is
  strong enough to keep the detector measurable

That split keeps the shipped detector honest about what it already covers in
GCP today: service-account and IAM Credentials pivots, not generic
workload-identity abuse.

### Window semantics

Default 15 minutes post-anchor. Rationale: attackers tend to act fast after acquiring a more powerful cloud identity. A longer window catches more but produces more false positives on legitimate cross-service traffic.

Operators can override the runtime thresholds without forking the skill:

- `DETECT_LATERAL_MOVEMENT_WINDOW_MS`
- `DETECT_LATERAL_MOVEMENT_MIN_BYTES`

### Batch sizing guidance

This detector is designed for bounded batch windows, not as an infinite-stream
in-memory correlator. Today it materializes the normalized event set for the
current run before correlation.

Recommended operator pattern:

- partition by provider and account or tenant where possible
- keep replay or scheduled jobs in explicit time windows
- use upstream chunking for higher-volume environments instead of sending a full
  mixed day of audit and flow telemetry through one process

If you need continuous or very high-volume operation, put a runner in front of
this skill and let the runner own checkpointing and chunk boundaries.

### Why RFC1918-only

The purpose of this rule is **east-west detection**. Egress to the public internet is a different detector (data exfiltration). Filtering to RFC1918 destinations — `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, plus the shared `100.64.0.0/10` — means any fire is definitionally east-west.

## Output contract

By default, the skill emits OCSF 1.8 Detection Finding (class `2004`). When `--output-format native` is selected, it emits the repo's native detection-finding shape with the same deterministic IDs and ATT&CK mappings.

## Native output format

`--output-format native` returns one JSON object per finding with:

- `schema_mode: "native"`
- `record_type: "detection_finding"`
- `finding_uid`
- `rule_id`, `title`, `description`
- `severity_id`, `severity`
- `provider`, `account_uid`, `session_uid`
- `attacks`
- `observables`
- `evidence`

The native finding preserves the same correlation result and deterministic
identity as the OCSF projection while omitting the OCSF 2004 wrapper fields.

The output includes:

- `finding_info.attacks[]` — two techniques populated per MITRE v14:
  - **T1021** Remote Services (Lateral Movement tactic, TA0008)
  - **T1078.004** Valid Accounts: Cloud Accounts (Defense Evasion / Persistence / Privilege Escalation / Initial Access — v14 lists multiple tactics for this technique; we pin Persistence as the primary)
- `finding_info.uid` — deterministic (`det-lm-<provider-hash>-<session-hash>-<dst-hash>`)
- `finding_info.types[]` — `["cloud-lateral-movement"]`
- `observables[]` — provider, account, session uid, source principal, anchor operation, source instance, destination IP, destination port, bytes transferred, correlation window

## Usage

```bash
# Merge cloud audit + flow OCSF streams, then pipe through the detector
{
  python ../ingest-cloudtrail-ocsf/src/ingest.py cloudtrail.json
  python ../ingest-vpc-flow-logs-ocsf/src/ingest.py vpc-flow.log
} > merged.ocsf.jsonl

python src/detect.py < merged.ocsf.jsonl > findings.ocsf.jsonl

# Keep the repo-native finding shape instead of OCSF
python src/detect.py --output-format native < merged.native.jsonl > findings.native.jsonl

# Or, run the whole pipe and feed into the SARIF converter
cat merged.ocsf.jsonl \
  | python src/detect.py \
  | python ../convert-ocsf-to-sarif/src/convert.py \
  > lateral-movement.sarif
```

## What does NOT fire

- identity pivot with no subsequent internal traffic → not fired
- Internal traffic with no preceding identity-pivot anchor (`AssumeRole*`, service-account impersonation, or Azure access-elevation event) → not fired
- Identity-pivot anchor followed by egress traffic (public internet dst) → not fired (data exfil detector, roadmap)
- identity pivots with no valid `cloud.provider` or account context → not fired
- Small flows under 1024 bytes → filtered (scan / handshake noise)
- `REJECT` flows → not fired (failed connection attempts don't count as movement)

## Tests

Golden fixture parity: `../golden/lateral_movement_input.ocsf.jsonl` → `../golden/lateral_movement_findings.ocsf.jsonl`. Plus unit tests for the RFC1918 detector, the window logic, provider/account correlation, byte-threshold filtering, and negative controls (egress dst, REJECT flow, no preceding anchor, stale correlation outside the window).

## See also

- [`ingest-cloudtrail-ocsf/REFERENCES.md`](../ingest-cloudtrail-ocsf/REFERENCES.md) — CloudTrail source format
- [`ingest-vpc-flow-logs-ocsf/REFERENCES.md`](../ingest-vpc-flow-logs-ocsf/REFERENCES.md) — VPC Flow Logs v5 source format
- [`OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) — the wire contract both upstream ingest skills honour
- `convert-ocsf-to-sarif` — downstream view layer
- `RUNBOOK.md` (this skill) — triage flow when a finding fires
