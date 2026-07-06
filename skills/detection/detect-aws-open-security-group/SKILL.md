---
name: detect-aws-open-security-group
description: >-
  Detect AWS Security Group ingress rules opened to the internet (0.0.0.0/0
  or ::/0) on risky admin / database / cache / search ports. Reads OCSF 1.8
  API Activity (class 6003) records emitted by ingest-cloudtrail-ocsf,
  fires on successful AuthorizeSecurityGroupIngress calls whose granted
  permissions cover any of the configured risky ports (default: SSH, RDP,
  MySQL, Postgres, Redis, Mongo, Cassandra, Kafka, Elasticsearch, etc.),
  and emits an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE
  ATT&CK T1190 (Exploit Public-Facing Application). Use when the user
  mentions "detect open security groups," "AWS SG public exposure," "find
  internet-facing SG ingress," or "T1190 detection." Do NOT use as a
  remediator (pair with remediate-aws-sg-revoke), for GCP firewall rules
  (different shape — see #307 phase B), or as a posture check (CSPM
  evaluates state at rest; this detector fires on the create-event so
  response can be near-real-time). Out of scope: ICMP / non-IP protocols,
  VPC Network ACLs (different API surface), and intentionally-open
  exposures (operators tag those via SG tag `intentionally-open` and the
  paired remediator's deny-list refuses to revoke them).
purpose: "Detect AWS Security Group ingress rules opened to the internet (0.0.0.0/0 or ::/0) on risky admin / database / cache / search ports. Reads OCSF 1.8 API Activity (class 6003) records emitted by ingest-cloudtrail-ocsf,..."
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
compatibility: >-
  Requires Python 3.11+. Read-only — consumes OCSF 1.8 API Activity records
  from stdin/file, emits OCSF 1.8 Detection Finding 2004 to stdout. No AWS
  SDK; pairs with the existing ingest-cloudtrail-ocsf upstream and the new
  remediate-aws-sg-revoke downstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-aws-open-security-group
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - CIS AWS Foundations
  cloud: aws
  capability: read-only
---

# detect-aws-open-security-group

Streaming detector for AWS Security Group ingress opened to the internet on risky ports. Pairs with [`remediate-aws-sg-revoke`](../../remediation/remediate-aws-sg-revoke/) (closes #307 phase A's detection-side gap; the remediator closes the act-side).

## Use when

- You stream CloudTrail through `ingest-cloudtrail-ocsf` and want near-real-time T1190 findings
- You want a streaming alternative to the periodic CSPM check that catches SG exposures the moment they land
- You feed findings into the closed-loop remediator (`remediate-aws-sg-revoke`)

## Do NOT use

- For VPC Network ACL changes (different API surface)
- For GCP firewall or Azure NSG (separate detectors per #307 phases B + C)
- For ICMP-only or non-TCP/UDP protocol grants
- As a posture-at-rest scan (use the CSPM benchmark for that)

## Rule

A finding fires on every `AuthorizeSecurityGroupIngress` event from `ingest-cloudtrail-ocsf` that:

1. has `status_id == 1` (success)
2. carries `requestParameters.ipPermissions[*]` with at least one CIDR in `{0.0.0.0/0, ::/0}`
3. covers at least one risky port (default list in `DEFAULT_RISKY_PORTS`; protocol `-1` or `fromPort=-1` count as "all ports")

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[].tactic_uid = TA0001` (Initial Access)
- `finding_info.attacks[].technique_uid = T1190` (Exploit Public-Facing Application)
- `observables[]` includes `target.uid` (the SG id), `target.name`, `target.type=SecurityGroup`, `account.uid`, `region`, plus per-CIDR and per-port observables for the remediator to consume

The native projection (`--output-format native`) carries `permission` (the raw IpPermission item) for forensic context.

## Run

```bash
# CloudTrail → ingest → detect (default OCSF output)
python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-aws-open-security-group/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-aws-open-security-group/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-cloudtrail-ocsf`](../../ingestion/ingest-cloudtrail-ocsf/) — upstream ingester
- [`remediate-aws-sg-revoke`](../../remediation/remediate-aws-sg-revoke/) — pair remediator
- [`cspm-aws-cis-benchmark`](../../evaluation/cspm-aws-cis-benchmark/) — posture-at-rest equivalent
- [`detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)
