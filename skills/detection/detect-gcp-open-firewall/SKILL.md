---
name: detect-gcp-open-firewall
description: >-
  Use when GCP audit log shows compute.firewalls.insert or
  compute.firewalls.patch opening 0.0.0.0/0 or ::/0 to risky admin / DB /
  cache ports; ATT&CK T1190 (Exploit Public-Facing Application). Reads
  OCSF 1.8 API Activity (class 6003) records emitted by
  ingest-gcp-audit-ocsf, fires on successful Compute Engine firewall
  insert/patch calls whose `unmapped.gcp.request` opens INGRESS from
  0.0.0.0/0 or ::/0 to any of the configured risky ports (default: SSH,
  RDP, MySQL, Postgres, Redis, Mongo, Cassandra, Kafka, Elasticsearch,
  etc.) on a non-disabled rule, and emits an OCSF 1.8 Detection Finding
  (class 2004) tagged with MITRE ATT&CK T1190. Pairs with
  remediate-gcp-firewall-revoke. Do NOT use for AWS Security Groups
  (different shape — see detect-aws-open-security-group), for Azure
  Network Security Groups (separate detector planned), for private-only
  source-range changes (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), for
  EGRESS firewall changes, for rules created with `disabled: true`, or
  as a posture check (CSPM evaluates state at rest; this detector fires
  on the create/patch event so response can be near-real-time).
purpose: "Use when GCP audit log shows compute.firewalls.insert or compute.firewalls.patch opening 0.0.0.0/0 or ::/0 to risky admin / DB / cache ports; ATT&CK T1190 (Exploit Public-Facing Application). Reads OCSF 1.8 API Activi..."
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
  from stdin/file, emits OCSF 1.8 Detection Finding 2004 to stdout. No GCP
  SDK; pairs with the existing ingest-gcp-audit-ocsf upstream and the
  remediate-gcp-firewall-revoke downstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-gcp-open-firewall
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - CIS GCP Foundations
  cloud: gcp
  capability: read-only
---

# detect-gcp-open-firewall

Streaming detector for GCP VPC firewall rules opened to the internet on risky
ports. Pairs with [`remediate-gcp-firewall-revoke`](../../remediation/remediate-gcp-firewall-revoke/).

## Use when

- You stream GCP Cloud Audit Logs through `ingest-gcp-audit-ocsf` and want
  near-real-time T1190 findings on `compute.firewalls.insert` and
  `compute.firewalls.patch`
- You want a streaming alternative to the periodic CSPM check that catches
  firewall exposures the moment they land
- You feed findings into the closed-loop remediator
  (`remediate-gcp-firewall-revoke`)

## Do NOT use

- For AWS Security Groups (use `detect-aws-open-security-group`)
- For Azure Network Security Groups (separate detector planned)
- For private-only source-range changes (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- For EGRESS firewall rule changes (different blast radius)
- For rules created with `disabled: true` (no live traffic)
- As a posture-at-rest scan (use `cspm-gcp-cis-benchmark`)

## Rule

A finding fires on every `compute.firewalls.insert` / `compute.firewalls.patch`
event from `ingest-gcp-audit-ocsf` that:

1. has `status_id == 1` (success)
2. carries `unmapped.gcp.request.direction == "INGRESS"`
3. is not disabled (`unmapped.gcp.request.disabled` is False / missing)
4. carries at least one CIDR in `sourceRanges` that is `0.0.0.0/0` or `::/0`
5. covers at least one risky port across its `allowed[]` entries (protocol
   `all` or port range covering a risky port counts as a hit)

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`),
with:

- `finding_info.attacks[].tactic_uid = TA0001` (Initial Access)
- `finding_info.attacks[].technique_uid = T1190` (Exploit Public-Facing Application)
- `observables[]` includes `target.uid` (firewall rule name), `target.name`,
  `target.type=GcpFirewallRule`, `account.uid` (project id), plus per-CIDR
  and per-port observables for the remediator to consume

## Run

```bash
# GCP audit logs → ingest → detect (default OCSF output)
python skills/ingestion/ingest-gcp-audit-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-gcp-open-firewall/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-gcp-open-firewall/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-gcp-audit-ocsf`](../../ingestion/ingest-gcp-audit-ocsf/) — upstream ingester
- [`remediate-gcp-firewall-revoke`](../../remediation/remediate-gcp-firewall-revoke/) — pair remediator
- [`cspm-gcp-cis-benchmark`](../../evaluation/cspm-gcp-cis-benchmark/) — posture-at-rest equivalent
- [`detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)
