---
name: detect-azure-open-nsg
description: >-
  Use when Azure activity log shows
  Microsoft.Network/networkSecurityGroups/securityRules/write opening * /
  Internet / 0.0.0.0/0 / ::/0 to risky admin/DB/cache ports; ATT&CK T1190.
  Reads OCSF 1.8 API Activity (class 6003) records emitted by
  ingest-azure-activity-ocsf, fires on successful Inbound + Allow security
  rule writes whose source prefix is `*`, `Internet`, `0.0.0.0/0`, or `::/0`
  and whose destination port range covers any of the configured risky
  ports (default: SSH, RDP, MySQL, Postgres, Redis, Mongo, Elasticsearch,
  Memcached, etc.). Parses single ports, port ranges (`22-25` matches
  because 22 is in range), and `*` (all ports). Emits an OCSF 1.8
  Detection Finding (class 2004) tagged with MITRE ATT&CK T1190 (Exploit
  Public-Facing Application). Do NOT use as a remediator (pair with
  remediate-azure-nsg-revoke), for AWS Security Groups (separate detector
  detect-aws-open-security-group), for GCP firewall rules (separate
  detector detect-gcp-open-firewall), for Outbound rules (irrelevant to
  ingress exposure), for Deny rules (not granting access), or for rules
  whose source prefix is a private CIDR (10.0.0.0/8, 172.16.0.0/12,
  192.168.0.0/16, VirtualNetwork tag, AzureLoadBalancer tag, etc.).
purpose: "Use when Azure activity log shows Microsoft.Network/networkSecurityGroups/securityRules/write opening * / Internet / 0.0.0.0/0 / ::/0 to risky admin/DB/cache ports; ATT&CK T1190. Reads OCSF 1.8 API Activity (class 600..."
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
  from stdin/file, emits OCSF 1.8 Detection Finding 2004 to stdout. No Azure
  SDK; pairs with the existing ingest-azure-activity-ocsf upstream and the
  new remediate-azure-nsg-revoke downstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-azure-open-nsg
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - CIS Azure Foundations
  cloud: azure
  capability: read-only
---

# detect-azure-open-nsg

Streaming detector for Azure Network Security Group inbound rules opened to the internet on risky ports. Pairs with [`remediate-azure-nsg-revoke`](../../remediation/remediate-azure-nsg-revoke/).

## Use when

- You stream Azure Activity Log entries through `ingest-azure-activity-ocsf` and want near-real-time T1190 findings on NSG inbound exposure
- You want a streaming alternative to the periodic CSPM check (`cspm-azure-cis-benchmark`) that catches NSG exposures the moment they land
- You feed findings into the closed-loop remediator (`remediate-azure-nsg-revoke`)

## Do NOT use

- For AWS Security Group changes (use `detect-aws-open-security-group`)
- For GCP firewall changes (use `detect-gcp-open-firewall`)
- For Outbound NSG rules (different threat surface; this detector is ingress-only)
- For Deny rules (they don't grant access)
- For rules whose source is a private CIDR (10/8, 172.16/12, 192.168/16) or an Azure service tag like `VirtualNetwork` / `AzureLoadBalancer`
- As a posture-at-rest scan (use the CSPM benchmark)

## Rule

A finding fires on every `Microsoft.Network/networkSecurityGroups/securityRules/write` event from `ingest-azure-activity-ocsf` that:

1. has `status_id == 1` (success)
2. carries a security rule with `direction == "Inbound"` and `access == "Allow"`
3. lists at least one source prefix in `{*, Internet, 0.0.0.0/0, ::/0}` (across `sourceAddressPrefix` and `sourceAddressPrefixes[]`)
4. covers at least one risky port across `destinationPortRange` and `destinationPortRanges[]`. A range like `"22-25"` matches because port 22 is in the range; `"*"` always matches.

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[].tactic_uid = TA0001` (Initial Access)
- `finding_info.attacks[].technique_uid = T1190` (Exploit Public-Facing Application)
- `observables[]` includes `target.uid` (the rule's fully-qualified Azure Resource Manager id), `target.name` (rule name), `target.type=NetworkSecurityRule`, `account.uid` (subscription id), `region`, plus per-source-prefix and per-port observables for the remediator to consume

The native projection (`--output-format native`) carries the full `rule` body for forensic context.

## Run

```bash
# Activity log → ingest → detect (default OCSF output)
python skills/ingestion/ingest-azure-activity-ocsf/src/ingest.py raw.json \
  | python skills/detection/detect-azure-open-nsg/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-azure-open-nsg/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-azure-activity-ocsf`](../../ingestion/ingest-azure-activity-ocsf/) — upstream ingester
- [`remediate-azure-nsg-revoke`](../../remediation/remediate-azure-nsg-revoke/) — pair remediator
- [`cspm-azure-cis-benchmark`](../../evaluation/cspm-azure-cis-benchmark/) — posture-at-rest equivalent
- [`detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)
