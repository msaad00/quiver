---
name: detect-gcp-outbound-peering-anomaly
description: >-
  Detect GCP `compute.networks.addPeering` audit events whose peer network is
  in a different GCP project than the source network — an egress lateral path
  used as a transport for `T1071.001` (Web Protocols) and `T1041`
  (Exfiltration Over C2 Channel). Reads OCSF 1.8 API Activity (class 6003)
  records produced by `ingest-gcp-audit-ocsf`, parses
  `unmapped.gcp.network` and `unmapped.gcp.peer_network` URIs of the form
  `projects/{project}/global/networks/{network}`, and emits an OCSF 1.8
  Detection Finding (class 2004) when the two projects differ AND the peer
  project is not on the `GCP_PEERING_AUTHORIZED_PROJECTS` allow-list. Use
  when the user mentions "GCP cross-project peering", "VPC egress to
  attacker project", "T1071.001 in GCP", or "T1041 via peering". Do NOT
  use as a posture-at-rest peering inventory, for shared-VPC host /
  service-project relationships approved at the org level, or on non-GCP
  audit-log events.
purpose: Detect GCP outbound VPC peering created with an external project as a C2 / exfiltration path.
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
  Requires Python 3.11+. Read-only — consumes OCSF 1.8 API Activity 6003
  records from stdin/file and emits OCSF 1.8 Detection Finding 2004 to
  stdout. No GCP SDK; pairs with `ingest-gcp-audit-ocsf` upstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-gcp-outbound-peering-anomaly
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud: gcp
  capability: read-only
---

# detect-gcp-outbound-peering-anomaly

## Use when

You want to detect new GCP VPC network peering connections whose peer
network lives in a different GCP project — an outbound lateral path an
attacker with `compute.networks.addPeering` can establish to quietly
bridge a controlled project into your VPC for exfiltration or C2.

## Do NOT use

- as a posture-at-rest peering inventory (this fires on
  `compute.networks.addPeering` events, not on existing topology)
- for cross-region peerings within the same project (legitimate
  intra-tenant routing)
- on raw GCP audit logs before normalization — pipe through
  `ingest-gcp-audit-ocsf` first

## Attack pattern

GCP VPC peering establishes a private routing path between two VPC
networks. The peer can live in the same project or in any other GCP
project. An attacker who lands `compute.networks.addPeering` permission
on a target VPC can wire it to a network in **an attacker-controlled
project**, opening an egress lane that bypasses public-internet egress
controls. From the attacker's network it then becomes a C2 transport
(`T1071.001`) or a direct exfiltration channel (`T1041`).

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose producer
is `ingest-gcp-audit-ocsf`:

1. Filter to `api.operation == "compute.networks.addPeering"`.
2. Require `status_id == 1` (success).
3. Read `unmapped.gcp.network` and `unmapped.gcp.peer_network`
   (URIs of the form `projects/{project}/global/networks/{network}`).
4. Extract the project prefix from each. If they match → skip.
5. **Fail-open allow-list**: if `GCP_PEERING_AUTHORIZED_PROJECTS` is
   empty, fire on every cross-project peering (with
   `evidence.allowlist_mode = "fail-open"`). Operators must set the
   allow-list explicitly in prod; the warning is emitted to stderr.
6. When the allow-list is set, fire only when the peer project is
   **not** on it.

The detector is stateless — one finding per event, deduplicated on
`metadata.uid`.

Operators tune the policy at runtime:

- `GCP_PEERING_AUTHORIZED_PROJECTS` — comma-separated project IDs
  (default empty = fail-open).

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["gcp-outbound-peering-anomaly", "peer-project-<...>"]`
- `finding_info.attacks[]` carries MITRE ATT&CK `T1071.001` (TA0011) and
  `T1041` (TA0010)
- `observables[]` for source / peer network and project, peering name, actor
- `evidence` carries `allowlist_mode`, `peer_project`, `source_project`

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
export GCP_PEERING_AUTHORIZED_PROJECTS="shared-host-prod,partner-acme-dr"
cat gcp_audit.ocsf.jsonl \
  | python src/detect.py \
  > gcp_outbound_peering_anomaly_findings.ocsf.jsonl
```

## Do NOT use

- As a posture-at-rest peering inventory.
- For shared-VPC host / service-project relationships approved at the
  org level — add those to `GCP_PEERING_AUTHORIZED_PROJECTS`.
- On non-GCP audit-log events.

## Tests

The test suite covers:

- positive: cross-project peering in fail-open fires
- positive: cross-project peering with allowlist enforced (peer not listed) fires
- negative: same-project peering does NOT fire
- negative: cross-project peering where peer is on allow-list does NOT fire
- malformed: missing peer URI → no fire, stderr warning
- threshold edge: malformed network URIs are surfaced and skipped
- multi-event idempotence: duplicate `metadata.uid` does not inflate counts
- vendor-name: non-gcp-audit producer ignored
- env-override: `GCP_PEERING_AUTHORIZED_PROJECTS` honored
- golden fixture: input / output round-trip

## Roadmap

First slice of the cloud exfiltration + defense-evasion expansion under
issue `#253` (MITRE ATT&CK coverage to 50%).
