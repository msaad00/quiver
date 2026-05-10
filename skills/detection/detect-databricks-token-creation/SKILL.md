---
name: detect-databricks-token-creation
description: >-
  Detect creation of Databricks personal access tokens (PATs) on a workspace.
  Reads OCSF 1.8 API Activity (class 6003) records carrying
  `metadata.product.vendor_name == "Databricks"`, `api.operation ==
  "tokens/create"`, an `actor.user.uid` (or `email_addr`), and
  `unmapped.databricks.workspace_id`, and emits one OCSF 1.8 Detection Finding
  (class 2004) per successful token issuance, tagged with MITRE ATT&CK
  T1098.001 (Additional Cloud Credentials). Once a PAT exists it can be used
  for headless API access without an interactive login. Use when the user
  mentions "Databricks PAT created", "Databricks token issued",
  "T1098.001 in Databricks", or "additional cloud credentials in
  Databricks". Do NOT use on raw Databricks audit-log JSON before OCSF
  normalization, as a posture-at-rest token inventory or age check, or as a
  generic credential-issuance detector for non-Databricks platforms.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native, ocsf
concurrency_safety: stateless
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-databricks-token-creation
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP LLM Top 10
  cloud:
    - databricks
---

# detect-databricks-token-creation

## Attack pattern

A Databricks personal access token (PAT) is the workspace-level equivalent of
an additional cloud credential. Once issued, a PAT lets a principal call the
Databricks REST API without going through an interactive SSO/OIDC login. The
default token TTL is "no expiry" unless the workspace admin has set a
`maxTokenLifetimeDays` policy, which means a single token-creation event by
a compromised user, a stale offboarded principal, or a service-principal
operating outside its declared automation window can sit on the wire
indefinitely.

The shape on the wire is a Databricks audit-log entry where
`actionName == "tokens/create"` (Databricks Token Management API) carrying
the requesting principal's `userIdentity.email`, the `workspaceId`, the
optional comment, and the optional `lifetime_seconds` request parameter. Once
normalized through the upstream `ingest-databricks-audit-ocsf` pipeline
(roadmap, see #436) the same record materializes as OCSF 1.8 API Activity
(class `6003`) with the action surfaced under `api.operation` and the
workspace ID surfaced under `unmapped.databricks.workspace_id`.

This detector does NOT model token *use* (every API call carries the token);
it models token *issuance*, which is the persistence anchor.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.vendor_name` is `Databricks` (or whose
`metadata.product.feature.name` identifies a Databricks ingest source):

1. Match `api.operation == "tokens/create"` (case-insensitive).
2. Require `status_id == 1` (success) — failed token-create attempts are
   noisy and not a persistence anchor on their own.
3. Require a non-empty `actor.user.uid` or `actor.user.email_addr`.
4. Fire **once per matching event** (no windowing, no dedupe across
   principals — each token issuance is its own persistence anchor).

When the operation matches the Databricks token-management surface
(`tokens/*`) but the action name is not in the recognized map (e.g. a future
Databricks API verb the detector hasn't seen yet), the skill emits an
`unmapped_event_type` stderr telemetry record and does not fire — same
pattern the Okta ingest pipeline uses post-#458, so operators can grep
the unmapped feed and propose new mappings without losing visibility.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["databricks-token-creation",
  "OWASP-LLM-Top-10-LLM02"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1098`
  (Account Manipulation) plus sub-technique `T1098.001`
  (Additional Cloud Credentials), tactic `TA0003 Persistence`
- `observables[]` carrying the actor (uid + email), the Databricks
  workspace ID, the API operation, and the optional token comment / token id
  when the upstream ingest surfaces them
- `evidence` carrying the raw event uid, the workspace id, the API
  operation, the token id (when known), and the requested token lifetime
  (when known)

Severity is `HIGH` (severity_id `4`) because a Databricks PAT never expires
by default and grants the same scope as the issuing principal.

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
cat databricks_audit.ocsf.jsonl \
  | python src/detect.py \
  > databricks_token_creation_findings.ocsf.jsonl

# Same input, native finding projection out:
cat databricks_audit.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > databricks_token_creation_findings.native.jsonl
```

## Do NOT use

- On raw Databricks audit-log JSON before OCSF normalization
- As a posture-at-rest token inventory or age / lifetime check
- As a token-use detector — this skill models issuance, not consumption
- On non-Databricks API Activity 6003 events (we filter on
  `metadata.product.vendor_name == "Databricks"` plus the producer source
  skill list)

## Tests

The test suite covers:

- positive: a single successful `tokens/create` fires exactly one finding
  with the expected MITRE T1098.001 mapping
- negative: a read-only `tokens/list` action does NOT fire
- negative: a failed `tokens/create` (`status_id != 1`) does NOT fire
- edge: a malformed JSON line is skipped with a stderr telemetry event,
  not crashed on
- edge: a multi-token burst (same principal, several tokens within seconds)
  fires once per token — no aggregation, no suppression
- edge: a Databricks audit event whose action is in the `tokens/*` family
  but is not in the recognized map emits an `unmapped_event_type` stderr
  telemetry event and does not fire

## Roadmap

This is the first Databricks vendor-depth detector for issue #436.
Five more Databricks detectors remain on the roadmap (token use beyond
declared windows, workspace-admin grants, MLflow model-artifact download,
DBFS / Unity Catalog cross-workspace data movement, cluster init-script
abuse) and will reuse the same OCSF 1.8 API Activity 6003 input contract
once the `ingest-databricks-audit-ocsf` ingester lands.
