---
name: ingest-okta-system-log-ocsf
description: >-
  Convert verified Okta System Log events into OCSF 1.8 or native Identity &
  Access Management records. The first slice maps session and SSO events to
  Authentication (3002), user lifecycle and account-control changes to Account
  Change (3001), app/group membership updates to User Access Management (3005),
  and a narrow verified set of Okta Verify MFA challenge and denial events to
  Authentication (3002). It preserves Okta natural IDs such as uuid, published,
  transaction.id, and authenticationContext.externalSessionId for SIEM-friendly
  dedupe and correlation. Use when the user mentions Okta System Log ingestion,
  Okta audit log normalization, cross-vendor identity telemetry, or feeding
  Okta identity events into an OCSF pipeline or native canonical-first flow. Do NOT use for raw Azure Entra,
  Google Workspace, or AWS IAM logs. Do NOT use as a detector or policy engine
  — this skill only normalizes verified Okta event payloads into OCSF or native output.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. No Okta SDK required when System Log payloads are
  already exported. Read-only — validates raw Okta event shape and emits OCSF
  or native JSONL. Never calls write APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-okta-system-log-ocsf
  version: 0.2.0
  frameworks:
    - OCSF 1.8
  cloud: okta
  capability: read-only
---

# ingest-okta-system-log-ocsf

Convert raw Okta System Log payloads into OCSF 1.8 or native IAM events with
deterministic IDs and verified field mappings.

## Use when

- You have Okta System Log exports from the `/api/v1/logs` API, event hooks, or archived JSON and need OCSF output
- You want to normalize Okta identity telemetry for SIEM, lake, MCP, or downstream detection use
- You need a portable identity event stream that preserves Okta `uuid`, `published`, session, and transaction identifiers
- You want app and group membership updates represented as OCSF user access events instead of vendor-only audit records

## Do NOT use

- On Entra, Workspace, CloudTrail, or Kubernetes audit logs
- To collect live Okta logs by itself — upstream collection and auth stay outside this skill
- To infer ATT&CK techniques or create findings directly
- To rewrite or mutate Okta objects, users, groups, apps, or sessions

## Input contract

Accepts one of three raw Okta System Log shapes:

1. **System Log API array**

```json
[
  {
    "uuid": "b9ab9263-a4ae-4780-9981-377ec8f2da86",
    "published": "2026-04-13T02:15:00.000Z",
    "eventType": "user.session.start"
  }
]
```

2. **Single event**

```json
{
  "uuid": "b9ab9263-a4ae-4780-9981-377ec8f2da86",
  "published": "2026-04-13T02:15:00.000Z",
  "eventType": "user.session.start"
}
```

3. **Event hook wrapper**

```json
{
  "data": {
    "events": [
      {
        "uuid": "b9ab9263-a4ae-4780-9981-377ec8f2da86",
        "published": "2026-04-13T02:15:00.000Z",
        "eventType": "user.session.start"
      }
    ]
  }
}
```

The first slice intentionally supports a narrow, verified event family:

- `user.session.start`
- `user.session.end`
- `user.authentication.sso`
- `user.authentication.auth_via_mfa`
- `user.lifecycle.create`
- `user.lifecycle.activate`
- `user.lifecycle.deactivate`
- `user.lifecycle.suspend`
- `user.lifecycle.unsuspend`
- `user.account.update_password`
- `user.account.reset_password`
- `user.account.lock`
- `user.account.unlock_by_admin`
- `user.mfa.factor.activate`
- `user.mfa.factor.deactivate`
- `user.mfa.okta_verify`
- `user.mfa.okta_verify.deny_push`
- `user.mfa.okta_verify.deny_push_upgrade_needed`
- `system.push.send_factor_verify_push`
- `application.user_membership.add`
- `application.user_membership.remove`
- `group.user_membership.add`
- `group.user_membership.remove`
- `user.account.privilege.grant`
- `user.account.privilege.revoke`

Unsupported event types are skipped, never silently dropped. Each occurrence emits
an `unmapped_event_type` warning to `stderr` with the offending `event_type` and
event uid. At end of run, an `unmapped_event_type_summary` info record reports
total skipped, distinct event types, and the top 10 unmapped types with counts —
so blind spots in the classification map surface immediately in CI logs and
log-search dashboards.

## Output contract

Emits OCSF 1.8 JSONL by default, with `--output-format native` available for
the repo-owned canonical projection.

OCSF output uses these verified class mappings:

- **Authentication (3002)** for session, SSO, and verified Okta Verify MFA verification events
- **Account Change (3001)** for user lifecycle and account-control events
- **User Access Management (3005)** for app/group membership and privilege grant/revoke events

Each output record includes:

- deterministic `metadata.uid` based on Okta `uuid` or a stable hash fallback
- UTC epoch-millisecond `time` from `published`
- Okta session and transaction correlation data preserved under `unmapped.okta.*`
- `actor`, `user`, `src_endpoint`, and `resources` where the raw event supports them
- **expanded v0.2 OCSF-native slots** (see table below) when the Okta payload carries geographicalContext, securityContext, client.userAgent, authenticationContext, debugContext, or request.ipChain

### OCSF 1.8 mapping (v0.2, #271)

The full Okta-field → OCSF-field table, the `unmapped.okta.*` native preservation list, and the risk-signal enrichment shape live in [`references/field-map.md`](references/field-map.md). Keeping the detail there keeps this file under the progressive-disclosure word target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)) while detectors and reviewers still get the exact mapping one click away.

## Usage

```bash
# API export file
python src/ingest.py okta-system-log.json > okta.ocsf.jsonl

# event hook payload from stdin
cat event-hook.json | python src/ingest.py > okta.ocsf.jsonl

# pretty output file
python src/ingest.py okta.json --output okta.ocsf.jsonl

# native projection for non-OCSF consumers
python src/ingest.py okta.json --output-format native > okta.native.jsonl
```

## Security guardrails

- Read-only only. No Okta writes. No subprocesses.
- Keeps vendor-native IDs for dedupe and correlation instead of inventing new random IDs.
- Uses verified raw fields from official Okta docs only; unsupported event types are skipped rather than guessed.
- Normalizes into OCSF only where the class fit is explicit. Unmapped vendor-specific detail stays under `unmapped`.

## Native output format

When `--output-format native` is selected, the skill emits:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type`
- `event_uid`
- `provider`
- `activity_id`
- `event_type`
- `severity` / `severity_id`
- `status` / `status_id`
- `time_ms`
- `actor`, `user`, `src_endpoint`, `session`, `resources`, and `privileges` where present
- `device`, `http_request`, `auth_protocol`, `auth_factors`, `observables`, `enrichments` where the Okta payload supports them (v0.2)
- `unmapped.okta.*` vendor-specific detail including verbatim `debug_data` round-trip

## See also

- [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) — shared OCSF wire contract and version pinning
- [`../ingest-azure-activity-ocsf/SKILL.md`](../ingest-azure-activity-ocsf/SKILL.md) — Azure control-plane audit equivalent
- [`../../detection/detect-lateral-movement/SKILL.md`](../../detection/detect-lateral-movement/SKILL.md) — downstream identity pivot detection
