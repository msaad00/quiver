# Okta System Log → OCSF 1.8 field map

Full source-field → OCSF-field mapping for `ingest-okta-system-log-ocsf`. Pulled out of `SKILL.md` to keep that file under the ~5,000-word progressive-disclosure target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)).

## Class mapping (verified)

Each Okta `eventType` is routed to one OCSF class. Output records always carry:

- deterministic `metadata.uid` based on `applicationName`, `time`, `uniqueQualifier`, and event name
- UTC epoch-millisecond `time` from the Okta `published` field
- `actor`, `user`, `src_endpoint`, and `resources` where the raw event supports them
- expanded v0.2 OCSF-native slots (table below) when the Okta payload carries `geographicalContext`, `securityContext`, `client.userAgent`, `authenticationContext`, `debugContext`, or `request.ipChain`

## OCSF 1.8 mapping (v0.2, [#271](https://github.com/msaad00/cloud-ai-security-skills/issues/271))

| Okta field | OCSF destination |
|---|---|
| `client.geographicalContext.{country,state,city,postalCode}` | `src_endpoint.location.{country,region,city,postal_code}` |
| `client.geographicalContext.geolocation.{lat,lon}` | `src_endpoint.location.coordinates` (`[lon, lat]`) |
| `client.userAgent.rawUserAgent` | `src_endpoint.svc_name` *and* `http_request.user_agent` |
| `client.userAgent.browser` + `.os` | `device.name`, `device.os.name` |
| `client.device` + `client.id` | `device.name`, `device.uid` |
| `client.zone` | `src_endpoint.zone` |
| `securityContext.asNumber` + `asOrg` | `src_endpoint.autonomous_system.{number, name}` |
| `securityContext.domain` | `src_endpoint.domain` |
| `securityContext.isProxy` | `src_endpoint.is_proxy` (bool) |
| `authenticationContext.authenticationProvider` | `auth_protocol` |
| `authenticationContext.credentialType` | `auth_factors[]` |
| `authenticationContext.interface` / `authenticationStep` | `metadata.labels` (`okta.interface=...`, `okta.authentication_step=...`) |
| `request.ipChain[]` per-hop `ip` + geo | `observables[]` (type_id=2, with location + reputation) |
| `debugContext.debugData.riskLevel` | `enrichments[]` (`name: okta.risk_level`, `type: security_risk`) |
| `debugContext.debugData.riskReasons` | `enrichments[]` (`name: okta.risk_reasons`, `data.reasons: [...]`) |
| `debugContext.debugData.behaviors` | `enrichments[]` (`name: okta.behaviors`) |

Slots are only emitted when the source field is present; minimal events (the v0.1 shape) remain byte-identical except for OCSF-native additions.

## `unmapped.okta.*` — native preservation

Fields without a clean OCSF slot round-trip verbatim for detectors that need full Okta fidelity:

- `debug_data` — full `debugContext.debugData` verbatim (riskLevel, riskReasons, behaviors, factorId, authenticatorId, deviceFingerprint, requestUri, authnRequestId — whatever Okta packs in)
- `actor_detail_entry`, `target_detail_entries[]` — free-form detail fields
- `transaction_type`, `transaction_detail`
- `authn_issuer` — `authenticationContext.issuer` object
- `event_type`, `legacy_event_type`, `transaction_id`, `root_session_id` — v0.1 correlation keys

## Risk signals as enrichments

Okta's risk engine output is surfaced as OCSF `enrichments[]` entries so downstream detectors can pattern-match risk without reading `unmapped.*`:

```json
"enrichments": [
  {"name": "okta.risk_level", "value": "HIGH", "type": "security_risk"},
  {"name": "okta.risk_reasons", "data": {"reasons": ["newCountry", "anomalousLocation"]}, "type": "security_risk"}
]
```

`riskReasons` accepts both the comma-joined string and list shapes Okta emits.

## See also

- [`SKILL.md`](../SKILL.md) — skill behavior and routing
- [`REFERENCES.md`](../REFERENCES.md) — Okta API docs, OCSF spec, MITRE refs
- Sister field maps: [`ingest-gcp-audit-ocsf/references/field-map.md`](../../ingest-gcp-audit-ocsf/references/field-map.md), [`ingest-azure-activity-ocsf/references/`](../../ingest-azure-activity-ocsf/references/)
