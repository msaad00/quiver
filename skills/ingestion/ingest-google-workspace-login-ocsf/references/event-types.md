# Google Workspace login → OCSF 1.8 — input shapes + supported event family

Pulled out of `SKILL.md` to keep it under the progressive-disclosure word target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)).

## Accepted input shapes

The skill accepts one of three raw Admin SDK Reports login audit shapes.

### 1. Activities list response

```json
{
  "items": [
    {
      "id": {
        "time": "2026-04-13T06:00:00.000Z",
        "uniqueQualifier": "workspace-1",
        "applicationName": "login"
      },
      "events": [
        {
          "type": "login",
          "name": "login_success"
        }
      ]
    }
  ]
}
```

### 2. Single activity

```json
{
  "id": {
    "time": "2026-04-13T06:00:00.000Z",
    "uniqueQualifier": "workspace-1",
    "applicationName": "login"
  },
  "events": [
    {
      "type": "login",
      "name": "login_success"
    }
  ]
}
```

### 3. JSONL stream of activities

```json
{"id":{"time":"2026-04-13T06:00:00.000Z","uniqueQualifier":"workspace-1","applicationName":"login"},"events":[{"type":"login","name":"login_success"}]}
```

## Supported event family (verified)

The first slice intentionally supports a narrow, verified event family from the Workspace login audit appendix:

| Event name | OCSF class |
|---|---|
| `login_success` | Authentication (3002) |
| `login_failure` | Authentication (3002) |
| `logout` | Authentication (3002) |
| `2sv_enroll` | Account Change (3001) |
| `2sv_disable` | Account Change (3001) |

Unsupported event names are skipped with a warning to `stderr`.

## Output guarantees

Each OCSF output record includes:

- deterministic `metadata.uid` based on `applicationName`, `time`, `uniqueQualifier`, and event name
- UTC epoch-millisecond `time` from `id.time`
- Workspace actor and profile IDs preserved under `actor` and `session`
- raw event parameters preserved under `unmapped.google_workspace_login`

## Source

- [Admin SDK Reports — login audit appendix](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login)
- [`SKILL.md`](../SKILL.md) — skill behavior and routing
- [`REFERENCES.md`](../REFERENCES.md) — full source / API references
