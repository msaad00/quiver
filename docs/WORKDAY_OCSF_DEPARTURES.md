# Workday OCSF Departures

Use `ingest-workday-audit-ocsf` when Workday audit or RaaS reports are already
exported and the departures workflow should consume a common OCSF stream instead
of running another Workday-specific query.

## First command

```bash
python skills/ingestion/ingest-workday-audit-ocsf/src/ingest.py workday-audit-report.json > workday-audit.ocsf.jsonl
python skills/detection/detect-mass-termination-anomaly/src/detect.py workday-audit.ocsf.jsonl > workday-termination-findings.ocsf.jsonl
```

The first artifact is OCSF Account Change (3001) JSONL. Termination events carry
`unmapped.workday.event_family=termination`, the worker identity in `user`, and
tenant-specific report evidence under `unmapped.workday.raw`.

## Departures reconciler path

`iam-departures-reconciler` remains compatible with its existing direct Workday
RaaS source for operators that have not moved HR evidence into OCSF yet. The
preferred path for new pipelines is:

1. Export the Workday audit/RaaS report upstream.
2. Normalize it with `ingest-workday-audit-ocsf`.
3. Feed Account Change (3001) termination records into the departures manifest
   builder or the mass-termination detector before IAM remediation.

This keeps the Workday credential boundary in the upstream collector and lets
CI, MCP, persistent runners, and downstream IAM skills share one event contract.
