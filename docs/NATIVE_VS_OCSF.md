# Native vs OCSF

`cloud-ai-security-skills` is **not OCSF-only**, but it is also not undecided.

The repo position is:

- **OCSF 1.8 by default for event and finding streams**
- **native by default for repo-owned operational artifacts**

The repo supports:

- `raw` for unnormalized source data
- `native` for the repo-owned external wire format
- `canonical` for the internal normalization model
- `ocsf` for interoperable external output
- `bridge` when both OCSF transport and repo/source detail matter

The short version:

- use `ocsf` when you want the default interoperable wire format for streams
- use `native` when you want the repo’s own stable operational contract
- use `bridge` when OCSF helps but would otherwise lose detail
- remember that `canonical` is internal and `raw` is pre-normalized input

Related docs:

- [`SCHEMA_VERSIONING.md`](./SCHEMA_VERSIONING.md)
- [`SCHEMA_COVERAGE.md`](./SCHEMA_COVERAGE.md)
- [`NORMALIZATION_REFERENCE.md`](./NORMALIZATION_REFERENCE.md)
- [`NORMALIZATION_EXAMPLES.md`](./NORMALIZATION_EXAMPLES.md)

## The five shapes

| Shape | What it is | Where it shows up |
|---|---|---|
| `raw` | source-native input with no repo normalization yet | source adapters, raw ingest inputs |
| `native` | repo-owned external wire format | native findings, sink results, evaluation output, remediation plans, native ingest output |
| `canonical` | stable internal normalization layer | implementation and storage design, not a public CLI default |
| `ocsf` | interoperable external wire format | SIEM/lakehouse delivery, shared cross-tool pipelines, standard findings/events |
| `bridge` | OCSF plus preserved repo/source detail | discovery and evidence paths where OCSF transport helps but detail still matters |

## Raw is not native

This is the confusion to avoid:

- `raw` = the source payload before normalization
- `native` = the repo’s stable external contract after normalization

Example:

- a raw CloudTrail record is still the original AWS event
- a native ingest output is a repo-owned JSONL event with stable repo fields
- an OCSF ingest output is the OCSF projection of the same normalized event

## What native means in this repo

`native` means the repo emits its own stable external schema with fields like:

- `schema_mode`
- `canonical_schema_version`
- `record_type`
- stable event or finding identifiers
- normalized cloud / actor / resource / evidence fields

It does **not** mean:

- raw vendor JSON
- a lightly edited OCSF event
- an unstable implementation detail

## Two rules, not one

The repo is making two different decisions:

### 1. For event and finding streams

Use **OCSF by default** because it improves:

- SIEM and lake interoperability
- shared pipelines between skills
- downstream correlation across tools

Keep `native` available where OCSF is incomplete or unnecessarily lossy.

### 2. For operational artifacts

Use **native by default** because these outputs are repo-owned contracts, not
clean OCSF event families:

- evaluation results
- discovery and evidence artifacts
- sink results
- remediation plans and audit summaries

These were never strong OCSF fits, and forcing them into OCSF would make the
contract less clear, not more standard.

## Event example

The same normalized event can be projected two ways.

### Native event shape

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "api_activity",
  "event_uid": "evt-4c8d...",
  "provider": "aws",
  "account_uid": "123456789012",
  "region": "us-east-1",
  "time_ms": 1713206400000,
  "actor": {
    "user": {
      "name": "alice"
    }
  },
  "api": {
    "service": "sts",
    "operation": "AssumeRole"
  },
  "resource": {
    "type": "iam_role",
    "name": "prod-admin"
  },
  "source": {
    "kind": "cloudtrail"
  }
}
```

### OCSF event shape

```json
{
  "metadata": {
    "version": "1.8.0"
  },
  "category_uid": 6,
  "class_uid": 6003,
  "time": 1713206400000,
  "activity_name": "AssumeRole",
  "cloud": {
    "provider": "aws",
    "account": {
      "uid": "123456789012"
    },
    "region": "us-east-1"
  },
  "actor": {
    "user": {
      "name": "alice"
    }
  },
  "resources": [
    {
      "type": "iam_role",
      "name": "prod-admin"
    }
  ]
}
```

## Finding example

### Native finding shape

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "detection_finding",
  "finding_uid": "det-lm-1f45...",
  "event_uid": "evt-4c8d...",
  "provider": "aws",
  "time_ms": 1713206460000,
  "severity_id": 3,
  "severity_label": "medium",
  "status_id": 1,
  "status": "new",
  "title": "Possible lateral movement",
  "description": "AssumeRole followed by accepted east-west traffic.",
  "attacks": [
    {
      "technique": "T1021"
    }
  ],
  "evidence": {
    "matched_signals": 2
  }
}
```

### OCSF finding shape

```json
{
  "metadata": {
    "version": "1.8.0"
  },
  "category_uid": 2,
  "class_uid": 2004,
  "finding_info": {
    "uid": "det-lm-1f45...",
    "title": "Possible lateral movement",
    "desc": "AssumeRole followed by accepted east-west traffic."
  },
  "severity_id": 3,
  "status_id": 1,
  "time": 1713206460000,
  "attack": {
    "tactic": [],
    "technique": [
      {
        "uid": "T1021"
      }
    ]
  }
}
```

## Example where OCSF is thinner

Okta is a better example of the trade-off than CloudTrail because the skill
preserves some vendor detail under `unmapped.okta.*` rather than pretending it
cleanly fits first-class OCSF fields.

### Native Okta event

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "authentication",
  "event_uid": "b9ab9263-a4ae-4780-9981-377ec8f2da86",
  "provider": "Okta",
  "event_type": "user.session.start",
  "session": {
    "uid": "sess-123"
  },
  "unmapped": {
    "okta": {
      "transaction_id": "trn-456",
      "root_session_id": "root-789"
    }
  }
}
```

### OCSF Okta event

```json
{
  "category_uid": 3,
  "class_uid": 3002,
  "time": 1713206400000,
  "metadata": {
    "version": "1.8.0",
    "uid": "b9ab9263-a4ae-4780-9981-377ec8f2da86"
  },
  "session": {
    "uid": "sess-123"
  },
  "unmapped": {
    "okta": {
      "transaction_id": "trn-456",
      "root_session_id": "root-789"
    }
  }
}
```

What this shows:

- the event is still usable in OCSF mode
- the most vendor-specific correlation fields survive under `unmapped`
- the loss is not “OCSF destroys everything”; it is that some detail is no
  longer first-class standard schema

## Column-level mental model

| Concern | Native | OCSF |
|---|---|---|
| Repo identity fields | explicit and repo-owned | mapped into OCSF fields where possible |
| Interoperability with SIEMs | acceptable, repo-specific | strongest |
| Fit for sink summaries / remediation results | strongest | weak |
| Fit for evidence / inventory | often needs bridge or native | partial |
| Fit for standard detections | good | good |
| Fit for raw source fidelity | no; use `raw` or `bridge` | no; use `raw` or `bridge` |

## Where OCSF fits well

OCSF is the right default when:

- the event or finding maps cleanly to a standard class
- the output is headed to a SIEM, lake, or standard downstream tool
- you want consistent cross-vendor transport
- a detector or view skill already expects OCSF on stdin

In this repo, OCSF fits especially well for:

- ingest event streams
- detection findings
- view/export conversions
- shared event pipelines between skills

## Where OCSF is still a partial fit

These are the practical OCSF gaps in the current repo surface:

### 1. Benchmark and posture results

Evaluation skills emit deterministic benchmark or control results. Those are
better represented today as native artifacts than as forced OCSF findings.

### 2. Inventory, evidence, and AI BOM outputs

Discovery output often needs richer asset, evidence, graph, or BOM structure
than a clean OCSF class provides. That is why discovery uses `native` and
`bridge` rather than pretending all inventory is a perfect OCSF event.

### 3. Sink and remediation result contracts

Sink summaries and remediation plans are repo-owned operational artifacts.
OCSF is not the clearest contract for:

- `sink_result`
- remediation dry-run plans
- remediation audit/result summaries

### 4. Raw source adapters

`source-*` adapters intentionally emit raw JSONL rows. They are data-retrieval
edges, not normalizers.

### 5. Warehouse-native query packs

Query packs emit OCSF-compatible finding rows, but they also need warehouse
specific type locking, result contracts, and SQL-level guarantees that are
outside a pure OCSF schema decision.

For source-by-source detail, see [`SCHEMA_COVERAGE.md`](./SCHEMA_COVERAGE.md).

## Practical decision tree

Choose the mode based on the consumer:

- want the standard transport format:
  - use `ocsf`
- want the repo’s own operational contract:
  - use `native`
- want both transport and preserved detail:
  - use `bridge`
- starting from vendor payloads:
  - use `raw` as input, then normalize

## Current repo posture

What the repo ships today:

- ingest and detect are fully dual-mode across the shipped skill set, with OCSF
  as the default interoperable stream format
- discovery is native-first with bridge where useful
- evaluation is native
- view skills convert OCSF into downstream artifacts
- sinks emit native sink summaries
- source adapters emit raw JSONL

So the repo answer is not “OCSF or not OCSF.”

It is:

`raw -> canonical -> native | ocsf | bridge`

with the projection chosen by the operational need, not by ideology.
