# detection-engineering/ (shared assets)

This folder owns shared OCSF wire-contract and golden-fixture assets used by
the layered skills elsewhere in the repo.

Canonical skill locations are:

- ingestion skills: [`../ingestion/`](../ingestion/)
- detection skills: [`../detection/`](../detection/)
- view / convert skills: [`../view/`](../view/)

This folder owns shared cross-skill assets:

- [`OCSF_CONTRACT.md`](./OCSF_CONTRACT.md)
- [`golden/`](./golden/) — synthetic snapshot fixtures only; see [`golden/README.md`](./golden/README.md) for what they verify and what they do not
- [`scoring/`](./scoring/) — per-detector precision/recall scorer plus the labelled corpus that drives it

It is not a skill layer. New executable skills belong under `ingestion/`,
`detection/`, or `view/` as appropriate.

## Precision/recall scoring

The [`scoring/`](./scoring/) directory ships:

- [`corpus.yaml`](./scoring/corpus.yaml) — declarative corpus manifest. Each
  entry pins a detector name, the labelled JSONL input fixture, and a
  ground-truth label map.
- [`score.py`](./scoring/score.py) — entrypoint. Runs each detector
  subprocess (`python skills/detection/<name>/src/detect.py`), compares
  emitted findings to the labels, and prints per-detector + aggregate
  TP / FP / FN / precision / recall / F1 to stdout as JSON.
- [`tests/`](./scoring/tests/) — unit tests covering perfect-precision,
  perfect-recall, mixed cases, missing-fixture handling, and empty
  corpora.

Two scoring modes are supported per entry:

| Mode          | Labels map                              | Predicted set                                                            |
| ------------- | --------------------------------------- | ------------------------------------------------------------------------ |
| `event_uid`   | input event `metadata.uid` -> bool      | uids referenced by `evidence.raw_event_uids` (or another configured path) |
| `finding_uid` | expected finding `metadata.uid` -> bool | uids on findings the detector emits                                       |

`event_uid` mode only counts predictions for events that the corpus has
labelled — unlabelled events do not count for or against the detector.
`finding_uid` mode is stricter: any finding the detector emits whose
uid is not in the labels is a false positive.

### Honesty contract

Every entry in `corpus.yaml` MUST set `synthetic: true` until the
captured-traffic corpus tracked in
[#420](https://github.com/msaad00/cloud-ai-security-skills/issues/420)
lands. The same rule from
[`golden/README.md`](./golden/README.md) applies: any public claim
about precision/recall must say "synthetic fixtures only".

### Local usage

Score the whole corpus:

```sh
python skills/detection-engineering/scoring/score.py
```

Score a single detector (used during development):

```sh
python skills/detection-engineering/scoring/score.py --detector detect-okta-mfa-fatigue
```

Score only detectors changed by the current branch:

```sh
python skills/detection-engineering/scoring/score.py --changed-only --base origin/main
```

### Per-PR CI

The [`detector-scoring`](../../.github/workflows/detector-scoring.yml)
workflow runs `scripts/score_pr_detectors.sh` on every PR that touches
`skills/detection/**`, uploads the JSON output as an artifact, and
posts (or updates) a markdown summary table as a PR comment.

### Adding a detector to the corpus

1. Add a labelled JSONL input under `scoring/fixtures/` (or reference an
   existing `golden/` fixture if it already covers your case).
2. Append an entry to `corpus.yaml` pinning `detector_name`,
   `input_fixture`, `mode`, and `labels`.
3. Run `python skills/detection-engineering/scoring/score.py --detector
   <name>` and confirm the numbers match what you expected.
4. Open a PR. The `detector-scoring` workflow will pick up the new entry
   automatically.
