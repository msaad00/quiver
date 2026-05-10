# Captured fixtures — provenance contract

This directory is the sibling of [`../golden/`](../golden/README.md). The two
have **opposite contracts**.

| Directory   | Provenance         | Used to verify                                 |
|-------------|--------------------|------------------------------------------------|
| `golden/`   | Synthetic, hand-crafted | Wire contract, determinism, schema validity   |
| `captured/` | Real public traces, license-clean | The above **plus** that detectors fire on actual attack-pattern traffic, not just on shapes we drew ourselves |

## Provenance contract

Every file in this directory MUST satisfy all five of the following:

1. **Known origin.** A URL, paper, or `CITATION` that anyone can open today.
2. **Permissive license.** One of: `Apache-2.0`, `MIT`, `BSD-2-Clause`,
   `BSD-3-Clause`, `CC0-1.0`, `CC-BY-4.0`. Copyleft, proprietary, and
   "unknown" are rejected by the validator.
3. **Recorded capture window.** The UTC timestamp range the traffic was
   originally observed (or the upstream project recorded it).
4. **Named consuming detector.** The fixture exists because exactly one
   shipped detector reads it. The validator rejects orphan files.
5. **`synthetic_seeded: false`.** A fixture flagged synthetic belongs under
   `golden/`, not here. The validator rejects `true`.

The contract is enforced by [`scripts/validate_captured_provenance.py`](../../../scripts/validate_captured_provenance.py),
wired into CI under the `skill-contract` job.

## Synthetic files belong under `golden/`

If you produce a fixture by hand-crafting JSON to exercise a detector, the
file goes under [`../golden/`](../golden/), not here. The two-directory split
exists so that downstream documents and PR descriptions can cite the right
provenance honestly:

> "Tested against captured public traces (`captured/`) and synthetic golden
> fixtures (`golden/`)."

If a captured fixture later turns out to be synthesised, move it back under
`golden/` — do not weaken the contract here.

## Manifest

[`MANIFEST.yaml`](./MANIFEST.yaml) is the source of truth. One entry per
fixture file with: `path`, `origin`, `license`, `capture_window_utc`,
`attack_pattern`, `consuming_detector`, `synthetic_seeded`.

Adding a new fixture = appending a manifest entry + dropping the file. CI
will refuse the PR if either side is missing.

## Roadmap

The first import (this PR) seeds the directory with two Atomic Red Team
atomics that map cleanly onto already-shipped AWS persistence detectors.
The next imports — gated on locating a permissive-licensed source for each —
are tracked here so we don't drift back to silent-synthesis:

- **AWS-Sample CloudTrail (open-data attack traces).** No permissive-licensed
  AWS-published CloudTrail attack corpus has been located yet. flaws.cloud
  (Scott Piper, CC-BY-4.0) is a candidate but its CloudTrail extract is not
  hosted in this repo today; the import is deferred until the licence pin
  and the host can be cited inline. Tracked: gap recorded here, no fixture
  shipped.
- **Anthropic public MCP-attack examples.** No CC-BY-published Anthropic MCP
  red-team trace has been located. Until one is published, MCP detector
  fixtures stay under `golden/` (clearly synthetic), and the
  `detect-mcp-tool-drift` / `detect-prompt-injection-mcp-proxy` row stays
  empty in this directory. Do not invent.
- **Mordor / Open Threat Research Forge** (MIT) and **MITRE CALDERA**
  (Apache-2.0) — both publish recorded attacker telemetry that can be
  reformatted to OCSF 1.8. These are the next two candidates and will be
  added in follow-up PRs as each is verified against a specific shipped
  detector.

When a row above is converted into a real fixture, delete it from this
list — the manifest is the new source of truth.

## Adding a fixture

1. Confirm the upstream source's licence is in the allowed set above. If it
   isn't, **stop**: document the gap in the Roadmap section and skip the
   import.
2. Reformat the trace into the OCSF 1.8 wire shape the consuming detector
   expects. Reformatting is structure-only — do not invent values.
3. Drop the file in this directory. Filename: lower-snake, prefixed with the
   upstream project name (e.g. `atomic_red_team_T1098_001_*`).
4. Add a `MANIFEST.yaml` entry with all six required keys.
5. Run `python scripts/validate_captured_provenance.py` locally. It must
   exit 0 before the PR is opened.
6. Wire the fixture into the consuming detector's test (in a follow-up PR if
   needed) so the file is exercised in CI, not just present.

## What this directory does NOT yet prove

Even with two captured fixtures shipped, this directory does **not** yet
support claims of the form "X% precision / Y% recall on real attacker
traffic at scale". Two atomics is a beachhead, not a corpus. Per-detector
precision/recall scoring on a corpus an order of magnitude larger is
tracked separately under
[issue #419](https://github.com/msaad00/cloud-ai-security-skills/issues/419).
