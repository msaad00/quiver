# Contributing

Contributions are welcome. This repo follows a skills-based structure — each security automation is a self-contained skill under `skills/`.

## Adding a new skill

1. Create a directory under the layered skill tree that matches the work:
   - `skills/ingestion/<skill-name>/`
   - `skills/discovery/<skill-name>/`
   - `skills/detection/<skill-name>/`
   - `skills/evaluation/<skill-name>/`
   - `skills/view/<skill-name>/`
   - `skills/remediation/<skill-name>/`
2. Add a `SKILL.md` with the required frontmatter:

```yaml
---
name: your-skill-name
description: >-
  One-paragraph description of what this skill does and when to use it.
license: Apache-2.0
compatibility: >-
  Runtime requirements (Python version, cloud SDKs, permissions needed).
metadata:
  author: your-github-handle
  version: 0.1.0
  frameworks:
    - Framework names this skill maps to
  cloud: aws | gcp | azure | multi
---
```

3. Put source code in `src/` within your skill directory
4. Put infrastructure-as-code in `infra/` only when the skill needs it
5. Put tests in `tests/` — every skill should have tests
6. Add a `REFERENCES.md` that links only to the official docs, schemas, APIs, or benchmark sources the skill depends on
7. Make sure `SKILL.md` explicitly includes both `Use when...` and `Do NOT use...`
8. Document whether the skill is read-only, dry-run capable, HITL-gated, or side-effectful
9. Document accepted input modes (`raw`, `canonical`, `ocsf`) and supported output modes (`native`, `ocsf`, `bridge`) when they apply
10. Document whether the mapping is lossless or lossy, and which source-native identifiers must survive normalization
11. Add tests for malformed input, provider quirks, and any deprecated API shape you are intentionally supporting during migration
12. Add your skill to the catalog in `README.md` and `skills/README.md`
13. Add or update the skill entry in `docs/framework-coverage.json` when the change affects framework, provider, or asset coverage

## Code standards

- Python 3.11+ with type hints
- No hardcoded credentials — use environment variables or AWS Secrets Manager
- Least-privilege IAM — document every permission your skill needs
- Tests use `pytest` with `moto` for AWS mocking
- Map to compliance frameworks where applicable (CIS, MITRE, NIST, OWASP)
- Prefer only official vendor docs, schemas, and APIs in `REFERENCES.md`
- Put structured results on `stdout`, debug/warning detail on `stderr`, and fail closed on invalid input
- Follow [`docs/SKILL_CONTRACT.md`](docs/SKILL_CONTRACT.md) for the minimum shipped-skill bar
- Keep framework claims measurable and machine-readable via [`docs/COVERAGE_MODEL.md`](docs/COVERAGE_MODEL.md) and [`docs/framework-coverage.json`](docs/framework-coverage.json)
- Design for all execution modes up front: CLI, CI, MCP, and persistent/serverless wrappers should not require different skill code
- If the skill can write state, require dry-run-first behavior and document the approval/audit model
- Use the repo schema-mode contract in [`docs/NATIVE_VS_OCSF.md`](docs/NATIVE_VS_OCSF.md) and keep state/history semantics aligned with [`docs/STATE_AND_TIMELINE_MODEL.md`](docs/STATE_AND_TIMELINE_MODEL.md)

## Pull request process

1. Fork the repo and create a feature branch
2. Add or modify skills following the structure above
3. Ensure tests pass: `pytest skills/<layer>/your-skill/tests/ -v`
4. Ensure linting passes: `ruff check .`
5. Ensure shared validators pass: `python scripts/validate_skill_contract.py`, `python scripts/validate_skill_integrity.py`, `python scripts/validate_skill_structure.py`, `python scripts/validate_dependency_consistency.py`, `python scripts/validate_framework_coverage.py`, and `python scripts/validate_safe_skill_bar.py`. If `validate_skill_structure.py` flags an empty subtree under `skills/detection-engineering/` (or anywhere else), it usually means stale `__pycache__` from an earlier on-disk layout — run `git clean -fdX skills/detection-engineering/` to drop ignored files only, then re-run the validator.
6. Open a PR against `main` with a clear description
7. If the PR is intended for a release cut, follow [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) before tagging

## Security

If you find a security vulnerability, do NOT open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
