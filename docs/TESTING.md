# Testing

This page records the test surface of each skill bundle so reviewers can spot
shallow coverage. The CSPM evaluation skills now exercise every check function
across five edge-case axes (issue #405):

1. **Empty input** — function returns 0 findings on `[]` / `{}` / no resources.
2. **Malformed payload** — missing/None fields produce a structured Finding,
   never a `KeyError`/`AttributeError`/`TypeError`.
3. **Partial-pass scenario** — heterogeneous input where some resources pass
   and others fail in one call.
4. **Permission denied** — the check survives a 403/AccessDenied/Forbidden
   payload from the SDK and surfaces a known-state outcome (`ERROR` for AWS,
   `ERROR` for GCP/Azure when the broad `except Exception:` catches it).
5. **Multi-resource happy path** — already covered by the original test suite.

Where the source code raised on an unmapped data shape, the source was hardened
with `.get(..., default)` / type-narrowing helpers and a `runtime_telemetry`
`emit_stderr_event(level="warning", event="check_skipped", ...)` so unmapped
payloads are visible to operators rather than silently dropped.

## CSPM evaluation test counts (issue #405)

| Skill                                | Before | After |
| ------------------------------------ | -----: | ----: |
| `cspm-aws-cis-benchmark`             |     91 |   167 |
| `cspm-gcp-cis-benchmark`             |     82 |   178 |
| `cspm-azure-cis-benchmark`           |     93 |   196 |
| `k8s-security-benchmark`             |     14 |   184 |
| `container-security`                 |     14 |   111 |
| **Totals (`skills/evaluation/`)**    |    367 |   909 |

Source-code resilience changes accompanying the test expansion:

- `container-security/src/checks.py` — every check now runs through
  `_safe_iter_images` / `_safe_dict` / `_safe_str` helpers; non-dict configs,
  `None` fields, mixed-type lists, and missing keys are absorbed with a
  stderr telemetry record (`SKILL_LOG_FORMAT=json` mode) when an item is
  skipped.
- `k8s-security-benchmark/src/checks.py` — `_safe_pods`, `_pod_containers`,
  `_pod_field`, `_safe_dict`, `_safe_list` helpers replace the previous
  positional fallbacks (`pod.get("spec", pod).get(...)`) which crashed when
  `spec` was explicitly `None`. Every check survives `pods=None`,
  `pods="string"`, list-of-junk, dict-with-None-fields, etc.
- `cspm-aws-cis-benchmark/src/checks.py` — `check_1_5_password_policy` now
  catches `ClientError` generically (delegating only the `NoSuchEntity`
  branch to the FAIL outcome). Previously it caught only
  `iam.exceptions.NoSuchEntityException`, so a generic AccessDenied raised
  by AWS during the `get_account_password_policy` call would propagate.
- `cspm-gcp-cis-benchmark` and `cspm-azure-cis-benchmark` — already wrapped
  every check body in `try/except Exception:` returning `ERROR`. The new
  edge-case suites pin that contract per check so future refactors can't
  regress to bare-raise behaviour.

## Running

```bash
uv run --group dev pytest skills/evaluation/ -q
uv run --group dev ruff check skills/evaluation/
bash scripts/run_mypy.sh \
  skills/evaluation/cspm-aws-cis-benchmark/src \
  skills/evaluation/cspm-gcp-cis-benchmark/src \
  skills/evaluation/cspm-azure-cis-benchmark/src \
  skills/evaluation/k8s-security-benchmark/src \
  skills/evaluation/container-security/src
python scripts/validate_skill_contract.py
python scripts/validate_skill_count_consistency.py
```
