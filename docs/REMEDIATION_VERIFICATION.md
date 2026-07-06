# Remediation Verification Contract

Every remediation skill in this repo closes a loop: **detect → act → audit →
re-verify**. This doc pins what "re-verify" looks like and how every
`remediate-*` skill should emit its verification outcome.

Closes part B of [#257](https://github.com/msaad00/cloud-ai-security-skills/issues/257).

## The three outcomes

Every re-verification run lands in exactly one:

| Status | Meaning | What to emit |
|---|---|---|
| **VERIFIED** | Post-remediation state matches expected. Closed loop. | `remediation_verification` native record only |
| **DRIFT** | State does NOT match. Action didn't land, OR landed then got reverted. | `remediation_verification` native record + OCSF Detection Finding (2004) with `finding_types: ["remediation-drift"]` |
| **UNREACHABLE** | Verifier couldn't reach the target (network, permissions, quota). Never silently downgrade to VERIFIED. | `remediation_verification` native record with `status: unreachable` |

## Why DRIFT flows through OCSF 2004

A DRIFT finding is a real security event — a user assumed a remediation was
complete, the SIEM/SOAR moved on, and now the state is back to broken. The
right place for that signal is the same detection pipeline every other
finding flows through:

1. Verifier emits `build_drift_finding()` → OCSF 2004
2. Pipeline carries it through `sink-*` into the consolidated feed
3. SIEM alerts the operator with the same routing as any other finding
4. Operator either re-runs remediation (if action didn't land) or treats
   it as a fresh incident (if action was reverted)

## Shared contract — `skills/_shared/remediation_verifier.py`

```python
from skills._shared.remediation_verifier import (
    RemediationReference,
    VerificationResult,
    VerificationStatus,
    build_verification_record,
    build_drift_finding,
    sla_deadline,
    DEFAULT_VERIFICATION_SLA_MS,
)

# 1. Populate the reference from the remediation's audit row.
ref = RemediationReference(
    remediation_skill="remediate-okta-session-kill",
    remediation_action_uid="rok-abc123",
    target_provider="Okta",
    target_identifier="00u-target-1",
    original_finding_uid="det-cred-stuffing-xyz",
    remediated_at_ms=1776046500000,
)

# 2. Run the real check against the target (Okta API, IAM list, kubectl, ...).
#    Return a VerificationResult.
result = VerificationResult(
    status=VerificationStatus.DRIFT,
    checked_at_ms=now_ms,
    sla_deadline_ms=sla_deadline(ref.remediated_at_ms, DEFAULT_VERIFICATION_SLA_MS),
    expected_state="user 00u-target-1 has zero active sessions",
    actual_state="user 00u-target-1 has 1 active session from 203.0.113.10",
    detail="session re-established 4m after remediation — attacker re-auth or stolen refresh token",
)

# 3. Emit the native verification record (always).
record = build_verification_record(
    reference=ref, result=result, verifier_skill="verify-okta-session-kill",
)
# ... emit to stdout / sink / etc.

# 4. If status is DRIFT, ALSO emit the OCSF Detection Finding.
if result.status == VerificationStatus.DRIFT:
    drift_finding = build_drift_finding(
        reference=ref, result=result, verifier_skill="verify-okta-session-kill",
    )
    # ... emit to the detection pipeline
```

## Integration pattern — adopted per remediation skill

Each `remediate-*` skill adopts the contract by:

1. Writing its audit row (`put_item` / `put_object`) as already documented
2. Scheduling a re-verify within its SLA window (EventBridge timer, DDB
   TTL, or a companion scanner Lambda) — **out of scope for the shared
   contract**; implementation detail per cloud / per skill
3. Shipping a paired verifier (`verify-*`) skill OR adding a `--verify`
   code path to the remediation skill itself that reads a `RemediationReference`
   from the audit table and calls the shared `build_verification_record()` /
   `build_drift_finding()`

## SLA rules

- Default SLA: **15 minutes** (`DEFAULT_VERIFICATION_SLA_MS`). This is what the
  operator sees as "we'll know if it stuck within 15 min."
- Verifier MUST run at least once by the SLA deadline. If it cannot (network,
  throttling), emit UNREACHABLE — never silent pass.
- Repeated DRIFT for the same remediation within a 7-day window SHOULD page a
  human instead of auto-retrying. This rule is enforced downstream (SIEM
  correlation), not in the contract.

## Reference implementation

Today [iam-departures-aws](../skills/remediation/iam-departures-aws/) implements
this pattern end-to-end via the warehouse ingest-back: the HR warehouse
receives the remediated-user mark, and the next reconciler run validates the
user is closed across every target system. That flow predates this shared
contract — adoption is tracked as follow-up work per skill.

Next adopters, in order of priority:

1. [`remediate-okta-session-kill`](../skills/remediation/remediate-okta-session-kill/) — straightforward: re-poll `/api/v1/users/{id}/sessions` 15 min after
2. `remediate-k8s-rbac-revoke` ([#241](https://github.com/msaad00/cloud-ai-security-skills/issues/241))
3. Each new `remediate-*` that ships, as a scaffold requirement

## Guardrails this contract enforces

- **No silent passes.** UNREACHABLE is a first-class outcome; a verifier that
  can't reach its target never returns VERIFIED.
- **Drift is a fresh finding**, not a warning. The DRIFT path emits OCSF 2004
  exactly like the original detector, so the alerting that already exists
  for the underlying attack pattern picks it up automatically.
- **Deterministic record UIDs.** Both the verification record and the drift
  finding derive their UIDs by content-hashing the remediation reference, so
  two verifiers agreeing on DRIFT for the same action produce the same UID —
  no duplicate findings in the SIEM.

## Related

- [`../SECURITY_BAR.md`](../SECURITY_BAR.md) principle 4 (Closed loop) — this
  is the contract that closes it.
- [`./HITL_POLICY.md`](HITL_POLICY.md) — on repeated drift the policy matrix
  says page a human; this doc is the machinery.
- [#257](https://github.com/msaad00/cloud-ai-security-skills/issues/257) — parent issue.
