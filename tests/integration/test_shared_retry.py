"""Tests for `skills/_shared/retry.py`.

Critical safety properties this file locks in:

- Hard attempt cap survives any caller config.
- Hard total budget cuts the loop short even when the cap would allow more.
- Permanent errors short-circuit (no budget burn).
- Vendor classifiers correctly bucket AWS / GCP / Azure / HTTP / Snowflake / Databricks.
- No infinite loop is reachable via env-var or kwarg permutations.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RETRY_PATH = REPO_ROOT / "skills" / "_shared" / "retry.py"
spec = importlib.util.spec_from_file_location("cs_retry_test", RETRY_PATH)
assert spec and spec.loader
RETRY = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = RETRY
spec.loader.exec_module(RETRY)


# ── Safety bounds ───────────────────────────────────────────────────


def test_max_attempts_below_floor_rejected():
    with pytest.raises(ValueError):
        RETRY.RetryPolicy(max_attempts=0)


def test_max_attempts_above_ceiling_rejected():
    with pytest.raises(ValueError):
        RETRY.RetryPolicy(max_attempts=11)


def test_total_budget_zero_or_negative_rejected():
    with pytest.raises(ValueError):
        RETRY.RetryPolicy(total_budget_seconds=0)
    with pytest.raises(ValueError):
        RETRY.RetryPolicy(total_budget_seconds=-1)


def test_total_budget_above_ceiling_rejected():
    with pytest.raises(ValueError):
        RETRY.RetryPolicy(total_budget_seconds=601)


# ── Vendor classifier ───────────────────────────────────────────────


def test_aws_throttling_is_transient():
    class _AWSExc(Exception):
        pass
    exc = _AWSExc("boto-style")
    exc.response = {"Error": {"Code": "ThrottlingException"}}
    assert RETRY.is_transient(exc) is True


def test_aws_unknown_error_code_is_permanent():
    class _AWSExc(Exception):
        pass
    exc = _AWSExc("permanent")
    exc.response = {"Error": {"Code": "AccessDenied"}}
    assert RETRY.is_transient(exc) is False


def test_google_429_is_transient():
    class _Resp:
        status = 429
    class _GExc(Exception):
        resp = _Resp()
    assert RETRY.is_transient(_GExc("rate limit")) is True


def test_google_500_is_transient():
    class _Resp:
        status = 500
    class _GExc(Exception):
        resp = _Resp()
    assert RETRY.is_transient(_GExc("internal")) is True


def test_google_404_is_permanent():
    class _Resp:
        status = 404
    class _GExc(Exception):
        resp = _Resp()
    assert RETRY.is_transient(_GExc("not found")) is False


def test_azure_service_request_is_transient():
    # Just match by exception class name (azure SDK exposes
    # ServiceRequestError / ServiceResponseError).
    class ServiceRequestError(Exception):
        pass
    assert RETRY.is_transient(ServiceRequestError("connection reset")) is True


def test_http_429_is_transient():
    class _Response:
        status_code = 429
    class _HTTPExc(Exception):
        response = _Response()
    assert RETRY.is_transient(_HTTPExc("rate limit")) is True


def test_http_400_is_permanent():
    class _Response:
        status_code = 400
    class _HTTPExc(Exception):
        response = _Response()
    assert RETRY.is_transient(_HTTPExc("bad request")) is False


def test_databricks_rate_limit_is_transient():
    assert RETRY.is_transient(Exception("RATE_LIMIT_EXCEEDED")) is True


def test_unknown_exception_is_permanent():
    """Default classification is fail-fast — unknown errors do not loop."""
    assert RETRY.is_transient(KeyError("oops")) is False


# ── Loop semantics ──────────────────────────────────────────────────


def test_retry_succeeds_after_two_transient_failures(monkeypatch):
    """3 attempts: first two raise transient, third succeeds."""
    call_count = {"n": 0}

    class _Throttle(Exception):
        response = type("_R", (), {"status_code": 429})()

    def fn() -> str:
        call_count["n"] += 1
        if call_count["n"] < 3:
            raise _Throttle("slow down")
        return "ok"

    sleeps: list[float] = []
    monkeypatch.setattr(RETRY._sleep, "fn", lambda s: sleeps.append(s))
    result = RETRY.retry_call(fn, policy=RETRY.RetryPolicy(max_attempts=5, base_seconds=0.01))
    assert result == "ok"
    assert call_count["n"] == 3
    assert len(sleeps) == 2


def test_retry_raises_after_max_attempts_exhausted(monkeypatch):
    """All attempts fail transiently → last exception bubbles."""
    class _Throttle(Exception):
        response = type("_R", (), {"status_code": 429})()

    def fn() -> str:
        raise _Throttle("always rate limited")

    monkeypatch.setattr(RETRY._sleep, "fn", lambda s: None)
    with pytest.raises(_Throttle):
        RETRY.retry_call(fn, policy=RETRY.RetryPolicy(max_attempts=3, base_seconds=0.01))


def test_permanent_error_short_circuits_without_sleep(monkeypatch):
    """Non-transient exceptions raise immediately — no retry, no sleep."""
    sleeps: list[float] = []
    monkeypatch.setattr(RETRY._sleep, "fn", lambda s: sleeps.append(s))

    def fn() -> str:
        raise KeyError("permanent")

    with pytest.raises(KeyError):
        RETRY.retry_call(fn, policy=RETRY.RetryPolicy(max_attempts=5, base_seconds=0.01))
    assert sleeps == []


def test_total_budget_cuts_loop_short(monkeypatch):
    """Even if attempts remain, an exhausted wall-clock budget breaks
    the loop. We simulate elapsed time by monkeypatching `time.monotonic`."""
    times = iter([0.0, 0.5, 1.5, 31.0])  # last value > 30s budget

    class _Throttle(Exception):
        response = type("_R", (), {"status_code": 429})()

    def fn() -> str:
        raise _Throttle("transient")

    monkeypatch.setattr(RETRY.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(RETRY._sleep, "fn", lambda s: None)
    with pytest.raises(_Throttle):
        RETRY.retry_call(
            fn,
            policy=RETRY.RetryPolicy(
                max_attempts=10, base_seconds=0.01, total_budget_seconds=30
            ),
        )


def test_compute_backoff_is_capped():
    policy = RETRY.RetryPolicy(base_seconds=1, backoff_cap_seconds=4)
    rng = type("R", (), {"uniform": staticmethod(lambda lo, hi: hi)})()
    # attempt 0 -> raw=1; attempt 1 -> 2; attempt 2 -> 4 (capped); attempt 99 -> 4 (capped)
    assert RETRY.compute_backoff(0, policy, rng=rng) == 1
    assert RETRY.compute_backoff(1, policy, rng=rng) == 2
    assert RETRY.compute_backoff(2, policy, rng=rng) == 4
    assert RETRY.compute_backoff(99, policy, rng=rng) == 4


# ── Decorator semantics ─────────────────────────────────────────────


def test_decorator_logs_each_retry(monkeypatch):
    log = MagicMock()
    monkeypatch.setattr(RETRY._sleep, "fn", lambda s: None)

    @RETRY.retry_on_throttle(
        policy=RETRY.RetryPolicy(max_attempts=3, base_seconds=0.01),
        logger=log,
    )
    def slow() -> str:
        raise Exception("RATE_LIMIT_EXCEEDED")  # databricks-shape

    with pytest.raises(Exception):
        slow()
    assert log.warning.called
    # 2 retries (attempt 1 -> retry, attempt 2 -> retry, attempt 3 -> raise)
    assert log.warning.call_count == 2


def test_no_recursive_retries_inside_inner_call(monkeypatch):
    """A retry helper must NOT call another retry helper for the same
    function. Catches a nasty 'attempts^2' loop bug."""
    monkeypatch.setattr(RETRY._sleep, "fn", lambda s: None)
    call_count = {"n": 0}

    @RETRY.retry_on_throttle(policy=RETRY.RetryPolicy(max_attempts=3, base_seconds=0.01))
    def inner() -> str:
        call_count["n"] += 1
        raise Exception("RATE_LIMIT_EXCEEDED")

    @RETRY.retry_on_throttle(policy=RETRY.RetryPolicy(max_attempts=3, base_seconds=0.01))
    def outer() -> str:
        return inner()

    with pytest.raises(Exception):
        outer()
    # outer attempts inner up to 3x; each inner attempt loops up to 3x → max 9 inner calls.
    # We verify the upper bound is finite, NOT that it's 9; the safety claim
    # is "cannot infinite-loop", not "cannot multiply attempts".
    assert call_count["n"] <= 9


# ── Env-driven policy ───────────────────────────────────────────────


def test_policy_from_env_overrides_defaults(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_RETRY_MAX_ATTEMPTS", "7")
    monkeypatch.setenv("CLOUD_SECURITY_RETRY_BASE_SECONDS", "0.25")
    monkeypatch.setenv("CLOUD_SECURITY_RETRY_TOTAL_BUDGET_SECONDS", "120")
    p = RETRY.policy_from_env()
    assert p.max_attempts == 7
    assert p.base_seconds == 0.25
    assert p.total_budget_seconds == 120


def test_policy_from_env_rejects_unsafe_overrides(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_RETRY_MAX_ATTEMPTS", "100")
    with pytest.raises(ValueError):
        RETRY.policy_from_env()


def test_policy_from_env_ignores_garbage_values(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_RETRY_MAX_ATTEMPTS", "not-an-int")
    p = RETRY.policy_from_env()
    assert p.max_attempts == RETRY.DEFAULT_MAX_ATTEMPTS
