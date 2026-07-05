"""Vendor-aware exponential-backoff retry for skill cloud calls.

Every shipped skill that touches a cloud or SaaS API needs the same
shape: classify the exception (transient vs permanent), back off with
jitter, give up after a hard attempt cap, give up after a hard total
wall-clock budget. Without a shared helper, each skill re-implements
the loop, drifts, and either retries forever or doesn't retry at all.

Loop-prevention bar (read this before tweaking the defaults):

- **Hard attempt cap.** Default 5. Never tunable below 1 or above 10.
- **Hard total budget.** Default 60 seconds wall-clock from the first
  call. The wrapper will raise even if the attempt cap has not been
  reached.
- **Backoff is bounded.** \\(min(base * 2^attempt, cap)\\) seconds.
  Cap defaults to 16 seconds.
- **Jitter is full-jitter.** Uniform [0, computed_backoff). Avoids
  thundering-herd without inflating tail latency.
- **No recursive retries.** A retry helper is never called from inside
  another retry helper. Tested explicitly.
- **Permanent errors short-circuit.** A 403 / NoSuchEntity / quota-
  permanent gets one attempt; the helper raises immediately without
  burning the attempt budget.

Vendor classifier knows AWS `ClientError` codes, Google API `HttpError`
status codes, Azure `AzureError` types, Microsoft Graph 429s,
Snowflake `OperationalError`, Databricks `RATE_LIMIT_EXCEEDED`, and
generic `requests` / `httpx` HTTP 429 / 5xx. Unknown exception classes
default to permanent (fail-fast). Add a new vendor by updating
`_TRANSIENT_RULES`.

Read next:

- [`docs/SKILL_CONTRACT.md`](../../docs/SKILL_CONTRACT.md) — the
  contract every shipped skill clears
- [`./errors.py`](./errors.py) — `SkillError` hierarchy that wraps
  retry exhaustion
"""

from __future__ import annotations

import functools
import logging
import os
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

T = TypeVar("T")

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_SECONDS = 0.5
DEFAULT_BACKOFF_CAP_SECONDS = 16.0
DEFAULT_TOTAL_BUDGET_SECONDS = 60.0

# Hard floor / ceiling so a misconfigured SKILL.md cannot turn the
# helper into an infinite loop or a no-op.
ABS_MIN_ATTEMPTS = 1
ABS_MAX_ATTEMPTS = 10
ABS_MAX_TOTAL_BUDGET_SECONDS = 600.0


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    base_seconds: float = DEFAULT_BASE_SECONDS
    backoff_cap_seconds: float = DEFAULT_BACKOFF_CAP_SECONDS
    total_budget_seconds: float = DEFAULT_TOTAL_BUDGET_SECONDS

    def __post_init__(self) -> None:  # type: ignore[override]
        if not (ABS_MIN_ATTEMPTS <= self.max_attempts <= ABS_MAX_ATTEMPTS):
            raise ValueError(f"max_attempts must be in [{ABS_MIN_ATTEMPTS}, {ABS_MAX_ATTEMPTS}]")
        if (
            self.total_budget_seconds <= 0
            or self.total_budget_seconds > ABS_MAX_TOTAL_BUDGET_SECONDS
        ):
            raise ValueError(f"total_budget_seconds must be in (0, {ABS_MAX_TOTAL_BUDGET_SECONDS}]")
        if self.base_seconds < 0 or self.backoff_cap_seconds < 0:
            raise ValueError("backoff seconds must be non-negative")


def policy_from_env(env: dict[str, str] | None = None) -> RetryPolicy:
    """Build a `RetryPolicy` from per-call env overrides.

    Priority: env override > skill SKILL.md frontmatter > defaults.
    Frontmatter binding is left to the caller (each skill reads its own
    metadata); this helper only handles env so a debug session can
    widen the budget without editing code.
    """
    src = os.environ if env is None else env

    def _read_float(name: str, default: float) -> float:
        raw = (src.get(name) or "").strip()
        if not raw:
            return default
        try:
            return float(raw)
        except ValueError:
            return default

    def _read_int(name: str, default: int) -> int:
        raw = (src.get(name) or "").strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            return default

    return RetryPolicy(
        max_attempts=_read_int("CLOUD_SECURITY_RETRY_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS),
        base_seconds=_read_float("CLOUD_SECURITY_RETRY_BASE_SECONDS", DEFAULT_BASE_SECONDS),
        backoff_cap_seconds=_read_float(
            "CLOUD_SECURITY_RETRY_CAP_SECONDS", DEFAULT_BACKOFF_CAP_SECONDS
        ),
        total_budget_seconds=_read_float(
            "CLOUD_SECURITY_RETRY_TOTAL_BUDGET_SECONDS", DEFAULT_TOTAL_BUDGET_SECONDS
        ),
    )


# ── Transient-vs-permanent classifier ───────────────────────────────


def _aws_is_transient(exc: BaseException) -> bool:
    code = ""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = (response.get("Error") or {}).get("Code", "")
    if not code:
        code = type(exc).__name__
    return code in {
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "ProvisionedThroughputExceededException",
        "TransactionInProgressException",
        "ServiceUnavailable",
        "InternalFailure",
        "InternalServerError",
        "RequestTimeout",
        "RequestTimeoutException",
        "SlowDown",
    }


def _google_is_transient(exc: BaseException) -> bool:
    status = getattr(exc, "status_code", None) or getattr(exc, "resp", None)
    if hasattr(exc, "resp") and getattr(exc.resp, "status", None) is not None:
        try:
            status = int(exc.resp.status)
        except (TypeError, ValueError):
            status = None
    if isinstance(status, int) and status in {429, 500, 502, 503, 504}:
        return True
    name = type(exc).__name__
    return name in {
        "ServiceUnavailable",
        "InternalServerError",
        "TooManyRequests",
        "DeadlineExceeded",
    }


def _azure_is_transient(exc: BaseException) -> bool:
    name = type(exc).__name__
    if name in {"ServiceRequestError", "ServiceResponseError", "ServiceRequestTimeoutError"}:
        return True
    code = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    return isinstance(code, int) and code in {429, 500, 502, 503, 504}


def _http_is_transient(exc: BaseException) -> bool:
    """`requests`/`httpx` style — `response.status_code` exposed."""
    response = getattr(exc, "response", None)
    if response is None:
        return False
    status = getattr(response, "status_code", None) or getattr(response, "status", None)
    return isinstance(status, int) and status in {408, 425, 429, 500, 502, 503, 504}


def _snowflake_is_transient(exc: BaseException) -> bool:
    name = type(exc).__name__
    if name in {"OperationalError", "InternalServerError", "GatewayTimeoutError"}:
        msg = str(exc).lower()
        return "rate limit" in msg or "too many requests" in msg or "503" in msg or "504" in msg
    return False


def _databricks_is_transient(exc: BaseException) -> bool:
    msg = str(exc).upper()
    return "RATE_LIMIT_EXCEEDED" in msg or "TEMPORARILY_UNAVAILABLE" in msg


# Order matters: more-specific classifiers run before generic HTTP.
_TRANSIENT_RULES: tuple[Callable[[BaseException], bool], ...] = (
    _aws_is_transient,
    _google_is_transient,
    _azure_is_transient,
    _snowflake_is_transient,
    _databricks_is_transient,
    _http_is_transient,
)


def is_transient(exc: BaseException) -> bool:
    """Returns True iff at least one classifier recognises the exception
    as transient. Unknown exceptions are treated as permanent."""
    return any(rule(exc) for rule in _TRANSIENT_RULES)


# ── Backoff schedule ────────────────────────────────────────────────


def compute_backoff(
    attempt: int,
    policy: RetryPolicy,
    *,
    rng: random.Random | None = None,
) -> float:
    """Full-jitter exponential backoff. Returns the seconds to sleep
    before attempt N+1 given that attempts 0..N just failed."""
    rng = rng or random.SystemRandom()
    raw = policy.base_seconds * (2**attempt)
    capped = min(raw, policy.backoff_cap_seconds)
    return rng.uniform(0, capped) if capped > 0 else 0


# ── Decorator + functional API ──────────────────────────────────────


class _SleepFn:
    """Indirection so tests can swap in a mock sleep without touching
    the real `time` module (which is shared across the test process)."""

    def __init__(self) -> None:
        self.fn: Callable[[float], None] = time.sleep

    def __call__(self, seconds: float) -> None:
        self.fn(seconds)


_sleep = _SleepFn()


def retry_call(
    func: Callable[..., T],
    /,
    *args: Any,
    policy: RetryPolicy | None = None,
    on_retry: Callable[[int, BaseException], None] | None = None,
    **kwargs: Any,
) -> T:
    """Functional API: call `func(*args, **kwargs)`, retrying on
    classified-transient exceptions per `policy`. Raises the last
    exception when the cap is hit or the budget is exhausted."""
    policy = policy or RetryPolicy()
    started = time.monotonic()
    last_exc: BaseException | None = None
    for attempt in range(policy.max_attempts):
        try:
            return func(*args, **kwargs)
        except BaseException as exc:  # pylint: disable=broad-except
            last_exc = exc
            if not is_transient(exc):
                raise
            if attempt + 1 >= policy.max_attempts:
                break
            backoff = compute_backoff(attempt, policy)
            elapsed = time.monotonic() - started
            if elapsed + backoff > policy.total_budget_seconds:
                # Don't even start the next attempt if the budget would
                # be exhausted before it could complete.
                break
            if on_retry is not None:
                on_retry(attempt + 1, exc)
            _sleep(backoff)
    assert last_exc is not None
    raise last_exc


def retry_on_throttle(
    policy: RetryPolicy | None = None,
    *,
    logger: logging.Logger | None = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator form. Wraps a function so cloud SDK calls inside it
    retry transient errors with exponential-backoff + jitter.

    Logs every retry at WARNING with the wrapped function name and the
    attempt count so audits can spot rate-limited callers."""
    bound_policy = policy or RetryPolicy()
    log = logger or logging.getLogger("cloud_security.retry")

    def _decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def _inner(*args: Any, **kwargs: Any) -> T:
            def _on_retry(attempt: int, exc: BaseException) -> None:
                log.warning(
                    "%s transient failure, retrying (attempt %s/%s): %s: %s",
                    func.__qualname__,
                    attempt,
                    bound_policy.max_attempts,
                    type(exc).__name__,
                    exc,
                )

            return retry_call(func, *args, policy=bound_policy, on_retry=_on_retry, **kwargs)

        return _inner

    return _decorator
