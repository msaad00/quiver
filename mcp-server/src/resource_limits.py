"""Per-skill `RLIMIT_*` enforcement.

Process-level resource caps applied to every skill subprocess via
`preexec_fn`. Cheap defense-in-depth on top of the existing policy
controls (allowlist, dry-run, HITL, env scrub):

- A runaway regex no longer DoSes the wrapper.
- A buggy skill that allocates 10 GB no longer takes the host with it.
- A fork-bomb in a skill is bounded by `RLIMIT_NPROC`.
- A skill that tries to write 50 GB to disk is stopped at `RLIMIT_FSIZE`.

Limits are tunable per env var so operators can widen them for memory-
heavy detectors (lateral-movement on a 1 M-event window) without
touching code. Windows has no `resource` module — `apply_in_child` is a
no-op there so the wrapper still works.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass

# 1 GB virtual memory cap. Comfortably above what every shipped detector
# needs on the largest captured fixture; small enough that a leak is loud.
DEFAULT_MAX_BYTES = 1 * 1024 * 1024 * 1024

# 100 MB single-file write cap. Big enough for a full OCSF JSONL dump
# from a 1 M-event scan; small enough that runaway log writes get cut
# off before filling the disk.
DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024

# Sub-process count cap. RLIMIT_NPROC is per-UID (POSIX) — setting a low
# cap here counts every existing process the user has, not just the
# wrapper's children. Defaulting to 0 (= no enforcement) avoids the
# common dev-machine failure mode of `fork: Resource temporarily
# unavailable`. Operators on dedicated single-purpose hosts opt in via
# `CLOUD_SECURITY_SKILL_MAX_PROCESSES` (typical value: ~ existing process
# count + 32).
DEFAULT_MAX_PROCESSES = 0

# CPU-time cap is configured per call to mirror the wall-clock
# subprocess timeout. Without a cap, a CPU-bound bug could exhaust the
# wrapper's wall-clock budget without ever yielding for the timeout.
CPU_LIMIT_GRACE_SECONDS = 5  # let the wrapper's wall-clock timeout fire first


@dataclass(frozen=True)
class ResourceLimits:
    max_bytes: int
    max_file_bytes: int
    max_processes: int
    cpu_seconds: int


def _read_int_env(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(value, 0)


def from_env(timeout_seconds: int, env: dict[str, str] | None = None) -> ResourceLimits:
    """Resolve the limit set for one skill call. `timeout_seconds` is the
    wrapper's wall-clock cap; the CPU cap is set a few seconds higher so
    the wall-clock timeout fires first and the wrapper records the
    failure with a clean `subprocess.TimeoutExpired`."""
    src = os.environ if env is None else env
    return ResourceLimits(
        max_bytes=_read_int_env("CLOUD_SECURITY_SKILL_MAX_BYTES", DEFAULT_MAX_BYTES)
        if (src.get("CLOUD_SECURITY_SKILL_MAX_BYTES") or "").strip()
        else DEFAULT_MAX_BYTES,
        max_file_bytes=_read_int_env(
            "CLOUD_SECURITY_SKILL_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES
        )
        if (src.get("CLOUD_SECURITY_SKILL_MAX_FILE_BYTES") or "").strip()
        else DEFAULT_MAX_FILE_BYTES,
        max_processes=_read_int_env(
            "CLOUD_SECURITY_SKILL_MAX_PROCESSES", DEFAULT_MAX_PROCESSES
        )
        if (src.get("CLOUD_SECURITY_SKILL_MAX_PROCESSES") or "").strip()
        else DEFAULT_MAX_PROCESSES,
        cpu_seconds=max(timeout_seconds + CPU_LIMIT_GRACE_SECONDS, 1),
    )


def apply_in_child(limits: ResourceLimits) -> None:
    """Called inside the child process via `subprocess.run(preexec_fn=...)`.

    On Windows, `resource` is unavailable so this is a documented no-op —
    the OS-level controls there belong to AppContainer / Job Objects,
    which the wrapper does not configure. POSIX systems get the full
    quartet (`AS`, `FSIZE`, `NPROC`, `CPU`).
    """
    try:
        import resource  # pylint: disable=import-outside-toplevel
    except ImportError:  # pragma: no cover - Windows
        return

    def _set(rlim: int, soft: int) -> None:
        try:
            current_soft, current_hard = resource.getrlimit(rlim)
        except (OSError, ValueError):  # pragma: no cover - rlim not supported
            return
        # Never RAISE the existing hard limit (the kernel rejects that
        # for non-root processes anyway); only TIGHTEN.
        new_soft = soft
        new_hard = current_hard
        if current_hard != resource.RLIM_INFINITY:
            new_soft = min(new_soft, current_hard)
            new_hard = current_hard
        try:
            resource.setrlimit(rlim, (new_soft, new_hard))
        except (OSError, ValueError):  # pragma: no cover - kernel refusal
            return

    if limits.max_bytes > 0:
        _set(resource.RLIMIT_AS, limits.max_bytes)
    if limits.max_file_bytes > 0:
        _set(resource.RLIMIT_FSIZE, limits.max_file_bytes)
    if limits.max_processes > 0 and hasattr(resource, "RLIMIT_NPROC"):
        _set(resource.RLIMIT_NPROC, limits.max_processes)
    if limits.cpu_seconds > 0:
        _set(resource.RLIMIT_CPU, limits.cpu_seconds)


def make_preexec(limits: ResourceLimits) -> Callable[[], None]:
    """Build a closure suitable for `subprocess.run(preexec_fn=...)`."""
    def _preexec() -> None:  # pragma: no cover - exercised in subprocess
        apply_in_child(limits)
    return _preexec
