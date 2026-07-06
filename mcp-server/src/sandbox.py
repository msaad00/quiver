"""Layer 2 — opt-in OS-level sandbox for skill subprocesses.

Layer 1 of the sandboxing umbrella (#427) hardened the container image
(non-root, read-only fs, no-new-privileges, dropped caps). Layer 3
clamped per-process kernel resources via `RLIMIT_AS / FSIZE / CPU` in a
`preexec_fn`. Layer 2 (this module) is the optional middle layer:
operators who want filesystem / pid / ipc / mount-namespace isolation
opt in by setting `CLOUD_SECURITY_MCP_SANDBOX=on`, and the wrapper then
spawns each skill under `bwrap` (Linux) or `sandbox-exec` (macOS) with
a per-skill profile derived from the skill's `network_egress`
declaration in `SKILL.md` frontmatter.

Design constraints:

- **Off by default.** No behaviour change for any current operator
  unless they flip the env var.
- **No new Python deps.** `bwrap` and `sandbox-exec` are OS-installed
  binaries — the module shells out to whichever is present.
- **No-op fallback.** If the wrapper binary is missing, the platform
  isn't supported, or the env var is unset, `wrap_command` returns the
  original `cmd` unchanged. We log a warning to stderr the first time
  we have to fall back so operators notice their opt-in didn't take.
- **Network policy is binary, not per-host.** The repo's
  `network_egress` field is advisory and may list hostnames; layer 2
  enforces "all or nothing" — only `network_egress: ()` (declared
  empty) drops the network. Future PRs can add per-host iptables / pf
  rules when we're ready to own that complexity.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import only for type checking
    from tool_registry import SkillSpec

SANDBOX_ENV = "CLOUD_SECURITY_MCP_SANDBOX"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

_FALLBACK_WARNED: set[str] = set()


def is_enabled(env: dict[str, str] | None = None) -> bool:
    """Return True when `CLOUD_SECURITY_MCP_SANDBOX` is truthy.

    Truthy values match the rest of the wrapper: `1`, `true`, `yes`,
    `on` (case-insensitive). Anything else — including missing — is
    treated as off.
    """
    src = os.environ if env is None else env
    return src.get(SANDBOX_ENV, "").strip().lower() in _TRUTHY


def _platform() -> str:
    """Return `linux`, `darwin`, or `unsupported`. Split out so tests
    can monkeypatch `sys.platform`."""
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    return "unsupported"


def _network_locked_down(skill: SkillSpec) -> bool:
    """A skill drops the network only when it explicitly declared
    `network_egress: []` (an empty tuple after parsing). Any declared
    hostnames — or no declaration at all — keep the network on, because
    cloud SDKs need it."""
    return skill.network_egress == ()


def _warn_fallback(reason: str) -> None:
    """Log once-per-reason so operators notice their opt-in didn't
    take, without spamming stderr on every call."""
    if reason in _FALLBACK_WARNED:
        return
    _FALLBACK_WARNED.add(reason)
    sys.stderr.write(f'{{"event":"mcp_sandbox_fallback","reason":"{reason}"}}\n')
    sys.stderr.flush()


def _bwrap_command(cmd: list[str], skill: SkillSpec, repo: Path) -> list[str]:
    """Build a `bwrap`-prefixed command line.

    Read-only binds for the OS roots; bind the repo at its real path so
    the skill keeps working cwd. Tmpfs `/tmp`, fresh `/proc` and `/dev`,
    and `--unshare-all` to drop pid / ipc / mount / uts / cgroup
    namespaces. Keep network on by default (cloud SDKs need it); drop
    it when `network_egress: []` was declared.
    """
    repo_str = str(repo)
    args = ["bwrap"]
    for ro in ("/usr", "/etc", "/lib", "/lib64"):
        if Path(ro).exists():
            args += ["--ro-bind", ro, ro]
    # `/tmp`, `/proc`, `/dev` here are bwrap mount-target paths inside
    # the sandboxed namespace, NOT a Python tempfile path. Bandit's
    # B108 hardcoded-tmp-directory check is a false positive on this
    # well-known bwrap argument shape.
    args += [
        "--bind",
        repo_str,
        repo_str,
        "--tmpfs",
        "/tmp",  # nosec B108
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--unshare-all",
    ]
    args += ["--unshare-net"] if _network_locked_down(skill) else ["--share-net"]
    args += ["--die-with-parent"]
    args += ["--", *cmd]
    return args


def _sandbox_exec_command(cmd: list[str], skill: SkillSpec, repo: Path) -> list[str]:
    """Build a `sandbox-exec`-prefixed command line.

    Emits a deny-by-default `.sb` profile to a temp file, then invokes
    `sandbox-exec -f <profile> <cmd...>`. Allows file I/O under `/tmp`
    and the repo, plus process spawning; toggles `network*` based on
    `network_egress`.
    """
    repo_str = str(repo)
    network_clause = "(deny network*)" if _network_locked_down(skill) else "(allow network*)"
    profile = f"""(version 1)
(deny default)
(allow process*)
(allow signal (target self))
(allow sysctl-read)
(allow file-read*)
(allow file-write* (subpath "/tmp"))
(allow file-write* (subpath "/private/tmp"))
(allow file-write* (subpath "/private/var/folders"))
(allow file-write* (subpath {repo_str!r}))
(allow ipc-posix-shm)
(allow mach-lookup)
{network_clause}
"""
    fd, path = tempfile.mkstemp(prefix="mcp-sandbox-", suffix=".sb")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(profile)
    except Exception:  # pragma: no cover - tmp write failure
        os.close(fd)
        raise
    return ["sandbox-exec", "-f", path, *cmd]


def wrap_command(
    cmd: list[str],
    skill: SkillSpec,
    *,
    env: dict[str, str] | None = None,
    repo_root: Path | None = None,
) -> list[str]:
    """Return `cmd` with the platform's sandbox wrapper prepended.

    Falls back to the unwrapped command (logging a one-shot stderr
    warning) when:

    - `CLOUD_SECURITY_MCP_SANDBOX` is unset / falsy
    - the platform is not Linux or macOS
    - the platform's wrapper binary (`bwrap` / `sandbox-exec`) isn't
      installed

    The fallback is intentional — we never crash the wrapper just
    because the operator hasn't installed bwrap yet.
    """
    if not is_enabled(env):
        return cmd
    repo = repo_root or Path(__file__).resolve().parents[2]
    platform = _platform()
    if platform == "linux":
        if shutil.which("bwrap") is None:
            _warn_fallback("bwrap_not_installed")
            return cmd
        return _bwrap_command(cmd, skill, repo)
    if platform == "darwin":
        if shutil.which("sandbox-exec") is None:
            _warn_fallback("sandbox_exec_not_installed")
            return cmd
        return _sandbox_exec_command(cmd, skill, repo)
    _warn_fallback(f"unsupported_platform_{sys.platform}")
    return cmd
