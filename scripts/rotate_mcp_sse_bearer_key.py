"""Generate + register a new bearer key in the MCP SSE keys file.

Atomic write: stage to a sibling tmp file, fsync, rename. If anything
fails, the existing file is untouched and the script exits non-zero.

The script prints the **new secret to stdout once**. The secret is not
recoverable from logs after that (the keys file stores it, but the
banner reminds operators to capture it before they leave the shell).

Usage
-----

    python scripts/rotate_mcp_sse_bearer_key.py \
        --file /etc/cloud-security/sse-bearer-keys.json \
        --kid 2026-05-10 \
        --ttl-days 90

After the new key is in the file, send `SIGHUP` to the running listener
(or restart the deploy) to pick the rotation up:

    kill -HUP $(pgrep -f transports/sse.py)

The companion `KeyStore` will accept BOTH the old and the new secret
until the old key's `expires` ticks past, so clients can roll forward
on their own schedule.

Exit codes
----------
0  success
1  IO / parse error or missing required arguments
2  refusal — the resulting keyset would be empty (e.g. requested to
   retire all expired entries while no usable replacement was added)
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DEFAULT_TTL_DAYS = 90


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_existing(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"error: failed to read {path}: {exc}") from exc
    text = text.strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise SystemExit(f"error: {path} must contain a JSON array")
    for entry in payload:
        if not isinstance(entry, dict):
            raise SystemExit(f"error: {path} contains a non-object entry")
    return payload


def _atomic_write(path: Path, entries: list[dict[str, Any]]) -> None:
    """Write `entries` to `path` atomically.

    Strategy:
        1. write to a sibling tmp file inside the same directory so the
           rename is on the same filesystem (`os.rename` is atomic
           per-filesystem),
        2. fsync the tmp file,
        3. rename over the destination,
        4. fsync the parent directory so the rename itself survives a
           crash on common filesystems (ext4, xfs).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(entries, indent=2, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        # Best-effort cleanup; the rename is the only side-effect we
        # care about and it didn't happen.
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    # fsync the parent directory so the rename hits disk.
    dir_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _retire_expired(
    entries: list[dict[str, Any]], now: datetime, retire_one_oldest: bool
) -> tuple[list[dict[str, Any]], list[str]]:
    """Optionally drop one expired entry (the oldest by `expires`).

    Returns the kept entries + the kid(s) that were retired. The
    "retire one" mode is the conservative default — operators reviewing
    the resulting file should still see the rotation history.
    """
    if not retire_one_oldest:
        return entries, []
    expired = [
        (i, e)
        for i, e in enumerate(entries)
        if _parse_iso(e.get("expires")) is not None and _parse_iso(e.get("expires")) <= now  # type: ignore[operator]
    ]
    if not expired:
        return entries, []
    expired.sort(key=lambda item: _parse_iso(item[1].get("expires")) or now)
    drop_index, dropped = expired[0]
    kept = [e for i, e in enumerate(entries) if i != drop_index]
    return kept, [dropped.get("kid") or "<unknown>"]


def _generate_kid(now: datetime) -> str:
    """Deterministic-by-day kid so operators can read the rotation
    timeline at a glance. Suffixed with a 4-char random tail to keep
    same-day rotations distinguishable."""
    tail = secrets.token_hex(2)
    return f"{now.strftime('%Y-%m-%d')}-{tail}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rotate the MCP SSE bearer-key file.",
        epilog=(
            "After the file is rewritten, send SIGHUP to the running listener "
            "to pick up the new key without a restart."
        ),
    )
    parser.add_argument(
        "--file",
        required=True,
        type=Path,
        help="path to the keys JSON file (matches MCP_SSE_BEARER_KEYS_FILE).",
    )
    parser.add_argument(
        "--kid",
        default=None,
        help="explicit kid for the new key. Default is YYYY-MM-DD-<rand>.",
    )
    parser.add_argument(
        "--ttl-days",
        type=int,
        default=DEFAULT_TTL_DAYS,
        help=f"new key expires this many days from now (default {DEFAULT_TTL_DAYS}).",
    )
    parser.add_argument(
        "--retire-oldest-expired",
        action="store_true",
        help="drop the oldest expired key after adding the new one.",
    )
    parser.add_argument(
        "--no-expiry",
        action="store_true",
        help="omit the `expires` field — useful for break-glass-only deploys.",
    )
    args = parser.parse_args(argv)

    now = _utc_now()
    new_kid = args.kid or _generate_kid(now)
    new_secret = secrets.token_urlsafe(32)

    try:
        entries = _load_existing(args.file)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"error: failed to load existing keys file: {exc}\n")
        return 1

    existing_kids = {e.get("kid") for e in entries if isinstance(e.get("kid"), str)}
    if new_kid in existing_kids:
        sys.stderr.write(f"error: kid {new_kid!r} already exists; pick another with --kid.\n")
        return 1

    new_entry: dict[str, Any] = {
        "kid": new_kid,
        "secret": new_secret,
        "issued": _iso(now),
    }
    if not args.no_expiry:
        new_entry["expires"] = _iso(now + timedelta(days=args.ttl_days))

    entries.append(new_entry)
    entries, retired_kids = _retire_expired(entries, now, args.retire_oldest_expired)

    # Refuse to write a file that resolves to zero usable keys.
    usable = [e for e in entries if not _is_expired(e, now)]
    if not usable:
        sys.stderr.write(
            "error: resulting keyset is empty (every entry expired). "
            "Refusing to write — would lock out the listener.\n"
        )
        return 2

    try:
        _atomic_write(args.file, entries)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"error: atomic write failed: {exc}\n")
        return 1

    # Banner first so the operator sees it even on a noisy terminal.
    sys.stderr.write(
        "─" * 72 + "\n"
        "  NEW BEARER KEY GENERATED — capture it now.\n"
        "  This secret is NOT recoverable from logs or the audit chain.\n"
        "  Distribute through the same channel as the file itself.\n" + "─" * 72 + "\n"
        f"  kid:     {new_kid}\n"
        f"  expires: {new_entry.get('expires', '(none)')}\n"
    )
    if retired_kids:
        sys.stderr.write(f"  retired: {', '.join(retired_kids)}\n")
    sys.stderr.write(
        "─" * 72 + "\n  Reload the running listener:  kill -HUP <pid>\n" + "─" * 72 + "\n"
    )
    sys.stderr.flush()
    # The new secret goes on stdout alone so a `--quiet > /dev/null`
    # caller can pipe it cleanly into a sealed-secret tool.
    sys.stdout.write(new_secret + "\n")
    sys.stdout.flush()
    return 0


def _is_expired(entry: dict[str, Any], now: datetime) -> bool:
    expires = _parse_iso(entry.get("expires"))
    return expires is not None and expires <= now


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
