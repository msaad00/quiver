"""Verify the HMAC chain on an MCP audit log.

The MCP wrapper (`mcp-server/src/server.py`) optionally writes a
tamper-evident audit log: each event carries `prev_hash` and `chain_hash`
fields keyed by `CLOUD_SECURITY_AUDIT_HMAC_KEY`. This script replays the
chain and surfaces any record whose `chain_hash` does not match
`HMAC-SHA-256(key, prev_hash || canonical_event_json)`.

Exit status:
  0 — every event verifies, chain is contiguous
  1 — one or more events fail verification (gap, edit, or wrong key)
  2 — usage / IO error before verification could begin

Usage:
  CLOUD_SECURITY_AUDIT_HMAC_KEY=... \
    python scripts/verify_audit_chain.py path/to/audit.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

GENESIS_PREV_HASH = "0" * 64


def _canonical_event_bytes(event: dict[str, Any]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _expected_chain_hash(prev_hash: str, event_without_chain: dict[str, Any], key: bytes) -> str:
    payload = prev_hash.encode("ascii") + b"\n" + _canonical_event_bytes(event_without_chain)
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _iter_records(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    with path.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"line {lineno}: invalid JSON: {exc}") from exc
            if not isinstance(record, dict):
                raise SystemExit(f"line {lineno}: record is not a JSON object")
            yield lineno, record


def verify(path: Path, key: bytes) -> int:
    prev_hash = GENESIS_PREV_HASH
    errors = 0
    count = 0
    for lineno, record in _iter_records(path):
        count += 1
        actual_prev = record.get("prev_hash")
        actual_chain = record.get("chain_hash")
        if not isinstance(actual_chain, str) or not isinstance(actual_prev, str):
            print(f"line {lineno}: missing prev_hash/chain_hash", file=sys.stderr)
            errors += 1
            continue
        if actual_prev != prev_hash:
            print(
                f"line {lineno}: prev_hash mismatch — expected {prev_hash}, got {actual_prev}",
                file=sys.stderr,
            )
            errors += 1
        # Reconstruct the bytes fed to the chain hash. The annotator computes
        # the hash over the event AFTER prev_hash is added but BEFORE
        # chain_hash is added, so strip chain_hash for verification.
        replay = {k: v for k, v in record.items() if k != "chain_hash"}
        expected = _expected_chain_hash(actual_prev, replay, key)
        if not hmac.compare_digest(actual_chain, expected):
            print(
                f"line {lineno}: chain_hash mismatch — expected {expected}, got {actual_chain}",
                file=sys.stderr,
            )
            errors += 1
        prev_hash = actual_chain
    print(f"verified {count} records, {errors} error(s)")
    return 0 if errors == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="Path to the audit JSONL file")
    parser.add_argument(
        "--key-env",
        default="CLOUD_SECURITY_AUDIT_HMAC_KEY",
        help="Environment variable holding the HMAC key (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    raw_key = os.environ.get(args.key_env, "").strip()
    if not raw_key:
        print(f"error: {args.key_env} is not set", file=sys.stderr)
        return 2
    path = Path(args.path)
    if not path.is_file():
        print(f"error: {path} is not a file", file=sys.stderr)
        return 2
    return verify(path, raw_key.encode("utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
