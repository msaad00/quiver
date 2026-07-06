"""Build a deterministic IAM departures manifest from HR termination sources."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from reconciler.change_detect import ChangeDetector  # noqa: E402
from reconciler.export import ManifestBuilder  # noqa: E402
from reconciler.sources import get_source  # noqa: E402


class _HashOnlyS3:
    """Minimal S3-compatible stub for hash computation without network writes."""

    class exceptions:
        class NoSuchKey(Exception):
            """Raised when no previous hash exists."""

    def __init__(self, previous_hash: str | None) -> None:
        self._previous_hash = previous_hash

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, object]:  # noqa: ARG002
        if self._previous_hash is None:
            raise self.exceptions.NoSuchKey()
        return {"Body": _Body(self._previous_hash)}


class _Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> bytes:
        return self._text.encode("utf-8")


def build_manifest(source_name: str, previous_hash: str | None = None) -> dict[str, object]:
    source = get_source(source_name)
    records = source.fetch_departures()
    detector = ChangeDetector(_HashOnlyS3(previous_hash), bucket="unused")
    changed, content_hash = detector.has_changed(records)
    manifest = ManifestBuilder().build_manifest(records, source_name, content_hash)
    manifest["changed"] = changed
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", required=True, help="HR source name: snowflake, databricks, clickhouse, workday"
    )
    parser.add_argument(
        "--previous-hash", help="Optional previously persisted hash to compare against."
    )
    parser.add_argument(
        "--hash-only", action="store_true", help="Emit only the computed content hash as JSON."
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument("-o", "--output", help="Write JSON to a file instead of stdout.")
    args = parser.parse_args(argv)

    try:
        result = build_manifest(args.source, previous_hash=args.previous_hash)
    except ValueError as exc:
        print(f"warning: {exc}", file=sys.stderr)
        return 2

    payload: object
    if args.hash_only:
        payload = {"source": args.source, "hash": result["hash"], "changed": result["changed"]}
    else:
        payload = result

    rendered = json.dumps(payload, indent=2 if args.pretty else None, sort_keys=True)
    if args.output:
        Path(args.output).write_text(f"{rendered}\n")
    else:
        sys.stdout.write(f"{rendered}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
