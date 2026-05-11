#!/usr/bin/env python3
"""Add the five agent-bom trust-heuristic frontmatter fields to every
shipped SKILL.md.

Fields inserted (only if absent — existing values are never overwritten):

  - purpose                — one-sentence purpose statement derived from
                              the first sentence of `description`.
  - capability             — verb the skill performs, derived from the
                              skill category: ingestion → `ingest`,
                              detection → `detect`, discovery →
                              `discover`, evaluation → `evaluate`,
                              view → `view`, output → `output`,
                              remediation → `remediate`.
  - persistence            — `none` for read-only skills (side_effects =
                              `none`); `audit_log` for skills emitting
                              findings (`writes-audit` in side_effects);
                              `cloud_state` for the remediation layer
                              (mutates cloud resources).
  - telemetry              — `stderr_jsonl` for every shipped skill —
                              we route all runtime telemetry through
                              `skills/_shared/logging.py`.
  - privilege_escalation   — `none` for ingest/detect/view/output
                              layers; `read` for discover/evaluation
                              layers (read APIs); `read_write` for
                              remediation (the only write surface).

Heuristics are derived, never guessed. If a field is already present in
frontmatter, this script leaves it alone — making it idempotent.

Usage:
  python scripts/add_skill_trust_frontmatter.py            # write
  python scripts/add_skill_trust_frontmatter.py --check    # CI gate
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = ROOT / "skills"

# Layer (parent dir name) → canonical capability verb.
LAYER_TO_CAPABILITY: dict[str, str] = {
    "ingestion": "ingest",
    "detection": "detect",
    "discovery": "discover",
    "evaluation": "evaluate",
    "view": "view",
    "output": "output",
    "remediation": "remediate",
}

# Layer → privilege_escalation baseline.
# - ingest/detect/view/output never touch live cloud APIs in this repo
#   (ingest reads files, detect reads stdin, view converts, output
#   sinks into a pre-provisioned destination), so `none`.
# - discover/evaluation skills DO call cloud read APIs (Describe*,
#   List*) to assemble inventory or score posture, hence `read`.
# - remediation skills are the only write surface, hence `read_write`.
LAYER_TO_PRIV: dict[str, str] = {
    "ingestion": "none",
    "detection": "none",
    "view": "none",
    "output": "none",
    "discovery": "read",
    "evaluation": "read",
    "remediation": "read_write",
}

# Persistence: derive from side_effects (frontmatter), not from layer,
# so the answer reflects what the skill actually does.
# - side_effects: none → persistence: none
# - any `writes-audit` scope → persistence: audit_log (findings persist
#   to the configured audit sink)
# - remediation layer (mutates live cloud / identity / storage) →
#   persistence: cloud_state regardless of audit scope.
def _derive_persistence(layer: str, side_effects: tuple[str, ...]) -> str:
    if layer == "remediation":
        return "cloud_state"
    if any(s.startswith("writes-") for s in side_effects):
        # output sinks that write-database/storage and CSPM evaluators
        # that emit audit rows fall here. They persist findings, not
        # cloud state.
        return "audit_log"
    return "none"


# The five trust-heuristic fields, in the order we want them to appear
# in the file. They go right after `description` (or after `purpose`
# when only `purpose` is being inserted) because that's the most
# scannable spot for a human reviewer.
TRUST_FIELDS_ORDER: tuple[str, ...] = (
    "purpose",
    "capability",
    "persistence",
    "telemetry",
    "privilege_escalation",
)


_FRONTMATTER_RE = re.compile(r"\A(---\n)(.*?)(\n---\n)", re.DOTALL)


def _split_frontmatter(text: str) -> tuple[str, str, str] | None:
    """Return (opener, body, closer) for the YAML frontmatter, or None."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


def _top_level_keys(body: str) -> list[str]:
    """Return the top-level (column-0) keys in frontmatter order."""
    keys: list[str] = []
    for line in body.splitlines():
        if not line or line.startswith(" ") or line.startswith("\t"):
            continue
        # YAML block-scalar continuations like `>-` are siblings of the
        # previous key — they start with whitespace, so they're filtered
        # by the indent check above.
        if ":" not in line:
            continue
        key = line.split(":", 1)[0].strip()
        # Skip merge-conflict markers and similar artefacts.
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key):
            continue
        keys.append(key)
    return keys


def _read_scalar(body: str, key: str) -> str | None:
    """Read the value of a top-level scalar key. Returns the joined
    string for `>-` block scalars, or None if absent.
    """
    lines = body.splitlines()
    n = len(lines)
    idx = 0
    while idx < n:
        line = lines[idx]
        if line.startswith(" ") or line.startswith("\t") or not line:
            idx += 1
            continue
        if ":" not in line:
            idx += 1
            continue
        k, raw = line.split(":", 1)
        if k.strip() != key:
            idx += 1
            continue
        v = raw.strip()
        if v in {">", ">-", "|", "|-"}:
            # Multi-line block scalar — consume indented continuation.
            idx += 1
            parts: list[str] = []
            while idx < n:
                cont = lines[idx]
                if cont.startswith(" ") or cont.startswith("\t"):
                    parts.append(cont.strip())
                    idx += 1
                    continue
                if not cont.strip():
                    idx += 1
                    continue
                break
            return " ".join(parts).strip().strip("\"'")
        return v.strip("\"'")
    return None


def _derive_purpose(description: str | None) -> str:
    """Take the first sentence of `description` as the purpose. Trim to
    a single sentence ending in a period; if the description doesn't
    contain a sentence boundary, return the full description trimmed.
    """
    if not description:
        return "Read-only security skill."
    # Strip the YAML join-noise that block-scalar parsing introduces.
    text = re.sub(r"\s+", " ", description).strip()
    # First period followed by a space or end of string.
    m = re.search(r"^[^.!?]*[.!?](?=\s|$)", text)
    candidate = m.group(0).strip() if m else text
    # Defensive cap at 220 chars so the purpose stays one-liner.
    if len(candidate) > 220:
        candidate = candidate[:217].rstrip() + "..."
    return candidate


def _format_scalar_line(key: str, value: str) -> str:
    """Render a top-level `key: value` line, quoting the value when it
    contains characters that would otherwise need a YAML block scalar.
    """
    # Purpose may contain commas, colons, etc. Quote it.
    if key == "purpose" and (":" in value or value.startswith(("&", "*", "!", "?", "{", "[", ">", "|"))):
        # YAML double-quote with the doubled-quote escape.
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'{key}: "{escaped}"'
    return f"{key}: {value}"


def _remove_top_level_key(lines: list[str], key: str) -> tuple[list[str], str | None]:
    """Remove a top-level key (and any indented continuation block) from
    `lines`. Returns (new_lines, removed_value_line) where removed_value_line
    is the single-line `key: value` rendition or None if the key was a
    block scalar (we just keep the joined value via _read_scalar elsewhere).
    """
    out: list[str] = []
    removed_line: str | None = None
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if removed_line is None and ":" in line and not line.startswith((" ", "\t")):
            k = line.split(":", 1)[0].strip()
            if k == key:
                removed_line = line
                i += 1
                # Skip any indented continuation block.
                head = line.split(":", 1)[1].strip()
                if head in {">", ">-", "|", "|-"} or not head:
                    while i < n and (lines[i].startswith(" ") or lines[i].startswith("\t") or not lines[i].strip()):
                        i += 1
                continue
        out.append(line)
        i += 1
    return out, removed_line


def _insert_fields(
    body: str,
    derived: dict[str, str],
) -> tuple[str, list[str]]:
    """Insert trust-heuristic fields after `description`, preserving any
    pre-existing values. If `capability` already exists elsewhere in the
    file, it is relocated to the canonical slot (immediately after
    `description`) so the file satisfies the canonical key order.

    Returns (new_body, added_keys).
    """
    lines = body.splitlines()
    existing_keys = set(_top_level_keys(body))

    # Preserve pre-existing capability value (if any) and relocate it.
    relocated_capability: str | None = None
    if "capability" in existing_keys:
        existing_value = _read_scalar(body, "capability")
        lines, _ = _remove_top_level_key(lines, "capability")
        if existing_value is not None:
            relocated_capability = existing_value
        # Capability is now considered "missing" so it gets re-inserted in
        # the canonical slot below — with its original value preserved.
        existing_keys.discard("capability")

    # Build the to_add list in canonical order.
    to_add: list[tuple[str, str]] = []
    for k in TRUST_FIELDS_ORDER:
        if k in existing_keys:
            continue
        if k == "capability" and relocated_capability is not None:
            to_add.append((k, relocated_capability))
            continue
        if k in derived:
            to_add.append((k, derived[k]))

    if not to_add:
        return body, []

    # Find the line where `description` ends. If `description` is a
    # block scalar, scan past its indented continuation lines.
    out: list[str] = []
    i = 0
    n = len(lines)
    inserted = False
    while i < n:
        line = lines[i]
        out.append(line)
        if not inserted and line.startswith("description:"):
            head = line.split(":", 1)[1].strip()
            i += 1
            if head in {">", ">-", "|", "|-"}:
                while i < n and (lines[i].startswith(" ") or lines[i].startswith("\t") or not lines[i].strip()):
                    out.append(lines[i])
                    i += 1
            for key, value in to_add:
                out.append(_format_scalar_line(key, value))
            inserted = True
            continue
        i += 1

    if not inserted:
        for key, value in to_add:
            out.append(_format_scalar_line(key, value))

    # Report only newly-derived insertions, not the relocated capability.
    added_keys = [k for k, _ in to_add if not (k == "capability" and relocated_capability is not None)]
    return "\n".join(out), added_keys


def _process_skill(path: Path) -> tuple[bool, list[str]]:
    """Returns (changed, added_keys)."""
    text = path.read_text()
    parts = _split_frontmatter(text)
    if parts is None:
        return False, []
    opener, body, closer = parts

    layer = path.parent.parent.name
    if layer not in LAYER_TO_CAPABILITY:
        return False, []

    description = _read_scalar(body, "description")
    raw_side_effects = _read_scalar(body, "side_effects") or ""
    side_effects = tuple(s.strip() for s in raw_side_effects.split(",") if s.strip())

    derived: dict[str, str] = {
        "purpose": _derive_purpose(description),
        "capability": LAYER_TO_CAPABILITY[layer],
        "persistence": _derive_persistence(layer, side_effects),
        "telemetry": "stderr_jsonl",
        "privilege_escalation": LAYER_TO_PRIV[layer],
    }

    new_body, added = _insert_fields(body, derived)
    if not added:
        return False, []

    new_text = opener + new_body + closer + text[len(opener) + len(body) + len(closer):]
    path.write_text(new_text)
    return True, added


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any SKILL.md would be modified (CI drift gate).",
    )
    args = parser.parse_args(argv)

    skill_files = sorted(SKILLS_ROOT.glob("*/*/SKILL.md"))
    drift: list[str] = []
    total_added: dict[str, int] = {k: 0 for k in TRUST_FIELDS_ORDER}
    files_changed = 0

    for path in skill_files:
        # In --check mode we never write; recompute deltas in memory.
        text = path.read_text()
        parts = _split_frontmatter(text)
        if parts is None:
            continue
        _, body, _ = parts
        layer = path.parent.parent.name
        if layer not in LAYER_TO_CAPABILITY:
            continue
        description = _read_scalar(body, "description")
        raw_side_effects = _read_scalar(body, "side_effects") or ""
        side_effects = tuple(s.strip() for s in raw_side_effects.split(",") if s.strip())
        derived = {
            "purpose": _derive_purpose(description),
            "capability": LAYER_TO_CAPABILITY[layer],
            "persistence": _derive_persistence(layer, side_effects),
            "telemetry": "stderr_jsonl",
            "privilege_escalation": LAYER_TO_PRIV[layer],
        }
        existing_keys_list = _top_level_keys(body)
        existing = set(existing_keys_list)
        missing = [k for k in TRUST_FIELDS_ORDER if k not in existing and k in derived]
        # Capability that exists but is in the legacy slot (not directly
        # after the trust-axis cluster) also counts as drift, because
        # `_process_skill` will relocate it.
        misordered_capability = False
        if "capability" in existing:
            # Canonical position: must appear before `license`.
            try:
                cap_pos = existing_keys_list.index("capability")
                lic_pos = existing_keys_list.index("license") if "license" in existing else len(existing_keys_list)
                if cap_pos > lic_pos:
                    misordered_capability = True
            except ValueError:
                pass
        if missing or misordered_capability:
            reason = ", ".join(missing) if missing else ""
            if misordered_capability:
                reason = (reason + "; " if reason else "") + "capability misordered"
            drift.append(f"{path.relative_to(ROOT)}: {reason}")
            for k in missing:
                total_added[k] += 1
            if not args.check:
                changed, _ = _process_skill(path)
                if changed:
                    files_changed += 1

    if args.check:
        if drift:
            print("SKILL.md trust frontmatter drift:", file=sys.stderr)
            for line in drift:
                print(f" - {line}", file=sys.stderr)
            print(
                "\nRun: python scripts/add_skill_trust_frontmatter.py",
                file=sys.stderr,
            )
            return 1
        print("SKILL.md trust frontmatter in sync.")
        return 0

    print(f"updated {files_changed} SKILL.md file(s); added field counts: {total_added}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
