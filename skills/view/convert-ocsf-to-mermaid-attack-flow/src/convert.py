"""Convert OCSF 1.8 Detection Findings (class 2004) to a Mermaid attack flow.

Reads OCSF Detection Finding JSONL on stdin, emits a single Mermaid
flowchart LR block on stdout (wrapped in fenced code so it renders inline
on any Markdown surface that supports Mermaid — GitHub, GitLab, most
wikis).

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from typing import Any, Iterable

SKILL_NAME = "convert-ocsf-to-mermaid-attack-flow"
SKILL_VERSION = "0.1.0"

DETECTION_FINDING_CLASS_UID = 2004

# Severity → Mermaid CSS class
_SEVERITY_CLASS = {
    0: "low",  # Unknown
    1: "low",  # Informational
    2: "low",  # Low
    3: "medium",
    4: "high",
    5: "critical",
    6: "critical",
}


def severity_class(severity_id: int) -> str:
    return _SEVERITY_CLASS.get(severity_id, "low")


def _max_severity(a: int, b: int) -> int:
    return a if a >= b else b


# ---------------------------------------------------------------------------
# Mermaid ID safety
# ---------------------------------------------------------------------------

# Mermaid node IDs must be alphanumeric (plus underscore). We hash anything
# that contains other chars and prepend a letter so the ID never starts with
# a digit (Mermaid silently breaks on numeric-leading IDs).
_SAFE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def safe_id(prefix: str, raw: str) -> str:
    """Produce a Mermaid-safe stable node ID for an arbitrary string."""
    if _SAFE_ID.match(raw) and len(raw) <= 32:
        return prefix + raw
    digest = hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:10]
    return f"{prefix}{digest}"


# ---------------------------------------------------------------------------
# Observable extraction
# ---------------------------------------------------------------------------


def _observables_by_name(observables: list[dict[str, Any]]) -> dict[str, str]:
    """Index an observables[] array by name → first value."""
    out: dict[str, str] = {}
    for obs in observables or []:
        name = obs.get("name", "")
        value = obs.get("value", "")
        if name and value and name not in out:
            out[name] = str(value)
    return out


def extract_actor(finding: dict[str, Any]) -> str:
    """Pull the actor identifier from a finding's observables.

    Looks for (in order): actor.name, session.uid, then falls back to the
    finding_info.uid prefix if no actor is named.
    """
    obs = _observables_by_name(finding.get("observables") or [])
    for key in ("actor.name", "session.uid"):
        if key in obs:
            return obs[key]
    # Fall back to a slice of the finding uid
    uid = (finding.get("finding_info") or {}).get("uid") or "unknown-actor"
    return f"actor:{uid[:16]}"


def extract_target(finding: dict[str, Any]) -> tuple[str, str]:
    """Pull a target identifier and a human label from a finding's observables.

    Returns (raw_id, display_label). Looks for any *.name observable that
    isn't actor.name, otherwise builds a label from finding_info.types[0]
    plus the finding uid suffix.
    """
    obs_list = finding.get("observables") or []
    obs_by_name = _observables_by_name(obs_list)

    # Special-case the well-known target shapes the existing detect skills emit
    finding_info = finding.get("finding_info") or {}

    # K8s priv-esc rules
    if "secret.name" in obs_by_name:
        ns = obs_by_name.get("namespace", "")
        return (
            f"secret/{ns}/{obs_by_name['secret.name']}",
            f"secret · {ns}/{obs_by_name['secret.name']}",
        )
    if "pod.name" in obs_by_name:
        ns = obs_by_name.get("namespace", "")
        return (f"pod/{ns}/{obs_by_name['pod.name']}", f"pod · {ns}/{obs_by_name['pod.name']}")
    if "binding.name" in obs_by_name:
        bt = obs_by_name.get("binding.type", "binding")
        ns = obs_by_name.get("namespace", "")
        ns_part = f"{ns}/" if ns else ""
        return (
            f"{bt}/{ns_part}{obs_by_name['binding.name']}",
            f"{bt[:-1] if bt.endswith('s') else bt} · {ns_part}{obs_by_name['binding.name']}",
        )
    if "target.serviceaccount" in obs_by_name:
        ns = obs_by_name.get("namespace", "")
        return (
            f"sa/{ns}/{obs_by_name['target.serviceaccount']}",
            f"serviceaccount · {ns}/{obs_by_name['target.serviceaccount']}",
        )

    # MCP rules
    if "tool.name" in obs_by_name:
        sess = obs_by_name.get("session.uid", "")
        return (
            f"mcp-tool/{sess}/{obs_by_name['tool.name']}",
            f"mcp tool · {obs_by_name['tool.name']}",
        )

    # Fallback: first non-actor *.name observable
    for obs in obs_list:
        name = obs.get("name", "")
        if name == "actor.name":
            continue
        if name.endswith(".name") or name.endswith(".uid"):
            value = str(obs.get("value", ""))
            return (f"{name}/{value}", f"{name.split('.')[0]} · {value}")

    # Last resort: use the finding type
    types = finding_info.get("types") or []
    label = types[0] if types else "target"
    return (f"target/{label}", label)


def extract_attack(finding: dict[str, Any]) -> tuple[str, str]:
    """Return (technique_uid, technique_name) for the first MITRE attack."""
    attacks = (finding.get("finding_info") or {}).get("attacks") or []
    if not attacks:
        return ("no-mitre", "Unknown")
    a = attacks[0]
    technique = a.get("technique") or {}
    sub = a.get("sub_technique") or {}
    uid = sub.get("uid") or technique.get("uid") or "no-mitre"
    name = sub.get("name") or technique.get("name") or "Unknown technique"
    return (uid, name)


def extract_detector_short(finding: dict[str, Any]) -> str:
    """Return a short detector name for the edge label."""
    feature = ((finding.get("metadata") or {}).get("product") or {}).get("feature") or {}
    name = feature.get("name") or ""
    # Strip detect- / ingest- prefix and -k8s / -aws etc suffix for compactness
    name = name.replace("detect-", "").replace("ingest-", "")
    return name


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


_HEADER = """flowchart LR
    classDef critical fill:#3f1d1d,stroke:#f87171,color:#fecaca
    classDef high     fill:#3a2a0e,stroke:#fb923c,color:#fed7aa
    classDef medium   fill:#3a3a0e,stroke:#fbbf24,color:#fef08a
    classDef low      fill:#1e293b,stroke:#64748b,color:#cbd5e1
"""


def render(findings: Iterable[dict[str, Any]]) -> str:
    """Convert an iterable of OCSF Detection Findings to a Mermaid flowchart string.

    The string is a complete `flowchart LR` block. Wrap it in
    triple-backtick `mermaid` fences if you're embedding into Markdown.
    """
    materialised: list[dict[str, Any]] = []
    for f in findings:
        if f.get("class_uid") == DETECTION_FINDING_CLASS_UID:
            materialised.append(f)
        else:
            print(
                f"[{SKILL_NAME}] skipping event with class_uid={f.get('class_uid')} — only Detection Finding (2004) supported",
                file=sys.stderr,
            )

    if not materialised:
        return _HEADER + '    empty["No findings"]:::low\n'

    # Build node tables (id → display label, id → max severity)
    node_label: dict[str, str] = {}
    node_severity: dict[str, int] = {}
    actor_id_for: dict[str, str] = {}  # raw → mermaid id
    target_id_for: dict[str, str] = {}

    edges: list[tuple[str, str, str, str]] = []  # (actor_id, target_id, edge_label, finding_uid)

    for f in materialised:
        actor_raw = extract_actor(f)
        target_raw, target_label = extract_target(f)
        technique_uid, _technique_name = extract_attack(f)
        detector = extract_detector_short(f)
        severity = int(f.get("severity_id", 0))
        finding_uid = ((f.get("finding_info") or {}).get("uid")) or ""

        if actor_raw not in actor_id_for:
            actor_id_for[actor_raw] = safe_id("A", actor_raw)
        actor_id = actor_id_for[actor_raw]

        if target_raw not in target_id_for:
            target_id_for[target_raw] = safe_id("T", target_raw)
        target_id = target_id_for[target_raw]

        node_label[actor_id] = actor_raw
        node_label[target_id] = target_label
        node_severity[actor_id] = _max_severity(node_severity.get(actor_id, 0), severity)
        node_severity[target_id] = _max_severity(node_severity.get(target_id, 0), severity)

        rule_short = ""
        if detector:
            # Strip cloud / surface suffixes for a compact edge label
            rule_short = detector
        edge_label = f"{technique_uid}"
        if rule_short:
            edge_label = f"{technique_uid} · {rule_short}"
        edges.append((actor_id, target_id, edge_label, finding_uid))

    # Render — deterministic order: actors first (by id), then targets (by id), then edges
    lines: list[str] = [_HEADER]

    actor_ids_sorted = sorted({eid for eid in actor_id_for.values()})
    target_ids_sorted = sorted({tid for tid in target_id_for.values()})

    for nid in actor_ids_sorted:
        cls = severity_class(node_severity.get(nid, 0))
        # Mermaid: NodeId["display label"]:::class
        label = node_label[nid].replace('"', "'")
        lines.append(f'    {nid}["{label}"]:::{cls}')

    for nid in target_ids_sorted:
        cls = severity_class(node_severity.get(nid, 0))
        label = node_label[nid].replace('"', "'")
        lines.append(f'    {nid}["{label}"]:::{cls}')

    lines.append("")  # blank line between nodes and edges
    for actor_id, target_id, edge_label, _uid in edges:
        safe_label = edge_label.replace('"', "'")
        lines.append(f'    {actor_id} -- "{safe_label}" --> {target_id}')

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {e}", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert OCSF Detection Findings to a Mermaid attack flow."
    )
    parser.add_argument("input", nargs="?", help="OCSF JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Mermaid output file. Defaults to stdout.")
    parser.add_argument(
        "--fenced",
        action="store_true",
        help="Wrap output in ```mermaid ... ``` fences for direct Markdown embedding.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        body = render(load_jsonl(in_stream))
        if args.fenced:
            out_stream.write("```mermaid\n")
            out_stream.write(body)
            out_stream.write("```\n")
        else:
            out_stream.write(body)
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
