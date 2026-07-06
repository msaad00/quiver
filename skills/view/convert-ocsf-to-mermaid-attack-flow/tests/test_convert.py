"""Tests for convert-ocsf-to-mermaid-attack-flow."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from convert import (  # type: ignore[import-not-found]
    extract_actor,
    extract_attack,
    extract_target,
    load_jsonl,
    render,
    safe_id,
    severity_class,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT_FIXTURE = GOLDEN / "k8s_priv_esc_findings.ocsf.jsonl"
EXPECTED = GOLDEN / "k8s_priv_esc_attack_flow.mmd"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _finding(
    *,
    uid: str = "det-test-1",
    severity_id: int = 4,
    technique_uid: str = "T1611",
    technique_name: str = "Escape to Host",
    actor: str = "system:serviceaccount:default:builder",
    observables: list[dict] | None = None,
    detector: str = "detect-test",
) -> dict:
    return {
        "class_uid": 2004,
        "category_uid": 2,
        "type_uid": 200401,
        "severity_id": severity_id,
        "status_id": 1,
        "time": 1775797200000,
        "metadata": {
            "version": "1.8.0",
            "product": {
                "name": "cloud-ai-security-skills",
                "feature": {"name": detector},
            },
        },
        "finding_info": {
            "uid": uid,
            "title": "Test",
            "desc": "Test desc",
            "attacks": [
                {
                    "version": "v14",
                    "tactic": {"name": "Privilege Escalation", "uid": "TA0004"},
                    "technique": {"name": technique_name, "uid": technique_uid},
                }
            ],
        },
        "observables": observables
        or [
            {"name": "actor.name", "type": "Other", "value": actor},
            {"name": "pod.name", "type": "Other", "value": "test-pod"},
            {"name": "namespace", "type": "Other", "value": "default"},
        ],
    }


# ── Severity → CSS class ──────────────────────────────────────────────


class TestSeverityClass:
    def test_critical(self):
        assert severity_class(5) == "critical"
        assert severity_class(6) == "critical"

    def test_high(self):
        assert severity_class(4) == "high"

    def test_medium(self):
        assert severity_class(3) == "medium"

    def test_low(self):
        for s in (0, 1, 2):
            assert severity_class(s) == "low"

    def test_unmapped_falls_to_low(self):
        assert severity_class(99) == "low"


# ── safe_id (Mermaid ID safety) ──────────────────────────────────────


class TestSafeId:
    def test_simple_alphanumeric_passes_through(self):
        assert safe_id("A", "alice") == "Aalice"

    def test_special_chars_hashed(self):
        # Mermaid IDs cannot contain colons or slashes
        out = safe_id("A", "system:serviceaccount:default:builder")
        assert out.startswith("A")
        assert ":" not in out
        assert "/" not in out

    def test_deterministic(self):
        a = safe_id("T", "secret/default/db-password")
        b = safe_id("T", "secret/default/db-password")
        assert a == b

    def test_distinct_inputs_distinct_ids(self):
        a = safe_id("T", "secret/default/db-password")
        b = safe_id("T", "secret/default/api-key")
        assert a != b

    def test_long_input_hashed(self):
        long_str = "a" * 100
        out = safe_id("A", long_str)
        # Hashed IDs should be short and stable
        assert len(out) < 20

    def test_id_never_starts_with_digit(self):
        # Mermaid silently breaks on numeric-leading IDs
        out = safe_id("T", "123-numeric-start")
        assert out[0].isalpha()


# ── extract_actor / extract_target / extract_attack ──────────────────


class TestExtractors:
    def test_extract_actor_from_observables(self):
        f = _finding()
        assert extract_actor(f) == "system:serviceaccount:default:builder"

    def test_extract_actor_falls_back_to_session_uid(self):
        f = _finding(observables=[{"name": "session.uid", "type": "Other", "value": "sess-123"}])
        assert extract_actor(f) == "sess-123"

    def test_extract_actor_falls_back_to_uid_prefix(self):
        # Pass observables with no actor.name or session.uid → fall through to uid prefix
        f = _finding(observables=[{"name": "namespace", "type": "Other", "value": "default"}])
        assert extract_actor(f).startswith("actor:det-test")

    def test_extract_target_secret(self):
        f = _finding(
            observables=[
                {"name": "actor.name", "value": "alice"},
                {"name": "secret.name", "value": "db-password"},
                {"name": "namespace", "value": "default"},
            ]
        )
        raw, label = extract_target(f)
        assert "db-password" in raw
        assert "secret · default/db-password" == label

    def test_extract_target_pod(self):
        f = _finding(
            observables=[
                {"name": "actor.name", "value": "alice"},
                {"name": "pod.name", "value": "web-01"},
                {"name": "namespace", "value": "default"},
            ]
        )
        raw, label = extract_target(f)
        assert "web-01" in raw
        assert "pod · default/web-01" == label

    def test_extract_target_clusterrolebinding(self):
        f = _finding(
            observables=[
                {"name": "actor.name", "value": "alice"},
                {"name": "binding.type", "value": "clusterrolebindings"},
                {"name": "binding.name", "value": "attacker-admin"},
            ]
        )
        raw, label = extract_target(f)
        assert "attacker-admin" in raw
        assert "clusterrolebinding" in label

    def test_extract_target_mcp_tool(self):
        f = _finding(
            observables=[
                {"name": "actor.name", "value": "agent-1"},
                {"name": "tool.name", "value": "query_db"},
                {"name": "session.uid", "value": "sess-abc"},
            ]
        )
        raw, label = extract_target(f)
        assert "query_db" in raw
        assert "mcp tool" in label

    def test_extract_attack_with_sub_technique_prefers_sub(self):
        f = _finding()
        f["finding_info"]["attacks"][0]["sub_technique"] = {
            "name": "Container API",
            "uid": "T1552.007",
        }
        uid, _name = extract_attack(f)
        assert uid == "T1552.007"

    def test_extract_attack_no_attacks_returns_unknown(self):
        f = _finding()
        f["finding_info"]["attacks"] = []
        uid, name = extract_attack(f)
        assert uid == "no-mitre"
        assert name == "Unknown"


# ── render() ──────────────────────────────────────────────────────────


class TestRender:
    def test_empty_input_renders_empty_node(self):
        out = render([])
        assert "flowchart LR" in out
        assert "No findings" in out

    def test_skips_non_detection_finding(self, capsys):
        out = render([{"class_uid": 6003, "metadata": {}, "finding_info": {}}])
        assert "No findings" in out
        assert "skipping event with class_uid=6003" in capsys.readouterr().err

    def test_single_finding(self):
        out = render([_finding()])
        assert "flowchart LR" in out
        assert "system:serviceaccount:default:builder" in out
        assert "test-pod" in out
        assert "T1611" in out

    def test_severity_class_in_output(self):
        out = render([_finding(severity_id=5)])  # Critical
        assert ":::critical" in out

    def test_low_severity_class(self):
        out = render([_finding(severity_id=1)])
        assert ":::low" in out

    def test_node_max_severity_wins(self):
        # Same actor in two findings, one critical one medium → actor node should be critical
        f1 = _finding(uid="a", severity_id=3, technique_uid="T1098")
        f2 = _finding(uid="b", severity_id=5, technique_uid="T1611")
        out = render([f1, f2])
        # Find the actor line
        actor_lines = [line for line in out.splitlines() if "system:serviceaccount" in line]
        assert len(actor_lines) == 1
        assert ":::critical" in actor_lines[0]

    def test_three_findings_three_edges(self):
        out = render(
            [
                _finding(uid="a", technique_uid="T1611"),
                _finding(
                    uid="b",
                    technique_uid="T1098",
                    observables=[
                        {"name": "actor.name", "value": "system:serviceaccount:default:builder"},
                        {"name": "binding.type", "value": "clusterrolebindings"},
                        {"name": "binding.name", "value": "cb1"},
                    ],
                ),
                _finding(
                    uid="c",
                    technique_uid="T1552.007",
                    observables=[
                        {"name": "actor.name", "value": "system:serviceaccount:default:builder"},
                        {"name": "secret.name", "value": "s1"},
                        {"name": "namespace", "value": "default"},
                    ],
                ),
            ]
        )
        edges = [line for line in out.splitlines() if "-->" in line]
        assert len(edges) == 3

    def test_edge_label_format(self):
        out = render([_finding(detector="detect-privilege-escalation-k8s")])
        # Edge label should be 'TECHNIQUE · short-detector-name'
        assert '"T1611 · privilege-escalation-k8s"' in out

    def test_no_double_quotes_in_node_labels(self):
        # Mermaid node label syntax uses double quotes — internal " must be escaped/replaced
        f = _finding(actor='alice"injected')
        out = render([f])
        # Single quote replacement keeps Mermaid happy
        assert "alice'injected" in out


# ── load_jsonl robustness ────────────────────────────────────────────


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 2004}']))
        assert out == [{"class_uid": 2004}]
        assert "skipping line 1" in capsys.readouterr().err


# ── Golden fixture parity ────────────────────────────────────────────


class TestGoldenFixture:
    def test_k8s_priv_esc_to_mermaid_matches_frozen(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        produced = render(findings)
        expected = EXPECTED.read_text()
        assert produced == expected, (
            "Mermaid golden drift — re-generate via:\n  python src/convert.py ../golden/k8s_priv_esc_findings.ocsf.jsonl > ../golden/k8s_priv_esc_attack_flow.mmd"
        )

    def test_one_actor_three_targets(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        out = render(findings)
        # Filter to NODE definition lines only (have `]:::class`), skip edges (`-->`)
        node_lines = [line for line in out.splitlines() if "]:::" in line and "-->" not in line]
        actor_node_lines = [line for line in node_lines if line.strip().startswith("A")]
        target_node_lines = [line for line in node_lines if line.strip().startswith("T")]
        assert len(actor_node_lines) == 1, f"expected 1 actor node, got {actor_node_lines}"
        assert len(target_node_lines) == 3, f"expected 3 target nodes, got {target_node_lines}"

    def test_three_mitre_techniques_in_edges(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        out = render(findings)
        for technique in ("T1552.007", "T1611", "T1098"):
            assert technique in out

    def test_actor_is_critical(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        out = render(findings)
        actor_line = next(line for line in out.splitlines() if "system:serviceaccount" in line)
        assert ":::critical" in actor_line
