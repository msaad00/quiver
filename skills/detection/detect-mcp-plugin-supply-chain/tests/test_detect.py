"""Tests for detect-mcp-plugin-supply-chain."""

from __future__ import annotations

import json
from pathlib import Path

import detect as detect_mod  # type: ignore[import-not-found]
from detect import (  # type: ignore[import-not-found]
    FINDING_CATEGORY_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    SEVERITY_HIGH,
    SKILL_NAME,
    _walk_schema_for_urls,
    allowed_hosts,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT_FIXTURE = GOLDEN / "mcp_plugin_supply_chain_input.ocsf.jsonl"
EXPECTED = GOLDEN / "mcp_plugin_supply_chain_findings.ocsf.jsonl"

ALLOWLIST = frozenset({"trusted.allowed.io"})


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _ev(session: str, tool: str, schema: dict, time_ms: int = 100) -> dict:
    return {
        "class_uid": 6002,
        "time": time_ms,
        "mcp": {
            "session_uid": session,
            "method": "tools/list",
            "direction": "response",
            "tool": {"name": tool, "inputSchema": schema},
        },
    }


class TestWalker:
    def test_extracts_ref(self):
        urls = list(_walk_schema_for_urls({"$ref": "https://example.com/x"}))
        assert ("https://example.com/x", "$ref") in urls

    def test_extracts_default_under_items(self):
        urls = list(_walk_schema_for_urls({"items": {"default": "https://example.com/d"}}))
        assert any(u == "https://example.com/d" for u, _ in urls)

    def test_walks_oneof(self):
        schema = {"oneOf": [{"$ref": "https://oneof.example.com/a"}]}
        urls = list(_walk_schema_for_urls(schema))
        assert any("oneof.example.com" in u for u, _ in urls)

    def test_walks_nested_properties(self):
        schema = {"properties": {"x": {"$ref": "https://nested.example.com/x"}}}
        urls = list(_walk_schema_for_urls(schema))
        assert any("nested.example.com" in u for u, _ in urls)

    def test_extracts_url_from_description(self):
        schema = {
            "properties": {"x": {"description": "see https://desc.example.com/d for details"}}
        }
        urls = list(_walk_schema_for_urls(schema))
        assert any("desc.example.com" in u for u, _ in urls)


class TestDetect:
    def test_empty_allowlist_fails_open_no_findings(self, capsys):
        # Make sure the module's "warned once" sentinel is reset so the
        # stderr line is observable.
        detect_mod._warned_empty_allowlist = False
        events = [_ev("s1", "t", {"$ref": "https://evil.example.com/x"})]
        # allowlist=frozenset() explicitly empty
        out = list(detect(events, allowlist=frozenset()))
        assert out == []
        assert "MCP_PLUGIN_ALLOWED_HOSTS is empty" in capsys.readouterr().err

    def test_allowed_host_no_finding(self):
        events = [_ev("s1", "t", {"$ref": "https://trusted.allowed.io/x"})]
        assert list(detect(events, allowlist=ALLOWLIST)) == []

    def test_disallowed_host_fires(self):
        events = [_ev("s1", "t", {"$ref": "https://evil.example.com/x"})]
        findings = list(detect(events, allowlist=ALLOWLIST))
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID
        assert f["category_uid"] == FINDING_CATEGORY_UID
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["severity_id"] == SEVERITY_HIGH
        assert f["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_mitre_attack_populated(self):
        events = [_ev("s1", "t", {"$ref": "https://evil.example.com/x"})]
        finding = list(detect(events, allowlist=ALLOWLIST))[0]
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID

    def test_same_session_same_host_fires_once(self):
        # Two tools both reaching the same disallowed host → one finding.
        events = [
            _ev("s1", "a", {"$ref": "https://evil.example.com/a"}, time_ms=100),
            _ev("s1", "b", {"$ref": "https://evil.example.com/b"}, time_ms=200),
        ]
        assert len(list(detect(events, allowlist=ALLOWLIST))) == 1

    def test_separate_sessions_separate_findings(self):
        events = [
            _ev("s1", "t", {"$ref": "https://evil.example.com/x"}),
            _ev("s2", "t", {"$ref": "https://evil.example.com/x"}, time_ms=200),
        ]
        assert len(list(detect(events, allowlist=ALLOWLIST))) == 2

    def test_wrong_class_ignored(self):
        events = [_ev("s1", "t", {"$ref": "https://evil.example.com/x"})]
        events[0]["class_uid"] = 1234
        assert list(detect(events, allowlist=ALLOWLIST)) == []

    def test_wrong_method_ignored(self):
        events = [_ev("s1", "t", {"$ref": "https://evil.example.com/x"})]
        events[0]["mcp"]["method"] = "tools/call"
        assert list(detect(events, allowlist=ALLOWLIST)) == []

    def test_malformed_schema_handled(self):
        events = [_ev("s1", "t", {"properties": None, "items": "not-a-dict"})]
        assert list(detect(events, allowlist=ALLOWLIST)) == []

    def test_native_output_shape(self):
        events = [_ev("s1", "t", {"$ref": "https://evil.example.com/x"})]
        f = list(detect(events, output_format="native", allowlist=ALLOWLIST))[0]
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert f["schema_mode"] == "native"
        assert "class_uid" not in f

    def test_rejects_unsupported_output_format(self):
        try:
            list(detect([], output_format="bridge"))
        except ValueError as exc:
            assert "unsupported output_format" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestEnvAllowlist:
    def test_env_var_is_parsed(self, monkeypatch):
        monkeypatch.setenv("MCP_PLUGIN_ALLOWED_HOSTS", "a.example.com, b.example.com")
        assert allowed_hosts() == frozenset({"a.example.com", "b.example.com"})


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        lines = ['{"x"', '{"ok":true}']
        assert list(load_jsonl(lines)) == [{"ok": True}]
        assert "skipping line 1" in capsys.readouterr().err


class TestGoldenFixture:
    def test_two_findings_from_fixture(self):
        events = _load(INPUT_FIXTURE)
        findings = list(detect(events, allowlist=ALLOWLIST))
        assert len(findings) == 2

    def test_hosts_correct(self):
        events = _load(INPUT_FIXTURE)
        findings = list(detect(events, allowlist=ALLOWLIST))
        hosts = sorted(f["observables"][2]["value"] for f in findings)
        assert hosts == ["evil-registry.example.com", "malicious-cdn.example.net"]

    def test_finding_matches_frozen_golden(self):
        events = _load(INPUT_FIXTURE)
        produced = list(detect(events, allowlist=ALLOWLIST))
        expected = _load(EXPECTED)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e
