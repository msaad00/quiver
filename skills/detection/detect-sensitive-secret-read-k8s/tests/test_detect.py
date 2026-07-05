"""Tests for detect-sensitive-secret-read-k8s."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    FINDING_CATEGORY_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_SUB_UID,
    MITRE_TECH_UID,
    READ_VERBS,
    SENSITIVE_NAME_PATTERNS,
    SEVERITY_HIGH,
    SKILL_NAME,
    detect,
    load_jsonl,
    matches_sensitive_pattern,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT_FIXTURE = GOLDEN / "k8s_sensitive_secret_read_sample.ocsf.jsonl"
EXPECTED = GOLDEN / "k8s_sensitive_secret_read_findings.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    verb: str = "get",
    secret_name: str = "aws-access-key",
    namespace: str = "default",
    actor: str = "system:serviceaccount:default:app",
    actor_type: str = "ServiceAccount",
    resource_type: str = "secrets",
    time_ms: int = 1775797200000,
) -> dict:
    return {
        "class_uid": 6003,
        "category_uid": 6,
        "time": time_ms,
        "actor": {"user": {"name": actor, "type": actor_type}},
        "api": {"operation": verb, "service": {"name": "kubernetes"}},
        "resources": [{"type": resource_type, "name": secret_name, "namespace": namespace}],
    }


def _native_event(
    *,
    verb: str = "get",
    secret_name: str = "aws-access-key",
    namespace: str = "default",
    actor: str = "system:serviceaccount:default:app",
    time_ms: int = 1775797200000,
) -> dict:
    return {
        "schema_mode": "native",
        "record_type": "api_activity",
        "provider": "Kubernetes",
        "time_ms": time_ms,
        "actor_name": actor,
        "operation": verb,
        "resources": [{"type": "secrets", "name": secret_name, "namespace": namespace}],
    }


# ── Pattern matching ─────────────────────────────────────────────────


class TestPatternMatching:
    def test_credential_markers(self):
        for name in ("prod-credentials", "db-creds", "user-password", "admin-passwd"):
            assert matches_sensitive_pattern(name, SENSITIVE_NAME_PATTERNS), f"should match: {name}"

    def test_token_patterns(self):
        for name in ("auth-token", "bearer-token", "refresh-token", "github-token"):
            assert matches_sensitive_pattern(name, SENSITIVE_NAME_PATTERNS), f"should match: {name}"

    def test_api_key_patterns(self):
        for name in ("stripe-api-key", "openai-apikey", "internal-api_key"):
            assert matches_sensitive_pattern(name, SENSITIVE_NAME_PATTERNS), f"should match: {name}"

    def test_cloud_credential_patterns(self):
        for name in ("aws-access-key", "gcp-service-account-key", "azure-sp-creds"):
            assert matches_sensitive_pattern(name, SENSITIVE_NAME_PATTERNS), f"should match: {name}"

    def test_dockerconfig(self):
        for name in ("dockerconfigjson", "dockerconfig-prod", "regcred-dockerconfigjson"):
            assert matches_sensitive_pattern(name, SENSITIVE_NAME_PATTERNS), f"should match: {name}"

    def test_private_key_material(self):
        for name in ("server.pem", "signing.key", "root-private-key"):
            assert matches_sensitive_pattern(name, SENSITIVE_NAME_PATTERNS), f"should match: {name}"

    def test_benign_names_skipped(self):
        for name in ("my-app-config", "feature-flags", "locales", "deploy-env", "nginx-conf"):
            assert matches_sensitive_pattern(name, SENSITIVE_NAME_PATTERNS) == [], (
                f"should not match: {name}"
            )

    def test_case_insensitive(self):
        assert matches_sensitive_pattern("AWS-Access-Key", SENSITIVE_NAME_PATTERNS)
        assert matches_sensitive_pattern("STRIPE-API-KEY", SENSITIVE_NAME_PATTERNS)

    def test_multiple_patterns_can_match(self):
        # aws-access-key matches 'aws-*' AND '*aws-access*'
        hits = matches_sensitive_pattern("aws-access-key", SENSITIVE_NAME_PATTERNS)
        assert len(hits) >= 2

    def test_empty_name(self):
        assert matches_sensitive_pattern("", SENSITIVE_NAME_PATTERNS) == []

    def test_custom_patterns_additive(self):
        custom = list(SENSITIVE_NAME_PATTERNS) + ["stripe-*"]
        assert matches_sensitive_pattern("stripe-webhook-secret", custom)
        # The default pattern list already catches '*-secret' so this also matches via default
        assert matches_sensitive_pattern("stripe-webhook-secret", SENSITIVE_NAME_PATTERNS)


# ── Verb filtering ───────────────────────────────────────────────────


class TestVerbFiltering:
    def test_get_fires(self):
        assert len(list(detect([_event(verb="get")]))) == 1

    def test_list_fires_when_name_present(self):
        assert len(list(detect([_event(verb="list")]))) == 1

    def test_watch_does_not_fire(self):
        assert list(detect([_event(verb="watch")])) == []

    def test_create_does_not_fire(self):
        assert list(detect([_event(verb="create")])) == []

    def test_update_does_not_fire(self):
        assert list(detect([_event(verb="update")])) == []

    def test_delete_does_not_fire(self):
        assert list(detect([_event(verb="delete")])) == []

    def test_list_without_specific_name_does_not_fire(self):
        """Enumeration-style list is covered by detect-privilege-escalation-k8s Rule 1."""
        assert list(detect([_event(verb="list", secret_name="")])) == []

    def test_read_verbs_constant_matches_implementation(self):
        assert READ_VERBS == {"get", "list"}


# ── Resource filtering ───────────────────────────────────────────────


class TestResourceFiltering:
    def test_non_secret_resource_does_not_fire(self):
        for rtype in ("configmaps", "pods", "deployments", "services"):
            assert list(detect([_event(resource_type=rtype)])) == []

    def test_missing_resource_does_not_fire(self):
        ev = _event()
        ev["resources"] = []
        assert list(detect([ev])) == []


# ── Finding shape ────────────────────────────────────────────────────


class TestFindingShape:
    def test_class_pinning(self):
        f = list(detect([_event()]))[0]
        assert f["class_uid"] == FINDING_CLASS_UID == 2004
        assert f["category_uid"] == FINDING_CATEGORY_UID == 2
        assert f["type_uid"] == FINDING_TYPE_UID == 200401
        assert f["severity_id"] == SEVERITY_HIGH == 4
        assert f["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert f["metadata"]["version"] == "1.8.0"

    def test_mitre_inside_finding_info(self):
        f = list(detect([_event()]))[0]
        assert "attacks" not in f, "attacks[] must NOT be at event root in OCSF 1.8"
        attacks = f["finding_info"]["attacks"]
        assert len(attacks) == 1
        assert attacks[0]["technique"]["uid"] == MITRE_TECH_UID
        assert attacks[0]["sub_technique"]["uid"] == MITRE_SUB_UID

    def test_observables_have_matched_patterns(self):
        f = list(detect([_event()]))[0]
        obs = {o["name"]: o["value"] for o in f["observables"]}
        assert "matched_patterns" in obs
        assert "aws-" in obs["matched_patterns"] or "*aws-access*" in obs["matched_patterns"]

    def test_deterministic_uid(self):
        events = [_event()]
        a = list(detect(events))[0]["finding_info"]["uid"]
        b = list(detect(events))[0]["finding_info"]["uid"]
        assert a == b
        assert a.startswith("det-k8s-secret-read-")

    def test_native_input_can_emit_native_finding(self):
        findings = list(detect([_native_event()], output_format="native"))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "Kubernetes"
        assert finding["rule_name"] == "k8s-sensitive-secret-read"
        assert "class_uid" not in finding

    def test_native_input_can_emit_ocsf_finding(self):
        findings = list(detect([_native_event()], output_format="ocsf"))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID
        assert finding["finding_info"]["uid"].startswith("det-k8s-secret-read-")


# ── Idempotency / dedup ──────────────────────────────────────────────


class TestIdempotency:
    def test_same_actor_same_secret_deduped(self):
        # Same actor reading the same secret twice → one finding
        events = [
            _event(verb="get", secret_name="aws-access-key", time_ms=1000),
            _event(verb="get", secret_name="aws-access-key", time_ms=2000),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_different_secrets_dedup_independently(self):
        events = [
            _event(verb="get", secret_name="aws-access-key"),
            _event(verb="get", secret_name="gcp-service-account-key"),
        ]
        findings = list(detect(events))
        assert len(findings) == 2

    def test_different_actors_dedup_independently(self):
        events = [
            _event(
                verb="get", secret_name="aws-access-key", actor="system:serviceaccount:default:app1"
            ),
            _event(
                verb="get", secret_name="aws-access-key", actor="system:serviceaccount:default:app2"
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 2


# ── Custom patterns ──────────────────────────────────────────────────


class TestCustomPatterns:
    def test_custom_pattern_extends_defaults(self):
        custom = list(SENSITIVE_NAME_PATTERNS) + ["mfa-seed-*"]
        events = [_event(secret_name="mfa-seed-prod-01")]
        findings = list(detect(events, patterns=custom))
        assert len(findings) == 1

    def test_without_custom_pattern_no_match(self):
        events = [_event(secret_name="mfa-seed-prod-01")]
        # Default patterns don't have "mfa-seed" — no match
        findings = list(detect(events, patterns=SENSITIVE_NAME_PATTERNS))
        assert len(findings) == 0


# ── load_jsonl robustness ────────────────────────────────────────────


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err


# ── Golden fixture parity ────────────────────────────────────────────


class TestGoldenFixture:
    def test_exactly_two_findings_from_fixture(self):
        events = _load_jsonl(INPUT_FIXTURE)
        findings = list(detect(events))
        assert len(findings) == 2, (
            f"Expected 2 findings (aws-access-key + stripe-api-token). Got {len(findings)}. "
            f"my-app-config should be skipped (no sensitive pattern), "
            f"ingress-tls-cert should be skipped (default patterns don't cover mid-name '-tls-'), "
            f"watch verb should be skipped, "
            f"configmaps resource should be skipped."
        )

    def test_deep_eq_against_frozen_golden(self):
        events = _load_jsonl(INPUT_FIXTURE)
        produced = list(detect(events))
        expected = _load_jsonl(EXPECTED)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e, (
                f"finding drift:\n  produced: {json.dumps(p, sort_keys=True)}\n  expected: {json.dumps(e, sort_keys=True)}"
            )

    def test_fixture_fires_on_aws_access_key(self):
        events = _load_jsonl(INPUT_FIXTURE)
        findings = list(detect(events))
        names = set()
        for f in findings:
            obs = {o["name"]: o["value"] for o in f["observables"]}
            names.add(obs["secret.name"])
        assert "aws-access-key" in names

    def test_fixture_fires_on_stripe_token(self):
        events = _load_jsonl(INPUT_FIXTURE)
        findings = list(detect(events))
        names = {{o["name"]: o["value"] for o in f["observables"]}["secret.name"] for f in findings}
        assert "stripe-api-token" in names

    def test_fixture_does_not_fire_on_my_app_config(self):
        events = _load_jsonl(INPUT_FIXTURE)
        findings = list(detect(events))
        names = {{o["name"]: o["value"] for o in f["observables"]}["secret.name"] for f in findings}
        assert "my-app-config" not in names

    def test_fixture_does_not_fire_on_watch_verb(self):
        events = _load_jsonl(INPUT_FIXTURE)
        findings = list(detect(events))
        # The watch event in the fixture is on aws-access-key by SA 'watcher'
        # — if that fired we'd see a second aws-access-key finding from a different actor
        watcher_findings = [
            f
            for f in findings
            if {o["name"]: o["value"] for o in f["observables"]}.get("actor.name")
            == "system:serviceaccount:default:watcher"
        ]
        assert watcher_findings == []
