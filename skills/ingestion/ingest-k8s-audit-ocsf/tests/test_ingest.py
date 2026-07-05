"""Tests for ingest-k8s-audit-ocsf."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import ingest as ingest_module  # type: ignore[import-not-found]
from ingest import (  # type: ignore[import-not-found]
    ACTIVITY_CREATE,
    ACTIVITY_DELETE,
    ACTIVITY_OTHER,
    ACTIVITY_READ,
    ACTIVITY_UPDATE,
    CATEGORY_UID,
    CLASS_UID,
    OCSF_VERSION,
    SKILL_NAME,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    STATUS_UNKNOWN,
    _status_id_and_detail,
    convert_event,
    convert_event_native,
    infer_activity_id,
    ingest,
    is_service_account,
    service_account_namespace,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "k8s_audit_raw_sample.jsonl"
OCSF_FIXTURE = GOLDEN / "k8s_audit_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ── Verb → activity_id ────────────────────────────────────────────────


class TestInferActivity:
    def test_create(self):
        assert infer_activity_id("create") == ACTIVITY_CREATE

    def test_reads(self):
        for v in ("get", "list", "watch", "proxy"):
            assert infer_activity_id(v) == ACTIVITY_READ

    def test_updates(self):
        for v in ("update", "patch"):
            assert infer_activity_id(v) == ACTIVITY_UPDATE

    def test_deletes(self):
        for v in ("delete", "deletecollection"):
            assert infer_activity_id(v) == ACTIVITY_DELETE

    def test_unknown_verb(self):
        for v in ("connect", "bind", "custom-verb", ""):
            assert infer_activity_id(v) == ACTIVITY_OTHER

    def test_case_insensitive(self):
        assert infer_activity_id("CREATE") == ACTIVITY_CREATE
        assert infer_activity_id("Get") == ACTIVITY_READ


# ── Service account helpers ───────────────────────────────────────────


class TestServiceAccount:
    def test_is_service_account(self):
        assert is_service_account("system:serviceaccount:default:builder")
        assert is_service_account("system:serviceaccount:kube-system:coredns")

    def test_is_not_service_account(self):
        assert not is_service_account("kube-admin")
        assert not is_service_account("system:anonymous")
        assert not is_service_account("")

    def test_namespace_extraction(self):
        assert service_account_namespace("system:serviceaccount:default:builder") == "default"
        assert (
            service_account_namespace("system:serviceaccount:kube-system:coredns") == "kube-system"
        )

    def test_namespace_non_sa(self):
        assert service_account_namespace("kube-admin") is None
        assert service_account_namespace("") is None


# ── Status decoder ────────────────────────────────────────────────────


class TestStatus:
    def test_2xx_success(self):
        for c in (200, 201, 204):
            sid, detail = _status_id_and_detail({"code": c})
            assert sid == STATUS_SUCCESS
            assert detail is None

    def test_4xx_failure(self):
        sid, detail = _status_id_and_detail(
            {"code": 403, "reason": "Forbidden", "message": "denied"}
        )
        assert sid == STATUS_FAILURE
        assert "Forbidden" in detail
        assert "denied" in detail

    def test_5xx_failure(self):
        sid, detail = _status_id_and_detail({"code": 500, "reason": "InternalError"})
        assert sid == STATUS_FAILURE
        assert "InternalError" in detail

    def test_missing_code_is_unknown(self):
        sid, detail = _status_id_and_detail({})
        assert sid == STATUS_UNKNOWN

    def test_none_is_unknown(self):
        sid, detail = _status_id_and_detail(None)
        assert sid == STATUS_UNKNOWN

    def test_non_numeric_code_is_unknown(self):
        sid, detail = _status_id_and_detail({"code": "nope"})
        assert sid == STATUS_UNKNOWN


# ── convert_event ─────────────────────────────────────────────────────


class TestConvertEvent:
    def _event(self, **overrides):
        e = {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "level": "RequestResponse",
            "auditID": "a-123",
            "stage": "ResponseComplete",
            "requestURI": "/api/v1/namespaces/default/secrets",
            "verb": "list",
            "user": {
                "username": "system:serviceaccount:default:builder",
                "groups": ["system:serviceaccounts", "system:authenticated"],
            },
            "sourceIPs": ["10.0.0.42"],
            "userAgent": "kubectl/v1.28",
            "objectRef": {"resource": "secrets", "namespace": "default", "apiVersion": "v1"},
            "responseStatus": {"code": 200},
            "requestReceivedTimestamp": "2026-04-10T05:00:00Z",
            "annotations": {"authorization.k8s.io/decision": "allow"},
        }
        e.update(overrides)
        return e

    def test_wrong_kind_returns_none(self):
        assert convert_event(self._event(kind="Pod")) is None

    def test_wrong_api_version_returns_none(self):
        assert convert_event(self._event(apiVersion="audit.k8s.io/v1beta1")) is None

    def test_request_received_stage_skipped(self):
        assert convert_event(self._event(stage="RequestReceived")) is None

    def test_response_complete_processed(self):
        assert convert_event(self._event()) is not None

    def test_panic_stage_processed(self):
        assert convert_event(self._event(stage="Panic", responseStatus={"code": 500})) is not None

    def test_class_pinning(self):
        e = convert_event(self._event())
        assert e["class_uid"] == CLASS_UID == 6003
        assert e["category_uid"] == CATEGORY_UID == 6
        assert e["type_uid"] == CLASS_UID * 100 + ACTIVITY_READ
        assert e["metadata"]["version"] == OCSF_VERSION
        assert e["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_actor_service_account_type(self):
        e = convert_event(self._event())
        assert e["actor"]["user"]["type"] == "ServiceAccount"
        assert e["actor"]["user"]["name"] == "system:serviceaccount:default:builder"

    def test_actor_groups_projected(self):
        e = convert_event(self._event())
        group_names = {g["name"] for g in e["actor"]["user"]["groups"]}
        assert "system:serviceaccounts" in group_names
        assert "system:authenticated" in group_names

    def test_non_service_account_no_type(self):
        e = convert_event(
            self._event(user={"username": "kube-admin", "groups": ["system:masters"]})
        )
        assert e["actor"]["user"]["name"] == "kube-admin"
        assert "type" not in e["actor"]["user"]

    def test_resources_with_subresource(self):
        e = convert_event(
            self._event(
                verb="create",
                objectRef={
                    "resource": "pods",
                    "namespace": "default",
                    "name": "web-01",
                    "apiVersion": "v1",
                    "subresource": "exec",
                },
            )
        )
        r = e["resources"][0]
        assert r["type"] == "pods"
        assert r["subresource"] == "exec"
        assert r["name"] == "web-01"
        assert r["namespace"] == "default"

    def test_resources_with_api_group(self):
        e = convert_event(
            self._event(
                verb="create",
                objectRef={
                    "resource": "clusterrolebindings",
                    "name": "cb-1",
                    "apiGroup": "rbac.authorization.k8s.io",
                    "apiVersion": "v1",
                },
            )
        )
        r = e["resources"][0]
        assert r["group"] == "rbac.authorization.k8s.io"
        assert "namespace" not in r  # cluster-scoped

    def test_k8s_namespace_marker_for_sa(self):
        e = convert_event(self._event())
        assert e["k8s"]["service_account_namespace"] == "default"

    def test_no_k8s_marker_for_human_user(self):
        e = convert_event(self._event(user={"username": "kube-admin"}))
        assert "k8s" not in e

    def test_authz_label_allow(self):
        e = convert_event(self._event())
        assert "authz-allow" in e["metadata"]["labels"]

    def test_authz_label_deny(self):
        e = convert_event(self._event(annotations={"authorization.k8s.io/decision": "forbid"}))
        assert "authz-deny" in e["metadata"]["labels"]

    def test_native_output_keeps_canonical_fields_without_ocsf_envelope(self):
        e = convert_event_native(self._event())
        assert e["schema_mode"] == "native"
        assert e["record_type"] == "api_activity"
        assert e["provider"] == "Kubernetes"
        assert e["service_name"] == "kubernetes"
        assert e["output_format"] == "native"
        assert "class_uid" not in e
        assert "metadata" not in e

    def test_unmapped_round_trips_request_response_and_object_ref_in_ocsf(self):
        raw = self._event(
            verb="patch",
            objectRef={
                "resource": "pods",
                "namespace": "default",
                "name": "web-01",
                "apiVersion": "v1",
            },
            requestObject={
                "spec": {
                    "containers": [
                        {
                            "name": "web",
                            "securityContext": {"privileged": True},
                        }
                    ]
                }
            },
            responseObject={
                "metadata": {"name": "web-01"},
                "spec": {
                    "hostPID": True,
                },
            },
        )
        e = convert_event(raw)
        assert e["unmapped"]["k8s"]["request_object"] == raw["requestObject"]
        assert e["unmapped"]["k8s"]["response_object"] == raw["responseObject"]
        assert e["unmapped"]["k8s"]["object_ref"] == raw["objectRef"]

    def test_unmapped_round_trips_request_response_and_object_ref_in_native(self):
        raw = self._event(
            verb="patch",
            objectRef={
                "resource": "pods",
                "namespace": "default",
                "name": "web-01",
                "apiVersion": "v1",
            },
            requestObject={"spec": {"hostNetwork": True}},
            responseObject={"spec": {"ephemeralContainers": [{"name": "debugger"}]}},
        )
        e = convert_event_native(raw)
        assert e["unmapped"]["k8s"]["request_object"] == raw["requestObject"]
        assert e["unmapped"]["k8s"]["response_object"] == raw["responseObject"]
        assert e["unmapped"]["k8s"]["object_ref"] == raw["objectRef"]


# ── Golden fixture parity ──────────────────────────────────────────────


class TestGoldenFixture:
    def test_event_count_filters_early_stages(self):
        # Fixture has 6 entries but 1 is RequestReceived (must be skipped)
        produced = list(ingest(RAW_FIXTURE.read_text().splitlines()))
        assert len(produced) == 5

    def test_native_output_mode_emits_enriched_events(self):
        produced = list(ingest(RAW_FIXTURE.read_text().splitlines(), output_format="native"))
        assert len(produced) == 5
        first = produced[0]
        assert first["schema_mode"] == "native"
        assert first["record_type"] == "api_activity"
        assert "class_uid" not in first
        assert "metadata" not in first

    def test_deep_equality(self):
        produced = list(ingest(RAW_FIXTURE.read_text().splitlines()))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e, (
                f"event mismatch:\n  produced: {json.dumps(p, sort_keys=True)}\n  expected: {json.dumps(e, sort_keys=True)}"
            )

    def test_fixture_captures_priv_esc_chain(self):
        """The fixture is designed to be a minimum viable priv-esc chain:
        list secrets → get secret → exec pod → create clusterrolebinding → denied delete.
        """
        events = _load_jsonl(OCSF_FIXTURE)
        verbs_and_resources = [
            (e["api"]["operation"], (e["resources"] or [{}])[0].get("type")) for e in events
        ]
        assert ("list", "secrets") in verbs_and_resources
        assert ("get", "secrets") in verbs_and_resources
        assert ("create", "pods") in verbs_and_resources
        assert ("create", "clusterrolebindings") in verbs_and_resources
        assert ("delete", "deployments") in verbs_and_resources

    def test_fixture_has_one_forbidden(self):
        events = _load_jsonl(OCSF_FIXTURE)
        failures = [e for e in events if e["status_id"] == STATUS_FAILURE]
        assert len(failures) == 1
        assert failures[0]["api"]["operation"] == "delete"
        assert "Forbidden" in failures[0]["status_detail"]

    def test_fixture_all_events_from_same_sa(self):
        events = _load_jsonl(OCSF_FIXTURE)
        actors = {e["actor"]["user"]["name"] for e in events}
        assert actors == {"system:serviceaccount:default:builder"}


class TestStderrTelemetry:
    def test_skips_malformed_with_json_stderr(self, capsys, monkeypatch):
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        out = list(ingest_module.iter_raw_entries(['{"bad": ', '{"kind": "Event"}']))
        assert len(out) == 1
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["skill"] == SKILL_NAME
        assert payload["level"] == "warning"
        assert payload["event"] == "json_parse_failed"
        assert payload["line"] == 1

    def test_mixed_batch_keeps_valid_events(self, capsys, monkeypatch):
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        read_event = {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "stage": "ResponseComplete",
            "auditID": "k8s-read",
            "verb": "list",
            "user": {"username": "system:serviceaccount:default:builder"},
            "objectRef": {"resource": "secrets", "namespace": "default"},
            "responseStatus": {"code": 200},
            "requestReceivedTimestamp": "2026-04-10T05:00:00Z",
        }
        delete_event = {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "stage": "ResponseComplete",
            "auditID": "k8s-delete",
            "verb": "delete",
            "user": {"username": "system:serviceaccount:default:builder"},
            "objectRef": {"resource": "deployments", "namespace": "default"},
            "responseStatus": {"code": 403, "reason": "Forbidden"},
            "requestReceivedTimestamp": "2026-04-10T05:01:00Z",
        }
        out = list(ingest([json.dumps(read_event), '{"bad": ', "[]", json.dumps(delete_event)]))
        assert len(out) == 2
        assert [event["metadata"]["uid"] for event in out] == ["k8s-read", "k8s-delete"]
        stderr_lines = [
            json.loads(line) for line in capsys.readouterr().err.splitlines() if line.strip()
        ]
        assert [payload["event"] for payload in stderr_lines] == [
            "json_parse_failed",
            "invalid_json_shape",
        ]
        assert [payload["line"] for payload in stderr_lines] == [2, 3]
