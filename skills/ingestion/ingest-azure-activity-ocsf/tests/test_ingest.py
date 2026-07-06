"""Tests for ingest-azure-activity-ocsf."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

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
    _extract_subscription_id,
    _service_name_from_operation,
    _status_id_and_detail,
    convert_event,
    convert_event_native,
    infer_activity_id,
    ingest,
    iter_raw_entries,
    parse_ts_ms,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "azure_activity_raw_sample.jsonl"
OCSF_FIXTURE = GOLDEN / "azure_activity_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ── Verb → activity_id ────────────────────────────────────────────────


class TestInferActivity:
    def test_write_is_create(self):
        for n in (
            "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
            "Microsoft.Compute/virtualMachines/write",
            "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
        ):
            assert infer_activity_id(n) == ACTIVITY_CREATE

    def test_read_variants(self):
        for n in (
            "MICROSOFT.COMPUTE/VIRTUALMACHINES/READ",
            "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS",
            "Microsoft.Storage/storageAccounts/list",
        ):
            assert infer_activity_id(n) == ACTIVITY_READ

    def test_action_is_update(self):
        for n in (
            "MICROSOFT.COMPUTE/VIRTUALMACHINES/RESTART/ACTION",
            "MICROSOFT.WEB/SITES/MOVE",
        ):
            assert infer_activity_id(n) == ACTIVITY_UPDATE

    def test_delete_variants(self):
        for n in (
            "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/DELETE",
            "MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE",
            "Microsoft.Storage/storageAccounts/delete",
        ):
            assert infer_activity_id(n) == ACTIVITY_DELETE

    def test_unknown_falls_to_other(self):
        # 'register' and 'sync' aren't in the verb map. Even after walking past
        # generic suffixes there's no recognised verb, so → OTHER.
        for n in (
            "MICROSOFT.RESOURCES/SUBSCRIPTIONS/PROVIDERS/REGISTER",
            "Microsoft.Web/sites/sync/action",
        ):
            assert infer_activity_id(n) == ACTIVITY_OTHER

    def test_action_suffix_walks_to_real_verb(self):
        # The /ACTION suffix is generic — the meaningful verb is the segment before it.
        assert (
            infer_activity_id("MICROSOFT.COMPUTE/VIRTUALMACHINES/RESTART/ACTION") == ACTIVITY_UPDATE
        )
        # listSnapshots starts with 'list' which is in the read map (case-insensitive
        # via .upper()), so this is correctly classified as Read.
        assert infer_activity_id("MICROSOFT.WEB/SITES/LIST/ACTION") == ACTIVITY_READ

    def test_empty(self):
        assert infer_activity_id("") == ACTIVITY_OTHER


# ── Service / resource type extraction ────────────────────────────────


class TestExtractors:
    def test_service_name(self):
        assert (
            _service_name_from_operation("MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE")
            == "microsoft.storage"
        )

    def test_service_name_empty(self):
        assert _service_name_from_operation("") == ""

    def test_subscription_id_extracted(self):
        rid = "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.STORAGE/STORAGEACCOUNTS/STG"
        assert _extract_subscription_id(rid) == "00000000-0000-0000-0000-000000000000"

    def test_subscription_id_missing(self):
        assert _extract_subscription_id("") == ""
        assert _extract_subscription_id("/foo/bar") == ""


# ── Status decoder ────────────────────────────────────────────────────


class TestStatus:
    def test_result_type_success(self):
        sid, detail = _status_id_and_detail({"resultType": "Success"})
        assert sid == STATUS_SUCCESS
        assert detail is None

    def test_result_type_failure(self):
        sid, detail = _status_id_and_detail(
            {"resultType": "Failure", "resultSignature": "Forbidden.AuthorizationFailed"}
        )
        assert sid == STATUS_FAILURE
        assert detail == "Forbidden.AuthorizationFailed"

    def test_status_code_2xx_is_success(self):
        sid, detail = _status_id_and_detail({"properties": {"statusCode": "200"}})
        assert sid == STATUS_SUCCESS

    def test_status_code_4xx_is_failure(self):
        sid, detail = _status_id_and_detail({"properties": {"statusCode": "403"}})
        assert sid == STATUS_FAILURE
        assert detail == "403"

    def test_status_code_named_ok(self):
        sid, _ = _status_id_and_detail({"properties": {"statusCode": "OK"}})
        assert sid == STATUS_SUCCESS

    def test_status_code_named_forbidden(self):
        sid, detail = _status_id_and_detail({"properties": {"statusCode": "Forbidden"}})
        assert sid == STATUS_FAILURE
        assert detail == "Forbidden"

    def test_unknown_when_missing(self):
        sid, _ = _status_id_and_detail({})
        assert sid == STATUS_UNKNOWN


# ── Timestamp ─────────────────────────────────────────────────────────


class TestParseTs:
    def test_iso_z(self):
        assert parse_ts_ms("2026-04-10T05:00:00Z") == 1775797200000

    def test_seven_digit_fractional(self):
        # Azure exports nanosecond-style 7-digit fractional — we trim to 6
        assert parse_ts_ms("2026-04-10T05:00:00.0000000Z") == 1775797200000

    def test_garbage_falls_to_now(self):
        assert parse_ts_ms("not-a-date") > 1_700_000_000_000


# ── convert_event ─────────────────────────────────────────────────────


class TestConvertEvent:
    def _entry(self, **overrides):
        e = {
            "time": "2026-04-10T05:00:00.0000000Z",
            "resourceId": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.STORAGE/STORAGEACCOUNTS/STG",
            "operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
            "category": "Administrative",
            "resultType": "Success",
            "callerIpAddress": "1.2.3.4",
            "correlationId": "corr-1",
            "identity": {
                "claims": {
                    "appid": "11111111-2222-3333-4444-555555555555",
                    "name": "alice",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "alice@example.com",
                }
            },
            "properties": {"statusCode": "OK"},
        }
        e.update(overrides)
        return e

    def test_class_pinning(self):
        e = convert_event(self._entry())
        assert e["class_uid"] == CLASS_UID == 6003
        assert e["category_uid"] == CATEGORY_UID == 6
        assert e["type_uid"] == CLASS_UID * 100 + ACTIVITY_CREATE
        assert e["metadata"]["version"] == OCSF_VERSION
        assert e["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_actor_prefers_upn(self):
        e = convert_event(self._entry())
        assert e["actor"]["user"]["name"] == "alice@example.com"
        assert e["actor"]["user"]["uid"] == "11111111-2222-3333-4444-555555555555"

    def test_actor_service_principal_only(self):
        e = convert_event(
            self._entry(identity={"claims": {"appid": "99999999-8888-7777-6666-555555555555"}})
        )
        assert e["actor"]["user"]["name"] == "99999999-8888-7777-6666-555555555555"
        assert e["actor"]["user"]["type"] == "ServicePrincipal"

    def test_src_endpoint(self):
        e = convert_event(self._entry())
        assert e["src_endpoint"]["ip"] == "1.2.3.4"

    def test_api(self):
        e = convert_event(self._entry())
        assert e["api"]["operation"] == "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
        assert e["api"]["service"]["name"] == "microsoft.storage"
        assert e["api"]["request"]["uid"] == "corr-1"

    def test_cloud(self):
        e = convert_event(self._entry())
        assert e["cloud"]["provider"] == "Azure"
        assert e["cloud"]["account"]["uid"] == "00000000-0000-0000-0000-000000000000"

    def test_resources(self):
        e = convert_event(self._entry())
        assert len(e["resources"]) == 1
        assert e["resources"][0]["type"] == "storageaccounts"

    def test_failure_with_result_signature(self):
        e = convert_event(
            self._entry(resultType="Failure", resultSignature="Forbidden.AuthorizationFailed")
        )
        assert e["status_id"] == STATUS_FAILURE
        assert e["status_detail"] == "Forbidden.AuthorizationFailed"

    def test_native_output_keeps_canonical_fields_without_ocsf_envelope(self):
        e = convert_event_native(self._entry())
        assert e["schema_mode"] == "native"
        assert e["record_type"] == "api_activity"
        assert e["provider"] == "Azure"
        assert e["operation"] == "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
        assert e["event_uid"] == "corr-1"
        assert "class_uid" not in e
        assert "metadata" not in e


# ── Stream wrappers ───────────────────────────────────────────────────


class TestIterRawEntries:
    def test_records_wrapper(self):
        wrapped = {
            "records": [
                {"operationName": "X", "time": "2026-04-10T05:00:00Z"},
                {"operationName": "Y", "time": "2026-04-10T05:01:00Z"},
            ]
        }
        out = list(iter_raw_entries([json.dumps(wrapped)]))
        assert len(out) == 2

    def test_top_level_array(self):
        out = list(iter_raw_entries([json.dumps([{"operationName": "X"}, {"operationName": "Y"}])]))
        assert len(out) == 2

    def test_native_output_mode(self):
        payload = json.dumps(
            {
                "time": "2026-04-10T05:00:00.0000000Z",
                "operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
                "correlationId": "n1",
                "resourceId": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.STORAGE/STORAGEACCOUNTS/STG",
            }
        )
        out = list(ingest([payload], output_format="native"))
        assert len(out) == 1
        first = out[0]
        assert first["schema_mode"] == "native"
        assert first["record_type"] == "api_activity"
        assert "class_uid" not in first


# ── Golden fixture parity ──────────────────────────────────────────────


class TestGoldenFixture:
    def test_event_count(self):
        produced = list(ingest(RAW_FIXTURE.read_text().splitlines()))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert len(produced) == len(expected) == 4

    def test_deep_equality(self):
        produced = list(ingest(RAW_FIXTURE.read_text().splitlines()))
        expected = _load_jsonl(OCSF_FIXTURE)
        for p, e in zip(produced, expected):
            assert p == e, (
                f"event mismatch:\n  produced: {json.dumps(p, sort_keys=True)}\n  expected: {json.dumps(e, sort_keys=True)}"
            )

    def test_fixture_has_failure_with_signature(self):
        events = _load_jsonl(OCSF_FIXTURE)
        failures = [e for e in events if e["status_id"] == STATUS_FAILURE]
        assert len(failures) == 1
        assert "Forbidden.AuthorizationFailed" in failures[0]["status_detail"]
        assert "ROLEASSIGNMENTS/DELETE" in failures[0]["api"]["operation"]
