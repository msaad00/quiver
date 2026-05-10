"""Tests for ingest-okta-system-log-ocsf."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_okta_system_log", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _INGEST
_SPEC.loader.exec_module(_INGEST)

ACCOUNT_CHANGE_CLASS_UID = _INGEST.ACCOUNT_CHANGE_CLASS_UID
ACCOUNT_CHANGE_DISABLE = _INGEST.ACCOUNT_CHANGE_DISABLE
ACCOUNT_CHANGE_LOCK = _INGEST.ACCOUNT_CHANGE_LOCK
ACCOUNT_CHANGE_MFA_ENABLE = _INGEST.ACCOUNT_CHANGE_MFA_ENABLE
ACCOUNT_CHANGE_PASSWORD_CHANGE = _INGEST.ACCOUNT_CHANGE_PASSWORD_CHANGE
AUTH_ACTIVITY_LOGOFF = _INGEST.AUTH_ACTIVITY_LOGOFF
AUTH_ACTIVITY_LOGON = _INGEST.AUTH_ACTIVITY_LOGON
AUTH_ACTIVITY_OTHER = _INGEST.AUTH_ACTIVITY_OTHER
AUTH_CLASS_UID = _INGEST.AUTH_CLASS_UID
CANONICAL_VERSION = _INGEST.CANONICAL_VERSION
OCSF_VERSION = _INGEST.OCSF_VERSION
OUTPUT_FORMATS = _INGEST.OUTPUT_FORMATS
SKILL_NAME = _INGEST.SKILL_NAME
STATUS_FAILURE = _INGEST.STATUS_FAILURE
STATUS_SUCCESS = _INGEST.STATUS_SUCCESS
USER_ACCESS_ASSIGN = _INGEST.USER_ACCESS_ASSIGN
USER_ACCESS_CLASS_UID = _INGEST.USER_ACCESS_CLASS_UID
USER_ACCESS_REVOKE = _INGEST.USER_ACCESS_REVOKE
_classify_event = _INGEST._classify_event
convert_event = _INGEST.convert_event
ingest = _INGEST.ingest
iter_raw_events = _INGEST.iter_raw_events
parse_ts_ms = _INGEST.parse_ts_ms
severity_to_id = _INGEST.severity_to_id
status_from_outcome = _INGEST.status_from_outcome
validate_event = _INGEST.validate_event

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "okta_system_log_raw_sample.json"
OCSF_FIXTURE = GOLDEN / "okta_system_log_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(**overrides) -> dict:
    event = {
        "uuid": "okta-evt-1",
        "published": "2026-04-13T02:15:00.000Z",
        "eventType": "user.session.start",
        "displayMessage": "User signs in to Okta",
        "severity": "INFO",
        "actor": {
            "id": "00u-user-admin",
            "type": "User",
            "alternateId": "admin@example.com",
            "displayName": "Admin User",
        },
        "client": {
            "ipAddress": "198.51.100.10",
            "userAgent": {
                "rawUserAgent": "Mozilla/5.0",
            },
        },
        "authenticationContext": {
            "externalSessionId": "sess-123",
            "rootSessionId": "root-123",
        },
        "outcome": {"result": "SUCCESS", "reason": None},
        "transaction": {"id": "txn-123"},
        "target": [
            {
                "id": "00u-target",
                "type": "User",
                "alternateId": "alice@example.com",
                "displayName": "Alice Example",
                "detailEntry": None,
            }
        ],
    }
    event.update(overrides)
    return event


class TestParseTs:
    def test_iso_z(self):
        assert parse_ts_ms("2026-04-13T02:15:00.000Z") == 1776046500000

    def test_missing_falls_to_now(self):
        ms = parse_ts_ms(None)
        assert isinstance(ms, int) and ms > 1_700_000_000_000


class TestSeverityAndStatus:
    def test_severity_mapping(self):
        assert severity_to_id("INFO") == 1
        assert severity_to_id("WARN") == 2
        assert severity_to_id("ERROR") == 4

    def test_status_success(self):
        status_id, detail = status_from_outcome({"result": "SUCCESS"})
        assert status_id == STATUS_SUCCESS
        assert detail is None

    def test_status_failure(self):
        status_id, detail = status_from_outcome({"result": "FAILURE", "reason": "INVALID_CREDENTIALS"})
        assert status_id == STATUS_FAILURE
        assert detail == "INVALID_CREDENTIALS"


class TestClassification:
    def test_authentication_routes(self):
        assert _classify_event("user.session.start") == (AUTH_CLASS_UID, "Authentication", AUTH_ACTIVITY_LOGON)
        assert _classify_event("user.session.end") == (AUTH_CLASS_UID, "Authentication", AUTH_ACTIVITY_LOGOFF)
        assert _classify_event("user.authentication.auth_via_mfa") == (
            AUTH_CLASS_UID,
            "Authentication",
            AUTH_ACTIVITY_OTHER,
        )
        assert _classify_event("user.mfa.okta_verify.deny_push") == (
            AUTH_CLASS_UID,
            "Authentication",
            AUTH_ACTIVITY_OTHER,
        )
        assert _classify_event("system.push.send_factor_verify_push") == (
            AUTH_CLASS_UID,
            "Authentication",
            AUTH_ACTIVITY_OTHER,
        )

    def test_account_change_routes(self):
        assert _classify_event("user.lifecycle.deactivate") == (
            ACCOUNT_CHANGE_CLASS_UID,
            "Account Change",
            ACCOUNT_CHANGE_DISABLE,
        )
        assert _classify_event("user.account.update_password") == (
            ACCOUNT_CHANGE_CLASS_UID,
            "Account Change",
            ACCOUNT_CHANGE_PASSWORD_CHANGE,
        )
        assert _classify_event("user.account.lock") == (
            ACCOUNT_CHANGE_CLASS_UID,
            "Account Change",
            ACCOUNT_CHANGE_LOCK,
        )
        assert _classify_event("user.mfa.factor.activate") == (
            ACCOUNT_CHANGE_CLASS_UID,
            "Account Change",
            ACCOUNT_CHANGE_MFA_ENABLE,
        )

    def test_user_access_routes(self):
        assert _classify_event("application.user_membership.add") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_ASSIGN,
        )
        assert _classify_event("group.user_membership.remove") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_REVOKE,
        )


class TestValidation:
    def test_valid_event(self):
        ok, reason = validate_event(_event())
        assert ok, reason

    def test_unsupported_event(self):
        ok, reason = validate_event(_event(eventType="system.unknown"))
        assert not ok
        assert "unsupported eventType" in reason


class TestConvert:
    def test_authentication_event(self):
        event = convert_event(_event())
        assert event["class_uid"] == AUTH_CLASS_UID
        assert event["activity_id"] == AUTH_ACTIVITY_LOGON
        assert event["metadata"]["uid"] == "okta-evt-1"
        assert event["metadata"]["version"] == OCSF_VERSION
        assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert event["user"]["email_addr"] == "alice@example.com"
        assert event["actor"]["user"]["email_addr"] == "admin@example.com"
        assert event["session"]["uid"] == "sess-123"
        assert event["src_endpoint"]["ip"] == "198.51.100.10"

    def test_native_projection_strips_ocsf_envelope(self):
        event = convert_event(_event(), output_format="native")
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert event["schema_mode"] == "native"
        assert event["canonical_schema_version"] == CANONICAL_VERSION
        assert event["record_type"] == "authentication"
        assert event["event_uid"] == "okta-evt-1"
        assert event["provider"] == "Okta"
        assert event["event_type"] == "user.session.start"
        assert "class_uid" not in event
        assert "metadata" not in event

    def test_authentication_failure_without_session(self):
        event = convert_event(
            _event(
                uuid="okta-evt-2",
                outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
                authenticationContext={},
            )
        )
        assert event["status_id"] == STATUS_FAILURE
        assert event["status_detail"] == "INVALID_CREDENTIALS"
        assert "session" not in event

    def test_okta_verify_push_send_event(self):
        event = convert_event(
            _event(
                uuid="okta-evt-push-1",
                eventType="system.push.send_factor_verify_push",
                displayMessage="Push notification sent for verification",
                target=[
                    {
                        "id": "00u-target",
                        "type": "User",
                        "alternateId": "alice@example.com",
                        "displayName": "Alice Example",
                        "detailEntry": None,
                    },
                    {
                        "id": "opf-factor",
                        "type": "AuthenticatorEnrollment",
                        "alternateId": "okta_verify",
                        "displayName": "Okta Verify",
                        "detailEntry": "okta_verify",
                    },
                ],
            )
        )
        assert event["class_uid"] == AUTH_CLASS_UID
        assert event["activity_id"] == AUTH_ACTIVITY_OTHER
        assert event["resources"][0]["name"] == "Okta Verify"
        assert event["service"]["name"] == "Okta Verify"

    def test_okta_verify_deny_event(self):
        event = convert_event(
            _event(
                uuid="okta-evt-deny-1",
                eventType="user.mfa.okta_verify.deny_push",
                displayMessage="User rejected Okta push verify",
                outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
                target=[
                    {
                        "id": "00u-target",
                        "type": "User",
                        "alternateId": "alice@example.com",
                        "displayName": "Alice Example",
                        "detailEntry": None,
                    },
                    {
                        "id": "opf-factor",
                        "type": "AuthenticatorEnrollment",
                        "alternateId": "okta_verify",
                        "displayName": "Okta Verify",
                        "detailEntry": "okta_verify",
                    },
                ],
            )
        )
        assert event["class_uid"] == AUTH_CLASS_UID
        assert event["activity_id"] == AUTH_ACTIVITY_OTHER
        assert event["status_id"] == STATUS_FAILURE
        assert event["status_detail"] == "INVALID_CREDENTIALS"

    def test_account_change_event(self):
        event = convert_event(
            _event(
                uuid="okta-evt-3",
                eventType="user.lifecycle.deactivate",
                displayMessage="Deactivate Okta User",
            )
        )
        assert event["class_uid"] == ACCOUNT_CHANGE_CLASS_UID
        assert event["activity_id"] == ACCOUNT_CHANGE_DISABLE
        assert event["user"]["name"] == "alice@example.com"

    def test_user_access_event(self):
        event = convert_event(
            _event(
                uuid="okta-evt-4",
                eventType="application.user_membership.add",
                displayMessage="Add user to app membership",
                target=[
                    {
                        "id": "00u-target",
                        "type": "User",
                        "alternateId": "alice@example.com",
                        "displayName": "Alice Example",
                        "detailEntry": None,
                    },
                    {
                        "id": "0oa-app",
                        "type": "AppInstance",
                        "alternateId": "salesforce",
                        "displayName": "Salesforce",
                        "detailEntry": None,
                    },
                ],
            )
        )
        assert event["class_uid"] == USER_ACCESS_CLASS_UID
        assert event["activity_id"] == USER_ACCESS_ASSIGN
        assert event["privileges"] == ["Salesforce"]
        assert event["resources"] == [{"name": "Salesforce", "type": "AppInstance"}]


class TestIterRawEvents:
    def test_array(self):
        events = list(iter_raw_events([json.dumps([_event(uuid="a"), _event(uuid="b")])]))
        assert [event["uuid"] for event in events] == ["a", "b"]

    def test_event_hook_wrapper(self):
        wrapped = {"data": {"events": [_event(uuid="hook-1"), _event(uuid="hook-2")]}}
        events = list(iter_raw_events([json.dumps(wrapped)]))
        assert [event["uuid"] for event in events] == ["hook-1", "hook-2"]

    def test_ndjson_and_bad_line(self, capsys):
        events = list(iter_raw_events(['{"uuid":"ok","published":"2026-04-13T02:15:00.000Z","eventType":"user.session.start"}', '{"bad"']))
        assert len(events) == 1
        assert events[0]["uuid"] == "ok"
        assert "skipping line" in capsys.readouterr().err

    def test_json_stderr_telemetry_for_bad_line(self, capsys, monkeypatch):
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        list(iter_raw_events(['{"bad"']))
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["skill"] == SKILL_NAME
        assert payload["level"] == "warning"
        assert payload["event"] == "json_parse_failed"
        assert payload["line"] == 1

    def test_mixed_batch_keeps_valid_events(self, capsys, monkeypatch):
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        out = list(ingest([json.dumps(_event(uuid="okta-good-1")), '{"bad"', "[]", json.dumps(_event(uuid="okta-good-2"))]))
        assert [event["metadata"]["uid"] for event in out] == ["okta-good-1", "okta-good-2"]
        stderr_lines = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line.strip()]
        assert [payload["event"] for payload in stderr_lines] == ["json_parse_failed", "invalid_json_shape"]
        assert [payload["line"] for payload in stderr_lines] == [2, 3]


def _rich_event(**overrides) -> dict:
    """Event populating every #271 mapping slot for targeted tests."""
    event = {
        "uuid": "okta-rich-1",
        "published": "2026-04-13T02:22:00.000Z",
        "eventType": "user.session.start",
        "displayMessage": "User signs in to Okta",
        "severity": "WARN",
        "actor": {
            "id": "00u-rich-1",
            "type": "User",
            "alternateId": "henry@example.com",
            "displayName": "Henry Example",
            "detailEntry": "actor-detail",
        },
        "client": {
            "id": "cli-device-abc",
            "device": "Computer",
            "zone": "corp-perimeter",
            "ipAddress": "203.0.113.50",
            "userAgent": {
                "rawUserAgent": "Mozilla/5.0",
                "browser": "CHROME",
                "os": "Mac OS X",
            },
            "geographicalContext": {
                "country": "Russia",
                "state": "Moscow",
                "city": "Moscow",
                "postalCode": "101000",
                "geolocation": {"lat": 55.7558, "lon": 37.6173},
            },
        },
        "securityContext": {
            "asNumber": 13335,
            "asOrg": "Cloudflare, Inc.",
            "isp": "cloudflare",
            "domain": "cloudflare.com",
            "isProxy": True,
        },
        "authenticationContext": {
            "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
            "credentialType": "PASSWORD",
            "interface": "Okta FastPass",
            "authenticationStep": 0,
            "externalSessionId": "sess-rich-1",
            "rootSessionId": "root-rich-1",
            "issuer": {"id": "idp-okta", "type": "OKTA"},
        },
        "debugContext": {
            "debugData": {
                "riskLevel": "HIGH",
                "riskReasons": "newCountry, anomalousLocation",
                "behaviors": {"New Geo-Location": "POSITIVE"},
                "deviceFingerprint": "fp-xyz",
                "factorId": "opf-factor",
            }
        },
        "request": {
            "ipChain": [
                {
                    "ip": "203.0.113.50",
                    "geographicalContext": {"country": "Russia", "city": "Moscow"},
                    "source": "ATTACKER",
                },
                {
                    "ip": "198.51.100.7",
                    "geographicalContext": {"country": "United States", "city": "Ashburn"},
                    "source": "PROXY",
                },
            ]
        },
        "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
        "transaction": {
            "id": "txn-rich-1",
            "type": "WEB",
            "detail": {"requestApiTokenId": "api-xyz"},
        },
        "target": [
            {
                "id": "00u-rich-1",
                "type": "User",
                "alternateId": "henry@example.com",
                "displayName": "Henry Example",
                "detailEntry": "target-detail",
            }
        ],
    }
    event.update(overrides)
    return event


class TestExpandedMapping:
    """#271 — OCSF-native slots for geo, AS, device, UA, risk, ipChain; unmapped.debug_data round-trip."""

    def test_src_endpoint_location_from_geo(self):
        event = convert_event(_rich_event())
        loc = event["src_endpoint"]["location"]
        assert loc["country"] == "Russia"
        assert loc["region"] == "Moscow"
        assert loc["city"] == "Moscow"
        assert loc["postal_code"] == "101000"
        # OCSF convention: [longitude, latitude]
        assert loc["coordinates"] == [37.6173, 55.7558]

    def test_src_endpoint_autonomous_system(self):
        event = convert_event(_rich_event())
        assert event["src_endpoint"]["autonomous_system"] == {"number": 13335, "name": "Cloudflare, Inc."}

    def test_src_endpoint_is_proxy_and_domain_and_zone(self):
        event = convert_event(_rich_event())
        assert event["src_endpoint"]["is_proxy"] is True
        assert event["src_endpoint"]["domain"] == "cloudflare.com"
        assert event["src_endpoint"]["zone"] == "corp-perimeter"

    def test_device_and_http_request(self):
        event = convert_event(_rich_event())
        assert event["device"] == {"uid": "cli-device-abc", "name": "Computer", "os": {"name": "Mac OS X"}}
        assert event["http_request"] == {"user_agent": "Mozilla/5.0"}

    def test_auth_protocol_and_factors(self):
        event = convert_event(_rich_event())
        assert event["auth_protocol"] == "OKTA_AUTHENTICATION_PROVIDER"
        assert event["auth_factors"] == ["PASSWORD"]

    def test_metadata_labels_include_interface_and_step(self):
        event = convert_event(_rich_event())
        labels = event["metadata"]["labels"]
        assert "okta.interface=Okta FastPass" in labels
        assert "okta.authentication_step=0" in labels

    def test_observables_from_ip_chain_with_per_hop_geo(self):
        event = convert_event(_rich_event())
        observables = event["observables"]
        assert len(observables) == 2
        assert observables[0]["value"] == "203.0.113.50"
        assert observables[0]["type"] == "IP Address"
        assert observables[0]["type_id"] == 2
        assert observables[0]["location"]["country"] == "Russia"
        assert observables[1]["value"] == "198.51.100.7"
        assert observables[1]["location"]["city"] == "Ashburn"

    def test_enrichments_include_risk_level_and_reasons(self):
        event = convert_event(_rich_event())
        enrichments = event["enrichments"]
        by_name = {entry["name"]: entry for entry in enrichments}
        assert by_name["okta.risk_level"]["value"] == "HIGH"
        assert by_name["okta.risk_reasons"]["data"]["reasons"] == ["newCountry", "anomalousLocation"]
        assert by_name["okta.behaviors"]["data"]["behaviors"] == {"New Geo-Location": "POSITIVE"}

    def test_risk_reasons_accepts_list_shape(self):
        raw = _rich_event()
        raw["debugContext"]["debugData"]["riskReasons"] = ["newCountry", "tor"]
        event = convert_event(raw)
        by_name = {entry["name"]: entry for entry in event["enrichments"]}
        assert by_name["okta.risk_reasons"]["data"]["reasons"] == ["newCountry", "tor"]

    def test_unmapped_debug_data_round_trips_verbatim(self):
        raw = _rich_event()
        event = convert_event(raw)
        assert event["unmapped"]["okta"]["debug_data"] == raw["debugContext"]["debugData"]

    def test_unmapped_preserves_detail_entries_and_transaction(self):
        event = convert_event(_rich_event())
        unmapped = event["unmapped"]["okta"]
        assert unmapped["actor_detail_entry"] == "actor-detail"
        assert unmapped["target_detail_entries"] == [
            {"id": "00u-rich-1", "detail_entry": "target-detail"}
        ]
        assert unmapped["transaction_type"] == "WEB"
        assert unmapped["transaction_detail"] == {"requestApiTokenId": "api-xyz"}
        assert unmapped["authn_issuer"] == {"id": "idp-okta", "type": "OKTA"}

    def test_minimal_event_omits_new_slots(self):
        """Baseline event without geo/AS/risk must not emit empty OCSF slots.

        The baseline fixture still carries a rawUserAgent so http_request stays,
        but every securityContext/debugContext/geographicalContext-derived slot
        must be absent — we never emit empty shells.
        """
        event = convert_event(_event())
        assert "location" not in event["src_endpoint"]
        assert "autonomous_system" not in event["src_endpoint"]
        assert "is_proxy" not in event["src_endpoint"]
        assert "domain" not in event["src_endpoint"]
        assert "zone" not in event["src_endpoint"]
        assert "device" not in event
        assert "observables" not in event
        assert "enrichments" not in event
        assert "auth_protocol" not in event
        assert "auth_factors" not in event
        assert "debug_data" not in event["unmapped"]["okta"]

    def test_native_output_carries_expanded_slots(self):
        event = convert_event(_rich_event(), output_format="native")
        assert event["schema_mode"] == "native"
        assert event["src_endpoint"]["autonomous_system"]["number"] == 13335
        assert event["device"]["uid"] == "cli-device-abc"
        assert event["enrichments"][0]["name"] == "okta.risk_level"
        assert event["unmapped"]["okta"]["debug_data"]["riskLevel"] == "HIGH"


class TestGoldenFixture:
    def test_golden_fixture(self):
        produced = list(ingest([RAW_FIXTURE.read_text()]))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert produced == expected

    def test_native_fixture_projection(self):
        produced = list(ingest([RAW_FIXTURE.read_text()], output_format="native"))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert len(produced) == len(expected)
        assert produced[0]["schema_mode"] == "native"
        assert produced[0]["event_uid"] == expected[0]["metadata"]["uid"]
        assert "class_uid" not in produced[0]


class TestUnmappedEventCounter:
    """Audit honesty: every unmapped Okta eventType is counted, not silently dropped."""

    def _wrap(self, eventType: str) -> str:
        return json.dumps(
            {
                "uuid": f"uuid-{eventType}",
                "published": "2024-05-01T12:00:00.000Z",
                "eventType": eventType,
                "displayMessage": "x",
            }
        )

    def test_unmapped_counts_populated_with_repeats(self):
        unmapped: dict[str, int] = {}
        events = [
            self._wrap("totally.fake.event.one"),
            self._wrap("totally.fake.event.one"),
            self._wrap("totally.fake.event.two"),
        ]
        produced = list(ingest(events, unmapped_counts=unmapped))
        assert produced == []
        assert unmapped == {
            "totally.fake.event.one": 2,
            "totally.fake.event.two": 1,
        }

    def test_unmapped_counts_unaffected_by_invalid_payloads(self):
        unmapped: dict[str, int] = {}
        events = [
            json.dumps({"uuid": "u1", "eventType": "user.session.start"}),  # missing published
            self._wrap("totally.fake.event"),
        ]
        list(ingest(events, unmapped_counts=unmapped))
        assert unmapped == {"totally.fake.event": 1}

    def test_unmapped_counts_optional(self):
        # No regression: omitting the kwarg still works (per-event stderr only).
        list(ingest([self._wrap("totally.fake.event")]))
