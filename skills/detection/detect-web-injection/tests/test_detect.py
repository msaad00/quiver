"""Tests for detect-web-injection."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    INJECTION_PATTERNS,
    OUTPUT_FORMATS,
    PAYLOAD_EXCERPT_LEN,
    detect,
)


def _http_event(
    *,
    method: str = "GET",
    path: str = "/api/items",
    query_string: str = "",
    body: str | dict | None = None,
    headers: list[dict] | None = None,
    status: int = 200,
    src_ip: str = "203.0.113.10",
    actor_uid: str = "user-1",
    time_ms: int = 1_700_000_000_000,
) -> dict:
    req: dict = {
        "http_method": method,
        "url": {"path": path, "query_string": query_string},
        "headers": headers or [],
    }
    if body is not None:
        req["body"] = body
    return {
        "class_uid": 4002,
        "time": time_ms,
        "actor": {"user": {"uid": actor_uid}},
        "src_endpoint": {"ip": src_ip},
        "http_request": req,
        "http_response": {"status_code": status},
    }


# ---------- contract ----------


def test_output_formats_set():
    assert OUTPUT_FORMATS == frozenset({"ocsf", "native"})


def test_pattern_catalogue_covers_every_family():
    families = {family for family, _, _ in INJECTION_PATTERNS}
    assert {"sql", "command", "ldap", "nosql", "xpath", "template"}.issubset(families)


def test_payload_excerpt_len_60():
    assert PAYLOAD_EXCERPT_LEN == 60


# ---------- positive findings ----------


def test_fires_on_sql_union_select_in_query():
    findings = list(detect([_http_event(query_string="id=1 UNION SELECT password FROM users")]))
    assert findings
    f = findings[0]
    assert f["class_uid"] == 2004
    assert f["finding_info"]["attacks"][0]["technique_uid"] == "T1190"
    assert any(
        o["name"] == "injection.family" and o["value"] == "sql" for o in f["observables"]
    )


def test_fires_on_or_1_equals_1():
    findings = list(detect([_http_event(query_string="user=admin' OR 1=1 --")]))
    labels = {
        o["value"]
        for f in findings
        for o in f["observables"]
        if o["name"] == "injection.signature_label"
    }
    # Either the bare OR 1=1 signature or the quoted-tautology variant — both are SQL.
    assert labels & {"or-1-equals-1", "tautology-quoted", "comment-tail"}


def test_fires_on_command_substitution_in_body():
    findings = list(detect([_http_event(method="POST", body="name=$(whoami)")]))
    assert any(
        o["name"] == "injection.family" and o["value"] == "command" for f in findings for o in f["observables"]
    )
    assert any(
        o["name"] == "injection.matched_surface" and o["value"] == "body"
        for f in findings
        for o in f["observables"]
    )


def test_fires_on_ldap_wildcard_bypass():
    findings = list(detect([_http_event(query_string="filter=(|(uid=*")]))
    assert any(
        o["name"] == "injection.family" and o["value"] == "ldap" for f in findings for o in f["observables"]
    )


def test_fires_on_nosql_ne_operator_in_body():
    findings = list(detect([_http_event(method="POST", body={"username": {"$ne": ""}})]))
    assert any(
        o["name"] == "injection.family" and o["value"] == "nosql" for f in findings for o in f["observables"]
    )


def test_fires_on_template_injection_in_query():
    findings = list(detect([_http_event(query_string="name={{ 7*7 }}")]))
    assert any(
        o["name"] == "injection.family" and o["value"] == "template" for f in findings for o in f["observables"]
    )


def test_fires_on_user_agent_header_injection():
    findings = list(
        detect(
            [
                _http_event(
                    headers=[{"name": "User-Agent", "value": "Mozilla/5.0 ' OR 1=1 --"}],
                )
            ]
        )
    )
    assert any(
        o["name"] == "injection.matched_surface" and o["value"].startswith("header:")
        for f in findings
        for o in f["observables"]
    )


def test_fires_on_etc_passwd_path_traversal_signature():
    findings = list(detect([_http_event(query_string="file=../../etc/passwd")]))
    assert any(
        o["name"] == "injection.signature_label" and o["value"] == "etc-passwd"
        for f in findings
        for o in f["observables"]
    )


def test_payload_excerpt_is_redacted_when_long():
    long_payload = "id=1 UNION SELECT " + "X" * 200
    findings = list(detect([_http_event(query_string=long_payload)]))
    excerpt = next(
        o["value"] for f in findings for o in f["observables"] if o["name"] == "injection.payload_excerpt"
    )
    assert len(excerpt) <= PAYLOAD_EXCERPT_LEN + len("...")


# ---------- negatives ----------


def test_no_finding_on_clean_request():
    findings = list(detect([_http_event(query_string="page=1&limit=20")]))
    assert findings == []


def test_no_finding_on_non_http_event():
    findings = list(detect([{"class_uid": 9999, "time": 1}]))
    assert findings == []


def test_native_output_format():
    findings = list(detect([_http_event(query_string="UNION SELECT 1")], output_format="native"))
    assert findings[0]["schema_mode"] == "native"
    assert findings[0]["injection_family"] == "sql"


def test_unsupported_output_format_raises():
    import pytest

    with pytest.raises(ValueError, match="unsupported output_format"):
        list(detect([_http_event()], output_format="weird"))


def test_finding_uid_is_deterministic():
    e = _http_event(query_string="UNION SELECT 1")
    a = list(detect([e]))[0]["finding_info"]["uid"]
    b = list(detect([e]))[0]["finding_info"]["uid"]
    assert a == b
    assert a.startswith("inj-")
