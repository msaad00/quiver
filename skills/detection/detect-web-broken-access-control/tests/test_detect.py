"""Tests for detect-web-broken-access-control."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    DEFAULT_AUTH_SWAP_WINDOW_MS,
    DEFAULT_ID_PATH_PATTERNS,
    OUTPUT_FORMATS,
    detect,
)


def _http_event(
    *,
    path: str,
    actor_uid: str = "user-7",
    actor_groups: list[str] | None = None,
    method: str = "GET",
    status: int = 200,
    src_ip: str = "203.0.113.10",
    time_ms: int = 1_700_000_000_000,
    authorization: str | None = None,
) -> dict:
    headers: list[dict] = []
    if authorization is not None:
        headers.append({"name": "Authorization", "value": authorization})
    user: dict = {"uid": actor_uid}
    if actor_groups:
        user["groups"] = [{"uid": g} for g in actor_groups]
    return {
        "class_uid": 4002,
        "time": time_ms,
        "actor": {"user": user},
        "src_endpoint": {"ip": src_ip},
        "http_request": {
            "http_method": method,
            "url": {"path": path},
            "headers": headers,
        },
        "http_response": {"status_code": status},
    }


# ---------- contract ----------


def test_output_formats_set():
    assert OUTPUT_FORMATS == frozenset({"ocsf", "native"})


def test_default_id_paths_cover_users_accounts_orgs():
    pats = " ".join(DEFAULT_ID_PATH_PATTERNS)
    assert "/users/" in pats
    assert "/accounts/" in pats
    assert "/orgs/" in pats


def test_default_window_60s():
    assert DEFAULT_AUTH_SWAP_WINDOW_MS == 60 * 1000


# ---------- IDOR positive ----------


def test_fires_on_idor_user_id_mismatch():
    # user-7 hits /users/42 → IDOR
    findings = list(detect([_http_event(path="/users/42/profile", actor_uid="user-7")]))
    assert len(findings) == 1
    f = findings[0]
    assert f["class_uid"] == 2004
    assert f["severity_id"] == 4
    assert f["finding_info"]["attacks"][0]["technique_uid"] == "T1212"
    assert any(o["name"] == "rule" and o["value"] == "idor" for o in f["observables"])
    assert any(o["name"] == "target.uid" and o["value"] == "42" for o in f["observables"])


def test_fires_on_unauthenticated_id_path_access():
    # No actor uid + id-bearing path → still a finding (anonymous IDOR probe).
    ev = _http_event(path="/accounts/abc/keys", actor_uid="")
    findings = list(detect([ev]))
    assert len(findings) == 1
    assert findings[0]["finding_info"]["types"][0].startswith("A01")


def test_no_finding_when_id_matches_actor():
    findings = list(detect([_http_event(path="/users/user-7/profile", actor_uid="user-7")]))
    assert findings == []


def test_no_finding_when_id_in_actor_groups():
    findings = list(
        detect(
            [
                _http_event(
                    path="/orgs/acme/dashboard",
                    actor_uid="user-7",
                    actor_groups=["acme"],
                )
            ]
        )
    )
    assert findings == []


# ---------- auth-swap flip ----------


def test_fires_on_403_then_200_with_different_auth():
    events = [
        _http_event(path="/api/admin", status=403, authorization="Bearer first", time_ms=1000),
        _http_event(path="/api/admin", status=200, authorization="Bearer second", time_ms=2000),
    ]
    findings = list(detect(events))
    assert any(
        any(o["name"] == "rule" and o["value"] == "auth-swap-flip" for o in f["observables"])
        for f in findings
    )


def test_no_flip_when_authorization_unchanged():
    events = [
        _http_event(path="/api/admin", status=403, authorization="Bearer same", time_ms=1000),
        _http_event(path="/api/admin", status=200, authorization="Bearer same", time_ms=2000),
    ]
    flips = [
        f
        for f in detect(events)
        if any(o["name"] == "rule" and o["value"] == "auth-swap-flip" for o in f["observables"])
    ]
    assert flips == []


def test_no_flip_outside_window():
    events = [
        _http_event(path="/api/admin", status=403, authorization="Bearer first", time_ms=0),
        _http_event(
            path="/api/admin",
            status=200,
            authorization="Bearer second",
            time_ms=10 * 60 * 1000,  # 10 minutes later, default window 60s
        ),
    ]
    flips = [
        f
        for f in detect(events)
        if any(o["name"] == "rule" and o["value"] == "auth-swap-flip" for o in f["observables"])
    ]
    assert flips == []


# ---------- negative / robustness ----------


def test_skips_non_http_event():
    events = [{"class_uid": 9999, "time": 1, "actor": {}}]
    assert list(detect(events)) == []


def test_skips_event_without_path():
    events = [{"class_uid": 4002, "time": 1, "http_request": {"url": {}}}]
    assert list(detect(events)) == []


def test_native_output_format_idor():
    f = list(
        detect([_http_event(path="/users/42/profile", actor_uid="user-7")], output_format="native")
    )[0]
    assert f["schema_mode"] == "native"
    assert f["rule"] == "idor"
    assert f["target_id"] == "42"


def test_unsupported_output_format_raises():
    import pytest

    with pytest.raises(ValueError, match="unsupported output_format"):
        list(detect([_http_event(path="/users/1")], output_format="weird"))


def test_finding_uid_is_deterministic_for_same_event():
    e = _http_event(path="/users/42/profile", actor_uid="user-7")
    a = list(detect([e]))[0]["finding_info"]["uid"]
    b = list(detect([e]))[0]["finding_info"]["uid"]
    assert a == b
    assert a.startswith("bac-")
