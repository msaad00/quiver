"""Tests for detect-web-auth-failures."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    DEFAULT_MIN_FAILURES,
    DEFAULT_WINDOW_MS,
    OUTPUT_FORMATS,
    detect,
)


def _http_event(
    *,
    path: str = "/login",
    method: str = "POST",
    status: int = 401,
    src_ip: str = "203.0.113.10",
    actor_uid: str = "alice",
    body: str | dict | None = None,
    time_ms: int = 1_700_000_000_000,
) -> dict:
    req: dict = {"http_method": method, "url": {"path": path}, "headers": []}
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


def test_defaults():
    assert DEFAULT_WINDOW_MS == 60_000
    assert DEFAULT_MIN_FAILURES == 5


# ---------- positive findings ----------


def test_fires_on_brute_force_burst():
    """5 failures in window from one IP → brute-force-burst finding."""
    events = [
        _http_event(status=401, time_ms=1_000 + i * 1_000, actor_uid=f"u{i}") for i in range(5)
    ]
    findings = list(detect(events))
    bursts = [
        f
        for f in findings
        if any(o["name"] == "rule" and o["value"] == "brute-force-burst" for o in f["observables"])
    ]
    assert len(bursts) == 1
    f = bursts[0]
    assert f["finding_info"]["attacks"][0]["technique_uid"] == "T1110"
    # 5 unique users seen
    assert any(o["name"] == "auth.unique_users" and o["value"] == "5" for o in f["observables"])


def test_brute_force_dedupes_within_same_window():
    """One burst finding for the same window even after extra failures."""
    events = [_http_event(status=401, time_ms=1_000 + i * 1_000) for i in range(8)]
    bursts = [
        f
        for f in detect(events)
        if any(o["name"] == "rule" and o["value"] == "brute-force-burst" for o in f["observables"])
    ]
    assert len(bursts) == 1


def test_fires_on_stuffing_flip():
    """5 failures then a 200 success on the same login endpoint → stuffing-flip."""
    events = [_http_event(status=401, time_ms=1_000 + i * 1_000) for i in range(5)]
    events.append(_http_event(status=200, time_ms=10_000, actor_uid="alice"))
    findings = list(detect(events))
    flips = [
        f
        for f in findings
        if any(o["name"] == "rule" and o["value"] == "stuffing-flip" for o in f["observables"])
    ]
    assert len(flips) == 1


def test_fires_on_oauth_password_grant_weak_login():
    """A 200 on /oauth/token with grant_type=password → weak-login (T1078)."""
    findings = list(
        detect(
            [
                _http_event(
                    path="/oauth/token",
                    status=200,
                    body="grant_type=password&username=alice&password=hunter2",
                    time_ms=1_000,
                )
            ]
        )
    )
    weak = [
        f
        for f in findings
        if any(o["name"] == "rule" and o["value"] == "weak-login" for o in f["observables"])
    ]
    assert len(weak) == 1
    assert weak[0]["finding_info"]["attacks"][0]["technique_uid"] == "T1078"
    assert any(
        o["name"] == "auth.reason" and o["value"] == "oauth-password-grant"
        for o in weak[0]["observables"]
    )


def test_fires_on_login_without_mfa_challenge_in_window():
    """A 200 /login with no MFA challenge from the same IP → weak-login."""
    findings = list(detect([_http_event(path="/login", status=200, time_ms=1_000)]))
    weak = [
        f
        for f in findings
        if any(o["name"] == "rule" and o["value"] == "weak-login" for o in f["observables"])
    ]
    assert len(weak) == 1
    assert any(
        o["name"] == "auth.reason" and o["value"] == "no-mfa-challenge-in-window"
        for o in weak[0]["observables"]
    )


def test_no_weak_login_when_mfa_challenge_seen():
    """A 200 MFA challenge then a 200 /login from the same IP within window → no weak-login."""
    events = [
        _http_event(path="/auth/mfa", status=200, time_ms=1_000),
        _http_event(path="/login", status=200, time_ms=2_000),
    ]
    findings = list(detect(events))
    weak = [
        f
        for f in findings
        if any(o["name"] == "rule" and o["value"] == "weak-login" for o in f["observables"])
    ]
    assert weak == []


# ---------- negatives ----------


def test_failures_below_threshold_no_burst():
    events = [_http_event(status=401, time_ms=1_000 + i * 1_000) for i in range(3)]
    findings = list(detect(events))
    assert findings == []


def test_failures_outside_window_dont_aggregate():
    events = [
        _http_event(status=401, time_ms=0),
        _http_event(status=401, time_ms=10 * 60 * 1000),  # 10 minutes later
        _http_event(status=401, time_ms=10 * 60 * 1000 + 1_000),
        _http_event(status=401, time_ms=10 * 60 * 1000 + 2_000),
    ]
    findings = list(detect(events))
    bursts = [
        f
        for f in findings
        if any(o["name"] == "rule" and o["value"] == "brute-force-burst" for o in f["observables"])
    ]
    assert bursts == []


def test_skips_non_login_path():
    """A 401 on /api/items is not a login failure for this detector."""
    events = [
        _http_event(path="/api/items", status=401, time_ms=1_000 + i * 1_000) for i in range(6)
    ]
    findings = list(detect(events))
    assert findings == []


def test_skips_non_http_event():
    findings = list(detect([{"class_uid": 9999}]))
    assert findings == []


def test_native_output_format():
    events = [_http_event(status=401, time_ms=1_000 + i * 1_000) for i in range(5)]
    findings = list(detect(events, output_format="native"))
    assert any(f["schema_mode"] == "native" for f in findings)


def test_unsupported_output_format_raises():
    import pytest

    with pytest.raises(ValueError, match="unsupported output_format"):
        list(detect([_http_event()], output_format="weird"))


def test_finding_uid_is_deterministic():
    events = [_http_event(status=401, time_ms=1_000 + i * 1_000) for i in range(5)]
    a = list(detect(events))[0]["finding_info"]["uid"]
    b = list(detect(events))[0]["finding_info"]["uid"]
    assert a == b
    assert a.startswith("auth-")
