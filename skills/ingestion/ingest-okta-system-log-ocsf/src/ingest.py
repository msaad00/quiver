"""Convert raw Okta System Log events to native or OCSF IAM events.

Input:  Okta System Log API arrays, single-event JSON, event hook wrappers,
        or NDJSON.
Output: JSONL of either:
        - OCSF Identity & Access Management events across Authentication (3002),
          Account Change (3001), and User Access Management (3005), or
        - repo-owned native IAM activity records.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "ingest-okta-system-log-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
OUTPUT_FORMATS = ("ocsf", "native")

CATEGORY_UID = 3
CATEGORY_NAME = "Identity & Access Management"

AUTH_CLASS_UID = 3002
AUTH_CLASS_NAME = "Authentication"
AUTH_ACTIVITY_LOGON = 1
AUTH_ACTIVITY_LOGOFF = 2
AUTH_ACTIVITY_OTHER = 99

ACCOUNT_CHANGE_CLASS_UID = 3001
ACCOUNT_CHANGE_CLASS_NAME = "Account Change"
ACCOUNT_CHANGE_CREATE = 1
ACCOUNT_CHANGE_ENABLE = 2
ACCOUNT_CHANGE_PASSWORD_CHANGE = 3
ACCOUNT_CHANGE_PASSWORD_RESET = 4
ACCOUNT_CHANGE_DISABLE = 5
ACCOUNT_CHANGE_DELETE = 6
ACCOUNT_CHANGE_LOCK = 9
ACCOUNT_CHANGE_MFA_ENABLE = 10
ACCOUNT_CHANGE_MFA_DISABLE = 11
ACCOUNT_CHANGE_UNLOCK = 12
ACCOUNT_CHANGE_OTHER = 99

USER_ACCESS_CLASS_UID = 3005
USER_ACCESS_CLASS_NAME = "User Access Management"
USER_ACCESS_ASSIGN = 1
USER_ACCESS_REVOKE = 2
USER_ACCESS_OTHER = 99

STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

SEVERITY_UNKNOWN = 0
SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4

_AUTH_EVENT_MAP: dict[str, int] = {
    "user.session.start": AUTH_ACTIVITY_LOGON,
    "user.session.end": AUTH_ACTIVITY_LOGOFF,
    "user.authentication.sso": AUTH_ACTIVITY_LOGON,
    "user.authentication.auth_via_mfa": AUTH_ACTIVITY_OTHER,
    "user.mfa.okta_verify": AUTH_ACTIVITY_OTHER,
    "user.mfa.okta_verify.deny_push": AUTH_ACTIVITY_OTHER,
    "user.mfa.okta_verify.deny_push_upgrade_needed": AUTH_ACTIVITY_OTHER,
    "system.push.send_factor_verify_push": AUTH_ACTIVITY_OTHER,
}

_ACCOUNT_CHANGE_EVENT_MAP: dict[str, int] = {
    "user.lifecycle.create": ACCOUNT_CHANGE_CREATE,
    "user.lifecycle.activate": ACCOUNT_CHANGE_ENABLE,
    "user.lifecycle.unsuspend": ACCOUNT_CHANGE_ENABLE,
    "user.lifecycle.deactivate": ACCOUNT_CHANGE_DISABLE,
    "user.lifecycle.suspend": ACCOUNT_CHANGE_DISABLE,
    "user.account.update_password": ACCOUNT_CHANGE_PASSWORD_CHANGE,
    "user.account.reset_password": ACCOUNT_CHANGE_PASSWORD_RESET,
    "user.account.lock": ACCOUNT_CHANGE_LOCK,
    "user.account.unlock_by_admin": ACCOUNT_CHANGE_UNLOCK,
    "user.mfa.factor.activate": ACCOUNT_CHANGE_MFA_ENABLE,
    "user.mfa.factor.deactivate": ACCOUNT_CHANGE_MFA_DISABLE,
}

_USER_ACCESS_EVENT_MAP: dict[str, int] = {
    "application.user_membership.add": USER_ACCESS_ASSIGN,
    "application.user_membership.remove": USER_ACCESS_REVOKE,
    "group.user_membership.add": USER_ACCESS_ASSIGN,
    "group.user_membership.remove": USER_ACCESS_REVOKE,
    "user.account.privilege.grant": USER_ACCESS_ASSIGN,
    "user.account.privilege.revoke": USER_ACCESS_REVOKE,
}


def parse_ts_ms(ts: str | None) -> int:
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def severity_to_id(severity: str | None) -> int:
    value = (severity or "").upper()
    if value in {"INFO", "INFORMATIONAL", "DEBUG"}:
        return SEVERITY_INFORMATIONAL
    if value in {"WARN", "WARNING"}:
        return SEVERITY_LOW
    if value in {"ERROR"}:
        return SEVERITY_HIGH
    return SEVERITY_UNKNOWN


def status_from_outcome(outcome: dict[str, Any] | None) -> tuple[int, str | None]:
    if not isinstance(outcome, dict):
        return STATUS_UNKNOWN, None
    result = (outcome.get("result") or "").upper()
    reason = outcome.get("reason") or None
    if result == "SUCCESS":
        return STATUS_SUCCESS, None
    if result == "FAILURE":
        return STATUS_FAILURE, str(reason) if reason else None
    return STATUS_UNKNOWN, str(reason) if reason else None


def _classify_event(event_type: str) -> tuple[int, str, int] | None:
    if event_type in _AUTH_EVENT_MAP:
        return AUTH_CLASS_UID, AUTH_CLASS_NAME, _AUTH_EVENT_MAP[event_type]
    if event_type in _ACCOUNT_CHANGE_EVENT_MAP:
        return ACCOUNT_CHANGE_CLASS_UID, ACCOUNT_CHANGE_CLASS_NAME, _ACCOUNT_CHANGE_EVENT_MAP[event_type]
    if event_type in _USER_ACCESS_EVENT_MAP:
        return USER_ACCESS_CLASS_UID, USER_ACCESS_CLASS_NAME, _USER_ACCESS_EVENT_MAP[event_type]
    return None


def _user_object(entity: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(entity, dict):
        return {}
    user: dict[str, Any] = {}
    if entity.get("id"):
        user["uid"] = str(entity["id"])
    name = entity.get("alternateId") or entity.get("displayName") or entity.get("id") or ""
    if name:
        user["name"] = str(name)
    if entity.get("type"):
        user["type"] = str(entity["type"])
    alt = entity.get("alternateId") or ""
    if isinstance(alt, str) and "@" in alt:
        user["email_addr"] = alt
    return user


def _find_target(event: dict[str, Any], allowed_types: set[str]) -> dict[str, Any] | None:
    for target in event.get("target") or []:
        if not isinstance(target, dict):
            continue
        if str(target.get("type") or "") in allowed_types:
            return target
    return None


def _actor(event: dict[str, Any]) -> dict[str, Any]:
    user = _user_object(event.get("actor") or {})
    return {"user": user} if user else {}


def _subject_user(event: dict[str, Any]) -> dict[str, Any]:
    target_user = _find_target(event, {"User"})
    user = _user_object(target_user or event.get("actor") or {})
    return user


def _location_from_geo(geo: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(geo, dict):
        return {}
    location: dict[str, Any] = {}
    for src_key, dst_key in (
        ("country", "country"),
        ("state", "region"),
        ("city", "city"),
        ("postalCode", "postal_code"),
    ):
        value = geo.get(src_key)
        if isinstance(value, str) and value:
            location[dst_key] = value
    geoloc = geo.get("geolocation") or {}
    if isinstance(geoloc, dict):
        lat = geoloc.get("lat")
        lon = geoloc.get("lon")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            # OCSF src_endpoint.location.coordinates: [longitude, latitude]
            location["coordinates"] = [float(lon), float(lat)]
    return location


def _autonomous_system(sec_ctx: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(sec_ctx, dict):
        return {}
    asn: dict[str, Any] = {}
    as_number = sec_ctx.get("asNumber")
    if isinstance(as_number, int):
        asn["number"] = as_number
    as_org = sec_ctx.get("asOrg")
    if isinstance(as_org, str) and as_org:
        asn["name"] = as_org
    return asn


def _src_endpoint(event: dict[str, Any]) -> dict[str, Any]:
    client = event.get("client") or {}
    request = event.get("request") or {}
    sec_ctx = event.get("securityContext") or {}
    ip = client.get("ipAddress") or ""
    if not ip:
        ip_chain = request.get("ipChain") or []
        if ip_chain and isinstance(ip_chain[0], dict):
            ip = ip_chain[0].get("ip") or ""
    endpoint: dict[str, Any] = {}
    if ip:
        endpoint["ip"] = ip
    user_agent = (client.get("userAgent") or {}).get("rawUserAgent") or ""
    if user_agent:
        # Kept for cross-ingester consistency (cloudtrail, gcp-audit, k8s-audit
        # all expose raw UA under src_endpoint.svc_name). Also duplicated into
        # http_request.user_agent for OCSF-native consumers.
        endpoint["svc_name"] = user_agent
    zone = client.get("zone")
    if isinstance(zone, str) and zone:
        endpoint["zone"] = zone
    location = _location_from_geo(client.get("geographicalContext"))
    if location:
        endpoint["location"] = location
    asn = _autonomous_system(sec_ctx)
    if asn:
        endpoint["autonomous_system"] = asn
    is_proxy = sec_ctx.get("isProxy")
    if isinstance(is_proxy, bool):
        endpoint["is_proxy"] = is_proxy
    domain = sec_ctx.get("domain")
    if isinstance(domain, str) and domain:
        endpoint["domain"] = domain
    return endpoint


def _device(event: dict[str, Any]) -> dict[str, Any]:
    client = event.get("client") or {}
    device: dict[str, Any] = {}
    client_id = client.get("id")
    if isinstance(client_id, str) and client_id:
        device["uid"] = client_id
    device_name = client.get("device")
    user_agent = client.get("userAgent") or {}
    browser = user_agent.get("browser") if isinstance(user_agent, dict) else None
    # Prefer Okta's `client.device` label ("Computer", "Mobile"); fall back to
    # parsed browser name so a device object is emitted when either is present.
    if isinstance(device_name, str) and device_name:
        device["name"] = device_name
    elif isinstance(browser, str) and browser:
        device["name"] = browser
    os_name = user_agent.get("os") if isinstance(user_agent, dict) else None
    if isinstance(os_name, str) and os_name:
        device["os"] = {"name": os_name}
    return device


def _http_request(event: dict[str, Any]) -> dict[str, Any]:
    client = event.get("client") or {}
    user_agent = (client.get("userAgent") or {}).get("rawUserAgent") or ""
    if not user_agent:
        return {}
    return {"user_agent": user_agent}


def _observables_from_ip_chain(event: dict[str, Any]) -> list[dict[str, Any]]:
    chain = ((event.get("request") or {}).get("ipChain")) or []
    if not isinstance(chain, list):
        return []
    observables: list[dict[str, Any]] = []
    for hop in chain:
        if not isinstance(hop, dict):
            continue
        hop_ip = hop.get("ip")
        if not isinstance(hop_ip, str) or not hop_ip:
            continue
        entry: dict[str, Any] = {
            "name": "src_endpoint.ip",
            "type": "IP Address",
            "type_id": 2,
            "value": hop_ip,
        }
        location = _location_from_geo(hop.get("geographicalContext"))
        if location:
            entry["location"] = location
        source = hop.get("source")
        if isinstance(source, str) and source:
            entry["reputation"] = {"provider": "okta", "base_score": 0, "score": source}
        observables.append(entry)
    return observables


def _enrichments_from_risk(event: dict[str, Any]) -> list[dict[str, Any]]:
    debug_data = ((event.get("debugContext") or {}).get("debugData")) or {}
    if not isinstance(debug_data, dict):
        return []
    enrichments: list[dict[str, Any]] = []
    risk_level = debug_data.get("riskLevel")
    if isinstance(risk_level, str) and risk_level:
        enrichments.append(
            {"name": "okta.risk_level", "value": risk_level, "type": "security_risk"}
        )
    risk_reasons = debug_data.get("riskReasons")
    # Okta emits riskReasons as a comma-joined string or a list depending on the
    # surface. Normalize to list[str] so downstream rules can iterate.
    reasons_list: list[str] = []
    if isinstance(risk_reasons, str) and risk_reasons:
        reasons_list = [part.strip() for part in risk_reasons.split(",") if part.strip()]
    elif isinstance(risk_reasons, list):
        reasons_list = [str(part) for part in risk_reasons if isinstance(part, (str, int, float))]
    if reasons_list:
        enrichments.append(
            {
                "name": "okta.risk_reasons",
                "data": {"reasons": reasons_list},
                "type": "security_risk",
            }
        )
    behaviors = debug_data.get("behaviors")
    if isinstance(behaviors, dict) and behaviors:
        enrichments.append(
            {"name": "okta.behaviors", "data": {"behaviors": behaviors}, "type": "security_risk"}
        )
    return enrichments


def _session(event: dict[str, Any]) -> dict[str, Any]:
    auth_ctx = event.get("authenticationContext") or {}
    session: dict[str, Any] = {}
    if auth_ctx.get("externalSessionId"):
        session["uid"] = str(auth_ctx["externalSessionId"])
    if auth_ctx.get("rootSessionId"):
        session["issuer"] = str(auth_ctx["rootSessionId"])
    return session


def _resources(event: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for target in event.get("target") or []:
        if not isinstance(target, dict):
            continue
        if str(target.get("type") or "") == "User":
            continue
        name = target.get("displayName") or target.get("alternateId") or target.get("id") or ""
        if not name:
            continue
        resources.append({"name": str(name), "type": str(target.get("type") or "resource")})
    return resources


def _privileges(event: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for target in event.get("target") or []:
        if not isinstance(target, dict):
            continue
        if str(target.get("type") or "") == "User":
            continue
        detail = target.get("detailEntry")
        if isinstance(detail, str) and detail:
            values.append(detail)
            continue
        for key in ("displayName", "alternateId", "id"):
            value = target.get(key)
            if isinstance(value, str) and value:
                values.append(value)
                break
    if not values:
        values.append(str(event.get("eventType") or "unknown"))
    return values


def _metadata_uid(event: dict[str, Any]) -> str:
    natural = str(event.get("uuid") or "").strip()
    if natural:
        return natural
    stable = {
        "published": event.get("published", ""),
        "eventType": event.get("eventType", ""),
        "actorId": (event.get("actor") or {}).get("id", ""),
        "targetIds": [target.get("id") for target in event.get("target") or [] if isinstance(target, dict)],
        "transactionId": (event.get("transaction") or {}).get("id", ""),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _status_name(status_id: int) -> str:
    return {
        STATUS_SUCCESS: "success",
        STATUS_FAILURE: "failure",
        STATUS_UNKNOWN: "unknown",
    }.get(status_id, "unknown")


def _severity_name(severity_id: int) -> str:
    return {
        SEVERITY_INFORMATIONAL: "informational",
        SEVERITY_LOW: "low",
        SEVERITY_MEDIUM: "medium",
        SEVERITY_HIGH: "high",
        SEVERITY_UNKNOWN: "unknown",
    }.get(severity_id, "unknown")


def _record_type(class_uid: int) -> str:
    return {
        AUTH_CLASS_UID: "authentication",
        ACCOUNT_CHANGE_CLASS_UID: "account_change",
        USER_ACCESS_CLASS_UID: "user_access_management",
    }.get(class_uid, "iam_activity")


def _auth_metadata(event: dict[str, Any]) -> tuple[str | None, list[str], dict[str, str]]:
    """Extract `auth_protocol`, `auth_factors[]`, and a label dict from authenticationContext."""
    auth_ctx = event.get("authenticationContext") or {}
    if not isinstance(auth_ctx, dict):
        return None, [], {}
    protocol = auth_ctx.get("authenticationProvider")
    protocol_str = protocol if isinstance(protocol, str) and protocol else None
    factors: list[str] = []
    cred_type = auth_ctx.get("credentialType")
    if isinstance(cred_type, str) and cred_type:
        factors.append(cred_type)
    extra_labels: dict[str, str] = {}
    interface = auth_ctx.get("interface")
    if isinstance(interface, str) and interface:
        extra_labels["okta.interface"] = interface
    step = auth_ctx.get("authenticationStep")
    if step is not None:
        extra_labels["okta.authentication_step"] = str(step)
    return protocol_str, factors, extra_labels


def _unmapped_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Full Okta-native preservation under `unmapped.okta.*`.

    Captures fields OCSF 1.8 has no clean slot for so downstream detectors can
    reach for Okta-specific signal without re-parsing the raw System Log event.
    `debug_data` round-trips verbatim per #271 acceptance.
    """
    auth_ctx = event.get("authenticationContext") or {}
    transaction = event.get("transaction") or {}
    debug_ctx = event.get("debugContext") or {}
    payload: dict[str, Any] = {
        "event_type": event.get("eventType"),
        "legacy_event_type": event.get("legacyEventType"),
        "transaction_id": transaction.get("id") if isinstance(transaction, dict) else None,
        "root_session_id": auth_ctx.get("rootSessionId") if isinstance(auth_ctx, dict) else None,
    }
    if isinstance(debug_ctx, dict):
        debug_data = debug_ctx.get("debugData")
        if debug_data is not None:
            payload["debug_data"] = debug_data
    actor = event.get("actor")
    if isinstance(actor, dict):
        detail = actor.get("detailEntry")
        if detail:
            payload["actor_detail_entry"] = detail
    target_details: list[dict[str, Any]] = []
    for target in event.get("target") or []:
        if not isinstance(target, dict):
            continue
        detail = target.get("detailEntry")
        if detail:
            target_details.append({"id": target.get("id"), "detail_entry": detail})
    if target_details:
        payload["target_detail_entries"] = target_details
    if isinstance(transaction, dict):
        if transaction.get("type"):
            payload["transaction_type"] = transaction.get("type")
        if transaction.get("detail"):
            payload["transaction_detail"] = transaction.get("detail")
    if isinstance(auth_ctx, dict):
        issuer = auth_ctx.get("issuer")
        if isinstance(issuer, dict) and issuer:
            payload["authn_issuer"] = issuer
    return payload


def _build_canonical_event(event: dict[str, Any], class_uid: int, activity_id: int) -> dict[str, Any]:
    status_id, status_detail = status_from_outcome(event.get("outcome") or {})
    severity_id = severity_to_id(event.get("severity"))
    auth_protocol, auth_factors, extra_labels = _auth_metadata(event)
    canonical: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": _record_type(class_uid),
        "source_skill": SKILL_NAME,
        "event_uid": _metadata_uid(event),
        "provider": "Okta",
        "activity_id": activity_id,
        "event_type": str(event.get("eventType") or ""),
        "severity_id": severity_id,
        "severity": _severity_name(severity_id),
        "status_id": status_id,
        "status": _status_name(status_id),
        "time_ms": parse_ts_ms(event.get("published")),
        "message": str(event.get("displayMessage") or event.get("eventType") or _record_type(class_uid)),
        "actor": _actor(event),
        "src_endpoint": _src_endpoint(event),
        "unmapped": {"okta": _unmapped_payload(event)},
    }
    if status_detail:
        canonical["status_detail"] = status_detail
    device = _device(event)
    if device:
        canonical["device"] = device
    http_request = _http_request(event)
    if http_request:
        canonical["http_request"] = http_request
    if auth_protocol:
        canonical["auth_protocol"] = auth_protocol
    if auth_factors:
        canonical["auth_factors"] = auth_factors
    observables = _observables_from_ip_chain(event)
    if observables:
        canonical["observables"] = observables
    enrichments = _enrichments_from_risk(event)
    if enrichments:
        canonical["enrichments"] = enrichments
    if extra_labels:
        canonical["extra_labels"] = extra_labels
    return canonical


def _build_authentication_event(event: dict[str, Any], activity_id: int) -> dict[str, Any]:
    out = _build_canonical_event(event, AUTH_CLASS_UID, activity_id)
    user = _subject_user(event)
    if user:
        out["user"] = user
    session = _session(event)
    if session:
        out["session"] = session
    resources = _resources(event)
    if resources:
        out["resources"] = resources
        out["service"] = {"name": resources[0]["name"]}
    return out


def _build_account_change_event(event: dict[str, Any], activity_id: int) -> dict[str, Any]:
    out = _build_canonical_event(event, ACCOUNT_CHANGE_CLASS_UID, activity_id)
    out["user"] = _subject_user(event)
    resources = _resources(event)
    if resources:
        out["resources"] = resources
    return out


def _build_user_access_event(event: dict[str, Any], activity_id: int) -> dict[str, Any]:
    out = _build_canonical_event(event, USER_ACCESS_CLASS_UID, activity_id)
    out["user"] = _subject_user(event)
    out["resources"] = _resources(event)
    out["privileges"] = _privileges(event)
    return out


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    class_uid = {
        "authentication": AUTH_CLASS_UID,
        "account_change": ACCOUNT_CHANGE_CLASS_UID,
        "user_access_management": USER_ACCESS_CLASS_UID,
    }.get(canonical["record_type"], AUTH_CLASS_UID)
    class_name = {
        AUTH_CLASS_UID: AUTH_CLASS_NAME,
        ACCOUNT_CHANGE_CLASS_UID: ACCOUNT_CHANGE_CLASS_NAME,
        USER_ACCESS_CLASS_UID: USER_ACCESS_CLASS_NAME,
    }[class_uid]
    labels: list[str] = ["identity", "okta", "system-log", "ingest"]
    extra_labels = canonical.get("extra_labels") or {}
    if isinstance(extra_labels, dict):
        for key, value in extra_labels.items():
            labels.append(f"{key}={value}")
    out: dict[str, Any] = {
        "activity_id": canonical["activity_id"],
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": class_uid,
        "class_name": class_name,
        "type_uid": class_uid * 100 + canonical["activity_id"],
        "severity_id": canonical["severity_id"],
        "status_id": canonical["status_id"],
        "time": canonical["time_ms"],
        "message": canonical["message"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": labels,
        },
        "unmapped": canonical["unmapped"],
    }
    for field in (
        "actor",
        "src_endpoint",
        "user",
        "session",
        "resources",
        "service",
        "privileges",
        "status_detail",
        "device",
        "http_request",
        "auth_protocol",
        "auth_factors",
        "observables",
        "enrichments",
    ):
        if canonical.get(field):
            out[field] = canonical[field]
    return out


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["output_format"] = "native"
    return native


def validate_event(event: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(event, dict):
        return False, "not a dict"
    for field in ("eventType", "published"):
        if not event.get(field):
            return False, f"missing required field: {field}"
    if _classify_event(str(event.get("eventType") or "")) is None:
        return False, f"unsupported eventType: {event.get('eventType')}"
    return True, ""


def convert_event(event: dict[str, Any], output_format: str = "ocsf") -> dict[str, Any]:
    event_type = str(event.get("eventType") or "")
    route = _classify_event(event_type)
    if route is None:
        raise ValueError(f"unsupported eventType: {event_type}")

    class_uid, _class_name, activity_id = route
    if class_uid == AUTH_CLASS_UID:
        canonical = _build_authentication_event(event, activity_id)
    elif class_uid == ACCOUNT_CHANGE_CLASS_UID:
        canonical = _build_account_change_event(event, activity_id)
    elif class_uid == USER_ACCESS_CLASS_UID:
        canonical = _build_user_access_event(event, activity_id)
    else:
        raise ValueError(f"unsupported class route for {event_type}")
    if output_format == "native":
        return _render_native_event(canonical)
    if output_format == "ocsf":
        return _render_ocsf_event(canonical)
    raise ValueError(f"unsupported class route for {event_type}")


def iter_raw_events(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    buf = list(stream)
    if not buf:
        return

    full = "\n".join(line.rstrip("\n") for line in buf).strip()
    if not full:
        return

    try:
        whole = json.loads(full)
    except json.JSONDecodeError:
        whole = None

    if isinstance(whole, dict):
        if isinstance(((whole.get("data") or {}).get("events")), list):
            for event in (whole.get("data") or {}).get("events") or []:
                if isinstance(event, dict):
                    yield event
            return
        yield whole
        return

    if isinstance(whole, list):
        for event in whole:
            if isinstance(event, dict):
                yield event
        return

    for lineno, raw_line in enumerate(buf, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=f"skipping line {lineno}: json parse failed: {exc}",
                line=lineno,
                error=str(exc),
            )
            continue
        if isinstance(obj, dict) and isinstance(((obj.get("data") or {}).get("events")), list):
            for event in (obj.get("data") or {}).get("events") or []:
                if isinstance(event, dict):
                    yield event
        elif isinstance(obj, dict):
            yield obj
        else:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_json_shape",
                message=f"skipping line {lineno}: not a JSON object or Okta wrapper",
                line=lineno,
            )


def ingest(stream: Iterable[str], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    for raw in iter_raw_events(stream):
        ok, reason = validate_event(raw)
        if not ok:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_event",
                message=f"skipping event: {reason}",
                reason=reason,
                event_type=str(raw.get("eventType") or ""),
                event_uid=str(raw.get("uuid") or ""),
            )
            continue
        try:
            yield convert_event(raw, output_format=output_format)
        except Exception as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="convert_error",
                message=f"skipping event: convert error: {exc}",
                error=str(exc),
                event_type=str(raw.get("eventType") or ""),
                event_uid=str(raw.get("uuid") or ""),
            )
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert raw Okta System Log JSON to OCSF or native IAM JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF IAM events (default) or the native canonical projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        for event in ingest(in_stream, output_format=args.output_format):
            out_stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
