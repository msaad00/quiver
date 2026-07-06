"""OCSF 1.8 event validator.

Catches drift in emitted OCSF events before they hit the consolidated feed.
Validates the fields that `skills/detection-engineering/OCSF_CONTRACT.md`
pins — the minimum set every event in this repo must carry on the wire.

Design:
  - No external dependencies (no `jsonschema` — keeps skills lightweight).
  - Returns a list of error strings; empty list = valid.
  - Does NOT fetch the OCSF schema at runtime. Required fields per class are
    hardcoded from the pinned contract (`1.8.0+mcp.2026.04`) so validation
    runs the same way offline, in CI, and in a Lambda.
  - Scoped to the classes this repo actually emits: 3001, 3002, 6003, 6002,
    4002, 2004, 2003, 5023. Unknown classes are permitted (pass-through) so
    a future skill adding a new class is not blocked by the validator — just
    add the class to `CLASS_ACTIVITY_NAMES` when ready.

Usage:
    from skills._shared.ocsf_validator import validate_event

    errors = validate_event(ocsf_event)
    if errors:
        # In strict mode a skill raises; in telemetry mode it emits a stderr
        # warning and continues. That policy belongs to the caller.
        for err in errors:
            ...

Contract: ../detection-engineering/OCSF_CONTRACT.md
"""

from __future__ import annotations

from typing import Any

OCSF_VERSION = "1.8.0"

REPO_PRODUCT_NAME = "cloud-ai-security-skills"
REPO_PRODUCT_VENDOR = "msaad00/cloud-ai-security-skills"

# OCSF severity_id enum per 1.8.
SEVERITY_IDS = {0, 1, 2, 3, 4, 5, 6}

# OCSF status_id enum for classes that use it (Authentication, Account Change,
# API Activity, Application Activity, HTTP Activity all accept 0/1/2).
STATUS_IDS = {0, 1, 2}

# Class -> (category_uid, valid activity_ids) pulled from OCSF 1.8.
#
# Categories:
#   2 = Findings
#   3 = Identity & Access Management
#   4 = Network Activity
#   5 = Discovery
#   6 = Application Activity
CLASS_ACTIVITY_NAMES: dict[int, tuple[int, set[int], str]] = {
    # Findings
    2003: (2, {0, 1, 2, 3, 99}, "Compliance Finding"),
    2004: (2, {0, 1, 2, 3, 99}, "Detection Finding"),
    # Identity & Access Management
    3001: (3, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 99}, "Account Change"),
    3002: (3, {0, 1, 2, 3, 4, 5, 99}, "Authentication"),
    # Network Activity
    4002: (4, {0, 1, 2, 3, 4, 5, 6, 7, 8, 99}, "HTTP Activity"),
    # Discovery
    5023: (5, {0, 1, 2, 99}, "Cloud Resources Inventory Info"),
    # Application Activity
    6002: (6, {0, 1, 2, 3, 4, 5, 6, 99}, "Application Activity"),
    6003: (6, {0, 1, 2, 3, 4, 99}, "API Activity"),
}


def _is_int(value: Any) -> bool:
    # Booleans are ints in Python; exclude them explicitly.
    return isinstance(value, int) and not isinstance(value, bool)


def _get(event: dict[str, Any], *path: str) -> Any:
    node: Any = event
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _check_required_int(
    event: dict[str, Any], field: str, errors: list[str], *, allowed: set[int] | None = None
) -> int | None:
    value = event.get(field)
    if value is None:
        errors.append(f"missing required field `{field}`")
        return None
    if not _is_int(value):
        errors.append(f"`{field}` must be an int, got {type(value).__name__}")
        return None
    if allowed is not None and value not in allowed:
        errors.append(f"`{field}` value {value} not in allowed set {sorted(allowed)}")
    # _is_int narrowed value to int at runtime; cast explicitly for mypy.
    return int(value)


def _check_required_string(
    event: dict[str, Any], path: tuple[str, ...], errors: list[str]
) -> str | None:
    value = _get(event, *path)
    if value is None or value == "":
        errors.append(f"missing required field `{'.'.join(path)}`")
        return None
    if not isinstance(value, str):
        errors.append(f"`{'.'.join(path)}` must be a string, got {type(value).__name__}")
        return None
    return value


def _check_pinned_string(
    event: dict[str, Any], path: tuple[str, ...], expected: str, errors: list[str]
) -> None:
    value = _get(event, *path)
    if value != expected:
        errors.append(
            f"`{'.'.join(path)}` must be pinned to `{expected}` (OCSF_CONTRACT.md), got `{value!r}`"
        )


def validate_event(event: dict[str, Any]) -> list[str]:
    """Validate one OCSF 1.8 event. Returns a list of error messages.

    Empty list = valid. Callers decide whether to raise, warn-and-skip, or
    accumulate errors for a batch report.
    """
    errors: list[str] = []

    if not isinstance(event, dict):
        return [f"event must be a dict, got {type(event).__name__}"]

    # Core enumerations
    class_uid = _check_required_int(event, "class_uid", errors)
    activity_id = _check_required_int(event, "activity_id", errors)
    category_uid = _check_required_int(event, "category_uid", errors)
    type_uid = _check_required_int(event, "type_uid", errors)
    _check_required_int(event, "severity_id", errors, allowed=SEVERITY_IDS)

    # Class-aware cross-field checks
    if class_uid is not None and class_uid in CLASS_ACTIVITY_NAMES:
        expected_category, valid_activities, class_name_pin = CLASS_ACTIVITY_NAMES[class_uid]
        if activity_id is not None and activity_id not in valid_activities:
            errors.append(
                f"`activity_id` {activity_id} not valid for class {class_uid} "
                f"({class_name_pin}); allowed: {sorted(valid_activities)}"
            )
        if category_uid is not None and category_uid != expected_category:
            errors.append(
                f"`category_uid` {category_uid} does not match class {class_uid} "
                f"({class_name_pin}); expected {expected_category}"
            )
        # type_uid invariant per OCSF 1.8
        if activity_id is not None and type_uid is not None:
            expected_type_uid = class_uid * 100 + activity_id
            if type_uid != expected_type_uid:
                errors.append(
                    f"`type_uid` must equal class_uid*100 + activity_id "
                    f"= {expected_type_uid}, got {type_uid}"
                )
    # Unknown class_uid is allowed — caller may be emitting a class not yet
    # registered in CLASS_ACTIVITY_NAMES. Cross-field invariants are skipped
    # but core scalar checks above still run.

    # status_id is [rec] not [req] by OCSF 1.8 but pinned as expected-when-present.
    status_id = event.get("status_id")
    if status_id is not None:
        if not _is_int(status_id):
            errors.append(f"`status_id` must be an int, got {type(status_id).__name__}")
        elif status_id not in STATUS_IDS:
            errors.append(f"`status_id` value {status_id} not in allowed set {sorted(STATUS_IDS)}")

    # time: epoch milliseconds per contract, not seconds
    time_value = event.get("time")
    if time_value is None:
        errors.append("missing required field `time`")
    elif not _is_int(time_value):
        errors.append(
            f"`time` must be an int (epoch milliseconds), got {type(time_value).__name__}"
        )
    elif time_value < 1_000_000_000_000:
        # Any sane epoch-ms value after 2001-09-09 is > 1e12. Epoch-seconds
        # values (~1.7e9) are a common bug: caller emitted seconds not ms.
        errors.append(
            f"`time` looks like epoch seconds ({time_value}), OCSF_CONTRACT.md "
            "requires epoch milliseconds"
        )

    # metadata envelope
    metadata = event.get("metadata")
    if not isinstance(metadata, dict):
        errors.append("missing required field `metadata`")
    else:
        _check_pinned_string(event, ("metadata", "version"), OCSF_VERSION, errors)
        _check_required_string(event, ("metadata", "uid"), errors)
        _check_pinned_string(event, ("metadata", "product", "name"), REPO_PRODUCT_NAME, errors)
        _check_pinned_string(
            event, ("metadata", "product", "vendor_name"), REPO_PRODUCT_VENDOR, errors
        )
        feature_name = _check_required_string(
            event, ("metadata", "product", "feature", "name"), errors
        )
        if feature_name is not None and not feature_name.strip():
            errors.append("`metadata.product.feature.name` must not be blank")

    # Detection Finding (2004): finding_info.uid is load-bearing for dedupe
    if class_uid == 2004:
        _check_required_string(event, ("finding_info", "uid"), errors)
        _check_required_string(event, ("finding_info", "title"), errors)

    return errors


def validate_batch(events: list[dict[str, Any]]) -> list[tuple[int, list[str]]]:
    """Validate a list of events. Returns (index, errors) for each invalid event."""
    out: list[tuple[int, list[str]]] = []
    for idx, event in enumerate(events):
        errs = validate_event(event)
        if errs:
            out.append((idx, errs))
    return out
