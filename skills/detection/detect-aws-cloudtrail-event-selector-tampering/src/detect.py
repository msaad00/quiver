"""Detect AWS CloudTrail event-selector tampering — defense-evasion via narrowed audit scope.

Reads OCSF 1.8 API Activity (class 6003) records produced by
`ingest-cloudtrail-ocsf` and fires when a `PutEventSelectors` or
`UpdateTrail` call **structurally reduces** the audit-scope on a
CloudTrail trail without fully disabling it.

The detector commits to the structural signals it can prove from a
single OCSF event:

- `empty_event_selectors`       — `eventSelectors[]` is an empty array
- `management_events_disabled`  — `IncludeManagementEvents == false`
- `read_write_type_none`        — `ReadWriteType == "None"`
- `multi_region_collapsed`      — `UpdateTrail` flips `IsMultiRegionTrail`
                                  from true to false (requires the new
                                  value to be false AND the request
                                  payload to carry
                                  `previousIsMultiRegionTrail: true`)

A softer `data_resources_removed` signal is emitted when the upstream
ingester surfaces a diff under
`unmapped.cloudtrail.event_selector_change.removed_data_resources[]`.
The SKILL.md `Honesty caveat` documents why per-event-selector
data-resource subtraction cannot be detected from a single audit event
without that side-channel diff.

The detector backs MITRE ATT&CK T1562.001 (Disable or Modify Tools) —
the audit-impairment idiom executed against CloudTrail itself.

Contract: see ../SKILL.md and ../REFERENCES.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-aws-cloudtrail-event-selector-tampering"
CANONICAL_VERSION = "2026-04"
OCSF_VERSION = "1.8.0"
REPO_NAME = "cloud-ai-security-skills"

_log = get_logger(__name__, skill=SKILL_NAME, layer="detection")

API_ACTIVITY_CLASS_UID = 6003
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

MITRE_VERSION = "v14"
TACTIC_UID = "TA0005"
TACTIC_NAME = "Defense Evasion"
TECHNIQUE_UID = "T1562.001"
TECHNIQUE_NAME = "Impair Defenses: Disable or Modify Tools"

ACCEPTED_PRODUCERS = frozenset({"ingest-cloudtrail-ocsf"})
ANCHOR_OPERATIONS = frozenset({"PutEventSelectors", "UpdateTrail"})
OUTPUT_FORMATS = frozenset({"ocsf", "native"})

# Structural signal kinds (provable from one OCSF event) and the diff-context
# kind (requires upstream side-channel diff under
# unmapped.cloudtrail.event_selector_change).
SIGNAL_EMPTY = "empty_event_selectors"
SIGNAL_MGMT_DISABLED = "management_events_disabled"
SIGNAL_RW_NONE = "read_write_type_none"
SIGNAL_MULTI_REGION = "multi_region_collapsed"
SIGNAL_DATA_RESOURCES = "data_resources_removed"

STRUCTURAL_SIGNALS = frozenset(
    {SIGNAL_EMPTY, SIGNAL_MGMT_DISABLED, SIGNAL_RW_NONE, SIGNAL_MULTI_REGION}
)


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "")


def _is_success(event: dict[str, Any]) -> bool:
    return event.get("status_id") == STATUS_SUCCESS


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _account_uid(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    account = cloud.get("account") or {}
    return str(account.get("uid") or "")


def _region(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    return str(cloud.get("region") or "")


def _cloudtrail_unmapped(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    ct = unmapped.get("cloudtrail") if isinstance(unmapped, dict) else None
    return ct if isinstance(ct, dict) else {}


def _request_parameters(event: dict[str, Any]) -> dict[str, Any]:
    ct = _cloudtrail_unmapped(event)
    params = ct.get("request_parameters") or ct.get("requestParameters")
    return params if isinstance(params, dict) else {}


def _event_selector_change(event: dict[str, Any]) -> dict[str, Any]:
    ct = _cloudtrail_unmapped(event)
    change = ct.get("event_selector_change")
    return change if isinstance(change, dict) else {}


def _trail_identifier(event: dict[str, Any], params: dict[str, Any]) -> tuple[str, str]:
    name = str(params.get("trailName") or params.get("name") or "")
    arn = ""
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        rtype = str(resource.get("type") or "").lower()
        rname = str(resource.get("name") or resource.get("uid") or "")
        if not rname:
            continue
        if rname.startswith("arn:") and not arn:
            arn = rname
        if rtype in {"trailname", "trail"} and not name:
            name = rname
    if not name and arn:
        name = arn.split("/")[-1]
    return name, arn


def _event_selectors(params: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """Return (event-selectors list, present_flag).

    `present_flag` is True when the `eventSelectors` key is present in the
    payload (even if empty), False when absent. We distinguish them because
    only an explicit empty array on `PutEventSelectors` signals the operator
    intent to zero out the trail scope; an absent key is just an
    `UpdateTrail` event that touched a different field.
    """
    if "eventSelectors" in params:
        raw = params.get("eventSelectors")
        if isinstance(raw, list):
            return [s for s in raw if isinstance(s, dict)], True
        return [], True
    if "EventSelectors" in params:
        raw = params.get("EventSelectors")
        if isinstance(raw, list):
            return [s for s in raw if isinstance(s, dict)], True
        return [], True
    return [], False


def _truthy_false(value: Any) -> bool:
    """Treat the JSON booleans / strings `False`, `"false"` (case-insens) as false."""
    if value is False:
        return True
    if isinstance(value, str):
        return value.strip().lower() == "false"
    return False


def _truthy_true(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def _structural_signals(*, operation: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the structural-signal entries proven by this single event."""
    signals: list[dict[str, Any]] = []
    selectors, present = _event_selectors(params)

    if operation == "PutEventSelectors":
        if present and not selectors:
            signals.append(
                {
                    "kind": SIGNAL_EMPTY,
                    "summary": "PutEventSelectors shipped an empty eventSelectors array",
                    "evidence_payload": {"eventSelectors": []},
                }
            )
        for idx, sel in enumerate(selectors):
            include_mgmt = sel.get("IncludeManagementEvents")
            if include_mgmt is None:
                include_mgmt = sel.get("includeManagementEvents")
            if include_mgmt is not None and _truthy_false(include_mgmt):
                signals.append(
                    {
                        "kind": SIGNAL_MGMT_DISABLED,
                        "summary": (f"selector[{idx}] has IncludeManagementEvents=false"),
                        "evidence_payload": {
                            "selector_index": idx,
                            "IncludeManagementEvents": False,
                        },
                    }
                )
            rwt = sel.get("ReadWriteType") or sel.get("readWriteType")
            if isinstance(rwt, str) and rwt.strip().lower() == "none":
                signals.append(
                    {
                        "kind": SIGNAL_RW_NONE,
                        "summary": (f"selector[{idx}] has ReadWriteType='None'"),
                        "evidence_payload": {
                            "selector_index": idx,
                            "ReadWriteType": "None",
                        },
                    }
                )

    if operation == "UpdateTrail":
        # The request payload for UpdateTrail carries the *new* settings.
        # Multi-region collapse is only confirmable when both the new value
        # is false AND the upstream surfaces the previous value.
        new_is_multi = params.get("isMultiRegionTrail")
        if new_is_multi is None:
            new_is_multi = params.get("IsMultiRegionTrail")
        prev_is_multi = params.get("previousIsMultiRegionTrail")
        if prev_is_multi is None:
            prev_is_multi = params.get("PreviousIsMultiRegionTrail")
        if (
            new_is_multi is not None
            and _truthy_false(new_is_multi)
            and prev_is_multi is not None
            and _truthy_true(prev_is_multi)
        ):
            signals.append(
                {
                    "kind": SIGNAL_MULTI_REGION,
                    "summary": ("UpdateTrail collapsed IsMultiRegionTrail from true to false"),
                    "evidence_payload": {
                        "IsMultiRegionTrail": False,
                        "previousIsMultiRegionTrail": True,
                    },
                }
            )

    return signals


def _diff_context_signals(event: dict[str, Any]) -> list[dict[str, Any]]:
    change = _event_selector_change(event)
    removed = change.get("removed_data_resources") if isinstance(change, dict) else None
    if not isinstance(removed, list) or not removed:
        return []
    # Compact each removed entry to a JSON-stable shape for the evidence body.
    normalized: list[dict[str, Any]] = []
    for entry in removed:
        if isinstance(entry, dict):
            normalized.append(entry)
    if not normalized:
        return []
    return [
        {
            "kind": SIGNAL_DATA_RESOURCES,
            "summary": (
                f"{len(normalized)} DataResources entry/entries removed "
                "(upstream-supplied diff context)"
            ),
            "evidence_payload": {"removed_data_resources": normalized},
        }
    ]


def _finding_uid(
    *,
    trail_name: str,
    trail_arn: str,
    account_uid: str,
    signal_kind: str,
    time_ms: int,
) -> str:
    material = f"{SKILL_NAME}|{trail_arn or trail_name}|{account_uid}|{signal_kind}|{time_ms}"
    return f"ctest-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(
    *,
    event: dict[str, Any],
    operation: str,
    trail_name: str,
    trail_arn: str,
    account_uid: str,
    region: str,
    signal: dict[str, Any],
) -> dict[str, Any]:
    time_ms = int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)
    event_uid = str((event.get("metadata") or {}).get("uid") or "")
    signal_provenance = "diff_context" if signal["kind"] == SIGNAL_DATA_RESOURCES else "structural"
    finding_uid = _finding_uid(
        trail_name=trail_name,
        trail_arn=trail_arn,
        account_uid=account_uid,
        signal_kind=signal["kind"],
        time_ms=time_ms,
    )
    actor = _actor_name(event)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "api_operation": operation,
        "trail_name": trail_name,
        "trail_arn": trail_arn,
        "account_uid": account_uid,
        "region": region,
        "signal_kind": signal["kind"],
        "signal_provenance": signal_provenance,
        "signal_summary": signal["summary"],
        "signal_evidence": signal["evidence_payload"],
        "actor_name": actor,
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "raw_event_uid": event_uid,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    trail_label = native["trail_arn"] or native["trail_name"] or "<unknown>"
    description = (
        f"Actor `{native['actor_name'] or 'unknown'}` invoked "
        f"`{native['api_operation']}` against CloudTrail trail `{trail_label}` "
        f"(account `{native['account_uid']}` / region `{native['region']}`) and "
        f"triggered the `{native['signal_kind']}` structural signal: "
        f"{native['signal_summary']}. Signal provenance: "
        f"{native['signal_provenance']}."
    )
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "AWS"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "api.operation", "type": "Other", "value": native["api_operation"]},
        {"name": "trail.name", "type": "Other", "value": native["trail_name"]},
        {"name": "trail.arn", "type": "Other", "value": native["trail_arn"]},
        {"name": "account.uid", "type": "Other", "value": native["account_uid"]},
        {"name": "region", "type": "Other", "value": native["region"]},
    ]
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_HIGH,
        "status_id": STATUS_SUCCESS,
        "time": native["first_seen_time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native["finding_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["aws", "cloudtrail", "defense-evasion", "audit-impair"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": (
                f"CloudTrail audit scope reduced on `{native['trail_name'] or trail_label}` "
                f"({native['signal_kind']})"
            ),
            "desc": description,
            "types": [
                "aws-cloudtrail-event-selector-tampering",
                f"signal-{native['signal_kind']}",
            ],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": TACTIC_NAME, "uid": TACTIC_UID},
                    "technique": {
                        "name": TECHNIQUE_NAME,
                        "uid": TECHNIQUE_UID,
                    },
                }
            ],
        },
        "observables": observables,
        "evidence": {
            "events_observed": 1,
            "api_operation": native["api_operation"],
            "trail_name": native["trail_name"],
            "trail_arn": native["trail_arn"],
            "account_uid": native["account_uid"],
            "region": native["region"],
            "signal_kind": native["signal_kind"],
            "signal_provenance": native["signal_provenance"],
            "signal_summary": native["signal_summary"],
            "signal_evidence": native["signal_evidence"],
        },
    }


def coverage_metadata() -> dict[str, Any]:
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14"),
        "providers": ("aws",),
        "asset_classes": ("cloudtrail", "audit-log", "trails"),
        "attack_coverage": {
            "aws": {
                "anchor_operations": sorted(ANCHOR_OPERATIONS),
                "techniques": [TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "structural_signals": sorted(STRUCTURAL_SIGNALS),
            "diff_context_signals": [SIGNAL_DATA_RESOURCES],
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(
            f"unsupported output_format `{output_format}`",
            hint=f"choose one of: {', '.join(sorted(OUTPUT_FORMATS))}",
        )

    dedupe: set[str] = set()
    for event in events:
        producer = _producer(event)
        if producer not in ACCEPTED_PRODUCERS:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="wrong_source",
                message=f"skipping event from non-cloudtrail producer `{producer}`",
            )
            continue
        operation = _api_operation(event)
        if operation not in ANCHOR_OPERATIONS:
            continue
        if not _is_success(event):
            continue

        meta_uid = str((event.get("metadata") or {}).get("uid") or "")
        if meta_uid and meta_uid in dedupe:
            continue
        if meta_uid:
            dedupe.add(meta_uid)

        params = _request_parameters(event)
        if not params and not _event_selector_change(event):
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_request_parameters",
                message=(
                    f"{operation} event has no `unmapped.cloudtrail.request_parameters`; skipping"
                ),
            )
            continue

        trail_name, trail_arn = _trail_identifier(event, params)
        account_uid = _account_uid(event)
        region = _region(event)

        signals = _structural_signals(operation=operation, params=params)
        signals.extend(_diff_context_signals(event))
        if not signals:
            continue

        # Deduplicate (trail_uid, signal_kind) within one event so a
        # malformed payload listing the same kind twice does not double-fire.
        seen: set[str] = set()
        for signal in signals:
            key = f"{trail_arn or trail_name}|{signal['kind']}"
            if key in seen:
                continue
            seen.add(key)
            native = _build_native_finding(
                event=event,
                operation=operation,
                trail_name=trail_name,
                trail_arn=trail_arn,
                account_uid=account_uid,
                region=region,
                signal=signal,
            )
            yield native if output_format == "native" else _to_ocsf(native)


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
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
            )
            continue
        if isinstance(obj, dict):
            yield obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Detect AWS CloudTrail event-selector tampering — defense-evasion "
            "via narrowed audit scope."
        )
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="Emit OCSF Detection Finding (default) or native projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    findings_emitted = 0
    try:
        events = list(load_jsonl(in_stream))
        _log.info(
            f"{SKILL_NAME} starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            f"{SKILL_NAME} complete",
            extra={"findings_emitted": findings_emitted},
        )
    except SkillError as exc:
        return emit_error(SKILL_NAME, exc)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return emit_error(
            SKILL_NAME,
            ContractError(
                f"input is not JSONL: {exc}",
                hint="ensure each input line is a valid OCSF 1.8 API Activity 6003 JSON object",
            ),
        )
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
