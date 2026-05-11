"""Detect AWS S3 cross-region or cross-account replication-rule creation.

Reads OCSF 1.8 API Activity (class 6003) records produced by
`ingest-cloudtrail-ocsf` and fires when a `PutBucketReplication` call ships
data to a destination bucket in a different region OR a different account
than the source. The detector backs MITRE ATT&CK T1537 (Transfer Data to
Cloud Account) and T1567 (Exfiltration Over Web Service).

The destination-bucket allowlist `AWS_REPLICATION_AUTHORIZED_BUCKETS`
(comma-separated list of bucket names or ARNs; default empty = fail-open
with a stderr warning, mirroring `detect-snowflake-unauthorized-grant`)
narrows the rule to bucket destinations the operator has not approved.

Contract: see ../SKILL.md and ../REFERENCES.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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

SKILL_NAME = "detect-aws-s3-cross-region-replication"
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
TACTIC_UID = "TA0010"
TACTIC_NAME = "Exfiltration"
PRIMARY_TECHNIQUE_UID = "T1537"
PRIMARY_TECHNIQUE_NAME = "Transfer Data to Cloud Account"
SECONDARY_TECHNIQUE_UID = "T1567"
SECONDARY_TECHNIQUE_NAME = "Exfiltration Over Web Service"

ACCEPTED_PRODUCERS = frozenset({"ingest-cloudtrail-ocsf"})
ANCHOR_OPERATION = "PutBucketReplication"
OUTPUT_FORMATS = frozenset({"ocsf", "native"})

AUTHORIZED_BUCKETS_ENV = "AWS_REPLICATION_AUTHORIZED_BUCKETS"

_ARN_PATTERN = re.compile(
    r"^arn:aws[^:]*:s3:::(?P<bucket>[a-z0-9.\-]+)(?:/.*)?$"
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


def _source_account(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    account = cloud.get("account") or {}
    return str(account.get("uid") or "")


def _source_region(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    return str(cloud.get("region") or "")


def _request_parameters(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    cloudtrail = unmapped.get("cloudtrail") if isinstance(unmapped, dict) else None
    if isinstance(cloudtrail, dict):
        params = cloudtrail.get("request_parameters") or cloudtrail.get("requestParameters")
        if isinstance(params, dict):
            return params
    return {}


def _source_bucket(event: dict[str, Any], params: dict[str, Any]) -> str:
    bucket = str(params.get("bucketName") or params.get("bucket") or "")
    if bucket:
        return bucket
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        rtype = str(resource.get("type") or "").lower()
        rname = str(resource.get("name") or "")
        if rtype in {"bucketname", "bucket"} and rname:
            return rname
    return ""


def _parse_arn(arn: str) -> tuple[str, str, str]:
    """Return (bucket, account, region) from an S3 destination ARN.

    `arn:aws:s3:::bucket-name` carries the bucket only. We surface the bucket
    and leave account/region empty — the replication-rule destination
    parameters explicitly carry account / region fields alongside.
    """
    m = _ARN_PATTERN.match(arn or "")
    bucket = m.group("bucket") if m else ""
    return bucket, "", ""


def _destination_rules(params: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract replication rules from the request-parameter payload.

    The CloudTrail-shaped payload for `PutBucketReplication` carries the
    request as either `replicationConfiguration.rules[]` or the
    `ReplicationConfiguration.Rule` XML shape. We accept both.
    """
    config = (
        params.get("replicationConfiguration")
        or params.get("ReplicationConfiguration")
        or {}
    )
    if not isinstance(config, dict):
        return []
    rules: list[dict[str, Any]] = []
    raw_rules = config.get("rules") or config.get("Rule") or config.get("Rules") or []
    if isinstance(raw_rules, dict):
        raw_rules = [raw_rules]
    if not isinstance(raw_rules, list):
        return []
    for rule in raw_rules:
        if isinstance(rule, dict):
            rules.append(rule)
    return rules


def _destination_block(rule: dict[str, Any]) -> dict[str, Any]:
    dest = rule.get("destination") or rule.get("Destination") or {}
    return dest if isinstance(dest, dict) else {}


def _destination_attrs(rule: dict[str, Any]) -> tuple[str, str, str]:
    """Return (destination_bucket, destination_account, destination_region)."""
    dest = _destination_block(rule)
    bucket = str(dest.get("bucket") or dest.get("Bucket") or "")
    account = str(dest.get("account") or dest.get("Account") or "")
    storage_class = str(dest.get("storageClass") or dest.get("StorageClass") or "")
    del storage_class  # not used for the decision; reserved for evidence
    region = ""
    bucket_from_arn = ""
    if bucket.startswith("arn:"):
        bucket_from_arn, _, _ = _parse_arn(bucket)
    bucket_name = bucket_from_arn or bucket
    # Optional explicit region on the rule destination.
    raw_region = dest.get("region") or dest.get("Region") or ""
    if isinstance(raw_region, str):
        region = raw_region
    return bucket_name, account, region


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def _authorized_buckets() -> frozenset[str]:
    return _parse_env_set(AUTHORIZED_BUCKETS_ENV)


def _is_authorized_bucket(bucket: str, allowlist: frozenset[str]) -> bool:
    candidate = bucket.strip().lower()
    if not candidate:
        return False
    if candidate in allowlist:
        return True
    # arn:aws:s3:::bucket entries — strip prefix
    parsed, _, _ = _parse_arn(bucket)
    if parsed and parsed.lower() in allowlist:
        return True
    return False


def _finding_uid(
    *, source_bucket: str, dest_bucket: str, source_account: str, dest_account: str, time_ms: int
) -> str:
    material = (
        f"{SKILL_NAME}|{source_bucket}|{dest_bucket}|{source_account}|{dest_account}|{time_ms}"
    )
    return f"s3xr-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _classify(
    *,
    source_region: str,
    dest_region: str,
    source_account: str,
    dest_account: str,
) -> str:
    cross_region = bool(dest_region and source_region and dest_region != source_region)
    cross_account = bool(dest_account and source_account and dest_account != source_account)
    if cross_account and cross_region:
        return "cross-account-and-region"
    if cross_account:
        return "cross-account"
    if cross_region:
        return "cross-region"
    return "same-region-and-account"


def _build_native_finding(
    *,
    event: dict[str, Any],
    source_bucket: str,
    source_account: str,
    source_region: str,
    rule: dict[str, Any],
    dest_bucket: str,
    dest_account: str,
    dest_region: str,
    allowlist_mode: str,
    boundary: str,
) -> dict[str, Any]:
    time_ms = int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)
    event_uid = str((event.get("metadata") or {}).get("uid") or "")
    finding_uid = _finding_uid(
        source_bucket=source_bucket,
        dest_bucket=dest_bucket,
        source_account=source_account,
        dest_account=dest_account,
        time_ms=time_ms,
    )
    actor = _actor_name(event)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule_id": str(rule.get("id") or rule.get("ID") or ""),
        "api_operation": ANCHOR_OPERATION,
        "source_bucket": source_bucket,
        "source_account": source_account,
        "source_region": source_region,
        "destination_bucket": dest_bucket,
        "destination_account": dest_account,
        "destination_region": dest_region,
        "boundary": boundary,
        "allowlist_mode": allowlist_mode,
        "actor_name": actor,
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "raw_event_uid": event_uid,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    src_label = native["source_bucket"] or "<unknown>"
    dest_label = native["destination_bucket"] or "<unknown>"
    description = (
        f"Actor `{native['actor_name'] or 'unknown'}` configured an S3 "
        f"`PutBucketReplication` rule on bucket `{src_label}` (account "
        f"`{native['source_account']}` / region `{native['source_region']}`) "
        f"that ships objects to `{dest_label}` (account `{native['destination_account'] or 'same'}` "
        f"/ region `{native['destination_region'] or 'unspecified'}`). Boundary: "
        f"{native['boundary']}. Allow-list mode: {native['allowlist_mode']}."
    )
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "AWS"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "api.operation", "type": "Other", "value": native["api_operation"]},
        {"name": "source.bucket", "type": "Other", "value": native["source_bucket"]},
        {"name": "destination.bucket", "type": "Other", "value": native["destination_bucket"]},
        {"name": "source.account", "type": "Other", "value": native["source_account"]},
        {"name": "destination.account", "type": "Other", "value": native["destination_account"]},
        {"name": "source.region", "type": "Other", "value": native["source_region"]},
        {"name": "destination.region", "type": "Other", "value": native["destination_region"]},
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
            "labels": ["aws", "s3", "exfiltration", "replication"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": f"S3 {native['boundary']} replication to `{native['destination_bucket']}`",
            "desc": description,
            "types": [
                "aws-s3-cross-region-replication",
                f"boundary-{native['boundary']}",
            ],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": TACTIC_NAME, "uid": TACTIC_UID},
                    "technique": {
                        "name": PRIMARY_TECHNIQUE_NAME,
                        "uid": PRIMARY_TECHNIQUE_UID,
                    },
                },
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": TACTIC_NAME, "uid": TACTIC_UID},
                    "technique": {
                        "name": SECONDARY_TECHNIQUE_NAME,
                        "uid": SECONDARY_TECHNIQUE_UID,
                    },
                },
            ],
        },
        "observables": observables,
        "evidence": {
            "events_observed": 1,
            "api_operation": native["api_operation"],
            "source_bucket": native["source_bucket"],
            "source_account": native["source_account"],
            "source_region": native["source_region"],
            "destination_bucket": native["destination_bucket"],
            "destination_account": native["destination_account"],
            "destination_region": native["destination_region"],
            "boundary": native["boundary"],
            "allowlist_mode": native["allowlist_mode"],
            "rule_id": native["rule_id"],
        },
    }


def coverage_metadata() -> dict[str, Any]:
    allowlist = _authorized_buckets()
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14"),
        "providers": ("aws",),
        "asset_classes": ("s3", "buckets", "data"),
        "attack_coverage": {
            "aws": {
                "anchor_operations": [ANCHOR_OPERATION],
                "techniques": [PRIMARY_TECHNIQUE_UID, SECONDARY_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "authorized_bucket_count": len(allowlist),
            "allowlist_mode": "fail-open" if not allowlist else "enforced",
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

    allowlist = _authorized_buckets()
    allowlist_mode = "enforced" if allowlist else "fail-open"
    if allowlist_mode == "fail-open":
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="allowlist_fail_open",
            message=(
                "AWS_REPLICATION_AUTHORIZED_BUCKETS is empty; firing on every "
                "cross-region / cross-account replication rule. Set the allow-list "
                "to scope the detection to approved destinations."
            ),
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
        if _api_operation(event) != ANCHOR_OPERATION:
            continue
        if not _is_success(event):
            continue

        meta_uid = str((event.get("metadata") or {}).get("uid") or "")
        if meta_uid and meta_uid in dedupe:
            continue
        if meta_uid:
            dedupe.add(meta_uid)

        params = _request_parameters(event)
        source_bucket = _source_bucket(event, params)
        if not source_bucket:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_source_bucket",
                message="PutBucketReplication event missing source bucket; skipping",
            )
            continue

        source_account = _source_account(event)
        source_region = _source_region(event)
        rules = _destination_rules(params)
        if not rules:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_replication_rules",
                message=f"PutBucketReplication on `{source_bucket}` carries no rules; skipping",
            )
            continue

        for rule in rules:
            dest_bucket, dest_account, dest_region = _destination_attrs(rule)
            if not dest_bucket:
                continue
            boundary = _classify(
                source_region=source_region,
                dest_region=dest_region,
                source_account=source_account,
                dest_account=dest_account,
            )
            if boundary == "same-region-and-account":
                continue
            if allowlist_mode == "enforced" and _is_authorized_bucket(dest_bucket, allowlist):
                continue
            native = _build_native_finding(
                event=event,
                source_bucket=source_bucket,
                source_account=source_account,
                source_region=source_region,
                rule=rule,
                dest_bucket=dest_bucket,
                dest_account=dest_account,
                dest_region=dest_region,
                allowlist_mode=allowlist_mode,
                boundary=boundary,
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
        description="Detect AWS S3 cross-region / cross-account replication-rule creation."
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
