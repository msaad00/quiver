"""Evaluate CIS AWS Foundations controls from AWS Config OCSF evidence.

This is the decoupled evaluator half of the AWS Config roadmap path:
`ingest-aws-config-ocsf` records configuration evidence, this skill reads that
evidence without calling AWS APIs, and the output is one Compliance Finding per
implemented CIS AWS Foundations v3.0 control.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.evaluation_ocsf import findings_to_native, findings_to_ocsf  # noqa: E402

SKILL_NAME = "evaluate-cis-aws-foundations-ocsf"
BENCHMARK_NAME = "CIS AWS Foundations Benchmark v3.0 over AWS Config OCSF"
PROVIDER_NAME = "AWS"
FRAMEWORKS = ("CIS AWS Foundations v3.0", "OCSF 1.8", "NIST CSF 2.0", "ISO 27001:2022", "SOC 2 TSC")
OUTPUT_FORMATS = ("native", "ocsf")

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_NA = "NOT_APPLICABLE"
STATUS_ERROR = "ERROR"


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    section: str
    severity: str
    nist_csf: str
    iso_27001: str
    remediation: str


@dataclass
class Finding:
    control_id: str
    title: str
    section: str
    severity: str
    status: str
    detail: str = ""
    remediation: str = ""
    cis_control: str = ""
    nist_csf: str = ""
    iso_27001: str = ""
    resources: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ConfigItem:
    resource_type: str
    resource_id: str
    resource_name: str
    account_uid: str
    region: str
    time_ms: int
    configuration: dict[str, Any]
    tags: dict[str, Any]
    relationships: list[dict[str, Any]]
    source_uid: str


@dataclass(frozen=True)
class ConfigCompliance:
    rule_name: str
    status: str
    resource_type: str
    resource_id: str
    account_uid: str
    region: str
    time_ms: int
    description: str


CONTROLS: tuple[Control, ...] = (
    Control(
        "2.1",
        "S3 buckets have default server-side encryption enabled",
        "storage",
        "HIGH",
        "PR.DS-1",
        "A.8.24",
        "Enable S3 default encryption with SSE-S3 or SSE-KMS on every bucket.",
    ),
    Control(
        "2.2",
        "S3 buckets have server access logging enabled",
        "storage",
        "MEDIUM",
        "DE.AE-3",
        "A.8.15",
        "Configure S3 server access logging to a controlled log bucket.",
    ),
    Control(
        "2.3",
        "S3 buckets block public access",
        "storage",
        "CRITICAL",
        "PR.AC-3",
        "A.8.3",
        "Enable all four S3 public access block settings at bucket or account scope.",
    ),
    Control(
        "2.4",
        "S3 buckets have versioning enabled",
        "storage",
        "MEDIUM",
        "PR.DS-1",
        "A.8.13",
        "Enable S3 bucket versioning for recovery and evidence retention.",
    ),
    Control(
        "3.1",
        "CloudTrail trails are multi-region",
        "logging",
        "CRITICAL",
        "DE.AE-3",
        "A.8.15",
        "Create or update CloudTrail trails with IsMultiRegionTrail enabled.",
    ),
    Control(
        "3.2",
        "CloudTrail log file validation is enabled",
        "logging",
        "HIGH",
        "PR.DS-6",
        "A.8.15",
        "Enable CloudTrail log file validation on every trail.",
    ),
    Control(
        "3.5",
        "CloudTrail logs are encrypted with KMS",
        "logging",
        "MEDIUM",
        "PR.DS-1",
        "A.8.24",
        "Set a customer-managed KMS key on CloudTrail log delivery.",
    ),
    Control(
        "4.1",
        "Security groups do not allow unrestricted SSH",
        "networking",
        "HIGH",
        "PR.AC-5",
        "A.8.20",
        "Restrict inbound TCP/22 to approved administrative networks.",
    ),
    Control(
        "4.2",
        "Security groups do not allow unrestricted RDP",
        "networking",
        "HIGH",
        "PR.AC-5",
        "A.8.20",
        "Restrict inbound TCP/3389 to approved administrative networks.",
    ),
    Control(
        "4.3",
        "VPC flow logs are enabled",
        "networking",
        "MEDIUM",
        "DE.CM-1",
        "A.8.16",
        "Enable VPC flow logs for each VPC and retain them in a monitored sink.",
    ),
    Control(
        "6.1",
        "GuardDuty is enabled",
        "security-services",
        "MEDIUM",
        "DE.CM-1",
        "A.8.16",
        "Enable GuardDuty detectors in each account and region.",
    ),
    Control(
        "6.2",
        "Security Hub is enabled",
        "security-services",
        "MEDIUM",
        "DE.CM-1",
        "A.8.16",
        "Enable Security Hub and import AWS Foundational Security Best Practices.",
    ),
)

DOCUMENTED_NOT_IMPLEMENTED: tuple[str, ...] = (
    "1.1",
    "1.2",
    "1.3",
    "1.4",
    "1.5",
    "1.6",
    "1.7",
    "3.3",
    "3.4",
    "3.6",
)

CONFIG_RULE_TO_CONTROL = {
    "s3-bucket-server-side-encryption-enabled": "2.1",
    "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED": "2.1",
    "s3-bucket-logging-enabled": "2.2",
    "S3_BUCKET_LOGGING_ENABLED": "2.2",
    "s3-bucket-public-read-prohibited": "2.3",
    "s3-bucket-public-write-prohibited": "2.3",
    "S3_BUCKET_PUBLIC_READ_PROHIBITED": "2.3",
    "S3_BUCKET_PUBLIC_WRITE_PROHIBITED": "2.3",
    "s3-bucket-versioning-enabled": "2.4",
    "S3_BUCKET_VERSIONING_ENABLED": "2.4",
    "multi-region-cloudtrail-enabled": "3.1",
    "MULTI_REGION_CLOUD_TRAIL_ENABLED": "3.1",
    "cloud-trail-log-file-validation-enabled": "3.2",
    "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED": "3.2",
    "cloud-trail-encryption-enabled": "3.5",
    "CLOUD_TRAIL_ENCRYPTION_ENABLED": "3.5",
    "restricted-ssh": "4.1",
    "INCOMING_SSH_DISABLED": "4.1",
    "restricted-common-ports": "4.2",
    "VPC_FLOW_LOGS_ENABLED": "4.3",
    "vpc-flow-logs-enabled": "4.3",
    "GUARDDUTY_ENABLED_CENTRALIZED": "6.1",
    "guardduty-enabled-centralized": "6.1",
    "SECURITYHUB_ENABLED": "6.2",
    "securityhub-enabled": "6.2",
}


def benchmark_metadata() -> dict[str, Any]:
    return {
        "frameworks": list(FRAMEWORKS),
        "implemented_controls": [control.control_id for control in CONTROLS],
        "implemented_count": len(CONTROLS),
        "documented_not_implemented": list(DOCUMENTED_NOT_IMPLEMENTED),
        "input_classes": [6003, 2003],
        "source_skill": "ingest-aws-config-ocsf",
    }


def load_records(
    path: str | Path | None, stream: Iterable[str] | None = None
) -> list[dict[str, Any]]:
    if path:
        text = Path(path).read_text(encoding="utf-8")
    elif stream is not None:
        text = "".join(stream)
    else:
        text = sys.stdin.read()
    return parse_records(text)


def parse_records(text: str) -> list[dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {lineno}: JSON parse failed: {exc}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"line {lineno}: JSONL records must be objects")
            records.append(obj)
        return records
    if isinstance(parsed, list):
        if not all(isinstance(item, dict) for item in parsed):
            raise ValueError("JSON array input must contain objects")
        return list(parsed)
    if isinstance(parsed, dict):
        return [parsed]
    raise ValueError(f"input must be JSON object, array, or JSONL; got {type(parsed).__name__}")


def _lower_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k).lower(): _lower_keys(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_lower_keys(v) for v in value]
    return value


def _as_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(k): v for k, v in value.items()}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [_as_dict(item) for item in value if isinstance(item, dict)]


def _get_ci(record: dict[str, Any]) -> ConfigItem | None:
    record_type = str(record.get("record_type") or "")
    class_uid = int(record.get("class_uid") or 0)
    if record_type != "aws_config_configuration_item" and class_uid != 6003:
        return None

    if record_type == "aws_config_configuration_item":
        resource = _as_dict(record.get("resource"))
        return ConfigItem(
            resource_type=str(record.get("resource_type") or resource.get("type") or ""),
            resource_id=str(record.get("resource_id") or resource.get("uid") or ""),
            resource_name=str(resource.get("name") or record.get("resource_id") or ""),
            account_uid=str(record.get("account_uid") or ""),
            region=str(record.get("region") or resource.get("region") or ""),
            time_ms=int(record.get("time_ms") or 0),
            configuration=_as_dict(record.get("configuration")),
            tags=_as_dict(record.get("tags")),
            relationships=_as_dict_list(record.get("relationships")),
            source_uid=str(record.get("event_uid") or ""),
        )

    unmapped = _as_dict(record.get("unmapped"))
    aws_config = _as_dict(unmapped.get("aws_config"))
    resources = _as_list(record.get("resources"))
    resource = _as_dict(resources[0]) if resources else {}
    cloud = _as_dict(record.get("cloud"))
    account = _as_dict(cloud.get("account"))
    metadata = _as_dict(record.get("metadata"))
    return ConfigItem(
        resource_type=str(resource.get("type") or ""),
        resource_id=str(resource.get("uid") or resource.get("name") or ""),
        resource_name=str(resource.get("name") or resource.get("uid") or ""),
        account_uid=str(account.get("uid") or ""),
        region=str(resource.get("region") or cloud.get("region") or ""),
        time_ms=int(record.get("time") or 0),
        configuration=_as_dict(aws_config.get("configuration")),
        tags=_as_dict(aws_config.get("tags")),
        relationships=_as_dict_list(aws_config.get("relationships")),
        source_uid=str(metadata.get("uid") or ""),
    )


def _get_compliance(record: dict[str, Any]) -> ConfigCompliance | None:
    record_type = str(record.get("record_type") or "")
    class_uid = int(record.get("class_uid") or 0)
    if record_type != "aws_config_compliance_finding" and class_uid != 2003:
        return None

    if record_type == "aws_config_compliance_finding":
        return ConfigCompliance(
            rule_name=str(record.get("rule_name") or ""),
            status=str(record.get("status") or ""),
            resource_type=str(record.get("resource_type") or ""),
            resource_id=str(record.get("resource_id") or ""),
            account_uid=str(record.get("account_uid") or ""),
            region=str(record.get("region") or ""),
            time_ms=int(record.get("time_ms") or 0),
            description=str(record.get("description") or ""),
        )

    evidence = _as_dict(record.get("evidence"))
    if evidence.get("source") != "AWS Config":
        return None
    compliance = _as_dict(record.get("compliance"))
    resources = _as_list(record.get("resources"))
    resource = _as_dict(resources[0]) if resources else {}
    cloud = _as_dict(record.get("cloud"))
    account = _as_dict(cloud.get("account"))
    finding_info = _as_dict(record.get("finding_info"))
    return ConfigCompliance(
        rule_name=str(evidence.get("rule_name") or compliance.get("control") or ""),
        status=str(compliance.get("status") or ""),
        resource_type=str(resource.get("type") or ""),
        resource_id=str(resource.get("uid") or resource.get("name") or ""),
        account_uid=str(account.get("uid") or ""),
        region=str(resource.get("region") or cloud.get("region") or ""),
        time_ms=int(record.get("time") or 0),
        description=str(finding_info.get("desc") or ""),
    )


def _latest_items(records: list[dict[str, Any]]) -> list[ConfigItem]:
    by_key: dict[tuple[str, str], ConfigItem] = {}
    for record in records:
        item = _get_ci(record)
        if item is None or not item.resource_type or not item.resource_id:
            continue
        key = (item.resource_type, item.resource_id)
        if key not in by_key or item.time_ms >= by_key[key].time_ms:
            by_key[key] = item
    return list(by_key.values())


def _compliance_by_control(records: list[dict[str, Any]]) -> dict[str, list[ConfigCompliance]]:
    mapped: dict[str, list[ConfigCompliance]] = {}
    for record in records:
        compliance = _get_compliance(record)
        if compliance is None or not compliance.rule_name:
            continue
        control_id = CONFIG_RULE_TO_CONTROL.get(compliance.rule_name)
        if control_id is None:
            control_id = CONFIG_RULE_TO_CONTROL.get(compliance.rule_name.lower())
        if control_id:
            mapped.setdefault(control_id, []).append(compliance)
    return mapped


def _items_of(items: list[ConfigItem], resource_type: str) -> list[ConfigItem]:
    return [item for item in items if item.resource_type == resource_type]


def _bool(config: dict[str, Any], *keys: str) -> bool:
    cur: Any = _lower_keys(config)
    for key in keys:
        if not isinstance(cur, dict):
            return False
        cur = cur.get(key.lower())
    return cur is True or str(cur).lower() == "true"


def _dict(config: dict[str, Any], *keys: str) -> dict[str, Any]:
    cur: Any = _lower_keys(config)
    for key in keys:
        if not isinstance(cur, dict):
            return {}
        cur = cur.get(key.lower())
    return cur if isinstance(cur, dict) else {}


def _list(config: dict[str, Any], *keys: str) -> list[Any]:
    cur: Any = _lower_keys(config)
    for key in keys:
        if not isinstance(cur, dict):
            return []
        cur = cur.get(key.lower())
    return cur if isinstance(cur, list) else []


def _resource_label(item: ConfigItem) -> str:
    region = f":{item.region}" if item.region else ""
    return f"{item.resource_type}:{item.resource_id}{region}"


def _finding(control: Control, status: str, detail: str, resources: list[str]) -> Finding:
    return Finding(
        control_id=control.control_id,
        title=control.title,
        section=control.section,
        severity=control.severity,
        status=status,
        detail=detail,
        remediation="" if status == STATUS_PASS else control.remediation,
        cis_control=f"CIS AWS Foundations v3.0 {control.control_id}",
        nist_csf=control.nist_csf,
        iso_27001=control.iso_27001,
        resources=resources,
    )


def _aggregate_resource_check(
    control: Control,
    items: list[ConfigItem],
    predicate: Any,
    *,
    empty_detail: str,
    fail_detail: str,
) -> Finding:
    if not items:
        return _finding(control, STATUS_NA, empty_detail, [])
    failed = [_resource_label(item) for item in items if not predicate(item.configuration, item)]
    if failed:
        return _finding(control, STATUS_FAIL, f"{fail_detail}: {', '.join(failed)}", failed)
    return _finding(
        control,
        STATUS_PASS,
        f"{len(items)} resource(s) passed",
        [_resource_label(i) for i in items],
    )


def _has_s3_encryption(config: dict[str, Any], _item: ConfigItem) -> bool:
    cfg = _dict(config, "bucketEncryption")
    if cfg:
        rules = _list(cfg, "serverSideEncryptionConfiguration")
        return bool(rules)
    return bool(_list(config, "serverSideEncryptionConfiguration"))


def _has_s3_logging(config: dict[str, Any], _item: ConfigItem) -> bool:
    logging_cfg = _dict(config, "loggingConfiguration")
    if logging_cfg.get("destinationbucketname") or logging_cfg.get("targetbucket"):
        return True
    nested = _dict(config, "bucketLoggingConfiguration", "loggingEnabled")
    return bool(nested.get("targetbucket") or nested.get("destinationbucketname"))


def _has_public_access_block(config: dict[str, Any], _item: ConfigItem) -> bool:
    pab = _dict(config, "publicAccessBlockConfiguration") or _dict(
        config, "PublicAccessBlockConfiguration"
    )
    required = ("blockpublicacls", "ignorepublicacls", "blockpublicpolicy", "restrictpublicbuckets")
    return bool(pab) and all(pab.get(key) is True for key in required)


def _has_versioning(config: dict[str, Any], _item: ConfigItem) -> bool:
    versioning = _dict(config, "versioningConfiguration")
    return str(versioning.get("status") or "").lower() == "enabled"


def _trail_multi_region(config: dict[str, Any], _item: ConfigItem) -> bool:
    return _bool(config, "isMultiRegionTrail")


def _trail_validation(config: dict[str, Any], _item: ConfigItem) -> bool:
    return _bool(config, "logFileValidationEnabled")


def _trail_kms(config: dict[str, Any], _item: ConfigItem) -> bool:
    lower = _lower_keys(config)
    return isinstance(lower, dict) and bool(lower.get("kmskeyid"))


def _cidr_open(entry: dict[str, Any]) -> bool:
    cidr = str(entry.get("cidrip") or entry.get("cidripv6") or "")
    return cidr in {"0.0.0.0/0", "::/0"}


def _permission_covers_port(permission: dict[str, Any], port: int) -> bool:
    proto = str(permission.get("ipprotocol") or "").lower()
    if proto == "-1":
        return True
    from_port = permission.get("fromport")
    to_port = permission.get("toport")
    if from_port is None or to_port is None:
        return False
    try:
        return int(from_port) <= port <= int(to_port)
    except (TypeError, ValueError):
        return False


def _has_unrestricted_port(config: dict[str, Any], port: int) -> bool:
    permissions = _list(config, "ipPermissions") or _list(config, "IpPermissions")
    for permission in permissions:
        if not isinstance(permission, dict):
            continue
        p = _lower_keys(permission)
        if not isinstance(p, dict) or not _permission_covers_port(p, port):
            continue
        ranges: list[Any] = []
        ranges.extend(_as_list(p.get("ipranges")))
        ranges.extend(_as_list(p.get("ipv6ranges")))
        if any(isinstance(entry, dict) and _cidr_open(entry) for entry in ranges):
            return True
    return False


def _no_unrestricted_ssh(config: dict[str, Any], _item: ConfigItem) -> bool:
    return not _has_unrestricted_port(config, 22)


def _no_unrestricted_rdp(config: dict[str, Any], _item: ConfigItem) -> bool:
    return not _has_unrestricted_port(config, 3389)


def _check_vpc_flow_logs(control: Control, items: list[ConfigItem]) -> Finding:
    vpcs = _items_of(items, "AWS::EC2::VPC")
    flowlogs = _items_of(items, "AWS::EC2::FlowLog")
    if not vpcs:
        return _finding(control, STATUS_NA, "No AWS::EC2::VPC evidence in input", [])
    flowlog_vpc_ids: set[str] = set()
    for flowlog in flowlogs:
        cfg = _lower_keys(flowlog.configuration)
        if isinstance(cfg, dict):
            resource_id = cfg.get("resourceid") or cfg.get("vpcid")
            if resource_id:
                flowlog_vpc_ids.add(str(resource_id))
        for rel in flowlog.relationships:
            if rel.get("resource_type") == "AWS::EC2::VPC" and rel.get("resource_id"):
                flowlog_vpc_ids.add(str(rel["resource_id"]))
    failed = [_resource_label(vpc) for vpc in vpcs if vpc.resource_id not in flowlog_vpc_ids]
    if failed:
        return _finding(
            control, STATUS_FAIL, f"VPCs without flow log evidence: {', '.join(failed)}", failed
        )
    return _finding(
        control,
        STATUS_PASS,
        f"{len(vpcs)} VPC(s) have flow log evidence",
        [_resource_label(v) for v in vpcs],
    )


def _check_guardduty(control: Control, items: list[ConfigItem]) -> Finding:
    detectors = _items_of(items, "AWS::GuardDuty::Detector")
    if not detectors:
        return _finding(control, STATUS_FAIL, "No GuardDuty detector evidence in input", [])
    failed: list[str] = []
    for detector in detectors:
        cfg = _lower_keys(detector.configuration)
        enabled = False
        if isinstance(cfg, dict):
            enabled = str(cfg.get("status") or "").lower() == "enabled" or cfg.get("enable") is True
        if not enabled:
            failed.append(_resource_label(detector))
    if failed:
        return _finding(
            control,
            STATUS_FAIL,
            f"Disabled GuardDuty detector evidence: {', '.join(failed)}",
            failed,
        )
    return _finding(
        control,
        STATUS_PASS,
        f"{len(detectors)} GuardDuty detector(s) enabled",
        [_resource_label(d) for d in detectors],
    )


def _check_security_hub(control: Control, items: list[ConfigItem]) -> Finding:
    hubs = _items_of(items, "AWS::SecurityHub::Hub")
    if not hubs:
        return _finding(control, STATUS_FAIL, "No Security Hub hub evidence in input", [])
    return _finding(
        control,
        STATUS_PASS,
        f"{len(hubs)} Security Hub hub resource(s) present",
        [_resource_label(h) for h in hubs],
    )


def _apply_config_rule_evidence(
    finding: Finding,
    compliance: list[ConfigCompliance],
) -> Finding:
    if not compliance:
        return finding
    failed = [c for c in compliance if c.status.upper() == STATUS_FAIL]
    if failed:
        resources = [
            f"{c.resource_type}:{c.resource_id}:{c.region}" for c in failed if c.resource_id
        ]
        finding.status = STATUS_FAIL
        finding.detail = (
            f"{finding.detail}; " if finding.detail else ""
        ) + f"AWS Config rule failure evidence: {', '.join(c.rule_name for c in failed)}"
        finding.resources = sorted(set(finding.resources + resources))
        return finding
    passed = [c for c in compliance if c.status.upper() == STATUS_PASS]
    if finding.status == STATUS_NA and passed:
        finding.status = STATUS_PASS
        finding.detail = (
            f"AWS Config rule evidence passed: {', '.join(c.rule_name for c in passed)}"
        )
        finding.resources = [
            f"{c.resource_type}:{c.resource_id}:{c.region}" for c in passed if c.resource_id
        ]
    return finding


def run_benchmark(records: list[dict[str, Any]], *, control_id: str | None = None) -> list[Finding]:
    items = _latest_items(records)
    compliance = _compliance_by_control(records)
    findings: list[Finding] = []
    for control in CONTROLS:
        if control_id and control.control_id != control_id:
            continue
        if control.control_id == "2.1":
            finding = _aggregate_resource_check(
                control,
                _items_of(items, "AWS::S3::Bucket"),
                _has_s3_encryption,
                empty_detail="No AWS::S3::Bucket evidence in input",
                fail_detail="Buckets without default encryption evidence",
            )
        elif control.control_id == "2.2":
            finding = _aggregate_resource_check(
                control,
                _items_of(items, "AWS::S3::Bucket"),
                _has_s3_logging,
                empty_detail="No AWS::S3::Bucket evidence in input",
                fail_detail="Buckets without server access logging evidence",
            )
        elif control.control_id == "2.3":
            finding = _aggregate_resource_check(
                control,
                _items_of(items, "AWS::S3::Bucket"),
                _has_public_access_block,
                empty_detail="No AWS::S3::Bucket evidence in input",
                fail_detail="Buckets without full public access block evidence",
            )
        elif control.control_id == "2.4":
            finding = _aggregate_resource_check(
                control,
                _items_of(items, "AWS::S3::Bucket"),
                _has_versioning,
                empty_detail="No AWS::S3::Bucket evidence in input",
                fail_detail="Buckets without versioning evidence",
            )
        elif control.control_id == "3.1":
            finding = _aggregate_resource_check(
                control,
                _items_of(items, "AWS::CloudTrail::Trail"),
                _trail_multi_region,
                empty_detail="No AWS::CloudTrail::Trail evidence in input",
                fail_detail="CloudTrail trails without multi-region evidence",
            )
        elif control.control_id == "3.2":
            finding = _aggregate_resource_check(
                control,
                _items_of(items, "AWS::CloudTrail::Trail"),
                _trail_validation,
                empty_detail="No AWS::CloudTrail::Trail evidence in input",
                fail_detail="CloudTrail trails without log validation evidence",
            )
        elif control.control_id == "3.5":
            finding = _aggregate_resource_check(
                control,
                _items_of(items, "AWS::CloudTrail::Trail"),
                _trail_kms,
                empty_detail="No AWS::CloudTrail::Trail evidence in input",
                fail_detail="CloudTrail trails without KMS encryption evidence",
            )
        elif control.control_id == "4.1":
            finding = _aggregate_resource_check(
                control,
                _items_of(items, "AWS::EC2::SecurityGroup"),
                _no_unrestricted_ssh,
                empty_detail="No AWS::EC2::SecurityGroup evidence in input",
                fail_detail="Security groups with unrestricted SSH",
            )
        elif control.control_id == "4.2":
            finding = _aggregate_resource_check(
                control,
                _items_of(items, "AWS::EC2::SecurityGroup"),
                _no_unrestricted_rdp,
                empty_detail="No AWS::EC2::SecurityGroup evidence in input",
                fail_detail="Security groups with unrestricted RDP",
            )
        elif control.control_id == "4.3":
            finding = _check_vpc_flow_logs(control, items)
        elif control.control_id == "6.1":
            finding = _check_guardduty(control, items)
        elif control.control_id == "6.2":
            finding = _check_security_hub(control, items)
        else:  # pragma: no cover - keeps future control additions explicit
            finding = _finding(control, STATUS_ERROR, "Control not wired", [])
        findings.append(
            _apply_config_rule_evidence(finding, compliance.get(control.control_id, []))
        )
    return findings


def print_summary(findings: list[Finding]) -> None:
    counts = {STATUS_PASS: 0, STATUS_FAIL: 0, STATUS_NA: 0, STATUS_ERROR: 0}
    for finding in findings:
        counts[finding.status] = counts.get(finding.status, 0) + 1
    print(f"\n{'=' * 72}")
    print(f"  {BENCHMARK_NAME}")
    print(f"  Config-backed controls: {len(CONTROLS)}")
    print(f"{'=' * 72}\n")
    icon = {STATUS_PASS: "+", STATUS_FAIL: "x", STATUS_NA: "-", STATUS_ERROR: "?"}
    for finding in findings:
        print(
            f"  [{icon.get(finding.status, '?')}] {finding.control_id:4s} [{finding.severity:8s}] {finding.title}"
        )
        if finding.status != STATUS_PASS:
            print(f"      {finding.detail}")
    print(
        f"\n  Total: {len(findings)} | PASS {counts[STATUS_PASS]} | FAIL {counts[STATUS_FAIL]} | NA {counts[STATUS_NA]}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"{BENCHMARK_NAME} evaluator")
    parser.add_argument("input", nargs="?", help="OCSF/native JSON or JSONL. Defaults to stdin.")
    parser.add_argument("--control", help="Run one CIS control ID, e.g. 2.1.")
    parser.add_argument("--output", choices=["console", "json"], default="console")
    parser.add_argument("--output-format", choices=list(OUTPUT_FORMATS), default="native")
    args = parser.parse_args(argv)

    try:
        records = load_records(args.input)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    findings = run_benchmark(records, control_id=args.control)
    if args.output == "json":
        rendered = (
            findings_to_ocsf(
                findings,
                skill_name=SKILL_NAME,
                benchmark_name=BENCHMARK_NAME,
                provider=PROVIDER_NAME,
                frameworks=list(FRAMEWORKS),
            )
            if args.output_format == "ocsf"
            else findings_to_native(findings)
        )
        print(json.dumps(rendered, indent=2))
    else:
        print_summary(findings)

    high_fails = [
        f for f in findings if f.status == STATUS_FAIL and f.severity in {"HIGH", "CRITICAL"}
    ]
    return 1 if high_fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
