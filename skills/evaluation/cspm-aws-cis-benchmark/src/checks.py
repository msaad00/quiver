"""
CIS AWS Foundations Benchmark v3.0 — Automated Assessment

31 checks across IAM, Storage, Logging, Networking, and Security Services.
Read-only: requires SecurityAudit managed policy.

Frameworks:
    CIS AWS Foundations v3.0
    NIST CSF 2.0: PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-5, PR.DS-1, PR.DS-6,
                  DE.AE-3, DE.CM-1
    ISO 27001:2022: A.5.15, A.5.17, A.5.18, A.8.2, A.8.3, A.8.5, A.8.13,
                    A.8.15, A.8.16, A.8.20, A.8.24
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.evaluation_ocsf import findings_to_native, findings_to_ocsf  # noqa: E402

SKILL_NAME = "cspm-aws-cis-benchmark"
BENCHMARK_NAME = "CIS AWS Foundations Benchmark v3.0"
PROVIDER_NAME = "AWS"
OUTPUT_FORMATS = ("native", "ocsf")
CONFIRM_APPLY_PHRASE = "APPLY"
SUPPORTED_AUTOREMEDIATE_CONTROLS = frozenset({"2.1", "2.3", "2.4", "4.1", "4.2"})
RECORD_PLAN = "remediation_plan"
RECORD_ACTION = "remediation_action"
STATUS_PLANNED = "planned"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_SKIPPED_UNSUPPORTED = "skipped_unsupported_control"
STATUS_WOULD_VIOLATE_PROTECTED = "would-violate-protected-resource"
DEFAULT_PROTECTED_BUCKET_PREFIXES = ("break-glass-",)
DEFAULT_PROTECTED_SECURITY_GROUP_PREFIXES = ("default", "break-glass-")
DEFAULT_PROTECTED_TAG_KEYS = (
    "cspm:auto-remediate-protected",
    "security.company.io/protected",
)
DEFAULT_INTENTIONALLY_OPEN_TAG = "intentionally-open"

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    control_id: str
    title: str
    section: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    status: str  # PASS, FAIL, ERROR
    detail: str = ""
    nist_csf: str = ""
    iso_27001: str = ""
    resources: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RemediationTarget:
    control_id: str
    title: str
    resource_type: str
    resource_id: str
    resource_name: str
    section: str
    severity: str
    region: str
    account_id: str
    action: str
    detail: str
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class DualAuditWriter:
    dynamodb_table: str
    s3_bucket: str
    kms_key_arn: str

    def record(
        self,
        *,
        target: RemediationTarget,
        status: str,
        detail: str,
        incident_id: str,
        approver: str,
    ) -> dict[str, str]:
        action_at = datetime.now(UTC).isoformat()
        row_uid = _deterministic_uid(target.control_id, target.resource_id, target.action, action_at)
        evidence_key = (
            "cspm-aws-cis-benchmark/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{_safe_path_component(target.control_id)}/{_safe_path_component(target.resource_id)}-{action_at}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"
        envelope = {
            "schema_mode": "native",
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "benchmark": BENCHMARK_NAME,
            "provider": PROVIDER_NAME,
            "row_uid": row_uid,
            "control_id": target.control_id,
            "title": target.title,
            "resource_type": target.resource_type,
            "resource_id": target.resource_id,
            "resource_name": target.resource_name,
            "region": target.region,
            "account_id": target.account_id,
            "action": target.action,
            "detail": detail,
            "parameters": target.parameters,
            "status": status,
            "incident_id": incident_id,
            "approver": approver,
            "action_at": action_at,
        }
        body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        boto3.client("s3").put_object(
            Bucket=self.s3_bucket,
            Key=evidence_key,
            Body=body,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self.kms_key_arn,
            ContentType="application/json",
        )
        boto3.client("dynamodb").put_item(
            TableName=self.dynamodb_table,
            Item={
                "resource_id": {"S": target.resource_id},
                "action_at": {"S": action_at},
                "row_uid": {"S": row_uid},
                "control_id": {"S": target.control_id},
                "action": {"S": target.action},
                "status": {"S": status},
                "incident_id": {"S": incident_id},
                "approver": {"S": approver},
                "resource_type": {"S": target.resource_type},
                "resource_name": {"S": target.resource_name},
                "section": {"S": target.section},
                "severity": {"S": target.severity},
                "s3_evidence_uri": {"S": evidence_uri},
            },
        )
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"cspmaws-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _safe_path_component(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (value or "_"))
    return safe[:120] or "_"


def _paginate(
    client: Any, operation_name: str, result_key: str, **kwargs: Any
) -> list[dict[str, Any]]:
    """Return all items for a paginated IAM-style operation.

    boto3 paginators are preferred for correctness on large accounts. The fallback
    keeps tests and minimal stubs working when a paginator is unavailable.
    """
    try:
        paginator = client.get_paginator(operation_name)
    except Exception:
        return client.__getattribute__(operation_name)(**kwargs).get(result_key, [])

    items: list[dict[str, Any]] = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def _parse_env_list(name: str) -> set[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _account_id(clients: dict[str, Any]) -> str:
    try:
        return str(clients["sts"].get_caller_identity()["Account"])
    except Exception:
        return ""


def _bucket_tags(s3: Any, bucket_name: str) -> dict[str, str]:
    try:
        tag_set = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
    except Exception:
        return {}
    return {str(tag["Key"]): str(tag["Value"]) for tag in tag_set if "Key" in tag and "Value" in tag}


def _sg_tags(group: dict[str, Any]) -> dict[str, str]:
    return {
        str(tag["Key"]): str(tag["Value"])
        for tag in group.get("Tags", [])
        if isinstance(tag, dict) and "Key" in tag and "Value" in tag
    }


def _is_protected_bucket(s3: Any, bucket_name: str) -> tuple[bool, str]:
    protected = _parse_env_list("CSPM_AWS_AUTOREMEDIATE_PROTECTED_BUCKETS")
    if bucket_name in protected:
        return True, "bucket listed in CSPM_AWS_AUTOREMEDIATE_PROTECTED_BUCKETS"
    if bucket_name.lower().startswith(DEFAULT_PROTECTED_BUCKET_PREFIXES):
        return True, "bucket matches protected prefix"
    tags = _bucket_tags(s3, bucket_name)
    for key in DEFAULT_PROTECTED_TAG_KEYS:
        if key in tags and _truthy(tags[key]):
            return True, f"bucket tag `{key}` marks it protected"
    return False, ""


def _is_protected_security_group(group: dict[str, Any]) -> tuple[bool, str]:
    group_id = str(group.get("GroupId") or "")
    group_name = str(group.get("GroupName") or "")
    protected = _parse_env_list("CSPM_AWS_AUTOREMEDIATE_PROTECTED_SECURITY_GROUPS")
    if group_id in protected or group_name in protected:
        return True, "security group listed in CSPM_AWS_AUTOREMEDIATE_PROTECTED_SECURITY_GROUPS"
    if group_name.lower().startswith(DEFAULT_PROTECTED_SECURITY_GROUP_PREFIXES):
        return True, "security group matches protected prefix"
    tags = _sg_tags(group)
    if _truthy(tags.get(DEFAULT_INTENTIONALLY_OPEN_TAG, "")):
        return True, f"security group tag `{DEFAULT_INTENTIONALLY_OPEN_TAG}` marks it intentionally open"
    for key in DEFAULT_PROTECTED_TAG_KEYS:
        if key in tags and _truthy(tags[key]):
            return True, f"security group tag `{key}` marks it protected"
    return False, ""


# ---------------------------------------------------------------------------
# Section 1 — IAM
# ---------------------------------------------------------------------------


def check_1_1_root_mfa(iam) -> Finding:
    """CIS 1.1 — MFA on root account."""
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        has_mfa = summary.get("AccountMFAEnabled", 0) == 1
        return Finding(
            control_id="1.1",
            title="MFA on root account",
            section="iam",
            severity="CRITICAL",
            status="PASS" if has_mfa else "FAIL",
            detail="Root MFA enabled" if has_mfa else "Root account has no MFA",
            nist_csf="PR.AC-1",
            iso_27001="A.8.5",
        )
    except ClientError as e:
        return Finding(
            control_id="1.1",
            title="MFA on root account",
            section="iam",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
            iso_27001="A.8.5",
        )


def check_1_2_user_mfa(iam) -> Finding:
    """CIS 1.2 — MFA for console users."""
    try:
        users = _paginate(iam, "list_users", "Users")
        no_mfa = []
        for user in users:
            try:
                iam.get_login_profile(UserName=user["UserName"])
            except ClientError:
                continue  # no console access
            mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
            if not mfa_devices:
                no_mfa.append(user["UserName"])
        return Finding(
            control_id="1.2",
            title="MFA for console users",
            section="iam",
            severity="HIGH",
            status="FAIL" if no_mfa else "PASS",
            detail=f"{len(no_mfa)} console users without MFA"
            if no_mfa
            else "All console users have MFA",
            nist_csf="PR.AC-1",
            iso_27001="A.8.5",
            resources=no_mfa,
        )
    except ClientError as e:
        return Finding(
            control_id="1.2",
            title="MFA for console users",
            section="iam",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
            iso_27001="A.8.5",
        )


def check_1_3_stale_credentials(iam) -> Finding:
    """CIS 1.3 — Credentials unused 45+ days."""
    try:
        iam.generate_credential_report()
        report = iam.get_credential_report()["Content"].decode()
        now = datetime.now(UTC)
        stale = []
        for line in report.strip().split("\n")[1:]:  # skip header
            fields = line.split(",")
            username = fields[0]
            password_last_used = fields[4]
            if password_last_used not in ("N/A", "no_information", "not_supported"):
                try:
                    last_used = datetime.fromisoformat(password_last_used.replace("Z", "+00:00"))
                    if (now - last_used).days > 45:
                        stale.append(username)
                except (ValueError, IndexError):
                    pass
        return Finding(
            control_id="1.3",
            title="Credentials unused 45+ days",
            section="iam",
            severity="MEDIUM",
            status="FAIL" if stale else "PASS",
            detail=f"{len(stale)} users with stale credentials"
            if stale
            else "No stale credentials",
            nist_csf="PR.AC-1",
            iso_27001="A.5.18",
            resources=stale,
        )
    except ClientError as e:
        return Finding(
            control_id="1.3",
            title="Credentials unused 45+ days",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
            iso_27001="A.5.18",
        )


def check_1_4_key_rotation(iam) -> Finding:
    """CIS 1.4 — Access keys rotated within 90 days."""
    try:
        now = datetime.now(UTC)
        old_keys = []
        for user in _paginate(iam, "list_users", "Users"):
            for key in _paginate(
                iam, "list_access_keys", "AccessKeyMetadata", UserName=user["UserName"]
            ):
                if key["Status"] == "Active":
                    age = (now - key["CreateDate"].replace(tzinfo=UTC)).days
                    if age > 90:
                        old_keys.append(f"{user['UserName']}:{key['AccessKeyId']} ({age}d)")
        return Finding(
            control_id="1.4",
            title="Access keys rotated 90 days",
            section="iam",
            severity="MEDIUM",
            status="FAIL" if old_keys else "PASS",
            detail=f"{len(old_keys)} keys older than 90 days"
            if old_keys
            else "All keys within 90 days",
            nist_csf="PR.AC-1",
            iso_27001="A.5.17",
            resources=old_keys,
        )
    except ClientError as e:
        return Finding(
            control_id="1.4",
            title="Access keys rotated 90 days",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
            iso_27001="A.5.17",
        )


def check_1_5_password_policy(iam) -> Finding:
    """CIS 1.5 — Password policy strength."""
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"MinLength={policy.get('MinimumPasswordLength', 0)} (need 14+)")
        if not policy.get("RequireSymbols", False):
            issues.append("RequireSymbols=false")
        if not policy.get("RequireNumbers", False):
            issues.append("RequireNumbers=false")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("RequireUppercase=false")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("RequireLowercase=false")
        return Finding(
            control_id="1.5",
            title="Password policy strength",
            section="iam",
            severity="MEDIUM",
            status="FAIL" if issues else "PASS",
            detail="; ".join(issues) if issues else "Password policy meets CIS requirements",
            nist_csf="PR.AC-1",
            iso_27001="A.5.17",
        )
    except iam.exceptions.NoSuchEntityException:
        return Finding(
            control_id="1.5",
            title="Password policy strength",
            section="iam",
            severity="MEDIUM",
            status="FAIL",
            detail="No password policy configured",
            nist_csf="PR.AC-1",
            iso_27001="A.5.17",
        )


def check_1_6_no_root_keys(iam) -> Finding:
    """CIS 1.6 — No root access keys."""
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        root_keys = summary.get("AccountAccessKeysPresent", 0)
        return Finding(
            control_id="1.6",
            title="No root access keys",
            section="iam",
            severity="CRITICAL",
            status="PASS" if root_keys == 0 else "FAIL",
            detail="No root access keys"
            if root_keys == 0
            else f"Root has {root_keys} access key(s)",
            nist_csf="PR.AC-4",
            iso_27001="A.8.2",
        )
    except ClientError as e:
        return Finding(
            control_id="1.6",
            title="No root access keys",
            section="iam",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-4",
            iso_27001="A.8.2",
        )


def check_1_7_no_inline_policies(iam) -> Finding:
    """CIS 1.7 — IAM policies not inline."""
    try:
        inline_users = []
        for user in _paginate(iam, "list_users", "Users"):
            policies = _paginate(
                iam, "list_user_policies", "PolicyNames", UserName=user["UserName"]
            )
            if policies:
                inline_users.append(user["UserName"])
        return Finding(
            control_id="1.7",
            title="No inline IAM policies",
            section="iam",
            severity="LOW",
            status="FAIL" if inline_users else "PASS",
            detail=f"{len(inline_users)} users with inline policies"
            if inline_users
            else "No inline policies",
            nist_csf="PR.AC-4",
            iso_27001="A.5.15",
            resources=inline_users,
        )
    except ClientError as e:
        return Finding(
            control_id="1.7",
            title="No inline IAM policies",
            section="iam",
            severity="LOW",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-4",
            iso_27001="A.5.15",
        )


def check_1_9_password_reuse(iam) -> Finding:
    """CIS 1.9 — Password policy prevents reuse (last 24)."""
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        reuse = int(policy.get("PasswordReusePrevention", 0) or 0)
        ok = reuse >= 24
        return Finding(
            control_id="1.9",
            title="Password reuse prevention >= 24",
            section="iam",
            severity="MEDIUM",
            status="PASS" if ok else "FAIL",
            detail=f"PasswordReusePrevention={reuse} (need >=24)"
            if not ok
            else "Password reuse policy meets CIS",
            nist_csf="PR.AC-1",
            iso_27001="A.5.17",
        )
    except iam.exceptions.NoSuchEntityException:
        return Finding(
            control_id="1.9",
            title="Password reuse prevention >= 24",
            section="iam",
            severity="MEDIUM",
            status="FAIL",
            detail="No password policy configured",
            nist_csf="PR.AC-1",
            iso_27001="A.5.17",
        )
    except ClientError as e:
        return Finding(
            control_id="1.9",
            title="Password reuse prevention >= 24",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
            iso_27001="A.5.17",
        )


def check_1_13_one_active_key(iam) -> Finding:
    """CIS 1.13 — Only one active access key per IAM user."""
    try:
        offenders: list[str] = []
        for user in _paginate(iam, "list_users", "Users"):
            keys = _paginate(
                iam,
                "list_access_keys",
                "AccessKeyMetadata",
                UserName=user["UserName"],
            )
            active = [k for k in keys if k.get("Status") == "Active"]
            if len(active) > 1:
                offenders.append(f"{user['UserName']} ({len(active)} active keys)")
        return Finding(
            control_id="1.13",
            title="One active access key per user",
            section="iam",
            severity="MEDIUM",
            status="FAIL" if offenders else "PASS",
            detail=f"{len(offenders)} users with >1 active key"
            if offenders
            else "All users have at most one active key",
            nist_csf="PR.AC-1",
            iso_27001="A.5.17",
            resources=offenders,
        )
    except ClientError as e:
        return Finding(
            control_id="1.13",
            title="One active access key per user",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
            iso_27001="A.5.17",
        )


def check_1_14_hardware_mfa_root(iam) -> Finding:
    """CIS 1.14 — Hardware MFA on root account."""
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) != 1:
            return Finding(
                control_id="1.14",
                title="Hardware MFA on root account",
                section="iam",
                severity="CRITICAL",
                status="FAIL",
                detail="Root has no MFA at all",
                nist_csf="PR.AC-1",
                iso_27001="A.8.5",
            )
        try:
            devices = iam.list_virtual_mfa_devices(AssignmentStatus="Assigned").get(
                "VirtualMFADevices", []
            )
        except ClientError:
            devices = []
        root_virtual = [
            d
            for d in devices
            if str(d.get("SerialNumber", "")).endswith(":mfa/root-account-mfa-device")
        ]
        if root_virtual:
            return Finding(
                control_id="1.14",
                title="Hardware MFA on root account",
                section="iam",
                severity="CRITICAL",
                status="FAIL",
                detail="Root uses virtual MFA, not hardware MFA",
                nist_csf="PR.AC-1",
                iso_27001="A.8.5",
            )
        return Finding(
            control_id="1.14",
            title="Hardware MFA on root account",
            section="iam",
            severity="CRITICAL",
            status="PASS",
            detail="Root MFA is hardware-backed",
            nist_csf="PR.AC-1",
            iso_27001="A.8.5",
        )
    except ClientError as e:
        return Finding(
            control_id="1.14",
            title="Hardware MFA on root account",
            section="iam",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
            iso_27001="A.8.5",
        )


def check_1_16_no_user_attached_policies(iam) -> Finding:
    """CIS 1.16 — IAM users receive permissions only via groups."""
    try:
        offenders: list[str] = []
        for user in _paginate(iam, "list_users", "Users"):
            attached = _paginate(
                iam,
                "list_attached_user_policies",
                "AttachedPolicies",
                UserName=user["UserName"],
            )
            if attached:
                offenders.append(user["UserName"])
        return Finding(
            control_id="1.16",
            title="No user-attached managed policies",
            section="iam",
            severity="LOW",
            status="FAIL" if offenders else "PASS",
            detail=f"{len(offenders)} users have managed policies attached directly"
            if offenders
            else "All user permissions flow through groups",
            nist_csf="PR.AC-4",
            iso_27001="A.5.15",
            resources=offenders,
        )
    except ClientError as e:
        return Finding(
            control_id="1.16",
            title="No user-attached managed policies",
            section="iam",
            severity="LOW",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-4",
            iso_27001="A.5.15",
        )


def check_1_20_access_analyzer(aa) -> Finding:
    """CIS 1.20 — IAM Access Analyzer enabled."""
    try:
        analyzers = aa.list_analyzers().get("analyzers", [])
        active = [
            str(a.get("arn") or a.get("name") or "")
            for a in analyzers
            if str(a.get("status", "")).upper() == "ACTIVE"
        ]
        return Finding(
            control_id="1.20",
            title="IAM Access Analyzer enabled",
            section="iam",
            severity="MEDIUM",
            status="PASS" if active else "FAIL",
            detail=f"{len(active)} active analyzer(s)"
            if active
            else "No active IAM Access Analyzer",
            nist_csf="DE.CM-1",
            iso_27001="A.8.16",
            resources=active,
        )
    except ClientError as e:
        return Finding(
            control_id="1.20",
            title="IAM Access Analyzer enabled",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
            iso_27001="A.8.16",
        )


# ---------------------------------------------------------------------------
# Section 2 — Storage
# ---------------------------------------------------------------------------


def check_2_1_s3_encryption(s3) -> Finding:
    """CIS 2.1 — S3 default encryption."""
    try:
        buckets = s3.list_buckets()["Buckets"]
        unencrypted = []
        for bucket in buckets:
            try:
                s3.get_bucket_encryption(Bucket=bucket["Name"])
            except ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    unencrypted.append(bucket["Name"])
        return Finding(
            control_id="2.1",
            title="S3 default encryption",
            section="storage",
            severity="HIGH",
            status="FAIL" if unencrypted else "PASS",
            detail=f"{len(unencrypted)} buckets without encryption"
            if unencrypted
            else "All buckets encrypted",
            nist_csf="PR.DS-1",
            iso_27001="A.8.24",
            resources=unencrypted,
        )
    except ClientError as e:
        return Finding(
            control_id="2.1",
            title="S3 default encryption",
            section="storage",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
            iso_27001="A.8.24",
        )


def check_2_2_s3_logging(s3) -> Finding:
    """CIS 2.2 — S3 server access logging."""
    try:
        buckets = s3.list_buckets()["Buckets"]
        no_logging = []
        for bucket in buckets:
            logging_config = s3.get_bucket_logging(Bucket=bucket["Name"])
            if "LoggingEnabled" not in logging_config:
                no_logging.append(bucket["Name"])
        return Finding(
            control_id="2.2",
            title="S3 server access logging",
            section="storage",
            severity="MEDIUM",
            status="FAIL" if no_logging else "PASS",
            detail=f"{len(no_logging)} buckets without logging"
            if no_logging
            else "All buckets have logging",
            nist_csf="DE.AE-3",
            iso_27001="A.8.15",
            resources=no_logging,
        )
    except ClientError as e:
        return Finding(
            control_id="2.2",
            title="S3 server access logging",
            section="storage",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
            iso_27001="A.8.15",
        )


def check_2_3_s3_public_access(s3) -> Finding:
    """CIS 2.3 — S3 public access blocked."""
    try:
        buckets = s3.list_buckets()["Buckets"]
        public_buckets = []
        for bucket in buckets:
            try:
                pab = s3.get_public_access_block(Bucket=bucket["Name"])[
                    "PublicAccessBlockConfiguration"
                ]
                if not all(
                    [
                        pab.get("BlockPublicAcls", False),
                        pab.get("IgnorePublicAcls", False),
                        pab.get("BlockPublicPolicy", False),
                        pab.get("RestrictPublicBuckets", False),
                    ]
                ):
                    public_buckets.append(bucket["Name"])
            except ClientError:
                public_buckets.append(bucket["Name"])
        return Finding(
            control_id="2.3",
            title="S3 public access blocked",
            section="storage",
            severity="CRITICAL",
            status="FAIL" if public_buckets else "PASS",
            detail=f"{len(public_buckets)} buckets without full public access block"
            if public_buckets
            else "All buckets block public access",
            nist_csf="PR.AC-3",
            iso_27001="A.8.3",
            resources=public_buckets,
        )
    except ClientError as e:
        return Finding(
            control_id="2.3",
            title="S3 public access blocked",
            section="storage",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-3",
            iso_27001="A.8.3",
        )


def check_2_4_s3_versioning(s3) -> Finding:
    """CIS 2.4 — S3 versioning enabled."""
    try:
        buckets = s3.list_buckets()["Buckets"]
        no_versioning = []
        for bucket in buckets:
            versioning = s3.get_bucket_versioning(Bucket=bucket["Name"])
            if versioning.get("Status") != "Enabled":
                no_versioning.append(bucket["Name"])
        return Finding(
            control_id="2.4",
            title="S3 versioning enabled",
            section="storage",
            severity="MEDIUM",
            status="FAIL" if no_versioning else "PASS",
            detail=f"{len(no_versioning)} buckets without versioning"
            if no_versioning
            else "All buckets versioned",
            nist_csf="PR.DS-1",
            iso_27001="A.8.13",
            resources=no_versioning,
        )
    except ClientError as e:
        return Finding(
            control_id="2.4",
            title="S3 versioning enabled",
            section="storage",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
            iso_27001="A.8.13",
        )


def _bucket_policy_requires_ssl(policy_doc: dict[str, Any]) -> bool:
    """True if the policy explicitly denies non-SSL (aws:SecureTransport=false) requests."""
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if str(stmt.get("Effect", "")).lower() != "deny":
            continue
        condition = stmt.get("Condition", {}) or {}
        bool_block = condition.get("Bool", {}) or {}
        secure = bool_block.get("aws:SecureTransport")
        if secure is None:
            continue
        if isinstance(secure, list):
            values = [str(v).lower() for v in secure]
        else:
            values = [str(secure).lower()]
        if "false" in values:
            return True
    return False


def check_2_1_4_s3_ssl_required(s3) -> Finding:
    """CIS 2.1.4 — S3 bucket policies require encryption-in-transit (SSL)."""
    try:
        buckets = s3.list_buckets()["Buckets"]
        non_ssl: list[str] = []
        for bucket in buckets:
            name = bucket["Name"]
            try:
                policy_text = s3.get_bucket_policy(Bucket=name).get("Policy")
            except ClientError as e:
                if e.response["Error"]["Code"] in {"NoSuchBucketPolicy", "NoSuchBucket"}:
                    non_ssl.append(name)
                    continue
                raise
            if not policy_text:
                non_ssl.append(name)
                continue
            try:
                policy_doc = json.loads(policy_text)
            except (TypeError, ValueError):
                non_ssl.append(name)
                continue
            if not _bucket_policy_requires_ssl(policy_doc):
                non_ssl.append(name)
        return Finding(
            control_id="2.1.4",
            title="S3 bucket policies require SSL",
            section="storage",
            severity="HIGH",
            status="FAIL" if non_ssl else "PASS",
            detail=f"{len(non_ssl)} buckets do not require encryption-in-transit"
            if non_ssl
            else "All buckets enforce SSL",
            nist_csf="PR.DS-2",
            iso_27001="A.8.24",
            resources=non_ssl,
        )
    except ClientError as e:
        return Finding(
            control_id="2.1.4",
            title="S3 bucket policies require SSL",
            section="storage",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-2",
            iso_27001="A.8.24",
        )


def check_2_2_1_ebs_encryption_default(ec2) -> Finding:
    """CIS 2.2.1 — EBS volume encryption enabled by default."""
    try:
        result = ec2.get_ebs_encryption_by_default()
        enabled = bool(result.get("EbsEncryptionByDefault"))
        return Finding(
            control_id="2.2.1",
            title="EBS encryption-by-default enabled",
            section="storage",
            severity="HIGH",
            status="PASS" if enabled else "FAIL",
            detail="EBS encryption-by-default is enabled in this region"
            if enabled
            else "EBS encryption-by-default is OFF in this region",
            nist_csf="PR.DS-1",
            iso_27001="A.8.24",
        )
    except ClientError as e:
        return Finding(
            control_id="2.2.1",
            title="EBS encryption-by-default enabled",
            section="storage",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
            iso_27001="A.8.24",
        )


# ---------------------------------------------------------------------------
# Section 3 — Logging
# ---------------------------------------------------------------------------


def check_3_1_cloudtrail_multiregion(ct) -> Finding:
    """CIS 3.1 — CloudTrail multi-region enabled."""
    try:
        trails = ct.describe_trails()["trailList"]
        multi_region = [t["Name"] for t in trails if t.get("IsMultiRegionTrail")]
        active_mr = []
        for name in multi_region:
            status = ct.get_trail_status(Name=name)
            if status.get("IsLogging"):
                active_mr.append(name)
        return Finding(
            control_id="3.1",
            title="CloudTrail multi-region",
            section="logging",
            severity="CRITICAL",
            status="PASS" if active_mr else "FAIL",
            detail=f"{len(active_mr)} active multi-region trail(s)"
            if active_mr
            else "No active multi-region trail",
            nist_csf="DE.AE-3",
            iso_27001="A.8.15",
            resources=active_mr,
        )
    except ClientError as e:
        return Finding(
            control_id="3.1",
            title="CloudTrail multi-region",
            section="logging",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
            iso_27001="A.8.15",
        )


def check_3_2_cloudtrail_validation(ct) -> Finding:
    """CIS 3.2 — CloudTrail log file validation."""
    try:
        trails = ct.describe_trails()["trailList"]
        no_validation = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]
        return Finding(
            control_id="3.2",
            title="CloudTrail log validation",
            section="logging",
            severity="HIGH",
            status="FAIL" if no_validation else "PASS",
            detail=f"{len(no_validation)} trails without log validation"
            if no_validation
            else "All trails have log validation",
            nist_csf="PR.DS-6",
            iso_27001="A.8.15",
            resources=no_validation,
        )
    except ClientError as e:
        return Finding(
            control_id="3.2",
            title="CloudTrail log validation",
            section="logging",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-6",
            iso_27001="A.8.15",
        )


def check_3_3_cloudtrail_s3_not_public(ct, s3) -> Finding:
    """CIS 3.3 — CloudTrail S3 bucket not public."""
    try:
        trails = ct.describe_trails()["trailList"]
        public_trail_buckets = []
        for trail in trails:
            bucket = trail.get("S3BucketName")
            if not bucket:
                continue
            try:
                pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                if not all(
                    [
                        pab.get("BlockPublicAcls", False),
                        pab.get("IgnorePublicAcls", False),
                        pab.get("BlockPublicPolicy", False),
                        pab.get("RestrictPublicBuckets", False),
                    ]
                ):
                    public_trail_buckets.append(bucket)
            except ClientError:
                public_trail_buckets.append(bucket)
        return Finding(
            control_id="3.3",
            title="CloudTrail S3 not public",
            section="logging",
            severity="CRITICAL",
            status="FAIL" if public_trail_buckets else "PASS",
            detail=f"{len(public_trail_buckets)} trail buckets without public access block"
            if public_trail_buckets
            else "All trail buckets block public access",
            nist_csf="PR.AC-3",
            iso_27001="A.8.3",
            resources=public_trail_buckets,
        )
    except ClientError as e:
        return Finding(
            control_id="3.3",
            title="CloudTrail S3 not public",
            section="logging",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-3",
            iso_27001="A.8.3",
        )


def check_3_4_cloudwatch_alarms(cw) -> Finding:
    """CIS 3.4 — CloudWatch alarms for key events."""
    try:
        alarms = cw.describe_alarms()["MetricAlarms"]
        return Finding(
            control_id="3.4",
            title="CloudWatch alarms configured",
            section="logging",
            severity="MEDIUM",
            status="PASS" if alarms else "FAIL",
            detail=f"{len(alarms)} alarm(s) configured"
            if alarms
            else "No CloudWatch alarms configured",
            nist_csf="DE.CM-1",
            iso_27001="A.8.16",
        )
    except ClientError as e:
        return Finding(
            control_id="3.4",
            title="CloudWatch alarms configured",
            section="logging",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
            iso_27001="A.8.16",
        )


def check_3_5_cloudtrail_kms_encryption(ct) -> Finding:
    """CIS 3.5 — CloudTrail trails encrypted with KMS."""
    try:
        trails = ct.describe_trails()["trailList"]
        if not trails:
            return Finding(
                control_id="3.5",
                title="CloudTrail KMS encryption",
                section="logging",
                severity="MEDIUM",
                status="FAIL",
                detail="No CloudTrail trails found",
                nist_csf="PR.DS-1",
                iso_27001="A.8.24",
            )
        no_kms = [t["Name"] for t in trails if not t.get("KmsKeyId")]
        return Finding(
            control_id="3.5",
            title="CloudTrail KMS encryption",
            section="logging",
            severity="MEDIUM",
            status="FAIL" if no_kms else "PASS",
            detail=f"{len(no_kms)} trails without KMS encryption"
            if no_kms
            else "All trails use KMS encryption",
            nist_csf="PR.DS-1",
            iso_27001="A.8.24",
            resources=no_kms,
        )
    except ClientError as e:
        return Finding(
            control_id="3.5",
            title="CloudTrail KMS encryption",
            section="logging",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
            iso_27001="A.8.24",
        )


def _trail_has_data_events(selectors: dict[str, Any]) -> bool:
    for selector in selectors.get("EventSelectors", []) or []:
        if selector.get("DataResources"):
            return True
    for selector in selectors.get("AdvancedEventSelectors", []) or []:
        field_selectors = selector.get("FieldSelectors", []) or []
        for field_selector in field_selectors:
            if field_selector.get("Field") != "eventCategory":
                continue
            values = field_selector.get("Equals") or []
            if any(str(value) == "Data" for value in values):
                return True
    return False


def check_3_6_cloudtrail_data_events(ct) -> Finding:
    """CIS 3.6 — CloudTrail data events enabled."""
    try:
        trails = ct.describe_trails()["trailList"]
        if not trails:
            return Finding(
                control_id="3.6",
                title="CloudTrail data events",
                section="logging",
                severity="MEDIUM",
                status="FAIL",
                detail="No CloudTrail trails found",
                nist_csf="DE.CM-1",
                iso_27001="A.8.15",
            )
        missing = []
        for trail in trails:
            trail_name = str(trail.get("Name") or "")
            selectors = ct.get_event_selectors(TrailName=trail_name)
            if not _trail_has_data_events(selectors):
                missing.append(trail_name)
        return Finding(
            control_id="3.6",
            title="CloudTrail data events",
            section="logging",
            severity="MEDIUM",
            status="FAIL" if missing else "PASS",
            detail=f"{len(missing)} trails without data events"
            if missing
            else "All trails record data events",
            nist_csf="DE.CM-1",
            iso_27001="A.8.15",
            resources=missing,
        )
    except ClientError as e:
        return Finding(
            control_id="3.6",
            title="CloudTrail data events",
            section="logging",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
            iso_27001="A.8.15",
        )


def check_3_7_cloudtrail_cloudwatch_integration(ct) -> Finding:
    """CIS 3.7 — CloudTrail trails integrated with CloudWatch Logs."""
    try:
        trails = ct.describe_trails()["trailList"]
        if not trails:
            return Finding(
                control_id="3.7",
                title="CloudTrail integrated with CloudWatch Logs",
                section="logging",
                severity="MEDIUM",
                status="FAIL",
                detail="No CloudTrail trails found",
                nist_csf="DE.AE-3",
                iso_27001="A.8.15",
            )
        not_integrated: list[str] = []
        for trail in trails:
            log_group = trail.get("CloudWatchLogsLogGroupArn")
            if not log_group:
                not_integrated.append(str(trail.get("Name") or ""))
                continue
            try:
                status = ct.get_trail_status(Name=trail["Name"])
            except ClientError:
                not_integrated.append(str(trail.get("Name") or ""))
                continue
            latest = status.get("LatestCloudWatchLogsDeliveryTime")
            if not latest:
                not_integrated.append(str(trail.get("Name") or ""))
        return Finding(
            control_id="3.7",
            title="CloudTrail integrated with CloudWatch Logs",
            section="logging",
            severity="MEDIUM",
            status="FAIL" if not_integrated else "PASS",
            detail=f"{len(not_integrated)} trails missing CloudWatch Logs integration"
            if not_integrated
            else "All trails ship to CloudWatch Logs",
            nist_csf="DE.AE-3",
            iso_27001="A.8.15",
            resources=not_integrated,
        )
    except ClientError as e:
        return Finding(
            control_id="3.7",
            title="CloudTrail integrated with CloudWatch Logs",
            section="logging",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
            iso_27001="A.8.15",
        )


# ---------------------------------------------------------------------------
# Section 4 — Networking
# ---------------------------------------------------------------------------


def _check_unrestricted_port(ec2, port: int, control_id: str, title: str) -> Finding:
    """Check for 0.0.0.0/0 on a specific port in security groups."""
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        open_sgs = []
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 0)
                if from_port <= port <= to_port:
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            open_sgs.append(f"{sg['GroupId']} ({sg.get('GroupName', '')})")
                    for ip_range in perm.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            open_sgs.append(f"{sg['GroupId']} ({sg.get('GroupName', '')})")
        return Finding(
            control_id=control_id,
            title=title,
            section="networking",
            severity="HIGH",
            status="FAIL" if open_sgs else "PASS",
            detail=f"{len(open_sgs)} SGs allow 0.0.0.0/0:{port}"
            if open_sgs
            else f"No SGs allow unrestricted port {port}",
            nist_csf="PR.AC-5",
            iso_27001="A.8.20",
            resources=open_sgs,
        )
    except ClientError as e:
        return Finding(
            control_id=control_id,
            title=title,
            section="networking",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
            iso_27001="A.8.20",
        )


def check_4_1_no_unrestricted_ssh(ec2) -> Finding:
    """CIS 4.1 — No unrestricted SSH."""
    return _check_unrestricted_port(ec2, 22, "4.1", "No unrestricted SSH")


def check_4_2_no_unrestricted_rdp(ec2) -> Finding:
    """CIS 4.2 — No unrestricted RDP."""
    return _check_unrestricted_port(ec2, 3389, "4.2", "No unrestricted RDP")


def check_4_3_vpc_flow_logs(ec2) -> Finding:
    """CIS 4.3 — VPC flow logs enabled."""
    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
        flow_logs = ec2.describe_flow_logs()["FlowLogs"]
        vpc_ids_with_logs = {fl["ResourceId"] for fl in flow_logs if fl.get("ResourceId")}
        no_logs = [v["VpcId"] for v in vpcs if v["VpcId"] not in vpc_ids_with_logs]
        return Finding(
            control_id="4.3",
            title="VPC flow logs enabled",
            section="networking",
            severity="MEDIUM",
            status="FAIL" if no_logs else "PASS",
            detail=f"{len(no_logs)} VPCs without flow logs"
            if no_logs
            else "All VPCs have flow logs",
            nist_csf="DE.CM-1",
            iso_27001="A.8.16",
            resources=no_logs,
        )
    except ClientError as e:
        return Finding(
            control_id="4.3",
            title="VPC flow logs enabled",
            section="networking",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
            iso_27001="A.8.16",
        )


def check_5_4_default_sg_restricts_traffic(ec2) -> Finding:
    """CIS 5.4 — Default VPC security group restricts all traffic."""
    try:
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        )["SecurityGroups"]
        offenders: list[str] = []
        for sg in sgs:
            if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                offenders.append(
                    f"{sg.get('GroupId', '')} (vpc {sg.get('VpcId', '')})"
                )
        return Finding(
            control_id="5.4",
            title="Default VPC SG restricts all traffic",
            section="networking",
            severity="HIGH",
            status="FAIL" if offenders else "PASS",
            detail=f"{len(offenders)} default security group(s) carry rules"
            if offenders
            else "All default security groups are empty",
            nist_csf="PR.AC-5",
            iso_27001="A.8.20",
            resources=offenders,
        )
    except ClientError as e:
        return Finding(
            control_id="5.4",
            title="Default VPC SG restricts all traffic",
            section="networking",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
            iso_27001="A.8.20",
        )


# ---------------------------------------------------------------------------
# Section 6 — Security Services
# ---------------------------------------------------------------------------


def check_6_1_guardduty_enabled(gd) -> Finding:
    """CIS 6.1 — GuardDuty enabled."""
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        return Finding(
            control_id="6.1",
            title="GuardDuty enabled",
            section="security-services",
            severity="MEDIUM",
            status="PASS" if detectors else "FAIL",
            detail=f"{len(detectors)} GuardDuty detector(s) enabled"
            if detectors
            else "GuardDuty is not enabled",
            nist_csf="DE.CM-1",
            iso_27001="A.8.16",
            resources=list(detectors),
        )
    except ClientError as e:
        return Finding(
            control_id="6.1",
            title="GuardDuty enabled",
            section="security-services",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
            iso_27001="A.8.16",
        )


def check_6_2_securityhub_enabled(sh) -> Finding:
    """CIS 6.2 — Security Hub enabled."""
    try:
        hub = sh.describe_hub()
        hub_arn = str(hub.get("HubArn") or "")
        return Finding(
            control_id="6.2",
            title="Security Hub enabled",
            section="security-services",
            severity="MEDIUM",
            status="PASS" if hub_arn else "FAIL",
            detail="Security Hub is enabled" if hub_arn else "Security Hub is not enabled",
            nist_csf="DE.CM-1",
            iso_27001="A.8.16",
            resources=[hub_arn] if hub_arn else [],
        )
    except ClientError as e:
        code = str(e.response.get("Error", {}).get("Code") or "")
        if code in {"InvalidAccessException", "ResourceNotFoundException"}:
            return Finding(
                control_id="6.2",
                title="Security Hub enabled",
                section="security-services",
                severity="MEDIUM",
                status="FAIL",
                detail="Security Hub is not enabled",
                nist_csf="DE.CM-1",
                iso_27001="A.8.16",
            )
        return Finding(
            control_id="6.2",
            title="Security Hub enabled",
            section="security-services",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
            iso_27001="A.8.16",
        )


# ---------------------------------------------------------------------------
# Auto-remediation planner / apply
# ---------------------------------------------------------------------------


def _build_bucket_target(
    finding: Finding,
    *,
    bucket_name: str,
    region: str,
    account_id: str,
    action: str,
    detail: str,
    parameters: dict[str, Any],
) -> RemediationTarget:
    return RemediationTarget(
        control_id=finding.control_id,
        title=finding.title,
        resource_type="s3_bucket",
        resource_id=bucket_name,
        resource_name=bucket_name,
        section=finding.section,
        severity=finding.severity,
        region=region,
        account_id=account_id,
        action=action,
        detail=detail,
        parameters=parameters,
    )


def _build_sg_targets(
    finding: Finding,
    *,
    ec2: Any,
    region: str,
    account_id: str,
    port: int,
) -> list[tuple[RemediationTarget, str | None]]:
    targets: list[tuple[RemediationTarget, str | None]] = []
    for resource in finding.resources:
        sg_id = resource.split(" ", 1)[0]
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        groups = response.get("SecurityGroups", [])
        if not groups:
            continue
        group = groups[0]
        protected, reason = _is_protected_security_group(group)
        for perm in group.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            if from_port is None or to_port is None or not (from_port <= port <= to_port):
                continue
            cidrs = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
            cidrs.extend(
                r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"
            )
            if not cidrs:
                continue
            targets.append(
                (
                    RemediationTarget(
                        control_id=finding.control_id,
                        title=finding.title,
                        resource_type="security_group_rule",
                        resource_id=sg_id,
                        resource_name=str(group.get("GroupName") or sg_id),
                        section=finding.section,
                        severity=finding.severity,
                        region=region,
                        account_id=account_id,
                        action="revoke_security_group_ingress",
                        detail=f"Revoke unrestricted ingress on port {port}",
                        parameters={
                            "ip_protocol": perm.get("IpProtocol", "tcp"),
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidrs": cidrs,
                        },
                    ),
                    reason if protected else None,
                )
            )
    return targets


def build_remediation_targets(
    findings: list[Finding],
    *,
    clients: dict[str, Any],
    region: str,
) -> list[tuple[RemediationTarget, str | None]]:
    targets: list[tuple[RemediationTarget, str | None]] = []
    account_id = _account_id(clients)
    s3 = clients["s3"]
    ec2 = clients["ec2"]

    for finding in findings:
        if finding.status != "FAIL":
            continue
        if finding.control_id not in SUPPORTED_AUTOREMEDIATE_CONTROLS:
            continue
        if finding.control_id == "2.1":
            for bucket_name in finding.resources:
                protected, reason = _is_protected_bucket(s3, bucket_name)
                targets.append(
                    (
                        _build_bucket_target(
                            finding,
                            bucket_name=bucket_name,
                            region=region,
                            account_id=account_id,
                            action="put_bucket_encryption",
                            detail="Enable AES256 default bucket encryption",
                            parameters={
                                "ServerSideEncryptionConfiguration": {
                                    "Rules": [
                                        {
                                            "ApplyServerSideEncryptionByDefault": {
                                                "SSEAlgorithm": "AES256"
                                            }
                                        }
                                    ]
                                }
                            },
                        ),
                        reason if protected else None,
                    )
                )
        elif finding.control_id == "2.3":
            for bucket_name in finding.resources:
                protected, reason = _is_protected_bucket(s3, bucket_name)
                targets.append(
                    (
                        _build_bucket_target(
                            finding,
                            bucket_name=bucket_name,
                            region=region,
                            account_id=account_id,
                            action="put_public_access_block",
                            detail="Enable all four S3 public access block settings",
                            parameters={
                                "PublicAccessBlockConfiguration": {
                                    "BlockPublicAcls": True,
                                    "IgnorePublicAcls": True,
                                    "BlockPublicPolicy": True,
                                    "RestrictPublicBuckets": True,
                                }
                            },
                        ),
                        reason if protected else None,
                    )
                )
        elif finding.control_id == "2.4":
            for bucket_name in finding.resources:
                protected, reason = _is_protected_bucket(s3, bucket_name)
                targets.append(
                    (
                        _build_bucket_target(
                            finding,
                            bucket_name=bucket_name,
                            region=region,
                            account_id=account_id,
                            action="put_bucket_versioning",
                            detail="Enable S3 bucket versioning",
                            parameters={"VersioningConfiguration": {"Status": "Enabled"}},
                        ),
                        reason if protected else None,
                    )
                )
        elif finding.control_id == "4.1":
            targets.extend(
                _build_sg_targets(
                    finding,
                    ec2=ec2,
                    region=region,
                    account_id=account_id,
                    port=22,
                )
            )
        elif finding.control_id == "4.2":
            targets.extend(
                _build_sg_targets(
                    finding,
                    ec2=ec2,
                    region=region,
                    account_id=account_id,
                    port=3389,
                )
            )
    return targets


def _record_for_target(
    target: RemediationTarget,
    *,
    dry_run: bool,
    status: str,
    status_detail: str,
    incident_id: str = "",
    approver: str = "",
    audit: dict[str, str] | None = None,
) -> dict[str, Any]:
    record = {
        "schema_mode": "native",
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "benchmark": BENCHMARK_NAME,
        "provider": PROVIDER_NAME,
        "control_id": target.control_id,
        "title": target.title,
        "target": {
            "resource_type": target.resource_type,
            "resource_id": target.resource_id,
            "resource_name": target.resource_name,
            "region": target.region,
            "account_id": target.account_id,
        },
        "action": {
            "name": target.action,
            "detail": target.detail,
            "parameters": target.parameters,
        },
        "status": status,
        "status_detail": status_detail,
        "dry_run": dry_run,
    }
    if not dry_run:
        record["incident_id"] = incident_id
        record["approver"] = approver
    if audit is not None:
        record["audit"] = audit
    return record


def _apply_target(target: RemediationTarget, clients: dict[str, Any]) -> None:
    if target.action == "put_bucket_encryption":
        clients["s3"].put_bucket_encryption(
            Bucket=target.resource_id,
            ServerSideEncryptionConfiguration=target.parameters["ServerSideEncryptionConfiguration"],
        )
        return
    if target.action == "put_public_access_block":
        clients["s3"].put_public_access_block(
            Bucket=target.resource_id,
            PublicAccessBlockConfiguration=target.parameters["PublicAccessBlockConfiguration"],
        )
        return
    if target.action == "put_bucket_versioning":
        clients["s3"].put_bucket_versioning(
            Bucket=target.resource_id,
            VersioningConfiguration=target.parameters["VersioningConfiguration"],
        )
        return
    if target.action == "revoke_security_group_ingress":
        params = target.parameters
        permission: dict[str, Any] = {
            "IpProtocol": params["ip_protocol"],
            "IpRanges": [{"CidrIp": cidr} for cidr in params["cidrs"] if ":" not in cidr],
            "Ipv6Ranges": [{"CidrIpv6": cidr} for cidr in params["cidrs"] if ":" in cidr],
        }
        if params["ip_protocol"] != "-1":
            permission["FromPort"] = params["from_port"]
            permission["ToPort"] = params["to_port"]
        if not permission["IpRanges"]:
            del permission["IpRanges"]
        if not permission["Ipv6Ranges"]:
            del permission["Ipv6Ranges"]
        clients["ec2"].revoke_security_group_ingress(GroupId=target.resource_id, IpPermissions=[permission])
        return
    raise ValueError(f"unsupported remediation action `{target.action}`")


def _check_apply_gate() -> tuple[bool, str]:
    incident_id = os.getenv("CSPM_AWS_AUTOREMEDIATE_INCIDENT_ID", "").strip()
    approver = os.getenv("CSPM_AWS_AUTOREMEDIATE_APPROVER", "").strip()
    if not incident_id:
        return False, "CSPM_AWS_AUTOREMEDIATE_INCIDENT_ID is required for --apply"
    if not approver:
        return False, "CSPM_AWS_AUTOREMEDIATE_APPROVER is required for --apply"
    allowed_accounts = _parse_env_list("CSPM_AWS_AUTOREMEDIATE_ALLOWED_ACCOUNT_IDS")
    if not allowed_accounts:
        return (
            False,
            "CSPM_AWS_AUTOREMEDIATE_ALLOWED_ACCOUNT_IDS must explicitly include the current account for --apply",
        )
    return True, ""


def _check_apply_account_boundary(clients: dict[str, Any]) -> tuple[bool, str]:
    account_id = _account_id(clients)
    if len(account_id) != 12 or not account_id.isdigit():
        return False, "unable to resolve a valid 12-digit AWS account ID for --apply"
    allowed_accounts = _parse_env_list("CSPM_AWS_AUTOREMEDIATE_ALLOWED_ACCOUNT_IDS")
    if account_id not in allowed_accounts:
        return (
            False,
            f"current AWS account {account_id} is not listed in CSPM_AWS_AUTOREMEDIATE_ALLOWED_ACCOUNT_IDS",
        )
    return True, ""


def _resolve_apply_identity() -> tuple[str, str]:
    return (
        os.getenv("CSPM_AWS_AUTOREMEDIATE_INCIDENT_ID", "").strip(),
        os.getenv("CSPM_AWS_AUTOREMEDIATE_APPROVER", "").strip(),
    )


def _confirm_apply(confirm: str | None) -> None:
    if confirm == CONFIRM_APPLY_PHRASE:
        return
    if not sys.stdin.isatty():
        raise ValueError(
            f"--apply requires interactive confirmation or --confirm {CONFIRM_APPLY_PHRASE}"
        )
    response = input(
        f"Type {CONFIRM_APPLY_PHRASE} to apply AWS CIS auto-remediation changes: "
    ).strip()
    if response != CONFIRM_APPLY_PHRASE:
        raise ValueError("confirmation declined")


def build_remediation_records(
    findings: list[Finding],
    *,
    clients: dict[str, Any],
    region: str,
    apply: bool,
    confirm: str | None = None,
) -> list[dict[str, Any]]:
    targets = build_remediation_targets(findings, clients=clients, region=region)
    if not targets:
        return []

    incident_id = ""
    approver = ""
    audit_writer: DualAuditWriter | None = None
    if apply:
        ok, reason = _check_apply_gate()
        if not ok:
            raise ValueError(reason)
        ok, reason = _check_apply_account_boundary(clients)
        if not ok:
            raise ValueError(reason)
        _confirm_apply(confirm)
        incident_id, approver = _resolve_apply_identity()
        audit_writer = DualAuditWriter(
            dynamodb_table=os.environ["CSPM_AWS_AUTOREMEDIATE_AUDIT_DYNAMODB_TABLE"],
            s3_bucket=os.environ["CSPM_AWS_AUTOREMEDIATE_AUDIT_BUCKET"],
            kms_key_arn=os.environ["CSPM_AWS_AUTOREMEDIATE_AUDIT_KMS_KEY_ARN"],
        )

    records: list[dict[str, Any]] = []
    for target, protected_reason in targets:
        if protected_reason:
            records.append(
                _record_for_target(
                    target,
                    dry_run=not apply,
                    status=STATUS_WOULD_VIOLATE_PROTECTED,
                    status_detail=protected_reason,
                    incident_id=incident_id,
                    approver=approver,
                )
            )
            continue

        if not apply:
            records.append(
                _record_for_target(
                    target,
                    dry_run=True,
                    status=STATUS_PLANNED,
                    status_detail=target.detail,
                )
            )
            continue

        assert audit_writer is not None
        audit = audit_writer.record(
            target=target,
            status="in_progress",
            detail=f"about to execute {target.action}",
            incident_id=incident_id,
            approver=approver,
        )
        try:
            _apply_target(target, clients)
        except Exception as exc:
            audit_writer.record(
                target=target,
                status=STATUS_FAILURE,
                detail=str(exc),
                incident_id=incident_id,
                approver=approver,
            )
            records.append(
                _record_for_target(
                    target,
                    dry_run=False,
                    status=STATUS_FAILURE,
                    status_detail=str(exc),
                    incident_id=incident_id,
                    approver=approver,
                    audit=audit,
                )
            )
            continue

        success_audit = audit_writer.record(
            target=target,
            status=STATUS_SUCCESS,
            detail=f"executed {target.action}",
            incident_id=incident_id,
            approver=approver,
        )
        records.append(
            _record_for_target(
                target,
                dry_run=False,
                status=STATUS_SUCCESS,
                status_detail=target.detail,
                incident_id=incident_id,
                approver=approver,
                audit=success_audit,
            )
        )
    return records


def print_remediation_summary(records: list[dict[str, Any]]) -> None:
    if not records:
        print("\n  No supported failing controls for auto-remediation.")
        return
    print("\n  [AUTO-REMEDIATE]")
    for record in records:
        target = record["target"]
        print(f"  {record['control_id']} {target['resource_id']} -> {record['action']['name']}")
        print(f"         {record['status']}: {record['status_detail']}")


def _auto_remediation_exit_code(
    findings: list[Finding],
    records: list[dict[str, Any]],
    *,
    apply: bool,
) -> int:
    critical_high_fails = [
        f for f in findings if f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH")
    ]
    if not records:
        return 1 if critical_high_fails else 0
    if apply:
        failed_records = [r for r in records if r["status"] in {STATUS_FAILURE, STATUS_WOULD_VIOLATE_PROTECTED}]
        return 1 if failed_records or critical_high_fails else 0
    return 1 if critical_high_fails else 0

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

SECTIONS: dict[str, list] = {
    "iam": [
        check_1_1_root_mfa,
        check_1_2_user_mfa,
        check_1_3_stale_credentials,
        check_1_4_key_rotation,
        check_1_5_password_policy,
        check_1_6_no_root_keys,
        check_1_7_no_inline_policies,
        check_1_9_password_reuse,
        check_1_13_one_active_key,
        check_1_14_hardware_mfa_root,
        check_1_16_no_user_attached_policies,
        check_1_20_access_analyzer,
    ],
    "storage": [
        check_2_1_s3_encryption,
        check_2_1_4_s3_ssl_required,
        check_2_2_s3_logging,
        check_2_2_1_ebs_encryption_default,
        check_2_3_s3_public_access,
        check_2_4_s3_versioning,
    ],
    "logging": [
        check_3_1_cloudtrail_multiregion,
        check_3_2_cloudtrail_validation,
        check_3_3_cloudtrail_s3_not_public,
        check_3_4_cloudwatch_alarms,
        check_3_5_cloudtrail_kms_encryption,
        check_3_6_cloudtrail_data_events,
        check_3_7_cloudtrail_cloudwatch_integration,
    ],
    "networking": [
        check_4_1_no_unrestricted_ssh,
        check_4_2_no_unrestricted_rdp,
        check_4_3_vpc_flow_logs,
        check_5_4_default_sg_restricts_traffic,
    ],
    "security-services": [
        check_6_1_guardduty_enabled,
        check_6_2_securityhub_enabled,
    ],
}


def _get_clients(region: str) -> dict[str, Any]:
    session = boto3.Session(region_name=region)
    return {
        "iam": session.client("iam"),
        "s3": session.client("s3"),
        "ct": session.client("cloudtrail"),
        "cw": session.client("cloudwatch"),
        "ec2": session.client("ec2"),
        "gd": session.client("guardduty"),
        "sh": session.client("securityhub"),
        "sts": session.client("sts"),
        "aa": session.client("accessanalyzer"),
    }


# Function-name → client-key overrides for checks whose default
# section-prefix routing would land on the wrong client.
_CLIENT_OVERRIDES: dict[str, str] = {
    "check_1_20_access_analyzer": "aa",
    "check_2_2_1_ebs_encryption_default": "ec2",
    "check_5_4_default_sg_restricts_traffic": "ec2",
}


def _run_check(fn, clients: dict) -> Finding:
    """Route check function to the right client(s)."""
    name = fn.__name__
    if name in _CLIENT_OVERRIDES:
        return fn(clients[_CLIENT_OVERRIDES[name]])
    if "cloudtrail_s3" in name:
        return fn(clients["ct"], clients["s3"])
    if name.startswith("check_1"):
        return fn(clients["iam"])
    if name.startswith("check_2"):
        return fn(clients["s3"])
    if name.startswith("check_3") or "cloudtrail" in name or "cloudwatch" in name:
        return fn(clients["ct"] if "cloudtrail" in name else clients["cw"])
    if name.startswith("check_4") or name.startswith("check_5"):
        return fn(clients["ec2"])
    if "guardduty" in name:
        return fn(clients["gd"])
    if "securityhub" in name:
        return fn(clients["sh"])
    return fn(clients["iam"])


def run_assessment(
    region: str = "us-east-1",
    section: str | None = None,
    *,
    clients: dict[str, Any] | None = None,
) -> list[Finding]:
    clients = clients or _get_clients(region)
    findings: list[Finding] = []

    sections_to_run = {section: SECTIONS[section]} if section and section in SECTIONS else SECTIONS
    for checks in sections_to_run.values():
        for check_fn in checks:
            findings.append(_run_check(check_fn, clients))

    return findings


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[93m",
        "MEDIUM": "\033[33m",
        "LOW": "\033[36m",
    }.get(severity, "")


def _status_symbol(status: str) -> str:
    return {
        "PASS": "\033[92m✓\033[0m",
        "FAIL": "\033[91m✗\033[0m",
        "ERROR": "\033[90m?\033[0m",
    }.get(status, "?")


def print_summary(findings: list[Finding]) -> None:
    passed = sum(1 for f in findings if f.status == "PASS")
    failed = sum(1 for f in findings if f.status == "FAIL")
    errors = sum(1 for f in findings if f.status == "ERROR")
    total = len(findings)

    print(f"\n{'=' * 60}")
    print("  CIS AWS Foundations v3.0 — Assessment Results")
    print(f"{'=' * 60}\n")

    current_section = ""
    for f in findings:
        if f.section != current_section:
            current_section = f.section
            print(f"\n  [{current_section.upper()}]")
        symbol = _status_symbol(f.status)
        print(f"  {symbol} {f.control_id}  {f.title}")
        if f.status != "PASS":
            print(f"         {f.detail}")
            if f.resources:
                for r in f.resources[:5]:
                    print(f"         - {r}")
                if len(f.resources) > 5:
                    print(f"         ... and {len(f.resources) - 5} more")

    print(f"\n{'─' * 60}")
    pct = (passed / total * 100) if total else 0
    print(f"  Score: {passed}/{total} passed ({pct:.0f}%)")
    print(f"  PASS: {passed}  FAIL: {failed}  ERROR: {errors}")
    print(f"{'─' * 60}\n")


def main():
    parser = argparse.ArgumentParser(description="CIS AWS Foundations Benchmark v3.0 Assessment")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument(
        "--section", choices=list(SECTIONS.keys()), help="Run specific section only"
    )
    parser.add_argument(
        "--output", choices=["console", "json"], default="console", help="Output format"
    )
    parser.add_argument(
        "--output-format",
        choices=list(OUTPUT_FORMATS),
        default="native",
        help="Structured JSON format for --output json",
    )
    parser.add_argument(
        "--auto-remediate",
        action="store_true",
        help="Emit remediation plans for supported failing controls (AWS-first slice: 2.1, 2.3, 2.4, 4.1, 4.2).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Execute supported remediation actions. Requires --auto-remediate, HITL env vars, and confirmation.",
    )
    parser.add_argument(
        "--confirm",
        help=f"Non-interactive confirmation helper. Must equal {CONFIRM_APPLY_PHRASE} when used with --apply.",
    )
    args = parser.parse_args()

    if args.apply and not args.auto_remediate:
        raise SystemExit("--apply requires --auto-remediate")

    clients = _get_clients(args.region)
    findings = run_assessment(region=args.region, section=args.section, clients=clients)
    remediation_records: list[dict[str, Any]] = []
    if args.auto_remediate:
        remediation_records = build_remediation_records(
            findings,
            clients=clients,
            region=args.region,
            apply=args.apply,
            confirm=args.confirm,
        )

    if args.output == "json":
        findings_rendered = (
            findings_to_ocsf(
                findings,
                skill_name=SKILL_NAME,
                benchmark_name=BENCHMARK_NAME,
                provider=PROVIDER_NAME,
                frameworks=["CIS AWS Foundations v3.0", "NIST CSF 2.0", "ISO/IEC 27001:2022"],
            )
            if args.output_format == "ocsf"
            else findings_to_native(findings)
        )
        payload: Any = findings_rendered
        if args.auto_remediate:
            payload = {
                "findings": findings_rendered,
                "remediation": remediation_records,
            }
        print(json.dumps(payload, indent=2))
    else:
        print_summary(findings)
        if args.auto_remediate:
            print_remediation_summary(remediation_records)

    if args.auto_remediate:
        sys.exit(_auto_remediation_exit_code(findings, remediation_records, apply=args.apply))

    critical_high_fails = [
        f for f in findings if f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH")
    ]
    sys.exit(1 if critical_high_fails else 0)


if __name__ == "__main__":
    if "--worker" in sys.argv:
        from skills._shared.worker_harness import run_worker

        raise SystemExit(run_worker(main))
    main()
