"""Revoke an Azure NSG inbound rule flagged as open to the internet.

Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by
detect-azure-open-nsg (T1190 — Exploit Public-Facing Application).
Plans (dry-run default), applies (--apply), or re-verifies (--reverify)
removal of the offending NSG security rule via the Azure Resource
Manager (`azure-mgmt-network` SDK).

Two modes:
- `--mode delete` (default) — `security_rules.begin_delete()`. Cleanest
  reversible op since rule definitions are versioned by Azure RM.
- `--mode patch` — `security_rules.begin_create_or_update()` with
  `access: Deny` for the same priority+source+destination tuple.

Why surgical revoke (not "delete the NSG"):
- The parent NSG hosts other legitimate rules; deleting the NSG breaks them
- The detector identifies the OFFENDING rule by its fully-qualified
  ARM resource id. We touch only that one rule.

Guardrails enforced in code:
- ACCEPTED_PRODUCERS limits input to detect-azure-open-nsg
- Protected rule deny-list:
    * any rule name beginning with `default` / `Default` (platform-default rules)
    * any NSG name ending with `-protected`
    * any parent NSG with the `intentionally-open` tag
    * any rule id in AZURE_NSG_REVOKE_DENY_RULE_IDS env var (comma-separated)
- --apply requires AZURE_NSG_REVOKE_INCIDENT_ID + AZURE_NSG_REVOKE_APPROVER
- Dual audit BEFORE and AFTER each action
- --reverify confirms the offending rule is absent or patched to Deny;
  DRIFT (re-added as Allow) emits paired OCSF Detection Finding via the
  shared remediation_verifier contract
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Protocol

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.remediation_verifier import (  # noqa: E402
    DEFAULT_VERIFICATION_SLA_MS,
    RemediationReference,
    VerificationResult,
    VerificationStatus,
    build_drift_finding,
    build_verification_record,
    sla_deadline,
)
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "remediate-azure-nsg-revoke"
CANONICAL_VERSION = "2026-04"
ACCEPTED_PRODUCERS = frozenset({"detect-azure-open-nsg"})

DEFAULT_PROTECTED_RULE_NAME_PREFIXES = ("default", "Default")
DEFAULT_PROTECTED_NSG_NAME_SUFFIXES = ("-protected",)
DEFAULT_INTENTIONALLY_OPEN_TAG = "intentionally-open"

MODE_DELETE = "delete"
MODE_PATCH = "patch"
SUPPORTED_MODES = frozenset({MODE_DELETE, MODE_PATCH})

RECORD_PLAN = "remediation_plan"
RECORD_ACTION = "remediation_action"
RECORD_VERIFICATION = "remediation_verification"

STEP_DELETE_RULE = "delete_security_rule"
STEP_PATCH_RULE = "patch_security_rule_to_deny"

STATUS_PLANNED = "planned"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_VERIFIED = "verified"
STATUS_DRIFT = "drift"
STATUS_SKIPPED_SOURCE = "skipped_wrong_source"
STATUS_SKIPPED_PROTECTED = "skipped_protected_rule"
STATUS_WOULD_VIOLATE_PROTECTED = "would-violate-protected-rule"
STATUS_SKIPPED_NO_RULE = "skipped_no_rule_pointer"
STATUS_SKIPPED_BAD_RULE_ID = "skipped_unparseable_rule_id"
STATUS_SKIPPED_SUBSCRIPTION_BOUNDARY = "skipped_subscription_boundary"

# Format: /subscriptions/<sub>/resourceGroups/<rg>/providers/
#         Microsoft.Network/networkSecurityGroups/<nsg>/securityRules/<rule>
_RULE_ID_RE = re.compile(
    r"^/subscriptions/(?P<sub>[^/]+)"
    r"/resourceGroups/(?P<rg>[^/]+)"
    r"/providers/Microsoft\.Network"
    r"/networkSecurityGroups/(?P<nsg>[^/]+)"
    r"/securityRules/(?P<rule>[^/]+)/?$",
    re.IGNORECASE,
)


@dataclasses.dataclass(frozen=True)
class Target:
    rule_id: str  # fully-qualified ARM id
    rule_name: str  # last path segment
    nsg_name: str
    resource_group: str
    subscription_id: str
    region: str
    source_prefixes: tuple[str, ...]
    ports: tuple[int, ...]
    protocol: str
    direction: str
    actor: str
    rule: str  # which detector rule fired
    producer_skill: str
    finding_uid: str


@dataclasses.dataclass(frozen=True)
class ParsedRuleId:
    subscription_id: str
    resource_group: str
    nsg_name: str
    rule_name: str


class NetworkClient(Protocol):
    """Minimal Azure NetworkManagementClient surface this skill needs.
    Tests inject a stub."""

    def get_security_rule(
        self, *, subscription_id: str, resource_group: str, nsg_name: str, rule_name: str
    ) -> dict[str, Any] | None: ...

    def get_network_security_group(
        self, *, subscription_id: str, resource_group: str, nsg_name: str
    ) -> dict[str, Any] | None: ...

    def delete_security_rule(
        self, *, subscription_id: str, resource_group: str, nsg_name: str, rule_name: str
    ) -> None: ...

    def patch_security_rule_to_deny(
        self,
        *,
        subscription_id: str,
        resource_group: str,
        nsg_name: str,
        rule_name: str,
        existing: dict[str, Any],
    ) -> None: ...


class AuditWriter(Protocol):
    def record(
        self,
        *,
        target: Target,
        step: str,
        status: str,
        detail: str | None,
        incident_id: str,
        approver: str,
    ) -> dict[str, str]: ...


@dataclasses.dataclass
class AzureNetworkClient:
    """Real Azure NetworkManagementClient. Lazy-imports azure-mgmt-network +
    azure-identity so tests don't need them installed."""

    def _credential(self) -> Any:
        from azure.identity import DefaultAzureCredential

        return DefaultAzureCredential()

    def _client(self, subscription_id: str) -> Any:
        from azure.mgmt.network import NetworkManagementClient

        return NetworkManagementClient(self._credential(), subscription_id)

    @staticmethod
    def _to_dict(obj: Any) -> dict[str, Any] | None:
        if obj is None:
            return None
        if hasattr(obj, "as_dict"):
            try:
                return obj.as_dict()
            except Exception:
                return None
        if isinstance(obj, dict):
            return obj
        return None

    def get_security_rule(
        self, *, subscription_id: str, resource_group: str, nsg_name: str, rule_name: str
    ) -> dict[str, Any] | None:
        try:
            rule = self._client(subscription_id).security_rules.get(
                resource_group, nsg_name, rule_name
            )
        except Exception:
            return None
        return self._to_dict(rule)

    def get_network_security_group(
        self, *, subscription_id: str, resource_group: str, nsg_name: str
    ) -> dict[str, Any] | None:
        try:
            nsg = self._client(subscription_id).network_security_groups.get(
                resource_group, nsg_name
            )
        except Exception:
            return None
        return self._to_dict(nsg)

    def delete_security_rule(
        self, *, subscription_id: str, resource_group: str, nsg_name: str, rule_name: str
    ) -> None:
        poller = self._client(subscription_id).security_rules.begin_delete(
            resource_group, nsg_name, rule_name
        )
        poller.result()

    def patch_security_rule_to_deny(
        self,
        *,
        subscription_id: str,
        resource_group: str,
        nsg_name: str,
        rule_name: str,
        existing: dict[str, Any],
    ) -> None:
        # Preserve priority + tuple; flip access to Deny.
        params = dict(existing or {})
        params["access"] = "Deny"
        params.pop("etag", None)
        params.pop("provisioning_state", None)
        params.pop("provisioningState", None)
        poller = self._client(subscription_id).security_rules.begin_create_or_update(
            resource_group, nsg_name, rule_name, params
        )
        poller.result()


@dataclasses.dataclass
class DualAuditWriter:
    dynamodb_table: str
    s3_bucket: str
    kms_key_arn: str

    def record(
        self,
        *,
        target: Target,
        step: str,
        status: str,
        detail: str | None,
        incident_id: str,
        approver: str,
    ) -> dict[str, str]:
        import boto3

        action_at = datetime.now(timezone.utc).isoformat()
        row_uid = _deterministic_uid(target.rule_id, step, action_at)
        evidence_key = (
            "azure-nsg-revoke/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{_safe_path_component(target.rule_name or target.rule_id)}/{action_at}-{step}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"

        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "provider": "azure",
            "rule_id": target.rule_id,
            "rule_name": target.rule_name,
            "nsg_name": target.nsg_name,
            "resource_group": target.resource_group,
            "subscription_id": target.subscription_id,
            "region": target.region,
            "cloud": {
                "account": {"uid": target.subscription_id},
                "region": target.region,
                "provider": "Azure",
            },
            "source_prefixes": list(target.source_prefixes),
            "ports": list(target.ports),
            "protocol": target.protocol,
            "direction": target.direction,
            "actor": target.actor,
            "rule": target.rule,
            "producer_skill": target.producer_skill,
            "finding_uid": target.finding_uid,
            "step": step,
            "status": status,
            "status_detail": detail,
            "incident_id": incident_id,
            "approver": approver,
            "action_at": action_at,
        }
        body = json.dumps(envelope, separators=(",", ":"))
        boto3.client("s3").put_object(
            Bucket=self.s3_bucket,
            Key=evidence_key,
            Body=body.encode("utf-8"),
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self.kms_key_arn,
            ContentType="application/json",
        )
        boto3.client("dynamodb").put_item(
            TableName=self.dynamodb_table,
            Item={
                "rule_id": {"S": target.rule_id},
                "action_at": {"S": action_at},
                "row_uid": {"S": row_uid},
                "step": {"S": step},
                "status": {"S": status},
                "incident_id": {"S": incident_id},
                "approver": {"S": approver},
                "rule_name": {"S": target.rule_name},
                "nsg_name": {"S": target.nsg_name},
                "resource_group": {"S": target.resource_group},
                "subscription_id": {"S": target.subscription_id},
                "region": {"S": target.region},
                "actor": {"S": target.actor},
                "rule": {"S": target.rule},
                "producer_skill": {"S": target.producer_skill},
                "finding_uid": {"S": target.finding_uid},
                "s3_evidence_uri": {"S": evidence_uri},
                "provider": {"S": "azure"},
            },
        )
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    return f"ansgr-{hashlib.sha256('|'.join(parts).encode('utf-8')).hexdigest()[:16]}"


def _safe_path_component(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (value or "_"))
    return safe[:120] or "_"


def parse_rule_id(rule_id: str) -> ParsedRuleId | None:
    if not rule_id:
        return None
    match = _RULE_ID_RE.match(rule_id.strip())
    if not match:
        return None
    return ParsedRuleId(
        subscription_id=match.group("sub"),
        resource_group=match.group("rg"),
        nsg_name=match.group("nsg"),
        rule_name=match.group("rule"),
    )


def _finding_product(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _finding_uid(event: dict[str, Any]) -> str:
    return str(
        (event.get("finding_info") or {}).get("uid")
        or (event.get("metadata") or {}).get("uid")
        or ""
    )


def _observable_value(event: dict[str, Any], name: str) -> str:
    for obs in event.get("observables") or []:
        if isinstance(obs, dict) and obs.get("name") == name and obs.get("value"):
            return str(obs["value"])
    return ""


def _observable_values(event: dict[str, Any], name: str) -> tuple[str, ...]:
    values = []
    for obs in event.get("observables") or []:
        if isinstance(obs, dict) and obs.get("name") == name and obs.get("value"):
            values.append(str(obs["value"]))
    return tuple(values)


def _safe_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _event_reference_time_ms(event: dict[str, Any]) -> int | None:
    candidates = (
        event.get("remediated_at_ms"),
        event.get("time_ms"),
        event.get("time"),
        ((event.get("finding_info") or {}).get("last_seen_time")),
        ((event.get("finding_info") or {}).get("first_seen_time")),
    )
    for value in candidates:
        parsed = _safe_int(str(value)) if value is not None else None
        if parsed is not None and parsed > 0:
            return parsed
    return None


def _target_from_event(event: dict[str, Any]) -> Target | None:
    producer = _finding_product(event)
    if producer not in ACCEPTED_PRODUCERS:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="wrong_source_skill",
            message=f"skipping finding from unaccepted producer `{producer or '<missing>'}`",
        )
        return None

    rule_id = _observable_value(event, "target.uid")
    rule_name_obs = _observable_value(event, "target.name")
    region = _observable_value(event, "region")
    account_uid = _observable_value(event, "account.uid")
    actor = _observable_value(event, "actor.name")
    rule = _observable_value(event, "rule")

    parsed = parse_rule_id(rule_id)
    if parsed is not None:
        rule_name = parsed.rule_name
        nsg_name = parsed.nsg_name
        resource_group = parsed.resource_group
        subscription_id = parsed.subscription_id or account_uid
    else:
        rule_name = rule_name_obs
        nsg_name = ""
        resource_group = ""
        subscription_id = account_uid

    source_prefixes = _observable_values(event, "rule.source_prefix")
    port_strs = _observable_values(event, "rule.port")
    ports: list[int] = []
    for p in port_strs:
        parsed_port = _safe_int(p)
        if parsed_port is not None:
            ports.append(parsed_port)
    protocol = _observable_value(event, "rule.protocol") or "Tcp"
    direction = _observable_value(event, "rule.direction") or "Inbound"

    return Target(
        rule_id=rule_id,
        rule_name=rule_name or rule_name_obs,
        nsg_name=nsg_name,
        resource_group=resource_group,
        subscription_id=subscription_id,
        region=region,
        source_prefixes=source_prefixes,
        ports=tuple(ports),
        protocol=protocol,
        direction=direction,
        actor=actor,
        rule=rule,
        producer_skill=producer,
        finding_uid=_finding_uid(event),
    )


def parse_targets(
    events: Iterable[dict[str, Any]],
) -> Iterator[tuple[Target | None, dict[str, Any]]]:
    for event in events:
        yield _target_from_event(event), event


def load_protected_rule_ids() -> tuple[str, ...]:
    raw = os.getenv("AZURE_NSG_REVOKE_DENY_RULE_IDS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def is_protected_rule(
    target: Target,
    *,
    rule_name_prefixes: Iterable[str],
    nsg_name_suffixes: Iterable[str],
    rule_ids: Iterable[str],
    intentionally_open_tag: str,
    nsg_describe: dict[str, Any] | None,
) -> tuple[bool, str]:
    if target.rule_id and target.rule_id in set(rule_ids):
        return True, f"rule-id allowlist match `{target.rule_id}`"
    rule_name = target.rule_name or ""
    for prefix in rule_name_prefixes:
        if rule_name.startswith(prefix):
            return True, f"rule-name prefix `{prefix}`"
    nsg_name_lc = (target.nsg_name or "").strip().lower()
    if nsg_name_lc:
        for suffix in nsg_name_suffixes:
            if nsg_name_lc.endswith(suffix.lower()):
                return True, f"nsg-name suffix `{suffix}`"
    if nsg_describe is not None:
        tags = nsg_describe.get("tags") or nsg_describe.get("Tags") or {}
        if isinstance(tags, dict) and intentionally_open_tag in tags:
            return True, f"tag `{intentionally_open_tag}={tags[intentionally_open_tag]}`"
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, dict) and tag.get("Key") == intentionally_open_tag:
                    return True, f"tag `{intentionally_open_tag}={tag.get('Value')}`"
    return False, ""


def check_apply_gate() -> tuple[bool, str]:
    incident_id = os.getenv("AZURE_NSG_REVOKE_INCIDENT_ID", "").strip()
    approver = os.getenv("AZURE_NSG_REVOKE_APPROVER", "").strip()
    if not incident_id:
        return False, "AZURE_NSG_REVOKE_INCIDENT_ID is required for --apply"
    if not approver:
        return False, "AZURE_NSG_REVOKE_APPROVER is required for --apply"
    if not load_allowed_subscription_ids():
        return False, "AZURE_NSG_REVOKE_ALLOWED_SUBSCRIPTION_IDS is required for --apply"
    return True, ""


def load_allowed_subscription_ids() -> tuple[str, ...]:
    raw = os.getenv("AZURE_NSG_REVOKE_ALLOWED_SUBSCRIPTION_IDS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _delete_endpoint(target: Target) -> str:
    return (
        "DELETE Microsoft.Network/networkSecurityGroups/securityRules "
        f"sub={target.subscription_id} rg={target.resource_group} "
        f"nsg={target.nsg_name} rule={target.rule_name}"
    )


def _patch_endpoint(target: Target) -> str:
    return (
        "PUT Microsoft.Network/networkSecurityGroups/securityRules "
        f"sub={target.subscription_id} rg={target.resource_group} "
        f"nsg={target.nsg_name} rule={target.rule_name} access=Deny"
    )


def _verify_endpoint(target: Target) -> str:
    return (
        "GET Microsoft.Network/networkSecurityGroups/securityRules "
        f"sub={target.subscription_id} rg={target.resource_group} "
        f"nsg={target.nsg_name} rule={target.rule_name}"
    )


def _target_block(target: Target) -> dict[str, Any]:
    return {
        "provider": "Azure",
        "rule_id": target.rule_id,
        "rule_name": target.rule_name,
        "nsg_name": target.nsg_name,
        "resource_group": target.resource_group,
        "subscription_id": target.subscription_id,
        "region": target.region,
        "source_prefixes": list(target.source_prefixes),
        "ports": list(target.ports),
        "protocol": target.protocol,
        "direction": target.direction,
        "actor": target.actor,
        "rule": target.rule,
    }


def _plan_record(
    target: Target, *, status: str, detail: str | None, dry_run: bool, mode: str
) -> dict[str, Any]:
    step = STEP_DELETE_RULE if mode == MODE_DELETE else STEP_PATCH_RULE
    endpoint = _delete_endpoint(target) if mode == MODE_DELETE else _patch_endpoint(target)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": _target_block(target),
        "actions": [
            {
                "step": step,
                "endpoint": endpoint,
                "status": status,
                "detail": detail,
            }
        ],
        "status": status,
        "mode": mode,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def _skip_record(
    target: Target, *, status: str, detail: str, dry_run: bool, mode: str
) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": _target_block(target),
        "actions": [],
        "status": status,
        "status_detail": detail,
        "mode": mode,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def revoke_rule(
    target: Target,
    *,
    network_client: NetworkClient,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
    mode: str,
) -> dict[str, Any]:
    step = STEP_DELETE_RULE if mode == MODE_DELETE else STEP_PATCH_RULE
    first = audit.record(
        target=target,
        step=step,
        status=STATUS_IN_PROGRESS,
        detail=(
            f"about to {mode} rule `{target.rule_name}` on NSG `{target.nsg_name}` "
            f"in rg `{target.resource_group}` (sub `{target.subscription_id}`)"
        ),
        incident_id=incident_id,
        approver=approver,
    )
    try:
        if mode == MODE_DELETE:
            network_client.delete_security_rule(
                subscription_id=target.subscription_id,
                resource_group=target.resource_group,
                nsg_name=target.nsg_name,
                rule_name=target.rule_name,
            )
        else:
            existing = (
                network_client.get_security_rule(
                    subscription_id=target.subscription_id,
                    resource_group=target.resource_group,
                    nsg_name=target.nsg_name,
                    rule_name=target.rule_name,
                )
                or {}
            )
            network_client.patch_security_rule_to_deny(
                subscription_id=target.subscription_id,
                resource_group=target.resource_group,
                nsg_name=target.nsg_name,
                rule_name=target.rule_name,
                existing=existing,
            )
    except Exception as exc:
        audit.record(
            target=target,
            step=step,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approver=approver,
        )
        rec = _plan_record(target, status=STATUS_FAILURE, detail=str(exc), dry_run=False, mode=mode)
        rec["audit"] = first
        return rec

    last = audit.record(
        target=target,
        step=step,
        status=STATUS_SUCCESS,
        detail=f"{mode} succeeded for rule `{target.rule_name}` on NSG `{target.nsg_name}`",
        incident_id=incident_id,
        approver=approver,
    )
    rec = _plan_record(target, status=STATUS_SUCCESS, detail=None, dry_run=False, mode=mode)
    rec["audit"] = last
    rec["incident_id"] = incident_id
    rec["approver"] = approver
    return rec


def _rule_is_open_allow(rule: dict[str, Any]) -> bool:
    """A rule is still 'offending' if direction=Inbound + access=Allow + a public source prefix."""
    props = rule.get("properties") if isinstance(rule.get("properties"), dict) else rule
    direction = str((props or {}).get("direction") or "").strip().lower()
    access = str((props or {}).get("access") or "").strip().lower()
    if direction != "inbound" or access != "allow":
        return False
    public = {"*", "internet", "0.0.0.0/0", "::/0"}
    src = (props or {}).get("sourceAddressPrefix")
    if isinstance(src, str) and src.strip().lower() in public:
        return True
    srcs = (props or {}).get("sourceAddressPrefixes")
    if isinstance(srcs, list):
        for s in srcs:
            if isinstance(s, str) and s.strip().lower() in public:
                return True
    return False


def reverify_target(
    target: Target,
    *,
    network_client: NetworkClient,
    now_ms: int | None = None,
    remediated_at_ms: int | None = None,
) -> list[dict[str, Any]]:
    """Re-verify the offending rule is gone (or patched to Deny).
    Emits one verification record; on DRIFT also emits OCSF Detection Finding."""
    checked_at_ms = (
        now_ms if now_ms is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    )
    remediated_at_ms_resolved = remediated_at_ms if remediated_at_ms is not None else checked_at_ms

    reference = RemediationReference(
        remediation_skill=SKILL_NAME,
        remediation_action_uid=_deterministic_uid("revoke", target.rule_id),
        target_provider="Azure",
        target_identifier=target.rule_id,
        original_finding_uid=target.finding_uid,
        remediated_at_ms=remediated_at_ms_resolved,
    )
    expected = (
        f"NSG security rule `{target.rule_id}` is absent OR patched to access=Deny "
        f"OR no longer carries a public source prefix"
    )

    if not (
        target.subscription_id and target.resource_group and target.nsg_name and target.rule_name
    ):
        result = VerificationResult(
            status=VerificationStatus.UNREACHABLE,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="rule id was not parseable into sub/rg/nsg/rule; cannot reverify",
            detail="missing target identifier components",
        )
        record = build_verification_record(
            reference=reference, result=result, verifier_skill=SKILL_NAME
        )
        record["target"] = _target_block(target)
        return [record]

    try:
        rule = network_client.get_security_rule(
            subscription_id=target.subscription_id,
            resource_group=target.resource_group,
            nsg_name=target.nsg_name,
            rule_name=target.rule_name,
        )
    except Exception as exc:
        result = VerificationResult(
            status=VerificationStatus.UNREACHABLE,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="security_rules.get raised; cannot determine state",
            detail=str(exc),
        )
        record = build_verification_record(
            reference=reference, result=result, verifier_skill=SKILL_NAME
        )
        record["target"] = _target_block(target)
        return [record]

    if rule is None:
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="security rule not found (deleted)",
            detail="containment confirmed via absence",
        )
    elif _rule_is_open_allow(rule):
        result = VerificationResult(
            status=VerificationStatus.DRIFT,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state=f"rule re-appeared as Inbound/Allow with public source: {rule}",
            detail="ingress was re-added or never landed",
        )
    else:
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="rule present but no longer Inbound/Allow with public source",
            detail="revoke confirmed (delete or patch landed)",
        )

    record = build_verification_record(
        reference=reference, result=result, verifier_skill=SKILL_NAME
    )
    record["target"] = _target_block(target)
    outputs: list[dict[str, Any]] = [record]
    if result.status == VerificationStatus.DRIFT:
        outputs.append(
            build_drift_finding(reference=reference, result=result, verifier_skill=SKILL_NAME)
        )
    return outputs


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


def run(
    events: Iterable[dict[str, Any]],
    *,
    network_client: NetworkClient,
    apply: bool = False,
    reverify: bool = False,
    audit: AuditWriter | None = None,
    rule_name_prefixes: Iterable[str] = DEFAULT_PROTECTED_RULE_NAME_PREFIXES,
    nsg_name_suffixes: Iterable[str] = DEFAULT_PROTECTED_NSG_NAME_SUFFIXES,
    rule_ids: Iterable[str] = (),
    intentionally_open_tag: str = DEFAULT_INTENTIONALLY_OPEN_TAG,
    incident_id: str = "",
    approver: str = "",
    mode: str = MODE_DELETE,
    allowed_subscription_ids: Iterable[str] = (),
) -> Iterator[dict[str, Any]]:
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"unsupported mode `{mode}`; choose one of {sorted(SUPPORTED_MODES)}")
    rule_name_prefixes = tuple(rule_name_prefixes)
    nsg_name_suffixes = tuple(nsg_name_suffixes)
    rule_ids = tuple(rule_ids)
    allowed_subscription_ids = tuple(allowed_subscription_ids)

    for target, event in parse_targets(events):
        if target is None:
            continue

        dry_run = not apply and not reverify

        if not target.rule_id:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_NO_RULE,
                detail="finding did not carry a target.uid (rule id) observable",
                dry_run=dry_run,
                mode=mode,
            )
            continue

        if not (
            target.subscription_id
            and target.resource_group
            and target.nsg_name
            and target.rule_name
        ):
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_BAD_RULE_ID,
                detail=(
                    f"target.uid `{target.rule_id}` did not parse as an Azure NSG "
                    "security rule resource id"
                ),
                dry_run=dry_run,
                mode=mode,
            )
            continue

        if apply and target.subscription_id not in allowed_subscription_ids:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_SUBSCRIPTION_BOUNDARY,
                detail=(
                    f"target subscription `{target.subscription_id}` is not listed in "
                    "AZURE_NSG_REVOKE_ALLOWED_SUBSCRIPTION_IDS"
                ),
                dry_run=False,
                mode=mode,
            )
            continue

        # Live tag check requires a NSG describe call.
        nsg_describe: dict[str, Any] | None = None
        try:
            nsg_describe = network_client.get_network_security_group(
                subscription_id=target.subscription_id,
                resource_group=target.resource_group,
                nsg_name=target.nsg_name,
            )
        except Exception:
            nsg_describe = None

        protected, why = is_protected_rule(
            target,
            rule_name_prefixes=rule_name_prefixes,
            nsg_name_suffixes=nsg_name_suffixes,
            rule_ids=rule_ids,
            intentionally_open_tag=intentionally_open_tag,
            nsg_describe=nsg_describe,
        )
        if protected:
            status = STATUS_SKIPPED_PROTECTED if apply else STATUS_WOULD_VIOLATE_PROTECTED
            yield _skip_record(
                target,
                status=status,
                detail=f"target is protected: {why}",
                dry_run=dry_run,
                mode=mode,
            )
            continue

        if reverify:
            yield from reverify_target(
                target,
                network_client=network_client,
                remediated_at_ms=_event_reference_time_ms(event),
            )
            continue

        if not apply:
            verb = "delete" if mode == MODE_DELETE else "patch (access=Deny on)"
            yield _plan_record(
                target,
                status=STATUS_PLANNED,
                detail=(
                    f"dry-run: would {verb} rule `{target.rule_name}` on NSG "
                    f"`{target.nsg_name}` (rg `{target.resource_group}`, sub "
                    f"`{target.subscription_id}`)"
                ),
                dry_run=True,
                mode=mode,
            )
            continue

        if audit is None:
            raise ValueError("audit writer is required under --apply")
        yield revoke_rule(
            target,
            network_client=network_client,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
            mode=mode,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan, apply, or re-verify Azure NSG security-rule revocation."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete (or patch) the offending rule after approval gates pass.",
    )
    parser.add_argument(
        "--reverify",
        action="store_true",
        help="Read-only verification: confirm the offending rule is gone or patched to Deny.",
    )
    parser.add_argument(
        "--mode",
        choices=sorted(SUPPORTED_MODES),
        default=MODE_DELETE,
        help="Action mode. `delete` (default) removes the rule. `patch` rewrites access=Deny.",
    )
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        network_client: NetworkClient = AzureNetworkClient()
        audit: AuditWriter | None = None
        incident_id = ""
        approver = ""
        if args.apply:
            ok, reason = check_apply_gate()
            if not ok:
                print(reason, file=sys.stderr)
                return 2
            incident_id = os.environ["AZURE_NSG_REVOKE_INCIDENT_ID"].strip()
            approver = os.environ["AZURE_NSG_REVOKE_APPROVER"].strip()
            audit = DualAuditWriter(
                dynamodb_table=os.environ["AZURE_NSG_REVOKE_AUDIT_DYNAMODB_TABLE"],
                s3_bucket=os.environ["AZURE_NSG_REVOKE_AUDIT_BUCKET"],
                kms_key_arn=os.environ["KMS_KEY_ARN"],
            )

        for record in run(
            load_jsonl(in_stream),
            network_client=network_client,
            apply=args.apply,
            reverify=args.reverify,
            audit=audit,
            rule_ids=load_protected_rule_ids(),
            incident_id=incident_id,
            approver=approver,
            mode=args.mode,
            allowed_subscription_ids=load_allowed_subscription_ids(),
        ):
            out_stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
