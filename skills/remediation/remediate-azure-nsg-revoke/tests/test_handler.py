"""Tests for remediate-azure-nsg-revoke."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from handler import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    DEFAULT_INTENTIONALLY_OPEN_TAG,
    DEFAULT_PROTECTED_NSG_NAME_SUFFIXES,
    DEFAULT_PROTECTED_RULE_NAME_PREFIXES,
    MODE_PATCH,
    STATUS_FAILURE,
    STATUS_IN_PROGRESS,
    STATUS_PLANNED,
    STATUS_SKIPPED_NO_RULE,
    STATUS_SKIPPED_PROTECTED,
    STATUS_SKIPPED_SUBSCRIPTION_BOUNDARY,
    STATUS_SUCCESS,
    STATUS_WOULD_VIOLATE_PROTECTED,
    AzureNetworkClient,
    Target,
    check_apply_gate,
    is_protected_rule,
    parse_rule_id,
    parse_targets,
    run,
)

SUB = "00000000-0000-0000-0000-000000000001"
RG = "rg-prod"
NSG = "nsg-web"
RULE = "open-rdp"


def _rule_uid(*, sub: str = SUB, rg: str = RG, nsg: str = NSG, rule: str = RULE) -> str:
    return (
        f"/subscriptions/{sub}/resourceGroups/{rg}/providers/"
        f"Microsoft.Network/networkSecurityGroups/{nsg}/securityRules/{rule}"
    )


def _finding(
    *,
    rule_uid: str | None = None,
    rule_name: str = RULE,
    nsg_name: str = NSG,
    source_prefixes: list[str] | None = None,
    ports: list[int] | None = None,
    protocol: str = "Tcp",
    direction: str = "Inbound",
    omit_rule_uid: bool = False,
) -> dict:
    rule_uid = rule_uid if rule_uid is not None else _rule_uid()
    source_prefixes = source_prefixes if source_prefixes is not None else ["*"]
    ports = ports if ports is not None else [3389]
    obs: list[dict] = [
        {"name": "cloud.provider", "type": "Other", "value": "Azure"},
        {"name": "actor.name", "type": "Other", "value": "alice"},
        {
            "name": "api.operation",
            "type": "Other",
            "value": "Microsoft.Network/networkSecurityGroups/securityRules/write",
        },
        {"name": "rule", "type": "Other", "value": "open-nsg-inbound"},
        {"name": "target.name", "type": "Other", "value": rule_name},
        {"name": "target.type", "type": "Other", "value": "NetworkSecurityRule"},
        {"name": "account.uid", "type": "Other", "value": SUB},
        {"name": "region", "type": "Other", "value": "eastus"},
        {"name": "rule.protocol", "type": "Other", "value": protocol},
        {"name": "rule.direction", "type": "Other", "value": direction},
    ]
    if not omit_rule_uid:
        obs.append({"name": "target.uid", "type": "Other", "value": rule_uid})
    for sp in source_prefixes:
        obs.append({"name": "rule.source_prefix", "type": "Other", "value": sp})
    for p in ports:
        obs.append({"name": "rule.port", "type": "Other", "value": str(p)})
    return {
        "class_uid": 2004,
        "metadata": {"uid": "find-1", "product": {"feature": {"name": "detect-azure-open-nsg"}}},
        "finding_info": {"uid": "find-1"},
        "observables": obs,
    }


@dataclass
class _FakeAudit:
    writes: list[dict] = field(default_factory=list)

    def record(self, *, target, step, status, detail, incident_id, approver):
        self.writes.append(
            {
                "rule_id": target.rule_id,
                "step": step,
                "status": status,
                "detail": detail,
                "incident_id": incident_id,
                "approver": approver,
            }
        )
        return {
            "row_uid": f"row-{len(self.writes)}",
            "s3_evidence_uri": f"s3://bucket/{target.rule_name}-{len(self.writes)}.json",
        }


@dataclass
class _FakeNetworkClient:
    rules: dict[str, dict] = field(default_factory=dict)
    nsgs: dict[str, dict] = field(default_factory=dict)
    raise_on_get_rule: bool = False
    raise_on_get_nsg: bool = False
    raise_on_delete: bool = False
    raise_on_patch: bool = False
    deletes: list[tuple] = field(default_factory=list)
    patches: list[tuple] = field(default_factory=list)

    def _rule_key(self, sub, rg, nsg, rule):
        return f"{sub}|{rg}|{nsg}|{rule}"

    def _nsg_key(self, sub, rg, nsg):
        return f"{sub}|{rg}|{nsg}"

    def get_security_rule(self, *, subscription_id, resource_group, nsg_name, rule_name):
        if self.raise_on_get_rule:
            raise RuntimeError("simulated azure 502")
        return self.rules.get(self._rule_key(subscription_id, resource_group, nsg_name, rule_name))

    def get_network_security_group(self, *, subscription_id, resource_group, nsg_name):
        if self.raise_on_get_nsg:
            raise RuntimeError("simulated azure 502 (nsg)")
        return self.nsgs.get(self._nsg_key(subscription_id, resource_group, nsg_name))

    def delete_security_rule(self, *, subscription_id, resource_group, nsg_name, rule_name):
        if self.raise_on_delete:
            raise RuntimeError("simulated azure 403")
        self.deletes.append((subscription_id, resource_group, nsg_name, rule_name))
        self.rules.pop(self._rule_key(subscription_id, resource_group, nsg_name, rule_name), None)

    def patch_security_rule_to_deny(
        self, *, subscription_id, resource_group, nsg_name, rule_name, existing
    ):
        if self.raise_on_patch:
            raise RuntimeError("simulated azure 403 (patch)")
        self.patches.append((subscription_id, resource_group, nsg_name, rule_name, dict(existing)))
        # Reflect the patch
        rule = dict(existing)
        rule["access"] = "Deny"
        self.rules[self._rule_key(subscription_id, resource_group, nsg_name, rule_name)] = rule


# ---------- contract ----------


def test_accepted_producers_set():
    assert ACCEPTED_PRODUCERS == frozenset({"detect-azure-open-nsg"})


def test_default_protected_rule_name_prefixes():
    assert "default" in DEFAULT_PROTECTED_RULE_NAME_PREFIXES
    assert "Default" in DEFAULT_PROTECTED_RULE_NAME_PREFIXES


def test_default_protected_nsg_name_suffixes():
    assert "-protected" in DEFAULT_PROTECTED_NSG_NAME_SUFFIXES


def test_intentionally_open_tag_default():
    assert DEFAULT_INTENTIONALLY_OPEN_TAG == "intentionally-open"


def test_check_apply_gate_requires_both_envs(monkeypatch):
    monkeypatch.delenv("AZURE_NSG_REVOKE_INCIDENT_ID", raising=False)
    monkeypatch.delenv("AZURE_NSG_REVOKE_APPROVER", raising=False)
    monkeypatch.delenv("AZURE_NSG_REVOKE_ALLOWED_SUBSCRIPTION_IDS", raising=False)
    ok, _ = check_apply_gate()
    assert ok is False
    monkeypatch.setenv("AZURE_NSG_REVOKE_INCIDENT_ID", "INC-1")
    ok, _ = check_apply_gate()
    assert ok is False
    monkeypatch.setenv("AZURE_NSG_REVOKE_APPROVER", "alice")
    ok, _ = check_apply_gate()
    assert ok is False
    monkeypatch.setenv("AZURE_NSG_REVOKE_ALLOWED_SUBSCRIPTION_IDS", SUB)
    ok, _ = check_apply_gate()
    assert ok is True


# ---------- parse_rule_id ----------


def test_parse_rule_id_extracts_components():
    parsed = parse_rule_id(_rule_uid())
    assert parsed is not None
    assert parsed.subscription_id == SUB
    assert parsed.resource_group == RG
    assert parsed.nsg_name == NSG
    assert parsed.rule_name == RULE


def test_parse_rule_id_rejects_bogus():
    assert parse_rule_id("/foo/bar") is None
    assert parse_rule_id("") is None


def test_parse_rule_id_case_insensitive_resource_segments():
    """ARM treats provider segments case-insensitively."""
    weird = (
        f"/SUBSCRIPTIONS/{SUB}/RESOURCEGROUPS/{RG}/"
        f"providers/microsoft.network/networkSecurityGroups/{NSG}/securityRules/{RULE}"
    )
    parsed = parse_rule_id(weird)
    assert parsed is not None
    assert parsed.rule_name == RULE


# ---------- parse_targets ----------


def test_parse_targets_extracts_full_target():
    target, _ = next(parse_targets([_finding(source_prefixes=["*", "::/0"], ports=[22, 3389])]))
    assert target is not None
    assert target.rule_id == _rule_uid()
    assert target.rule_name == RULE
    assert target.nsg_name == NSG
    assert target.resource_group == RG
    assert target.subscription_id == SUB
    assert target.source_prefixes == ("*", "::/0")
    assert target.ports == (22, 3389)
    assert target.protocol == "Tcp"
    assert target.direction == "Inbound"


def test_parse_targets_rejects_wrong_producer(capsys):
    e = _finding()
    e["metadata"]["product"]["feature"]["name"] = "detect-okta-mfa-fatigue"
    target, _ = next(parse_targets([e]))
    assert target is None
    assert "unaccepted producer" in capsys.readouterr().err


# ---------- protected check ----------


def _t(**overrides) -> Target:
    base = dict(
        rule_id=_rule_uid(),
        rule_name=RULE,
        nsg_name=NSG,
        resource_group=RG,
        subscription_id=SUB,
        region="eastus",
        source_prefixes=("*",),
        ports=(3389,),
        protocol="Tcp",
        direction="Inbound",
        actor="a",
        rule="open-nsg-inbound",
        producer_skill="detect-azure-open-nsg",
        finding_uid="f",
    )
    base.update(overrides)
    return Target(**base)


def test_protected_default_rule_name():
    p, why = is_protected_rule(
        _t(rule_name="DefaultInbound"),
        rule_name_prefixes=("default", "Default"),
        nsg_name_suffixes=(),
        rule_ids=(),
        intentionally_open_tag="intentionally-open",
        nsg_describe=None,
    )
    assert p is True
    assert "Default" in why


def test_protected_nsg_name_suffix():
    p, why = is_protected_rule(
        _t(nsg_name="bootstrap-protected"),
        rule_name_prefixes=(),
        nsg_name_suffixes=("-protected",),
        rule_ids=(),
        intentionally_open_tag="intentionally-open",
        nsg_describe=None,
    )
    assert p is True
    assert "-protected" in why


def test_protected_via_env_rule_id_allowlist():
    p, why = is_protected_rule(
        _t(),
        rule_name_prefixes=(),
        nsg_name_suffixes=(),
        rule_ids=(_rule_uid(),),
        intentionally_open_tag="intentionally-open",
        nsg_describe=None,
    )
    assert p is True
    assert "rule-id" in why


def test_protected_via_intentionally_open_tag_dict():
    nsg = {"tags": {"intentionally-open": "alb-443"}}
    p, why = is_protected_rule(
        _t(),
        rule_name_prefixes=(),
        nsg_name_suffixes=(),
        rule_ids=(),
        intentionally_open_tag="intentionally-open",
        nsg_describe=nsg,
    )
    assert p is True
    assert "intentionally-open" in why


def test_unprotected_when_no_match():
    p, _ = is_protected_rule(
        _t(rule_name="my-prod-rule", nsg_name="nsg-prod"),
        rule_name_prefixes=("default",),
        nsg_name_suffixes=("-protected",),
        rule_ids=(),
        intentionally_open_tag="intentionally-open",
        nsg_describe={"tags": {}},
    )
    assert p is False


# ---------- run: dry-run ----------


def test_run_dry_run_emits_plan():
    records = list(run([_finding()], network_client=_FakeNetworkClient()))
    rec = records[0]
    assert rec["record_type"] == "remediation_plan"
    assert rec["status"] == STATUS_PLANNED
    assert rec["dry_run"] is True
    assert rec["target"]["rule_id"] == _rule_uid()
    assert rec["target"]["nsg_name"] == NSG
    assert rec["mode"] == "delete"


def test_run_dry_run_does_not_call_delete_or_patch():
    nc = _FakeNetworkClient()
    list(run([_finding()], network_client=nc))
    assert nc.deletes == []
    assert nc.patches == []


def test_run_dry_run_patch_mode_emits_plan():
    records = list(run([_finding()], network_client=_FakeNetworkClient(), mode=MODE_PATCH))
    rec = records[0]
    assert rec["mode"] == "patch"
    assert rec["actions"][0]["step"] == "patch_security_rule_to_deny"


# ---------- run: skip paths ----------


def test_run_skips_finding_without_rule_uid():
    records = list(run([_finding(omit_rule_uid=True)], network_client=_FakeNetworkClient()))
    assert records[0]["status"] == STATUS_SKIPPED_NO_RULE


def test_run_skips_unparseable_rule_id():
    records = list(
        run([_finding(rule_uid="/not/a/valid/azure/id")], network_client=_FakeNetworkClient())
    )
    assert records[0]["status"] == "skipped_unparseable_rule_id"


def test_run_skips_default_rule_in_dry_run():
    records = list(
        run(
            [_finding(rule_uid=_rule_uid(rule="DefaultInbound"), rule_name="DefaultInbound")],
            network_client=_FakeNetworkClient(),
        )
    )
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_PROTECTED
    assert "Default" in records[0]["status_detail"]


def test_run_skips_intentionally_open_tagged_nsg_in_apply():
    audit = _FakeAudit()
    nc = _FakeNetworkClient(
        nsgs={f"{SUB}|{RG}|{NSG}": {"name": NSG, "tags": {"intentionally-open": "yes"}}},
    )
    records = list(
        run(
            [_finding()],
            network_client=nc,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            allowed_subscription_ids=(SUB,),
        )
    )
    assert records[0]["status"] == STATUS_SKIPPED_PROTECTED
    assert nc.deletes == []
    assert nc.patches == []
    assert audit.writes == []


def test_run_skips_via_env_protected_rule_id():
    records = list(run([_finding()], network_client=_FakeNetworkClient(), rule_ids=(_rule_uid(),)))
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_PROTECTED


# ---------- run: apply (delete mode) ----------


def test_run_apply_delete_with_dual_audit():
    audit = _FakeAudit()
    nc = _FakeNetworkClient(
        rules={
            f"{SUB}|{RG}|{NSG}|{RULE}": {
                "access": "Allow",
                "direction": "Inbound",
                "sourceAddressPrefix": "*",
                "destinationPortRange": "3389",
                "priority": 1000,
                "protocol": "Tcp",
            }
        },
        nsgs={f"{SUB}|{RG}|{NSG}": {"name": NSG, "tags": {}}},
    )
    records = list(
        run(
            [_finding()],
            network_client=nc,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice@security",
            allowed_subscription_ids=(SUB,),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS
    assert rec["dry_run"] is False
    assert rec["mode"] == "delete"
    assert nc.deletes == [(SUB, RG, NSG, RULE)]
    assert nc.patches == []
    assert len(audit.writes) == 2
    assert audit.writes[0]["status"] == STATUS_IN_PROGRESS
    assert audit.writes[1]["status"] == STATUS_SUCCESS


def test_run_apply_delete_writes_failure_audit_when_delete_throws():
    audit = _FakeAudit()
    nc = _FakeNetworkClient(
        raise_on_delete=True, nsgs={f"{SUB}|{RG}|{NSG}": {"name": NSG, "tags": {}}}
    )
    records = list(
        run(
            [_finding()],
            network_client=nc,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            allowed_subscription_ids=(SUB,),
        )
    )
    assert records[0]["status"] == STATUS_FAILURE
    assert len(audit.writes) == 2
    assert audit.writes[1]["status"] == STATUS_FAILURE


def test_run_apply_requires_audit_writer():
    import pytest

    with pytest.raises(ValueError, match="audit writer is required"):
        list(
            run(
                [_finding()],
                network_client=_FakeNetworkClient(),
                apply=True,
                audit=None,
                allowed_subscription_ids=(SUB,),
            )
        )


# ---------- run: apply (patch mode) ----------


def test_run_apply_patch_to_deny():
    audit = _FakeAudit()
    existing = {
        "access": "Allow",
        "direction": "Inbound",
        "sourceAddressPrefix": "*",
        "destinationPortRange": "3389",
        "priority": 1000,
        "protocol": "Tcp",
    }
    nc = _FakeNetworkClient(
        rules={f"{SUB}|{RG}|{NSG}|{RULE}": dict(existing)},
        nsgs={f"{SUB}|{RG}|{NSG}": {"name": NSG, "tags": {}}},
    )
    records = list(
        run(
            [_finding()],
            network_client=nc,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            mode=MODE_PATCH,
            allowed_subscription_ids=(SUB,),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS
    assert rec["mode"] == "patch"
    assert nc.deletes == []
    assert len(nc.patches) == 1
    sub, rg, nsg, rule, params = nc.patches[0]
    assert (sub, rg, nsg, rule) == (SUB, RG, NSG, RULE)
    assert params["access"] == "Allow"  # the existing value, before flip
    # The fake then writes Deny back to the in-memory store
    assert nc.rules[f"{SUB}|{RG}|{NSG}|{RULE}"]["access"] == "Deny"


def test_run_apply_skips_wrong_subscription_boundary():
    audit = _FakeAudit()
    nc = _FakeNetworkClient()
    records = list(
        run(
            [_finding()],
            network_client=nc,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            allowed_subscription_ids=("00000000-0000-0000-0000-000000000099",),
        )
    )
    assert records[0]["status"] == STATUS_SKIPPED_SUBSCRIPTION_BOUNDARY
    assert nc.deletes == []
    assert nc.patches == []
    assert audit.writes == []


# ---------- run: re-verify ----------


def test_run_reverify_verified_when_rule_gone():
    nc = _FakeNetworkClient(nsgs={f"{SUB}|{RG}|{NSG}": {"name": NSG, "tags": {}}})
    records = list(run([_finding()], network_client=nc, reverify=True))
    assert len(records) == 1
    assert records[0]["status"] == "verified"
    assert "not found" in records[0]["actual_state"]


def test_run_reverify_verified_when_rule_patched_to_deny():
    nc = _FakeNetworkClient(
        rules={
            f"{SUB}|{RG}|{NSG}|{RULE}": {
                "access": "Deny",
                "direction": "Inbound",
                "sourceAddressPrefix": "*",
            }
        },
        nsgs={f"{SUB}|{RG}|{NSG}": {"name": NSG, "tags": {}}},
    )
    records = list(run([_finding()], network_client=nc, reverify=True))
    assert len(records) == 1
    assert records[0]["status"] == "verified"


def test_run_reverify_drift_emits_ocsf_finding_alongside_verification():
    nc = _FakeNetworkClient(
        rules={
            f"{SUB}|{RG}|{NSG}|{RULE}": {
                "access": "Allow",
                "direction": "Inbound",
                "sourceAddressPrefix": "*",
                "destinationPortRange": "3389",
            }
        },
        nsgs={f"{SUB}|{RG}|{NSG}": {"name": NSG, "tags": {}}},
    )
    records = list(run([_finding()], network_client=nc, reverify=True))
    assert len(records) == 2
    verification, finding = records
    assert verification["status"] == "drift"
    assert finding["class_uid"] == 2004
    assert finding["category_uid"] == 2
    assert finding["severity_id"] == 4
    assert finding["finding_info"]["types"] == ["remediation-drift"]
    assert any(
        obs["name"] == "remediation.skill" and obs["value"] == "remediate-azure-nsg-revoke"
        for obs in finding["observables"]
    )


def test_run_reverify_uses_finding_time_as_remediation_reference():
    nc = _FakeNetworkClient(nsgs={f"{SUB}|{RG}|{NSG}": {"name": NSG, "tags": {}}})
    event = _finding()
    event["time"] = 1700000000123
    records = list(run([event], network_client=nc, reverify=True))
    assert records[0]["reference"]["remediated_at_ms"] == 1700000000123


def test_run_reverify_unreachable_when_get_raises():
    nc = _FakeNetworkClient(
        raise_on_get_rule=True, nsgs={f"{SUB}|{RG}|{NSG}": {"name": NSG, "tags": {}}}
    )
    records = list(run([_finding()], network_client=nc, reverify=True))
    assert any(r["status"] == "unreachable" for r in records)


# ---------- Azure SDK isolation: real client class never imports SDK in tests ----------


def test_real_azure_client_lazy_imports_sdk_only_when_used():
    """The real AzureNetworkClient must not import azure-mgmt-network at module load.
    We simulate the SDK presence via patch.dict on sys.modules and verify a call
    threads through to the mocked SDK classes (no real Azure import needed)."""
    fake_credential_cls = MagicMock()
    fake_network_cls = MagicMock()
    azure_identity_mod = MagicMock(DefaultAzureCredential=fake_credential_cls)
    azure_mgmt_network_mod = MagicMock(NetworkManagementClient=fake_network_cls)

    fake_client_instance = MagicMock()
    fake_network_cls.return_value = fake_client_instance
    fake_client_instance.security_rules.get.return_value = MagicMock(
        as_dict=lambda: {"access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "*"}
    )

    with patch.dict(
        sys.modules,
        {
            "azure": MagicMock(),
            "azure.identity": azure_identity_mod,
            "azure.mgmt": MagicMock(),
            "azure.mgmt.network": azure_mgmt_network_mod,
        },
    ):
        client = AzureNetworkClient()
        result = client.get_security_rule(
            subscription_id=SUB,
            resource_group=RG,
            nsg_name=NSG,
            rule_name=RULE,
        )
    assert result == {"access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "*"}
    fake_credential_cls.assert_called()
    fake_network_cls.assert_called_with(fake_credential_cls.return_value, SUB)
    fake_client_instance.security_rules.get.assert_called_with(RG, NSG, RULE)


def test_real_azure_client_delete_uses_poller():
    fake_credential_cls = MagicMock()
    fake_network_cls = MagicMock()
    azure_identity_mod = MagicMock(DefaultAzureCredential=fake_credential_cls)
    azure_mgmt_network_mod = MagicMock(NetworkManagementClient=fake_network_cls)

    fake_client_instance = MagicMock()
    fake_network_cls.return_value = fake_client_instance
    poller = MagicMock()
    fake_client_instance.security_rules.begin_delete.return_value = poller

    with patch.dict(
        sys.modules,
        {
            "azure": MagicMock(),
            "azure.identity": azure_identity_mod,
            "azure.mgmt": MagicMock(),
            "azure.mgmt.network": azure_mgmt_network_mod,
        },
    ):
        AzureNetworkClient().delete_security_rule(
            subscription_id=SUB,
            resource_group=RG,
            nsg_name=NSG,
            rule_name=RULE,
        )
    fake_client_instance.security_rules.begin_delete.assert_called_with(RG, NSG, RULE)
    poller.result.assert_called()
