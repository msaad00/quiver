"""Tests for detect-azure-open-nsg."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detect import (  # type: ignore[import-not-found]  # noqa: E402
    ACCEPTED_PRODUCERS,
    DEFAULT_RISKY_PORTS,
    NSG_RULE_WRITE_OPERATION,
    PUBLIC_SOURCE_PREFIXES,
    detect,
)

from skills._shared.errors import ContractError  # noqa: E402


def _rule_uid(
    *,
    sub: str = "00000000-0000-0000-0000-000000000001",
    rg: str = "rg-prod",
    nsg: str = "nsg-web",
    rule: str = "open-rule",
) -> str:
    return (
        f"/subscriptions/{sub}/resourceGroups/{rg}/providers/"
        f"Microsoft.Network/networkSecurityGroups/{nsg}/securityRules/{rule}"
    )


def _az_event(
    *,
    operation: str = NSG_RULE_WRITE_OPERATION,
    success: bool = True,
    rule_uid: str | None = None,
    direction: str = "Inbound",
    access: str = "Allow",
    protocol: str = "Tcp",
    source_prefix: str | None = "*",
    source_prefixes: list[str] | None = None,
    dest_port_range: str | None = "3389",
    dest_port_ranges: list[str] | None = None,
    priority: int = 1000,
    actor: str = "alice",
    account_uid: str = "00000000-0000-0000-0000-000000000001",
    region: str = "eastus",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-azure-activity-ocsf",
) -> dict:
    rule_uid = rule_uid if rule_uid is not None else _rule_uid()
    props: dict = {
        "direction": direction,
        "access": access,
        "protocol": protocol,
        "priority": priority,
    }
    if source_prefix is not None:
        props["sourceAddressPrefix"] = source_prefix
    if source_prefixes is not None:
        props["sourceAddressPrefixes"] = source_prefixes
    if dest_port_range is not None:
        props["destinationPortRange"] = dest_port_range
    if dest_port_ranges is not None:
        props["destinationPortRanges"] = dest_port_ranges
    return {
        "class_uid": 6003,
        "status_id": 1 if success else 2,
        "time": 1700000000000,
        "metadata": {
            "uid": "evt-1",
            "product": {"feature": {"name": producer}},
        },
        "actor": {"user": {"name": actor}},
        "src_endpoint": {"ip": src_ip},
        "api": {"operation": operation},
        "resources": [{"name": rule_uid, "type": "networksecuritygroups"}],
        "cloud": {"provider": "Azure", "account": {"uid": account_uid}, "region": region},
        "unmapped": {"azure": {"properties": props}},
    }


# ---------- contract ----------


def test_accepted_producer_is_azure_activity():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-azure-activity-ocsf"})


def test_default_risky_ports_cover_admin_and_database_classes():
    for required in (22, 3389, 3306, 5432, 6379, 27017, 9200):
        assert required in DEFAULT_RISKY_PORTS


def test_public_source_prefixes_set():
    assert PUBLIC_SOURCE_PREFIXES == frozenset({"*", "internet", "0.0.0.0/0", "::/0"})


# ---------- positive findings ----------


def test_fires_on_rdp_open_to_star():
    findings = list(
        detect([_az_event(source_prefix="*", dest_port_range="3389")])
    )
    assert len(findings) == 1
    f = findings[0]
    assert f["class_uid"] == 2004
    assert f["severity_id"] == 4
    assert f["finding_info"]["attacks"][0]["technique_uid"] == "T1190"
    assert any(
        obs["name"] == "target.uid" and obs["value"].endswith("/securityRules/open-rule")
        for obs in f["observables"]
    )
    assert any(
        obs["name"] == "rule.source_prefix" and obs["value"] == "*"
        for obs in f["observables"]
    )
    assert any(
        obs["name"] == "rule.port" and obs["value"] == "3389"
        for obs in f["observables"]
    )
    assert any(
        obs["name"] == "rule.protocol" and obs["value"] == "Tcp"
        for obs in f["observables"]
    )


def test_fires_on_mssql_open_from_internet_tag():
    findings = list(
        detect([_az_event(source_prefix="Internet", dest_port_range="1433")]),
    )
    # MSSQL 1433 is NOT in default risky_ports — pass an override
    findings = list(
        detect(
            [_az_event(source_prefix="Internet", dest_port_range="1433")],
            risky_ports=(1433,),
        )
    )
    assert len(findings) == 1
    f = findings[0]
    assert any(
        obs["name"] == "rule.source_prefix" and obs["value"] == "Internet"
        for obs in f["observables"]
    )


def test_fires_on_ssh_range_22_25_from_world():
    """A 22-25 range from 0.0.0.0/0 includes port 22 and must fire."""
    findings = list(
        detect([_az_event(source_prefix="0.0.0.0/0", dest_port_range="22-25")])
    )
    assert len(findings) == 1
    port_obs = [obs for obs in findings[0]["observables"] if obs["name"] == "rule.port"]
    # only 22 from default risky list overlaps 22-25
    assert any(obs["value"] == "22" for obs in port_obs)


def test_fires_on_ipv6_world_open_ssh():
    findings = list(
        detect([_az_event(source_prefix="::/0", dest_port_range="22")])
    )
    assert len(findings) == 1
    assert any(
        obs["name"] == "rule.source_prefix" and obs["value"] == "::/0"
        for obs in findings[0]["observables"]
    )


def test_fires_on_star_port_range():
    """destinationPortRange=`*` means all ports; every risky port is hit."""
    findings = list(
        detect([_az_event(source_prefix="*", dest_port_range="*")])
    )
    assert len(findings) == 1
    port_obs = [obs for obs in findings[0]["observables"] if obs["name"] == "rule.port"]
    # every default risky port should be observed
    assert len(port_obs) >= 5


def test_fires_when_source_in_prefixes_array():
    findings = list(
        detect(
            [
                _az_event(
                    source_prefix=None,
                    source_prefixes=["10.0.0.0/8", "0.0.0.0/0"],
                    dest_port_range="22",
                )
            ]
        )
    )
    assert len(findings) == 1
    src_obs = [
        obs["value"]
        for obs in findings[0]["observables"]
        if obs["name"] == "rule.source_prefix"
    ]
    # only the public one is cited
    assert src_obs == ["0.0.0.0/0"]


def test_fires_when_port_in_ranges_array():
    findings = list(
        detect(
            [
                _az_event(
                    source_prefix="*",
                    dest_port_range=None,
                    dest_port_ranges=["80", "3389"],
                )
            ]
        )
    )
    assert len(findings) == 1
    port_obs = {
        obs["value"]
        for obs in findings[0]["observables"]
        if obs["name"] == "rule.port"
    }
    # 3389 is risky, 80 is not
    assert "3389" in port_obs
    assert "80" not in port_obs


def test_native_output_format():
    findings = list(
        detect([_az_event()], output_format="native")
    )
    f = findings[0]
    assert f["schema_mode"] == "native"
    assert f["record_type"] == "detection_finding"
    assert f["rule_name"] == "open-rule"
    assert "nsg_rule" in f


# ---------- negative cases ----------


def test_no_finding_for_ntp_port_123():
    """0.0.0.0/0 on port 123 (NTP) is not in risky list."""
    findings = list(
        detect([_az_event(source_prefix="0.0.0.0/0", dest_port_range="123")])
    )
    assert findings == []


def test_no_finding_for_outbound_rule():
    findings = list(
        detect([_az_event(direction="Outbound", source_prefix="*", dest_port_range="22")])
    )
    assert findings == []


def test_no_finding_for_deny_rule():
    findings = list(
        detect([_az_event(access="Deny", source_prefix="*", dest_port_range="22")])
    )
    assert findings == []


def test_no_finding_for_private_source_10_8():
    findings = list(
        detect([_az_event(source_prefix="10.0.0.0/8", dest_port_range="22")])
    )
    assert findings == []


def test_no_finding_for_failed_event():
    findings = list(
        detect([_az_event(success=False, source_prefix="*", dest_port_range="22")])
    )
    assert findings == []


def test_no_finding_for_unrelated_operation():
    findings = list(
        detect(
            [_az_event(operation="Microsoft.Network/networkSecurityGroups/read", source_prefix="*", dest_port_range="22")]
        )
    )
    assert findings == []


def test_skips_event_from_wrong_producer(capsys):
    findings = list(
        detect([_az_event(producer="ingest-cloudtrail-ocsf", source_prefix="*", dest_port_range="22")])
    )
    assert findings == []
    assert "non-azure-activity producer" in capsys.readouterr().err


def test_skips_event_with_no_rule_properties():
    event = _az_event(source_prefix="*", dest_port_range="22")
    event["unmapped"] = {}
    findings = list(detect([event]))
    assert findings == []


def test_falls_back_to_api_request_data_properties():
    """If unmapped is missing, the detector should read api.request.data.properties."""
    event = _az_event(source_prefix="*", dest_port_range="22")
    props = event["unmapped"]["azure"]["properties"]
    event["unmapped"] = {}
    event["api"]["request"] = {"data": {"properties": props}}
    findings = list(detect([event]))
    assert len(findings) == 1


# ---------- determinism ----------


def test_unsupported_output_format_raises():
    import pytest

    with pytest.raises(ContractError, match="unsupported output_format") as excinfo:
        list(detect([_az_event()], output_format="weird"))
    assert excinfo.value.error_class == "contract"
    assert excinfo.value.retryable is False
    assert excinfo.value.hint
    assert "ocsf" in excinfo.value.hint or "native" in excinfo.value.hint


def test_finding_uid_is_deterministic():
    e = _az_event()
    a = list(detect([e]))[0]["finding_info"]["uid"]
    b = list(detect([e]))[0]["finding_info"]["uid"]
    assert a == b
    assert a.startswith("ansg-")
