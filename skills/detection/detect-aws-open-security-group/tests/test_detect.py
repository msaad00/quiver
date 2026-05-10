"""Tests for detect-aws-open-security-group."""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]  # noqa: E402
    ACCEPTED_PRODUCERS,
    DEFAULT_RISKY_PORTS,
    PUBLIC_CIDRS,
    detect,
)

from skills._shared.errors import ContractError  # noqa: E402


def _ct_event(
    *,
    operation: str = "AuthorizeSecurityGroupIngress",
    success: bool = True,
    sg_id: str = "sg-0123456789abcdef0",
    sg_name: str = "web-tier",
    cidrs_v4: list[str] | None = None,
    cidrs_v6: list[str] | None = None,
    from_port: int = 22,
    to_port: int = 22,
    protocol: str = "tcp",
    actor: str = "alice",
    account_uid: str = "111122223333",
    region: str = "us-east-1",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-cloudtrail-ocsf",
) -> dict:
    perm: dict = {"ipProtocol": protocol, "fromPort": from_port, "toPort": to_port}
    if cidrs_v4:
        perm["ipRanges"] = {"items": [{"cidrIp": c} for c in cidrs_v4]}
    if cidrs_v6:
        perm["ipv6Ranges"] = {"items": [{"cidrIpv6": c} for c in cidrs_v6]}
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
        "cloud": {"provider": "AWS", "account": {"uid": account_uid}, "region": region},
        "unmapped": {
            "cloudtrail": {
                "request_parameters": {
                    "groupId": sg_id,
                    "groupName": sg_name,
                    "ipPermissions": {"items": [perm]},
                }
            }
        },
    }


# ---------- contract ----------


def test_accepted_producer_is_cloudtrail():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-cloudtrail-ocsf"})


def test_default_risky_ports_cover_admin_and_database_classes():
    for required in (22, 3389, 3306, 5432, 6379, 27017, 9200):
        assert required in DEFAULT_RISKY_PORTS


def test_public_cidrs_set():
    assert PUBLIC_CIDRS == frozenset({"0.0.0.0/0", "::/0"})


# ---------- positive findings ----------


def test_fires_on_ssh_open_to_world():
    findings = list(detect([_ct_event(cidrs_v4=["0.0.0.0/0"], from_port=22, to_port=22)]))
    assert len(findings) == 1
    f = findings[0]
    assert f["class_uid"] == 2004
    assert f["severity_id"] == 4
    assert f["finding_info"]["attacks"][0]["technique_uid"] == "T1190"
    assert any(
        obs["name"] == "target.uid" and obs["value"] == "sg-0123456789abcdef0"
        for obs in f["observables"]
    )
    assert any(
        obs["name"] == "permission.cidr" and obs["value"] == "0.0.0.0/0"
        for obs in f["observables"]
    )
    assert any(
        obs["name"] == "permission.port" and obs["value"] == "22"
        for obs in f["observables"]
    )
    assert any(
        obs["name"] == "permission.protocol" and obs["value"] == "tcp"
        for obs in f["observables"]
    )
    assert any(
        obs["name"] == "permission.from_port" and obs["value"] == "22"
        for obs in f["observables"]
    )
    assert any(
        obs["name"] == "permission.to_port" and obs["value"] == "22"
        for obs in f["observables"]
    )


def test_fires_on_ipv6_world_open():
    findings = list(detect([_ct_event(cidrs_v6=["::/0"], from_port=3389, to_port=3389)]))
    assert len(findings) == 1
    assert any(
        obs["name"] == "permission.cidr" and obs["value"] == "::/0"
        for obs in findings[0]["observables"]
    )


def test_fires_on_port_range_covering_risky_port():
    """A 0-65535 range to 0.0.0.0/0 includes every risky port and must fire."""
    findings = list(detect([_ct_event(cidrs_v4=["0.0.0.0/0"], from_port=0, to_port=65535)]))
    assert len(findings) == 1
    # Should report multiple risky ports hit
    port_obs = [obs for obs in findings[0]["observables"] if obs["name"] == "permission.port"]
    assert len(port_obs) >= 5  # all default risky ports overlap


def test_fires_on_protocol_neg_one_all_ports():
    """ipProtocol=-1 means all protocols+all ports; must fire."""
    findings = list(detect([_ct_event(cidrs_v4=["0.0.0.0/0"], protocol="-1", from_port=-1, to_port=-1)]))
    assert len(findings) == 1
    assert any(
        obs["name"] == "permission.protocol" and obs["value"] == "-1"
        for obs in findings[0]["observables"]
    )


def test_native_output_format():
    findings = list(detect([_ct_event(cidrs_v4=["0.0.0.0/0"])], output_format="native"))
    f = findings[0]
    assert f["schema_mode"] == "native"
    assert f["record_type"] == "detection_finding"
    assert f["sg_id"] == "sg-0123456789abcdef0"
    assert "permission" in f


# ---------- negative cases ----------


def test_no_finding_when_grant_is_not_world():
    """Grant to a corporate CIDR is fine; no finding."""
    findings = list(detect([_ct_event(cidrs_v4=["10.0.0.0/8"], from_port=22, to_port=22)]))
    assert findings == []


def test_no_finding_for_world_open_to_non_risky_port():
    """0.0.0.0/0 on port 443 (HTTPS, common public service) is not in risky list."""
    findings = list(detect([_ct_event(cidrs_v4=["0.0.0.0/0"], from_port=443, to_port=443)]))
    assert findings == []


def test_no_finding_for_failed_event():
    """status_id != 1 means the AuthorizeSecurityGroupIngress was denied/failed."""
    findings = list(detect([_ct_event(cidrs_v4=["0.0.0.0/0"], success=False)]))
    assert findings == []


def test_no_finding_for_unrelated_operation():
    findings = list(detect([_ct_event(operation="DescribeSecurityGroups", cidrs_v4=["0.0.0.0/0"])]))
    assert findings == []


def test_skips_event_from_wrong_producer(capsys):
    findings = list(detect([_ct_event(producer="ingest-okta-system-log-ocsf", cidrs_v4=["0.0.0.0/0"])]))
    assert findings == []
    assert "non-cloudtrail producer" in capsys.readouterr().err


def test_skips_event_with_no_request_parameters():
    """Event without ipPermissions should yield no findings (and no crash)."""
    event = _ct_event(cidrs_v4=["0.0.0.0/0"])
    event["unmapped"] = {}
    findings = list(detect([event]))
    assert findings == []


# ---------- multi-permission events ----------


def test_one_event_with_multiple_permissions_emits_per_permission():
    event = _ct_event(cidrs_v4=["0.0.0.0/0"], from_port=22, to_port=22)
    # Add a second risky permission to the same event
    event["unmapped"]["cloudtrail"]["request_parameters"]["ipPermissions"]["items"].append(
        {"ipProtocol": "tcp", "fromPort": 3306, "toPort": 3306,
         "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}
    )
    findings = list(detect([event]))
    assert len(findings) == 2
    sg_ids = {obs["value"] for f in findings for obs in f["observables"] if obs["name"] == "target.uid"}
    assert sg_ids == {"sg-0123456789abcdef0"}


def test_mixed_world_and_corp_cidrs_only_emits_for_world():
    """If a permission has both 0.0.0.0/0 and 10.0.0.0/8, the finding only
    cites the world cidr in observables (we don't yell about corp CIDRs)."""
    findings = list(detect([_ct_event(
        cidrs_v4=["0.0.0.0/0", "10.0.0.0/8"], from_port=22, to_port=22,
    )]))
    assert len(findings) == 1
    cidr_obs = [obs["value"] for obs in findings[0]["observables"] if obs["name"] == "permission.cidr"]
    assert cidr_obs == ["0.0.0.0/0"]


def test_unsupported_output_format_raises():
    import pytest
    with pytest.raises(ContractError, match="unsupported output_format") as excinfo:
        list(detect([_ct_event(cidrs_v4=["0.0.0.0/0"])], output_format="weird"))
    assert excinfo.value.error_class == "contract"
    assert excinfo.value.retryable is False
    assert excinfo.value.hint
    assert "ocsf" in excinfo.value.hint or "native" in excinfo.value.hint


def test_finding_uid_is_deterministic():
    """Same event → same finding_uid (so SIEM dedupe works)."""
    e = _ct_event(cidrs_v4=["0.0.0.0/0"])
    a = list(detect([e]))[0]["finding_info"]["uid"]
    b = list(detect([e]))[0]["finding_info"]["uid"]
    assert a == b
    assert a.startswith("asg-")
