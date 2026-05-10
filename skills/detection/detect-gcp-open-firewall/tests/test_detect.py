"""Tests for detect-gcp-open-firewall."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detect import (  # type: ignore[import-not-found]  # noqa: E402
    ACCEPTED_OPERATIONS,
    ACCEPTED_PRODUCERS,
    DEFAULT_RISKY_PORTS,
    PUBLIC_CIDRS,
    detect,
)

from skills._shared.errors import ContractError  # noqa: E402


def _gcp_event(
    *,
    operation: str = "compute.firewalls.insert",
    success: bool = True,
    fw_name: str = "allow-ssh-world",
    network: str = "projects/p-1/global/networks/default",
    direction: str = "INGRESS",
    disabled: bool = False,
    source_ranges: list[str] | None = None,
    allowed: list[dict] | None = None,
    actor: str = "alice@example.com",
    account_uid: str = "p-1",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-gcp-audit-ocsf",
) -> dict:
    if source_ranges is None:
        source_ranges = ["0.0.0.0/0"]
    if allowed is None:
        allowed = [{"IPProtocol": "tcp", "ports": ["22"]}]
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
        "api": {"operation": operation, "service": {"name": "compute.googleapis.com"}},
        "cloud": {"provider": "GCP", "account": {"uid": account_uid}, "region": "global"},
        "resources": [
            {"name": f"projects/{account_uid}/global/firewalls/{fw_name}", "type": "gce_firewall_rule"}
        ],
        "unmapped": {
            "gcp": {
                "request": {
                    "name": fw_name,
                    "network": network,
                    "direction": direction,
                    "disabled": disabled,
                    "sourceRanges": source_ranges,
                    "allowed": allowed,
                }
            }
        },
    }


# ---------- contract ----------


def test_accepted_producer_is_gcp_audit():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-gcp-audit-ocsf"})


def test_accepted_operations_cover_insert_and_patch():
    assert "compute.firewalls.insert" in ACCEPTED_OPERATIONS
    assert "compute.firewalls.patch" in ACCEPTED_OPERATIONS


def test_default_risky_ports_cover_admin_and_database_classes():
    for required in (22, 3389, 3306, 5432, 6379, 27017, 9200):
        assert required in DEFAULT_RISKY_PORTS


def test_public_cidrs_set():
    assert PUBLIC_CIDRS == frozenset({"0.0.0.0/0", "::/0"})


# ---------- positive findings ----------


def test_fires_on_ssh_open_to_world():
    findings = list(detect([_gcp_event()]))
    assert len(findings) == 1
    f = findings[0]
    assert f["class_uid"] == 2004
    assert f["severity_id"] == 4
    assert f["finding_info"]["attacks"][0]["technique_uid"] == "T1190"
    assert any(
        obs["name"] == "target.uid" and obs["value"] == "allow-ssh-world"
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


def test_fires_on_mssql_ipv6_world_open():
    findings = list(
        detect(
            [
                _gcp_event(
                    fw_name="allow-mssql-v6",
                    source_ranges=["::/0"],
                    allowed=[{"IPProtocol": "tcp", "ports": ["1433"]}],
                )
            ]
        )
    )
    assert len(findings) == 1
    assert any(
        obs["name"] == "permission.cidr" and obs["value"] == "::/0"
        for obs in findings[0]["observables"]
    )
    assert any(
        obs["name"] == "permission.port" and obs["value"] == "1433"
        for obs in findings[0]["observables"]
    )


def test_fires_on_port_range_covering_risky_port():
    """A 1-65535 range to 0.0.0.0/0 includes every risky port and must fire."""
    findings = list(
        detect(
            [
                _gcp_event(
                    allowed=[{"IPProtocol": "tcp", "ports": ["1-65535"]}],
                )
            ]
        )
    )
    assert len(findings) == 1
    port_obs = [obs for obs in findings[0]["observables"] if obs["name"] == "permission.port"]
    assert len(port_obs) >= 5


def test_fires_on_protocol_all():
    """IPProtocol=all means every protocol + port; must fire."""
    findings = list(
        detect(
            [
                _gcp_event(allowed=[{"IPProtocol": "all"}]),
            ]
        )
    )
    assert len(findings) == 1
    assert any(
        obs["name"] == "permission.protocol" and obs["value"] == "all"
        for obs in findings[0]["observables"]
    )


def test_fires_on_tcp_no_ports_means_all_ports():
    """tcp without ports[] means every TCP port — every risky tcp port hit."""
    findings = list(
        detect(
            [
                _gcp_event(allowed=[{"IPProtocol": "tcp"}]),
            ]
        )
    )
    assert len(findings) == 1


def test_fires_on_patch_operation():
    findings = list(detect([_gcp_event(operation="compute.firewalls.patch")]))
    assert len(findings) == 1


def test_native_output_format():
    findings = list(detect([_gcp_event()], output_format="native"))
    f = findings[0]
    assert f["schema_mode"] == "native"
    assert f["record_type"] == "detection_finding"
    assert f["firewall_name"] == "allow-ssh-world"
    assert "allowed" in f


# ---------- negative cases ----------


def test_no_finding_when_source_is_private():
    findings = list(detect([_gcp_event(source_ranges=["10.0.0.0/8"])]))
    assert findings == []


def test_no_finding_for_world_open_to_non_risky_port():
    """0.0.0.0/0 on port 123 (NTP) is not in risky list."""
    findings = list(
        detect(
            [
                _gcp_event(
                    fw_name="allow-ntp-world",
                    allowed=[{"IPProtocol": "udp", "ports": ["123"]}],
                )
            ]
        )
    )
    assert findings == []


def test_no_finding_for_disabled_rule():
    """disabled=True means no live traffic; no finding."""
    findings = list(detect([_gcp_event(disabled=True)]))
    assert findings == []


def test_no_finding_for_egress_direction():
    findings = list(detect([_gcp_event(direction="EGRESS")]))
    assert findings == []


def test_no_finding_for_failed_event():
    findings = list(detect([_gcp_event(success=False)]))
    assert findings == []


def test_no_finding_for_unrelated_operation():
    findings = list(detect([_gcp_event(operation="compute.firewalls.delete")]))
    assert findings == []


def test_skips_event_from_wrong_producer(capsys):
    findings = list(detect([_gcp_event(producer="ingest-cloudtrail-ocsf")]))
    assert findings == []
    assert "non-gcp-audit producer" in capsys.readouterr().err


def test_skips_event_with_no_request_payload():
    event = _gcp_event()
    event["unmapped"] = {}
    findings = list(detect([event]))
    assert findings == []


# ---------- multi-allowed ----------


def test_one_event_with_multiple_allowed_emits_per_allowed():
    event = _gcp_event(
        allowed=[
            {"IPProtocol": "tcp", "ports": ["22"]},
            {"IPProtocol": "tcp", "ports": ["3306"]},
        ]
    )
    findings = list(detect([event]))
    assert len(findings) == 2
    fw_names = {
        obs["value"]
        for f in findings
        for obs in f["observables"]
        if obs["name"] == "target.uid"
    }
    assert fw_names == {"allow-ssh-world"}


def test_mixed_world_and_corp_source_ranges_only_emits_for_world():
    findings = list(
        detect([_gcp_event(source_ranges=["0.0.0.0/0", "10.0.0.0/8"])])
    )
    assert len(findings) == 1
    cidr_obs = [
        obs["value"] for obs in findings[0]["observables"] if obs["name"] == "permission.cidr"
    ]
    assert cidr_obs == ["0.0.0.0/0"]


def test_unsupported_output_format_raises():
    import pytest
    with pytest.raises(ContractError, match="unsupported output_format") as excinfo:
        list(detect([_gcp_event()], output_format="weird"))
    assert excinfo.value.error_class == "contract"
    assert excinfo.value.retryable is False
    assert excinfo.value.hint
    assert "ocsf" in excinfo.value.hint or "native" in excinfo.value.hint


def test_finding_uid_is_deterministic():
    e = _gcp_event()
    a = list(detect([e]))[0]["finding_info"]["uid"]
    b = list(detect([e]))[0]["finding_info"]["uid"]
    assert a == b
    assert a.startswith("gfw-")
