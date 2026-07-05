"""Tests for the Entra IAM departures parser Function."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

# Mock the Azure SDKs the parser tries to lazy-import so we never touch the network.
sys.modules.setdefault("azure", type(sys)("azure"))
for _mod in ("azure.identity", "azure.storage", "azure.storage.blob", "msgraph"):
    if _mod not in sys.modules:
        sys.modules[_mod] = type(sys)(_mod)

from function_parser import handler as parser_handler  # type: ignore[import-not-found]  # noqa: E402,I001

OBJECT_ID = "aaaaaaaa-1111-1111-1111-111111111111"


def _entry(**overrides):
    base = {
        "upn": "former.employee@acme.example",
        "object_id": OBJECT_ID,
        "display_name": "Former Employee",
        "user_created_at": "2024-01-01T00:00:00Z",
        "terminated_at": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
        "termination_source": "snowflake",
        "is_rehire": False,
        "rehire_date": None,
        "user_deleted": False,
        "user_last_signin_at": "2026-04-01T16:30:00Z",
    }
    base.update(overrides)
    return base


class _StubGraph:
    def __init__(self, present_object_ids=()):
        self.present = set(present_object_ids)

    def user_exists(self, *, object_id):
        return object_id in self.present


def test_remediates_after_grace_period():
    out = parser_handler._validate_entries(
        [_entry()],
        storage_account="acct",
        container="cnt",
        blob_name="departures/x.json",
        graph_client=_StubGraph(present_object_ids=[OBJECT_ID]),
    )
    assert out["validation_summary"]["validated_count"] == 1
    assert out["validation_summary"]["skipped_count"] == 0
    assert out["validated_entries"][0]["object_id"] == OBJECT_ID


def test_skips_within_grace_period():
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    out = parser_handler._validate_entries(
        [_entry(terminated_at=recent)],
        storage_account="acct",
        container="cnt",
        blob_name="x.json",
        graph_client=_StubGraph(),
    )
    assert out["validation_summary"]["validated_count"] == 0
    reasons = [s["reason"] for s in out["validation_summary"]["skipped"]]
    assert any("grace period" in r for r in reasons)


def test_skips_already_deleted():
    out = parser_handler._validate_entries(
        [_entry(user_deleted=True)],
        storage_account="a",
        container="b",
        blob_name="c",
        graph_client=_StubGraph(),
    )
    assert out["validation_summary"]["validated_count"] == 0
    assert any("already deleted" in s["reason"] for s in out["validation_summary"]["skipped"])


def test_rehire_with_signin_after_rehire_date_skips():
    out = parser_handler._validate_entries(
        [
            _entry(
                is_rehire=True,
                rehire_date="2026-03-01T00:00:00Z",
                user_last_signin_at="2026-04-01T00:00:00Z",
            )
        ],
        storage_account="a",
        container="b",
        blob_name="c",
        graph_client=_StubGraph(present_object_ids=[OBJECT_ID]),
    )
    assert out["validation_summary"]["validated_count"] == 0
    assert any("Rehired" in s["reason"] for s in out["validation_summary"]["skipped"])


def test_rehire_with_idle_user_remediates():
    # Rehired but the old Entra user has not been used since the rehire date.
    out = parser_handler._validate_entries(
        [
            _entry(
                is_rehire=True,
                rehire_date="2026-03-01T00:00:00Z",
                user_last_signin_at="2025-12-01T00:00:00Z",  # older than rehire date
            )
        ],
        storage_account="a",
        container="b",
        blob_name="c",
        graph_client=_StubGraph(present_object_ids=[OBJECT_ID]),
    )
    assert out["validation_summary"]["validated_count"] == 1


def test_skips_invalid_object_id():
    out = parser_handler._validate_entries(
        [_entry(object_id="not-a-guid")],
        storage_account="a",
        container="b",
        blob_name="c",
        graph_client=_StubGraph(),
    )
    assert out["validation_summary"]["validated_count"] == 0
    assert any(
        "Invalid Entra ObjectId" in s["reason"] for s in out["validation_summary"]["skipped"]
    )


def test_skips_when_user_not_in_tenant():
    out = parser_handler._validate_entries(
        [_entry()],
        storage_account="a",
        container="b",
        blob_name="c",
        graph_client=_StubGraph(present_object_ids=[]),
    )
    assert out["validation_summary"]["validated_count"] == 0
    assert any("not found in tenant" in s["reason"] for s in out["validation_summary"]["skipped"])


def test_handler_rejects_missing_event_fields():
    out = parser_handler.handler({"storage_account": "", "container": "", "blob_name": ""})
    assert out["validation_summary"]["error_count"] == 1


def test_cli_dry_run_reads_local_manifest(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        '{"entries":['
        + '{"upn":"a@b.example","object_id":"'
        + OBJECT_ID
        + '","terminated_at":"2025-01-01T00:00:00Z"}'
        + "]}",
        encoding="utf-8",
    )
    out_path = tmp_path / "out.jsonl"
    rc = parser_handler.main([str(manifest_path), "-o", str(out_path)])
    assert rc == 0
    lines = [line for line in out_path.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    assert "remediate" in lines[0]


def test_handler_reads_blob_via_lazy_sdk():
    """Smoke-test the Logic-App entrypoint by mocking the blob reader."""
    with patch.object(parser_handler, "_read_blob", return_value='{"entries":[]}'):
        out = parser_handler.handler(
            {"storage_account": "acct", "container": "cnt", "blob_name": "x.json"}
        )
    assert out["validation_summary"]["total_entries"] == 0
