"""Tests for the iam-departures-gcp parser Cloud Function."""

from __future__ import annotations

import json
import sys
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

# Mock googleapiclient + google.oauth2 BEFORE importing the parser module.
# The parser lazy-imports both inside its functions; for the `--dry-run`
# code path the imports are never reached, but module-import-time tests
# (and the existence-check tests) need them present.
_googleapiclient = types.ModuleType("googleapiclient")
_discovery = types.ModuleType("googleapiclient.discovery")
_discovery.build = MagicMock()
_googleapiclient.discovery = _discovery
sys.modules.setdefault("googleapiclient", _googleapiclient)
sys.modules.setdefault("googleapiclient.discovery", _discovery)
sys.modules.setdefault("google", types.ModuleType("google"))
sys.modules.setdefault("google.oauth2", types.ModuleType("google.oauth2"))

from cloud_function_parser.handler import (  # noqa: E402
    _validate_entry,
    handler,
    parse_local_manifest,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _days_ago_iso(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def _make_entry(
    *,
    email: str = "jane@acme.example",
    principal_type: str = "workspace_user",
    principal_id: str | None = None,
    gcp_org_id: str = "111122223333",
    project_ids: list[str] | None = None,
    folder_ids: list[str] | None = None,
    terminated_at: str | None = None,
    is_rehire: bool = False,
    rehire_date: str | None = None,
    principal_deleted: bool = False,
    last_used_at: str | None = None,
    created_at: str | None = None,
) -> dict:
    return {
        "email": email,
        "principal_type": principal_type,
        "principal_id": principal_id or email,
        "gcp_org_id": gcp_org_id,
        "project_ids": project_ids or ["acme-prod"],
        "folder_ids": folder_ids or [],
        "terminated_at": terminated_at or _days_ago_iso(30),
        "is_rehire": is_rehire,
        "rehire_date": rehire_date,
        "principal_deleted": principal_deleted,
        "principal_last_used_at": last_used_at,
        "principal_created_at": created_at or _days_ago_iso(365),
    }


@pytest.fixture(autouse=True)
def _skip_existence_check(monkeypatch):
    """Default to dry-run mode so tests don't hit the existence helper."""
    monkeypatch.setenv("IAM_DEPARTURES_GCP_SKIP_EXISTENCE_CHECK", "1")


class TestValidateEntry:
    def test_valid_workspace_user_passes(self):
        result = _validate_entry(_make_entry(terminated_at=_days_ago_iso(30)))
        assert result["action"] == "remediate"

    def test_valid_service_account_passes(self):
        entry = _make_entry(
            email="ci@acme-prod.iam.gserviceaccount.com",
            principal_type="service_account",
            principal_id="ci@acme-prod.iam.gserviceaccount.com",
        )
        assert _validate_entry(entry)["action"] == "remediate"

    def test_missing_required_fields_skipped(self):
        entry = _make_entry(email="")
        result = _validate_entry(entry)
        assert result["action"] == "skip"
        assert "Missing required field" in result["reason"]

    def test_unsupported_principal_type_skipped(self):
        entry = _make_entry()
        entry["principal_type"] = "device"
        result = _validate_entry(entry)
        assert result["action"] == "skip"
        assert "Unsupported principal_type" in result["reason"]

    def test_already_deleted_skipped(self):
        result = _validate_entry(_make_entry(principal_deleted=True))
        assert result["action"] == "skip"
        assert "already deleted" in result["reason"]

    def test_within_grace_period_skipped(self):
        result = _validate_entry(_make_entry(terminated_at=_days_ago_iso(3)))
        assert result["action"] == "skip"
        assert "grace period" in result["reason"]

    def test_grace_period_floor_one_day(self, monkeypatch):
        """Even if env var says 0, parser refuses to act < 1 day post-termination."""
        monkeypatch.setenv("IAM_DEPARTURES_GCP_GRACE_DAYS", "0")
        # Re-import to pick up env change
        from importlib import reload

        import cloud_function_parser.handler as handler_mod

        reload(handler_mod)
        result = handler_mod._validate_entry(_make_entry(terminated_at=_days_ago_iso(0)))
        assert result["action"] == "skip"
        assert "grace period" in result["reason"]

    def test_rehire_same_principal_in_use_skipped(self):
        entry = _make_entry(
            terminated_at=_days_ago_iso(60),
            is_rehire=True,
            rehire_date=_days_ago_iso(30),
            last_used_at=_days_ago_iso(5),
        )
        result = _validate_entry(entry)
        assert result["action"] == "skip"
        assert "rehire" in result["reason"].lower()

    def test_rehire_orphaned_principal_remediates(self):
        entry = _make_entry(
            terminated_at=_days_ago_iso(60),
            is_rehire=True,
            rehire_date=_days_ago_iso(30),
            last_used_at=_days_ago_iso(45),
            created_at=_days_ago_iso(365),
        )
        assert _validate_entry(entry)["action"] == "remediate"

    def test_invalid_org_id_skipped(self):
        result = _validate_entry(_make_entry(gcp_org_id="not-a-number"))
        assert result["action"] == "skip"
        assert "gcp_org_id" in result["reason"]

    def test_invalid_email_format_skipped(self):
        result = _validate_entry(_make_entry(email="no-at-sign"))
        assert result["action"] == "skip"
        assert "email" in result["reason"]


class TestParserHandler:
    def test_invalid_event_payload_returns_error(self):
        result = handler({"bucket": "", "name": ""}, None)
        assert result["validated_entries"] == []
        assert result["validation_summary"]["error_count"] == 1
        assert "Invalid event payload" in result["validation_summary"]["errors"][0]["error"]

    def test_handler_routes_through_validate(self, tmp_path):
        # Use parse_local_manifest path which exercises the same _validate code.
        manifest = {
            "entries": [
                _make_entry(email="a@acme.example", terminated_at=_days_ago_iso(30)),
                _make_entry(
                    email="b@acme.example", principal_id="b@acme.example", principal_deleted=True
                ),
                _make_entry(email="c@acme.example"),
            ]
        }
        path = tmp_path / "manifest.json"
        path.write_text(json.dumps(manifest))
        result = parse_local_manifest(path)
        assert result["validation_summary"]["total_entries"] == 3
        assert result["validation_summary"]["validated_count"] >= 1
        assert result["validation_summary"]["skipped_count"] >= 1

    def test_handler_reads_gcs_via_mocked_discovery(self, monkeypatch):
        manifest = {
            "entries": [_make_entry(email="x@acme.example", terminated_at=_days_ago_iso(30))]
        }

        def fake_build(api: str, version: str, **kwargs):
            client = MagicMock()
            client.objects.return_value.get_media.return_value.execute.return_value = json.dumps(
                manifest
            ).encode()
            return client

        monkeypatch.setattr("googleapiclient.discovery.build", fake_build)
        result = handler({"bucket": "bkt", "name": "departures/x.json"}, None)
        assert result["validation_summary"]["total_entries"] == 1


class TestParserCli:
    def test_dry_run_via_main(self, tmp_path, capsys):
        from cloud_function_parser.handler import main

        manifest = {
            "entries": [_make_entry(email="z@acme.example", terminated_at=_days_ago_iso(30))]
        }
        path = tmp_path / "m.json"
        path.write_text(json.dumps(manifest))
        rc = main([str(path), "--dry-run"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "validated_entries" in out
