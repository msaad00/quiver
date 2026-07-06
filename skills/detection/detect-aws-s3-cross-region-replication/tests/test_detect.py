"""Tests for detect-aws-s3-cross-region-replication."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    ANCHOR_OPERATION,
    AUTHORIZED_BUCKETS_ENV,
    FINDING_CLASS_UID,
    OUTPUT_FORMATS,
    PRIMARY_TECHNIQUE_UID,
    SECONDARY_TECHNIQUE_UID,
    SEVERITY_HIGH,
    SKILL_NAME,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "aws_s3_cross_region_replication_input.ocsf.jsonl"
EXPECTED = GOLDEN / "aws_s3_cross_region_replication_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str = "evt-1",
    time_ms: int = 1_700_000_000_000,
    actor: str = "mallory",
    source_bucket: str = "prod-customer-data",
    source_account: str = "111122223333",
    source_region: str = "us-east-1",
    dest_bucket: str = "attacker-archive",
    dest_account: str = "999988887777",
    dest_region: str = "eu-west-1",
    operation: str = "PutBucketReplication",
    status_id: int = 1,
    producer: str = "ingest-cloudtrail-ocsf",
    rule_id: str = "rule-1",
    extra_rules: list[dict] | None = None,
) -> dict:
    rules = [
        {
            "id": rule_id,
            "destination": {
                "bucket": f"arn:aws:s3:::{dest_bucket}",
                "account": dest_account,
                "region": dest_region,
                "storageClass": "STANDARD",
            },
        }
    ]
    if extra_rules:
        rules.extend(extra_rules)
    return {
        "class_uid": 6003,
        "status_id": status_id,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {"feature": {"name": producer}},
        },
        "actor": {"user": {"name": actor}},
        "api": {"operation": operation, "service": {"name": "s3.amazonaws.com"}},
        "cloud": {"provider": "AWS", "account": {"uid": source_account}, "region": source_region},
        "resources": [{"name": source_bucket, "type": "bucketName"}],
        "unmapped": {
            "cloudtrail": {
                "request_parameters": {
                    "bucketName": source_bucket,
                    "replicationConfiguration": {"rules": rules},
                }
            }
        },
    }


class TestCoreContract:
    def test_accepted_producer_is_cloudtrail(self) -> None:
        assert ACCEPTED_PRODUCERS == frozenset({"ingest-cloudtrail-ocsf"})

    def test_anchor_operation(self) -> None:
        assert ANCHOR_OPERATION == "PutBucketReplication"

    def test_coverage_metadata(self) -> None:
        meta = coverage_metadata()
        assert meta["providers"] == ("aws",)
        assert PRIMARY_TECHNIQUE_UID in meta["attack_coverage"]["aws"]["techniques"]
        assert SECONDARY_TECHNIQUE_UID in meta["attack_coverage"]["aws"]["techniques"]
        # default is fail-open with no env var
        assert meta["thresholds"]["allowlist_mode"] == "fail-open"


class TestDetection:
    def test_cross_region_fires_in_fail_open(self) -> None:
        findings = list(detect([_event(dest_account="111122223333", dest_region="us-west-2")]))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["evidence"]["boundary"] == "cross-region"
        assert finding["evidence"]["allowlist_mode"] == "fail-open"
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == PRIMARY_TECHNIQUE_UID
        assert finding["finding_info"]["attacks"][1]["technique"]["uid"] == SECONDARY_TECHNIQUE_UID

    def test_cross_account_fires(self, monkeypatch) -> None:
        # same region, different account; allowlist enforced and empty of the dest
        monkeypatch.setenv(AUTHORIZED_BUCKETS_ENV, "approved-dr-bucket")
        findings = list(detect([_event(dest_region="us-east-1", dest_account="999988887777")]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["boundary"] == "cross-account"
        assert findings[0]["evidence"]["allowlist_mode"] == "enforced"

    def test_cross_account_and_region_classification(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_BUCKETS_ENV, "approved-dr-bucket")
        findings = list(detect([_event(dest_account="999988887777", dest_region="eu-west-1")]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["boundary"] == "cross-account-and-region"

    def test_same_region_same_account_does_not_fire(self) -> None:
        findings = list(
            detect(
                [
                    _event(
                        dest_account="111122223333",
                        dest_region="us-east-1",
                        dest_bucket="approved-dr-bucket",
                    )
                ]
            )
        )
        assert findings == []

    def test_authorized_destination_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORIZED_BUCKETS_ENV, "attacker-archive,approved-dr-bucket")
        findings = list(detect([_event()]))
        assert findings == []

    def test_failed_call_does_not_fire(self) -> None:
        findings = list(detect([_event(status_id=2)]))
        assert findings == []

    def test_non_cloudtrail_producer_ignored(self, capsys) -> None:
        findings = list(detect([_event(producer="ingest-gcp-audit-ocsf")]))
        assert findings == []
        assert "non-cloudtrail producer" in capsys.readouterr().err

    def test_missing_rules_skipped(self, capsys) -> None:
        evt = _event()
        evt["unmapped"]["cloudtrail"]["request_parameters"]["replicationConfiguration"] = {}
        findings = list(detect([evt]))
        assert findings == []
        assert "carries no rules" in capsys.readouterr().err

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        evt = _event()
        findings = list(detect([evt, evt]))
        assert len(findings) == 1

    def test_two_unauthorized_rules_two_findings(self) -> None:
        extra = [
            {
                "id": "rule-2",
                "destination": {
                    "bucket": "arn:aws:s3:::another-attacker-bucket",
                    "account": "555566667777",
                    "region": "ap-southeast-1",
                    "storageClass": "STANDARD",
                },
            }
        ]
        findings = list(detect([_event(extra_rules=extra)]))
        assert len(findings) == 2
        boundaries = {f["evidence"]["boundary"] for f in findings}
        assert boundaries == {"cross-account-and-region"}

    def test_native_output(self) -> None:
        findings = list(detect([_event()], output_format="native"))
        assert len(findings) == 1
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["source_skill"] == SKILL_NAME
        assert OUTPUT_FORMATS == frozenset({"ocsf", "native"})

    def test_rejects_unsupported_output_format(self) -> None:
        from skills._shared.errors import ContractError

        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected ContractError")

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
