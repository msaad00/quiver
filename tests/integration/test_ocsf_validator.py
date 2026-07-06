"""Unit + integration tests for the OCSF 1.8 validator.

Covers:
- core envelope checks (class_uid, category_uid, type_uid invariant, severity_id)
- per-class activity_id enum enforcement
- metadata pinning (version, product name/vendor, feature name)
- time-as-epoch-milliseconds sanity check (catches seconds-vs-ms bugs)
- unknown-class permissive behaviour (new skill not yet registered is not blocked)
- Detection Finding (2004) finding_info.uid / title requirement
- Regression: every committed golden fixture validates clean
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_OCSF_MODULE = ROOT / "skills" / "_shared" / "ocsf_validator.py"
_spec = importlib.util.spec_from_file_location("cloud_security_ocsf_validator_test", _OCSF_MODULE)
assert _spec and _spec.loader
OCSF = importlib.util.module_from_spec(_spec)
sys.modules["cloud_security_ocsf_validator_test"] = OCSF
_spec.loader.exec_module(OCSF)

GOLDEN_DIR = ROOT / "skills" / "detection-engineering" / "golden"


def _base_auth_event(**overrides) -> dict:
    """OCSF 1.8 Authentication (3002) event with every required field populated."""
    event = {
        "activity_id": 1,
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "class_uid": 3002,
        "class_name": "Authentication",
        "type_uid": 300201,
        "severity_id": 1,
        "status_id": 1,
        "time": 1776046500000,
        "metadata": {
            "version": "1.8.0",
            "uid": "evt-001",
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": "msaad00/cloud-ai-security-skills",
                "feature": {"name": "ingest-okta-system-log-ocsf"},
            },
        },
    }
    event.update(overrides)
    return event


def _base_finding(**overrides) -> dict:
    """OCSF 1.8 Detection Finding (2004)."""
    event = {
        "activity_id": 1,
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "type_uid": 200401,
        "severity_id": 4,
        "status_id": 1,
        "time": 1776046500000,
        "metadata": {
            "version": "1.8.0",
            "uid": "det-001",
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": "msaad00/cloud-ai-security-skills",
                "feature": {"name": "detect-okta-mfa-fatigue"},
            },
        },
        "finding_info": {
            "uid": "det-001",
            "title": "Fatigue burst",
        },
    }
    event.update(overrides)
    return event


class TestRequiredFields:
    def test_clean_auth_event_validates(self):
        assert OCSF.validate_event(_base_auth_event()) == []

    def test_clean_finding_validates(self):
        assert OCSF.validate_event(_base_finding()) == []

    def test_missing_class_uid_fails(self):
        event = _base_auth_event()
        del event["class_uid"]
        errors = OCSF.validate_event(event)
        assert any("class_uid" in e for e in errors)

    def test_missing_activity_id_fails(self):
        event = _base_auth_event()
        del event["activity_id"]
        errors = OCSF.validate_event(event)
        assert any("activity_id" in e for e in errors)

    def test_missing_severity_id_fails(self):
        event = _base_auth_event()
        del event["severity_id"]
        errors = OCSF.validate_event(event)
        assert any("severity_id" in e for e in errors)

    def test_missing_time_fails(self):
        event = _base_auth_event()
        del event["time"]
        errors = OCSF.validate_event(event)
        assert any("`time`" in e for e in errors)

    def test_missing_metadata_fails(self):
        event = _base_auth_event()
        del event["metadata"]
        errors = OCSF.validate_event(event)
        assert any("metadata" in e for e in errors)

    def test_missing_metadata_uid_fails(self):
        event = _base_auth_event()
        del event["metadata"]["uid"]
        errors = OCSF.validate_event(event)
        assert any("metadata.uid" in e for e in errors)

    def test_missing_metadata_product_feature_fails(self):
        event = _base_auth_event()
        del event["metadata"]["product"]["feature"]
        errors = OCSF.validate_event(event)
        assert any("feature.name" in e for e in errors)


class TestCrossFieldInvariants:
    def test_type_uid_must_match_class_times_100_plus_activity(self):
        event = _base_auth_event(type_uid=999999)
        errors = OCSF.validate_event(event)
        assert any("type_uid" in e and "300201" in e for e in errors)

    def test_category_uid_must_match_class_category(self):
        event = _base_auth_event(category_uid=99)  # Authentication is in category 3
        errors = OCSF.validate_event(event)
        assert any("category_uid" in e and "match class" in e for e in errors)

    def test_activity_id_must_be_valid_for_class(self):
        # Detection Finding (2004) does not accept activity_id=5
        event = _base_finding(activity_id=5, type_uid=200405)
        errors = OCSF.validate_event(event)
        assert any("activity_id" in e and "2004" in e for e in errors)


class TestEnumRanges:
    def test_severity_id_out_of_range_fails(self):
        event = _base_auth_event(severity_id=99)
        errors = OCSF.validate_event(event)
        assert any("severity_id" in e for e in errors)

    def test_status_id_out_of_range_fails(self):
        event = _base_auth_event(status_id=99)
        errors = OCSF.validate_event(event)
        assert any("status_id" in e for e in errors)

    def test_status_id_may_be_absent(self):
        """status_id is OCSF [rec], not [req] — absence is fine."""
        event = _base_auth_event()
        del event["status_id"]
        assert OCSF.validate_event(event) == []


class TestTimeSanity:
    def test_epoch_seconds_detected(self):
        # 1776046500 = 2026-04-18 as epoch SECONDS. In milliseconds it would be
        # 1776046500000. OCSF_CONTRACT.md pins milliseconds.
        event = _base_auth_event(time=1776046500)
        errors = OCSF.validate_event(event)
        assert any("epoch seconds" in e for e in errors)

    def test_time_must_be_int_not_string(self):
        event = _base_auth_event(time="2026-04-18T00:00:00Z")
        errors = OCSF.validate_event(event)
        assert any("`time` must be an int" in e for e in errors)


class TestMetadataPinning:
    def test_version_must_be_pinned(self):
        event = _base_auth_event()
        event["metadata"]["version"] = "1.7.0"
        errors = OCSF.validate_event(event)
        assert any("metadata.version" in e and "1.8.0" in e for e in errors)

    def test_product_name_must_match_repo(self):
        event = _base_auth_event()
        event["metadata"]["product"]["name"] = "some-other-repo"
        errors = OCSF.validate_event(event)
        assert any("product.name" in e for e in errors)

    def test_vendor_name_must_match_repo(self):
        event = _base_auth_event()
        event["metadata"]["product"]["vendor_name"] = "someone-else/repo"
        errors = OCSF.validate_event(event)
        assert any("product.vendor_name" in e for e in errors)


class TestDetectionFindingSpecifics:
    def test_finding_requires_finding_info_uid(self):
        event = _base_finding()
        del event["finding_info"]["uid"]
        errors = OCSF.validate_event(event)
        assert any("finding_info.uid" in e for e in errors)

    def test_finding_requires_title(self):
        event = _base_finding()
        del event["finding_info"]["title"]
        errors = OCSF.validate_event(event)
        assert any("finding_info.title" in e for e in errors)


class TestUnknownClassPermissive:
    """A new skill registering an un-catalogued class is not blocked by the
    validator — core scalars still run, but cross-field invariants (category,
    activity-enum, type_uid math) are skipped until the class is added to
    CLASS_ACTIVITY_NAMES."""

    def test_unknown_class_with_clean_scalars_passes(self):
        event = _base_auth_event(class_uid=7999, class_name="Hypothetical")
        # Even though 7999 isn't registered, scalar checks still gate it.
        assert OCSF.validate_event(event) == []

    def test_unknown_class_still_rejects_bad_scalars(self):
        event = _base_auth_event(class_uid=7999, severity_id=99)
        errors = OCSF.validate_event(event)
        assert any("severity_id" in e for e in errors)


class TestBatch:
    def test_batch_returns_only_invalid_indices(self):
        events = [_base_auth_event(), {"bad": "event"}, _base_finding()]
        result = OCSF.validate_batch(events)
        assert len(result) == 1
        idx, errs = result[0]
        assert idx == 1
        assert len(errs) > 0


class TestNonDict:
    def test_non_dict_event_rejected(self):
        errors = OCSF.validate_event("not a dict")  # type: ignore[arg-type]
        assert len(errors) == 1
        assert "must be a dict" in errors[0]


class TestGoldenFixturesValidate:
    """Every frozen golden OCSF fixture must validate clean.

    This is the regression-detection value: a skill that drifts its emit shape
    breaks the fixture; the fixture is compared in the skill's own tests;
    validation catches structural drift that even fixture comparison might
    accept (e.g. a renamed product field that the detector doesn't read).
    """

    def test_all_golden_fixtures_validate(self):
        from collections import defaultdict

        fixtures = sorted(GOLDEN_DIR.glob("*.ocsf.jsonl"))
        assert fixtures, "expected at least one OCSF golden fixture"

        violations: dict[Path, list[str]] = defaultdict(list)
        total_events = 0
        for path in fixtures:
            for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
                line = raw.strip()
                if not line:
                    continue
                event = json.loads(line)
                total_events += 1
                errs = OCSF.validate_event(event)
                for err in errs:
                    violations[path].append(f"line {lineno}: {err}")

        assert not violations, (
            f"OCSF validation failed across {len(violations)} fixture(s):\n"
            + "\n".join(
                f"  {path.name}:\n    "
                + "\n    ".join(issues[:3])
                + ("\n    ..." if len(issues) > 3 else "")
                for path, issues in violations.items()
            )
        )
        assert total_events > 0
