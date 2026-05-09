from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COMMON = _load_module(
    "cloud_security_skill_validation_common_test",
    SCRIPTS / "skill_validation_common.py",
)
CONTRACT = _load_module(
    "cloud_security_validate_skill_contract_test",
    SCRIPTS / "validate_skill_contract.py",
)
SAFE = _load_module(
    "cloud_security_validate_safe_skill_bar_test",
    SCRIPTS / "validate_safe_skill_bar.py",
)
INTEGRITY = _load_module(
    "cloud_security_validate_skill_integrity_test",
    SCRIPTS / "validate_skill_integrity.py",
)
DEPENDENCIES = _load_module(
    "cloud_security_validate_dependency_consistency_test",
    SCRIPTS / "validate_dependency_consistency.py",
)
COVERAGE = _load_module(
    "cloud_security_validate_framework_coverage_test",
    SCRIPTS / "validate_framework_coverage.py",
)
OCSF_METADATA = _load_module(
    "cloud_security_validate_ocsf_metadata_test",
    SCRIPTS / "validate_ocsf_metadata.py",
)
TEST_COVERAGE = _load_module(
    "cloud_security_validate_test_coverage_test",
    SCRIPTS / "validate_test_coverage.py",
)


class TestSkillValidationCommon:
    def test_discovers_skills_and_entrypoints(self):
        skills = COMMON.discover_skill_contracts()
        assert len(skills) >= 32
        names = {skill.name for skill in skills}
        assert "source-s3-select" in names
        assert "source-databricks-query" in names
        assert "source-snowflake-query" in names
        assert "sink-s3-jsonl" in names
        assert "sink-snowflake-jsonl" in names
        assert "sink-clickhouse-jsonl" in names
        assert "detect-lateral-movement" in names
        assert "detect-okta-mfa-fatigue" in names
        assert "detect-entra-credential-addition" in names
        assert "detect-entra-role-grant-escalation" in names
        assert "detect-google-workspace-suspicious-login" in names
        assert "ingest-entra-directory-audit-ocsf" in names
        assert "ingest-google-workspace-login-ocsf" in names
        assert "ingest-gcp-scc-ocsf" in names
        assert "ingest-azure-defender-for-cloud-ocsf" in names
        assert "ingest-okta-system-log-ocsf" in names
        assert "discover-ai-bom" in names
        assert "discover-control-evidence" in names
        assert "discover-cloud-control-evidence" in names

        ingest = next(skill for skill in skills if skill.name == "ingest-cloudtrail-ocsf")
        assert ingest.entrypoint is not None
        assert ingest.entrypoint.name == "ingest.py"
        assert ingest.approval_model == "none"
        assert ingest.execution_modes == ("jit", "ci", "mcp", "persistent")
        assert ingest.side_effects == ("none",)
        assert ingest.concurrency_safety == "stateless"
        assert ingest.caller_roles == ()
        assert ingest.approver_roles == ()
        assert ingest.min_approvers is None

    def test_reference_policy_accepts_known_official_hosts(self):
        assert COMMON.reference_url_allowed("https://docs.aws.amazon.com/IAM/latest/APIReference/")
        assert COMMON.reference_url_allowed("https://attack.mitre.org/techniques/T1021/")
        assert COMMON.reference_url_allowed("https://github.com/opencontainers/image-spec")
        assert not COMMON.reference_url_allowed("http://example.com/not-https")
        assert not COMMON.reference_url_allowed("https://example.com/not-approved")


class TestValidationScripts:
    def test_contract_validator_passes(self):
        assert CONTRACT.main() == 0

    def test_safe_skill_validator_passes(self):
        assert SAFE.main() == 0


class TestRuntimeContractGuardrails:
    """Unit tests for the SKILL.md frontmatter ↔ src/ runtime contract checks."""

    def _fake_skill(self, tmp_path: Path, *, writable: bool, category: str = "remediation",
                    capability: str = "", src_contents: str = "") -> object:
        skill_dir = tmp_path / "skills" / category / "fake-skill"
        (skill_dir / "src").mkdir(parents=True, exist_ok=True)
        (skill_dir / "src" / "handler.py").write_text(src_contents or "# empty\n")
        (skill_dir / "tests").mkdir(exist_ok=True)

        class _Fake:
            pass

        fake = _Fake()
        fake.skill_dir = skill_dir
        fake.is_write_capable = writable
        fake.approval_model = "human_required" if writable else "none"
        fake.side_effects = ("writes-identity",) if writable else ("none",)
        fake.frontmatter = {"capability": capability} if capability else {}
        fake.category = category
        return fake

    def _run_source_guards(self, tmp_path: Path, fake: object) -> list[str]:
        original_root = SAFE.ROOT
        SAFE.ROOT = tmp_path
        try:
            return SAFE.validate_write_skill_source_guards(fake)
        finally:
            SAFE.ROOT = original_root

    def _run_read_only_no_writes(self, tmp_path: Path, fake: object) -> list[str]:
        original_root = SAFE.ROOT
        SAFE.ROOT = tmp_path
        try:
            return SAFE.validate_read_only_no_cloud_writes(fake)
        finally:
            SAFE.ROOT = original_root

    def test_writable_skill_passes_with_dry_run_and_audit(self, tmp_path: Path):
        fake = self._fake_skill(
            tmp_path,
            writable=True,
            src_contents=(
                "def run(dry_run=True):\n"
                "    audit.put_item(Table='audit-table')\n"
            ),
        )
        assert self._run_source_guards(tmp_path, fake) == []

    def test_writable_skill_missing_dry_run_fails(self, tmp_path: Path):
        fake = self._fake_skill(
            tmp_path,
            writable=True,
            src_contents="def run():\n    dynamodb.put_item(Table='x')\n",
        )
        errors = self._run_source_guards(tmp_path, fake)
        assert any("dry-run" in e for e in errors)

    def test_writable_skill_missing_audit_fails(self, tmp_path: Path):
        fake = self._fake_skill(
            tmp_path,
            writable=True,
            src_contents="def run(dry_run=True):\n    iam.delete_user()\n",
        )
        errors = self._run_source_guards(tmp_path, fake)
        assert any("audit" in e for e in errors)

    def test_sink_exempted_from_audit_requirement(self, tmp_path: Path):
        """Sinks are the audit artifact; they don't audit their own writes."""
        fake = self._fake_skill(
            tmp_path,
            writable=True,
            category="output",
            capability="write-sink",
            src_contents="def run():\n    s3.put_object(Body=x)\n",
        )
        assert self._run_source_guards(tmp_path, fake) == []

    def test_read_only_skill_never_checked_for_source_guards(self, tmp_path: Path):
        fake = self._fake_skill(
            tmp_path,
            writable=False,
            category="detection",
            src_contents="def detect():\n    pass\n",
        )
        assert self._run_source_guards(tmp_path, fake) == []

    def test_read_only_skill_calling_delete_user_fails(self, tmp_path: Path):
        fake = self._fake_skill(
            tmp_path,
            writable=False,
            category="detection",
            src_contents=(
                "def detect():\n"
                "    iam.delete_user(UserName='alice')\n"
            ),
        )
        errors = self._run_read_only_no_writes(tmp_path, fake)
        assert any("cloud-write method" in e and "delete" in e for e in errors)

    def test_read_only_skill_calling_put_object_fails(self, tmp_path: Path):
        fake = self._fake_skill(
            tmp_path,
            writable=False,
            category="discovery",
            src_contents="def scan():\n    s3.put_object(Body=b'x')\n",
        )
        errors = self._run_read_only_no_writes(tmp_path, fake)
        assert any("cloud-write method" in e for e in errors)

    def test_read_only_skill_calling_read_methods_passes(self, tmp_path: Path):
        fake = self._fake_skill(
            tmp_path,
            writable=False,
            category="detection",
            src_contents=(
                "def detect():\n"
                "    iam.get_user(UserName='alice')\n"
                "    iam.list_access_keys(UserName='alice')\n"
                "    s3.get_object(Bucket='x', Key='y')\n"
            ),
        )
        assert self._run_read_only_no_writes(tmp_path, fake) == []

    def test_writable_skill_skips_read_only_check(self, tmp_path: Path):
        fake = self._fake_skill(
            tmp_path,
            writable=True,
            src_contents="def run():\n    iam.delete_user()\n",
        )
        assert self._run_read_only_no_writes(tmp_path, fake) == []

    def test_write_method_in_string_literal_ignored(self, tmp_path: Path):
        """A write-method name inside a docstring or log message should not
        trip the read-only check."""
        fake = self._fake_skill(
            tmp_path,
            writable=False,
            category="detection",
            src_contents=(
                'def detect():\n'
                '    """This detector does NOT call iam.delete_user itself."""\n'
                '    msg = "Would call iam.delete_user to fix this"\n'
                '    log.info("Consider iam.remove_user_from_group")\n'
            ),
        )
        errors = self._run_read_only_no_writes(tmp_path, fake)
        assert errors == []


class TestHITLEnvVarGuardrail:
    """Unit tests for the remediation HITL env-var enforcement check.

    Every remediation skill (excluding sinks and grandfathered iam-departures-aws)
    must gate its --apply path on an incident env var AND an approver env var,
    backing up the human_required approval model declared in frontmatter.
    """

    def _fake_remediation(self, tmp_path: Path, *, src_contents: str,
                          capability: str = "") -> object:
        skill_dir = tmp_path / "skills" / "remediation" / "fake-remediation"
        (skill_dir / "src").mkdir(parents=True, exist_ok=True)
        (skill_dir / "src" / "handler.py").write_text(src_contents or "# empty\n")

        class _Fake:
            pass

        fake = _Fake()
        fake.skill_dir = skill_dir
        fake.is_write_capable = True
        fake.approval_model = "human_required"
        fake.side_effects = ("writes-identity",)
        fake.frontmatter = {"capability": capability} if capability else {}
        fake.category = "remediation"
        return fake

    def _run(self, tmp_path: Path, fake: object) -> list[str]:
        original_root = SAFE.ROOT
        SAFE.ROOT = tmp_path
        try:
            return SAFE.validate_remediation_hitl_env_vars(fake)
        finally:
            SAFE.ROOT = original_root

    def test_passes_with_both_incident_and_approver(self, tmp_path: Path):
        fake = self._fake_remediation(
            tmp_path,
            src_contents=(
                "import os\n"
                "INCIDENT_ID = os.environ['MY_SKILL_INCIDENT_ID']\n"
                "APPROVER = os.environ['MY_SKILL_APPROVER']\n"
            ),
        )
        assert self._run(tmp_path, fake) == []

    def test_passes_with_ticket_and_approved_by(self, tmp_path: Path):
        """Substring matching means TICKET and APPROVED_BY are also accepted."""
        fake = self._fake_remediation(
            tmp_path,
            src_contents=(
                "import os\n"
                "ticket = os.environ['SKILL_APPROVAL_TICKET']\n"
                "actor = os.environ['SKILL_APPROVED_BY']\n"
            ),
        )
        assert self._run(tmp_path, fake) == []

    def test_fails_when_incident_var_missing(self, tmp_path: Path):
        fake = self._fake_remediation(
            tmp_path,
            src_contents=(
                "import os\n"
                "APPROVER = os.environ['MY_SKILL_APPROVER']\n"
            ),
        )
        errors = self._run(tmp_path, fake)
        assert any("incident env var" in e for e in errors)

    def test_fails_when_approver_var_missing(self, tmp_path: Path):
        fake = self._fake_remediation(
            tmp_path,
            src_contents=(
                "import os\n"
                "INCIDENT_ID = os.environ['MY_SKILL_INCIDENT_ID']\n"
            ),
        )
        errors = self._run(tmp_path, fake)
        assert any("approver env var" in e for e in errors)

    def test_fails_when_both_missing(self, tmp_path: Path):
        fake = self._fake_remediation(
            tmp_path,
            src_contents="def run():\n    iam.delete_user()\n",
        )
        errors = self._run(tmp_path, fake)
        assert any("incident env var" in e for e in errors)
        assert any("approver env var" in e for e in errors)

    def test_grandfather_marker_skips_check(self, tmp_path: Path):
        fake = self._fake_remediation(
            tmp_path,
            src_contents=(
                "# HITL_ENV_OK: this skill uses Step-Functions-driven approval, not env vars\n"
                "def run():\n    iam.delete_user()\n"
            ),
        )
        assert self._run(tmp_path, fake) == []

    def test_sink_exempted(self, tmp_path: Path):
        """Sinks are the audit destination, not the gated remediation path."""
        fake = self._fake_remediation(
            tmp_path,
            capability="write-sink",
            src_contents="def run():\n    s3.put_object(Body=x)\n",
        )
        assert self._run(tmp_path, fake) == []

    def test_non_remediation_writable_skill_skipped(self, tmp_path: Path):
        """Output-category skills aren't checked even if write-capable."""
        fake = self._fake_remediation(tmp_path, src_contents="def run(): pass\n")
        fake.category = "output"
        assert self._run(tmp_path, fake) == []


class TestAssumeRoleBoundaryGuardrail:
    """Unit tests for the sts:AssumeRole boundary-condition check.

    Every Allow of sts:AssumeRole in a skill's IaC must carry a boundary
    condition (PrincipalOrgID, SourceAccount, PrincipalTag, SourceOrgID) or
    an explicit ASSUME_ROLE_CONDITION_OK justification. Trust-policy
    statements (Service/Federated principals) are exempt — they are bounded
    by the principal itself, not by the condition.
    """

    def _write_policy(self, tmp_path: Path, filename: str, body: str) -> None:
        # Put the file inside a skill-shaped tree so the recursive scan finds it.
        (tmp_path / "skills" / "remediation" / "fake" / "infra").mkdir(parents=True, exist_ok=True)
        (tmp_path / "skills" / "remediation" / "fake" / "infra" / filename).write_text(body)

    def _run_against(self, tmp_path: Path) -> list[str]:
        # Point both SKILLS_ROOT (scan target) and ROOT (relative-path anchor
        # for error messages) at the temp tree, then restore.
        original_root = SAFE.ROOT
        original_skills_root = SAFE.SKILLS_ROOT
        SAFE.ROOT = tmp_path
        SAFE.SKILLS_ROOT = tmp_path / "skills"
        try:
            return SAFE.validate_assume_role_boundaries()
        finally:
            SAFE.ROOT = original_root
            SAFE.SKILLS_ROOT = original_skills_root

    def test_passes_when_org_condition_present_json(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "role.json",
            json.dumps(
                {
                    "Statement": [
                        {
                            "Sid": "AssumeTarget",
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::*:role/target",
                            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
                        }
                    ]
                },
                indent=2,
            ),
        )
        assert self._run_against(tmp_path) == []

    def test_fails_when_no_condition_json(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "role.json",
            json.dumps(
                {
                    "Statement": [
                        {
                            "Sid": "AssumeTarget",
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::*:role/target",
                        }
                    ]
                },
                indent=2,
            ),
        )
        errors = self._run_against(tmp_path)
        assert len(errors) == 1
        assert "sts:AssumeRole Allow must carry" in errors[0]

    def test_trust_policy_service_principal_is_exempt(self, tmp_path: Path):
        """Lambda/EC2 service-role trust policies never need PrincipalOrgID."""
        self._write_policy(
            tmp_path,
            "lambda-trust.json",
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
                indent=2,
            ),
        )
        assert self._run_against(tmp_path) == []

    def test_source_account_condition_accepted(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "role.json",
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::123456789012:role/target",
                            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
                        }
                    ]
                },
                indent=2,
            ),
        )
        assert self._run_against(tmp_path) == []

    def test_explicit_opt_out_marker_accepted(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "role.json",
            "\n".join(
                [
                    "{",
                    "  // ASSUME_ROLE_CONDITION_OK: justified because ...",
                    "  \"Statement\": [",
                    "    {",
                    "      \"Effect\": \"Allow\",",
                    "      \"Action\": \"sts:AssumeRole\",",
                    "      \"Resource\": \"arn:aws:iam::*:role/target\"",
                    "    }",
                    "  ]",
                    "}",
                ]
            ),
        )
        assert self._run_against(tmp_path) == []

    def test_terraform_hcl_flavor_detected(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "main.tf",
            "\n".join(
                [
                    "resource \"aws_iam_role_policy\" \"worker\" {",
                    "  policy = jsonencode({",
                    "    Statement = [",
                    "      {",
                    "        Effect   = \"Allow\"",
                    "        Action   = \"sts:AssumeRole\"",
                    "        Resource = \"arn:aws:iam::*:role/target\"",
                    "      }",
                    "    ]",
                    "  })",
                    "}",
                ]
            ),
        )
        errors = self._run_against(tmp_path)
        assert len(errors) == 1

    def test_terraform_hcl_with_condition_passes(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "main.tf",
            "\n".join(
                [
                    "resource \"aws_iam_role_policy\" \"worker\" {",
                    "  policy = jsonencode({",
                    "    Statement = [",
                    "      {",
                    "        Effect   = \"Allow\"",
                    "        Action   = \"sts:AssumeRole\"",
                    "        Resource = \"arn:aws:iam::*:role/target\"",
                    "        Condition = {",
                    "          StringEquals = { \"aws:PrincipalOrgID\" = \"o-abc\" }",
                    "        }",
                    "      }",
                    "    ]",
                    "  })",
                    "}",
                ]
            ),
        )
        assert self._run_against(tmp_path) == []

    def test_integrity_validator_passes(self):
        assert INTEGRITY.main() == 0

    def test_dependency_consistency_validator_passes(self):
        assert DEPENDENCIES.main() == 0

    def test_framework_coverage_validator_passes(self):
        assert COVERAGE.main() == 0

    def test_ocsf_metadata_validator_passes(self):
        assert OCSF_METADATA.main() == 0

    def test_test_coverage_validator_passes(self, tmp_path: Path):
        # Synthetic report: every layer in LAYER_FLOORS gets a class whose hit
        # rate sits comfortably above its floor (90% for _shared, 70% for
        # remediation, 80% for the rest). If a future PR adds a new layer
        # floor, add a corresponding row here so the test keeps reflecting
        # what a clean run looks like.
        report = tmp_path / "coverage.xml"
        report.write_text(
            self._synthetic_coverage_xml(
                layers={
                    "_shared": (95, 100),
                    "detection": (85, 100),
                    "discovery": (85, 100),
                    "evaluation": (85, 100),
                    "ingestion": (85, 100),
                    "output": (85, 100),
                    "remediation": (75, 100),
                    "view": (85, 100),
                },
                overall_line_rate=0.86,
            ),
            encoding="utf-8",
        )
        assert TEST_COVERAGE.main([str(report)]) == 0

    @staticmethod
    def _synthetic_coverage_xml(
        *, layers: dict[str, tuple[int, int]], overall_line_rate: float
    ) -> str:
        """Build a minimal coverage.xml the validator can parse, with one
        class per layer whose hit/total ratio matches the provided tuple."""
        class_blocks: list[str] = []
        for layer, (hit, total) in layers.items():
            lines = "\n            ".join(
                f'<line number="{i + 1}" hits="{1 if i < hit else 0}" />'
                for i in range(total)
            )
            class_blocks.append(
                f'        <class filename="skills/{layer}/example/src/example.py">\n'
                f'          <lines>\n            {lines}\n          </lines>\n'
                f'        </class>'
            )
        joined = "\n".join(class_blocks)
        return (
            f'<?xml version="1.0" ?>\n'
            f'<coverage line-rate="{overall_line_rate}">\n'
            f'  <packages>\n'
            f'    <package name="skills">\n'
            f'      <classes>\n{joined}\n      </classes>\n'
            f'    </package>\n'
            f'  </packages>\n'
            f'</coverage>\n'
        )

    def test_test_coverage_validator_fails_low_detection_floor(self, tmp_path: Path):
        # Same shape as the passing fixture but `detection` drops to 60% —
        # below its 80% floor. The other layers still pass so we isolate the
        # failure mode to the floor we're testing.
        report = tmp_path / "coverage-low.xml"
        report.write_text(
            self._synthetic_coverage_xml(
                layers={
                    "_shared": (95, 100),
                    "detection": (60, 100),
                    "discovery": (85, 100),
                    "evaluation": (85, 100),
                    "ingestion": (85, 100),
                    "output": (85, 100),
                    "remediation": (75, 100),
                    "view": (85, 100),
                },
                overall_line_rate=0.85,
            ),
            encoding="utf-8",
        )
        assert TEST_COVERAGE.main([str(report)]) == 1

    def test_gpu_skill_ai_framework_depth_is_registered(self):
        registry = json.loads((ROOT / "docs" / "framework-coverage.json").read_text())
        gpu = next(item for item in registry["skills"] if item["path"] == "skills/evaluation/gpu-cluster-security")
        assert "mitre-atlas" in gpu["frameworks"]
        assert "nist-ai-rmf" in gpu["frameworks"]

    def test_model_serving_ai_framework_depth_is_registered(self):
        registry = json.loads((ROOT / "docs" / "framework-coverage.json").read_text())
        model_serving = next(item for item in registry["skills"] if item["path"] == "skills/evaluation/model-serving-security")
        assert "mitre-atlas" in model_serving["frameworks"]
        assert "nist-ai-rmf" in model_serving["frameworks"]

    def test_lateral_movement_identity_assets_are_registered(self):
        registry = json.loads((ROOT / "docs" / "framework-coverage.json").read_text())
        skill = next(item for item in registry["skills"] if item["path"] == "skills/detection/detect-lateral-movement")
        assert "service-accounts" in skill["asset_classes"]
        assert "service-principals" in skill["asset_classes"]
        assert "managed-identities" in skill["asset_classes"]

    def test_remediation_skill_declares_human_approval(self):
        skills = {skill.name: skill for skill in COMMON.discover_skill_contracts()}
        remediation = skills["iam-departures-aws"]
        assert remediation.approval_model == "human_required"
        assert remediation.execution_modes == ("jit", "persistent")
        assert "writes-identity" in remediation.side_effects
        assert remediation.concurrency_safety == "operator_coordinated"
        assert remediation.caller_roles == ("security_engineer", "incident_responder")
        assert remediation.approver_roles == ("security_lead", "cis_officer")
        assert remediation.min_approvers == 1

    def test_sink_skill_declares_human_approval(self):
        skills = {skill.name: skill for skill in COMMON.discover_skill_contracts()}
        sink = skills["sink-snowflake-jsonl"]
        assert sink.approval_model == "human_required"
        assert sink.execution_modes == ("jit", "mcp", "persistent")
        assert sink.side_effects == ("writes-database",)
        assert sink.concurrency_safety == "operator_coordinated"
        assert sink.caller_roles == ("security_engineer", "platform_engineer")
        assert sink.approver_roles == ("security_lead", "data_platform_owner")
        assert sink.min_approvers == 1

    def test_clickhouse_sink_declares_human_approval(self):
        skills = {skill.name: skill for skill in COMMON.discover_skill_contracts()}
        sink = skills["sink-clickhouse-jsonl"]
        assert sink.approval_model == "human_required"
        assert sink.execution_modes == ("jit", "mcp", "persistent")
        assert sink.side_effects == ("writes-database",)
        assert sink.concurrency_safety == "operator_coordinated"
        assert sink.caller_roles == ("security_engineer", "platform_engineer")
        assert sink.approver_roles == ("security_lead", "data_platform_owner")
        assert sink.min_approvers == 1

    def test_s3_sink_declares_human_approval(self):
        skills = {skill.name: skill for skill in COMMON.discover_skill_contracts()}
        sink = skills["sink-s3-jsonl"]
        assert sink.approval_model == "human_required"
        assert sink.execution_modes == ("jit", "mcp", "persistent")
        assert sink.side_effects == ("writes-storage",)
        assert sink.concurrency_safety == "operator_coordinated"
        assert sink.caller_roles == ("security_engineer", "platform_engineer")
        assert sink.approver_roles == ("security_lead", "data_platform_owner")
        assert sink.min_approvers == 1

    def test_skill_like_dirs_are_canonical_categories_only(self):
        skill_like_dirs = COMMON.iter_skill_like_dirs()
        assert skill_like_dirs
        for path in skill_like_dirs:
            assert path.parent.name in COMMON.CANONICAL_SKILL_CATEGORIES
            assert path.name != "__pycache__"

    def test_every_skill_like_dir_has_a_contract(self):
        skill_like_dirs = COMMON.iter_skill_like_dirs()
        missing = [path for path in skill_like_dirs if not (path / "SKILL.md").exists()]
        assert missing == []


COUNT_CONSISTENCY = _load_module(
    "cloud_security_validate_skill_count_consistency_test",
    SCRIPTS / "validate_skill_count_consistency.py",
)


class TestCountDriftScan:
    """Catch the issue #302 class of bug: a stale mermaid count slipped into
    a doc that wasn't on the explicit CLAIMS allow-list."""

    def test_scan_passes_against_current_repo_state(self):
        # The script's main() runs both CLAIMS and the catch-all scan.
        assert COUNT_CONSISTENCY.main() == 0

    def test_scan_resolves_layer_hint_to_specific_metric(self):
        resolve = COUNT_CONSISTENCY._resolve_metric_for_line
        assert resolve("L1 Ingest<br/>15 skills") == "ingest_only"
        assert resolve("L2 Discover<br/>4 skills") == "discovery"
        assert resolve("L3 Detect<br/>11 skills · ATT&CK") == "detection"
        assert resolve("L4 Evaluate<br/>7 skills · 82 checks") == "evaluation"
        assert resolve("L5 Remediate<br/>4 skills · HITL") == "remediation"
        assert resolve("L6 View<br/>2 skills · SARIF") == "view"
        assert resolve("L7 Output<br/>3 sinks · S3") == "output"
        assert resolve("Sources<br/>3 adapters") == "sources"

    def test_ingestion_vs_ingest_only_split(self):
        """README treats `Ingest = 15` and `Sources = 3` as separate counts,
        even though both live under skills/ingestion/. The validator must
        split `ingest_only` from full `ingestion` so it can tell them apart."""
        ingest_only = COUNT_CONSISTENCY._count_ingest_only()
        sources = COUNT_CONSISTENCY._count_sources()
        full = COUNT_CONSISTENCY._count_skills("ingestion")
        assert full == ingest_only + sources

    def test_scan_falls_back_to_total_when_no_layer_hint(self):
        resolve = COUNT_CONSISTENCY._resolve_metric_for_line
        assert resolve("Shared skill bundle<br/>49 shipped") == "total"
        assert resolve("<br/>49 something-unknown") == "total"

    def test_scan_pattern_matches_mermaid_node_labels(self):
        pat = COUNT_CONSISTENCY.SCAN_PATTERN
        assert pat.search('ingest["L1 Ingest<br/>15 skills"]') is not None
        assert pat.search('node["Shared skill bundle<br/>48 shipped"]') is not None
        assert pat.search('out["L7 Output<br/>3 sinks · S3"]') is not None
        # Should NOT match prose (no <br/> prefix)
        assert pat.search("The repo ships 49 skills today.") is None
