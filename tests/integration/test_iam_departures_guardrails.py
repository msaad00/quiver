from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
JSON_POLICY = (
    ROOT
    / "skills"
    / "remediation"
    / "iam-departures-aws"
    / "infra"
    / "iam_policies"
    / "worker_execution_role.json"
)
CLOUDFORMATION = (
    ROOT / "skills" / "remediation" / "iam-departures-aws" / "infra" / "cloudformation.yaml"
)
TERRAFORM = (
    ROOT / "skills" / "remediation" / "iam-departures-aws" / "infra" / "terraform" / "main.tf"
)


def test_worker_policy_explicitly_denies_direct_step_function_execution():
    policy = json.loads(JSON_POLICY.read_text())
    deny = next(
        stmt
        for stmt in policy["Statement"]
        if stmt["Effect"] == "Deny" and stmt["Action"] == "states:StartExecution"
    )
    assert deny["Resource"] == "*"


def test_cloudformation_keeps_direct_step_function_deny():
    text = CLOUDFORMATION.read_text()
    assert "Action: states:StartExecution" in text
    assert "Effect: Deny" in text


def test_terraform_keeps_direct_step_function_deny():
    text = TERRAFORM.read_text()
    assert 'Action   = "states:StartExecution"' in text
    assert 'Effect   = "Deny"' in text
