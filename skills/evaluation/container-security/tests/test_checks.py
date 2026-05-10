"""Tests for container security benchmark.

Each check function is exercised across five edge-case axes (issue #405):
    1. Empty input — no images/containers, no findings
    2. Malformed payload — missing/None fields, non-dict items, wrong types
    3. Partial-pass scenario — some resources pass, some fail in one call
    4. Permission-denied / opaque-error encoding — surface a known state
    5. Multi-resource happy path — already covered by the original suite
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checks import (  # noqa: E402
    Finding,
    check_1_1_no_root_user,
    check_1_2_no_latest_base,
    check_1_3_healthcheck_defined,
    check_2_1_no_secrets_in_env,
    check_2_2_minimal_packages,
    check_2_3_no_add_instruction,
    check_3_1_read_only_rootfs,
    check_3_2_resource_limits,
    run_benchmark,
)

# ---------------------------------------------------------------------------
# Section 1 — Dockerfile (kept verbatim from baseline)
# ---------------------------------------------------------------------------


class TestDockerfile:
    def test_root_user_fails(self):
        config = {"images": [{"name": "app", "user": "root"}]}
        findings = run_benchmark(config, section="dockerfile")
        assert findings[0].status == "FAIL"

    def test_non_root_passes(self):
        config = {"images": [{"name": "app", "user": "1000"}]}
        findings = run_benchmark(config, section="dockerfile")
        assert findings[0].status == "PASS"

    def test_latest_base_fails(self):
        config = {"images": [{"name": "app", "base_image": "python:latest"}]}
        findings = run_benchmark(config, section="dockerfile")
        tag = next(f for f in findings if f.check_id == "CTR-1.2")
        assert tag.status == "FAIL"

    def test_pinned_base_passes(self):
        config = {"images": [{"name": "app", "base_image": "python:3.11-alpine"}]}
        findings = run_benchmark(config, section="dockerfile")
        tag = next(f for f in findings if f.check_id == "CTR-1.2")
        assert tag.status == "PASS"

    def test_no_healthcheck_fails(self):
        config = {"images": [{"name": "app"}]}
        findings = run_benchmark(config, section="dockerfile")
        hc = next(f for f in findings if f.check_id == "CTR-1.3")
        assert hc.status == "FAIL"


class TestImageSecurity:
    def test_secret_in_env_fails(self):
        config = {"images": [{"name": "app", "env": ["DATABASE_PASSWORD=secret123"]}]}
        findings = run_benchmark(config, section="image_security")
        sec = next(f for f in findings if f.check_id == "CTR-2.1")
        assert sec.status == "FAIL"
        assert sec.severity == "CRITICAL"

    def test_clean_env_passes(self):
        config = {"images": [{"name": "app", "env": ["NODE_ENV=production"]}]}
        findings = run_benchmark(config, section="image_security")
        sec = next(f for f in findings if f.check_id == "CTR-2.1")
        assert sec.status == "PASS"

    def test_bloated_base_fails(self):
        config = {"images": [{"name": "app", "base_image": "ubuntu:22.04"}]}
        findings = run_benchmark(config, section="image_security")
        base = next(f for f in findings if f.check_id == "CTR-2.2")
        assert base.status == "FAIL"

    def test_alpine_base_passes(self):
        config = {"images": [{"name": "app", "base_image": "python:3.11-alpine"}]}
        findings = run_benchmark(config, section="image_security")
        base = next(f for f in findings if f.check_id == "CTR-2.2")
        assert base.status == "PASS"


class TestRuntime:
    def test_writable_rootfs_fails(self):
        config = {"containers": [{"name": "app", "security_context": {}}]}
        findings = run_benchmark(config, section="runtime")
        ro = next(f for f in findings if f.check_id == "CTR-3.1")
        assert ro.status == "FAIL"

    def test_no_resource_limits_fails(self):
        config = {"containers": [{"name": "app", "resources": {}}]}
        findings = run_benchmark(config, section="runtime")
        lim = next(f for f in findings if f.check_id == "CTR-3.2")
        assert lim.status == "FAIL"

    def test_with_limits_passes(self):
        config = {"containers": [{"name": "app", "resources": {"limits": {"cpu": "1", "memory": "512Mi"}}}]}
        findings = run_benchmark(config, section="runtime")
        lim = next(f for f in findings if f.check_id == "CTR-3.2")
        assert lim.status == "PASS"


class TestRunner:
    def test_run_all(self):
        config = {"images": [{"name": "app", "user": "1000", "base_image": "python:3.11-alpine"}], "containers": []}
        findings = run_benchmark(config)
        assert len(findings) == 8
        assert all(isinstance(f, Finding) for f in findings)

    def test_all_have_cis_mapping(self):
        config = {"images": [{"name": "test"}]}
        findings = run_benchmark(config)
        for f in findings:
            assert f.cis_docker, f"{f.check_id} missing CIS Docker mapping"


# ---------------------------------------------------------------------------
# Edge-case axis 1 — empty input (issue #405)
# ---------------------------------------------------------------------------


_DOCKERFILE_CHECKS = [
    check_1_1_no_root_user,
    check_1_2_no_latest_base,
    check_1_3_healthcheck_defined,
]
_IMAGE_CHECKS = [
    check_2_1_no_secrets_in_env,
    check_2_2_minimal_packages,
    check_2_3_no_add_instruction,
]
_RUNTIME_CHECKS = [
    check_3_1_read_only_rootfs,
    check_3_2_resource_limits,
]
_ALL_CHECKS = _DOCKERFILE_CHECKS + _IMAGE_CHECKS + _RUNTIME_CHECKS


@pytest.mark.parametrize("check_fn", _ALL_CHECKS)
@pytest.mark.parametrize(
    "empty_config",
    [
        {},
        {"images": []},
        {"containers": []},
        {"images": [], "containers": []},
    ],
    ids=["bare-dict", "empty-images", "empty-containers", "both-empty"],
)
class TestEmptyInput:
    """Axis 1: every check returns a Finding with PASS / 0 resources for empty input."""

    def test_returns_finding_with_no_resources(self, check_fn, empty_config):
        f = check_fn(empty_config)
        assert isinstance(f, Finding)
        assert f.status == "PASS"
        assert f.resources == []
        assert f.check_id.startswith("CTR-")
        assert f.cis_docker
        assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ---------------------------------------------------------------------------
# Edge-case axis 2 — malformed payload
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_fn", _ALL_CHECKS)
@pytest.mark.parametrize(
    "malformed_config",
    [
        {"images": None},
        {"containers": None},
        {"images": "not-a-list"},
        {"images": [None, 42, "string-item"]},
        {"images": [{}]},  # image dict missing every field
        {"images": [{"name": None, "base_image": None, "env": None}]},
    ],
    ids=["images-None", "containers-None", "images-string", "images-mixed-junk", "image-bare", "image-Nones"],
)
class TestMalformedPayload:
    """Axis 2: malformed input must not crash; the check returns a structured Finding."""

    def test_no_crash_returns_finding(self, check_fn, malformed_config):
        f = check_fn(malformed_config)
        assert isinstance(f, Finding)
        assert f.status in {"PASS", "FAIL"}
        assert isinstance(f.resources, list)


def test_non_dict_config_does_not_crash():
    """Smoke: every check survives a non-dict top-level payload."""
    for fn in _ALL_CHECKS:
        f = fn([])  # type: ignore[arg-type]
        assert isinstance(f, Finding)
        assert f.resources == []


# ---------------------------------------------------------------------------
# Edge-case axis 3 — partial pass (some resources pass, some fail)
# ---------------------------------------------------------------------------


class TestPartialPass:
    """Axis 3: heterogeneous input — failing items surface, passing items don't."""

    def test_root_user_partial(self):
        config = {
            "images": [
                {"name": "good", "user": "1000"},
                {"name": "bad-root", "user": "root"},
                {"name": "bad-implicit"},  # no user → defaults to root
            ]
        }
        f = check_1_1_no_root_user(config)
        assert f.status == "FAIL"
        assert "bad-root" in f.resources
        assert "bad-implicit" in f.resources
        assert "good" not in f.resources
        assert len(f.resources) == 2

    def test_base_image_partial(self):
        config = {
            "images": [
                {"name": "pinned", "base_image": "python:3.11-alpine"},
                {"name": "latest", "base_image": "python:latest"},
                {"name": "untagged", "base_image": "python"},
            ]
        }
        f = check_1_2_no_latest_base(config)
        assert f.status == "FAIL"
        assert any("latest" in r and "FROM python:latest" in r for r in f.resources)
        assert any("untagged" in r for r in f.resources)
        assert not any(r.startswith("pinned:") for r in f.resources)
        assert len(f.resources) == 2

    def test_minimal_base_partial(self):
        config = {
            "images": [
                {"name": "alpine", "base_image": "python:3.11-alpine"},
                {"name": "distroless", "base_image": "gcr.io/distroless/python3:nonroot"},
                {"name": "fat", "base_image": "ubuntu:22.04"},
            ]
        }
        f = check_2_2_minimal_packages(config)
        assert f.status == "FAIL"
        assert len(f.resources) == 1
        assert any("fat" in r for r in f.resources)

    def test_secrets_in_env_partial(self):
        config = {
            "images": [
                {"name": "clean", "env": ["LOG_LEVEL=info"]},
                {"name": "leaky", "env": ["DB_PASSWORD=hunter2", "API_TOKEN=abc"]},
            ]
        }
        f = check_2_1_no_secrets_in_env(config)
        assert f.status == "FAIL"
        assert any("DB_PASSWORD" in r for r in f.resources)
        assert any("API_TOKEN" in r for r in f.resources)
        assert not any(r.startswith("clean:") for r in f.resources)
        assert f.severity == "CRITICAL"

    def test_resource_limits_partial(self):
        config = {
            "containers": [
                {"name": "constrained", "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}}},
                {"name": "unbounded", "resources": {}},
            ]
        }
        f = check_3_2_resource_limits(config)
        assert f.status == "FAIL"
        assert "unbounded" in f.resources
        assert "constrained" not in f.resources

    def test_readonly_rootfs_partial(self):
        config = {
            "containers": [
                {"name": "ro", "security_context": {"readOnlyRootFilesystem": True}},
                {"name": "rw", "security_context": {"readOnlyRootFilesystem": False}},
                {"name": "default", "security_context": {}},
            ]
        }
        f = check_3_1_read_only_rootfs(config)
        assert f.status == "FAIL"
        assert "rw" in f.resources
        assert "default" in f.resources
        assert "ro" not in f.resources

    def test_add_instruction_partial(self):
        config = {
            "images": [
                {"name": "clean", "instructions": ["COPY app /app", "RUN pip install ."]},
                {"name": "uses-add", "instructions": ["ADD https://example/x.tar.gz /tmp/"]},
            ]
        }
        f = check_2_3_no_add_instruction(config)
        assert f.status == "FAIL"
        assert "uses-add" in f.resources
        assert "clean" not in f.resources


# ---------------------------------------------------------------------------
# Edge-case axis 4 — permission-denied / opaque-error encoding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_fn", _ALL_CHECKS)
def test_permission_denied_payload_does_not_crash(check_fn):
    """Axis 4: scanners that proxy a registry/socket 403 surface no resources, no crash."""
    payload = {
        "images": None,
        "containers": None,
        "error": {"code": 403, "type": "AccessDenied", "message": "registry credentials missing"},
    }
    f = check_fn(payload)
    assert isinstance(f, Finding)
    assert f.resources == []
    # No resources visible → check passes (cannot prove a violation).
    assert f.status == "PASS"


# ---------------------------------------------------------------------------
# Edge-case axis 5 — multi-resource happy path
# ---------------------------------------------------------------------------


def test_multi_resource_happy_path_all_pass():
    config = {
        "images": [
            {
                "name": "api",
                "user": "10001",
                "base_image": "python:3.11-alpine",
                "healthcheck": {"test": ["CMD", "curl", "-f", "http://localhost"]},
                "env": ["LOG_LEVEL=info", "PORT=8080"],
                "instructions": ["COPY . /app", "RUN pip install ."],
            },
            {
                "name": "worker",
                "user": "10002",
                "base_image": "gcr.io/distroless/python3:nonroot",
                "healthcheck": {"test": ["CMD", "true"]},
                "env": [{"name": "QUEUE", "value": "default"}],
                "instructions": ["COPY worker.py /worker.py"],
            },
        ],
        "containers": [
            {
                "name": "api",
                "security_context": {"readOnlyRootFilesystem": True},
                "resources": {"limits": {"cpu": "1", "memory": "512Mi"}},
            },
            {
                "name": "worker",
                "security_context": {"readOnlyRootFilesystem": True},
                "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
            },
        ],
    }
    findings = run_benchmark(config)
    assert len(findings) == 8
    statuses = [f.status for f in findings]
    assert all(s == "PASS" for s in statuses), [
        (f.check_id, f.status, f.detail) for f in findings if f.status != "PASS"
    ]
