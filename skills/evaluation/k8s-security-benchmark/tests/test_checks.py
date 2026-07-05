"""Tests for Kubernetes security benchmark.

Each check function is exercised across five edge-case axes (issue #405):
    1. Empty input — no pods/namespaces, no findings
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
    check_1_1_no_privileged_pods,
    check_1_2_no_host_pid,
    check_1_3_no_host_network,
    check_1_4_drop_all_capabilities,
    check_2_1_no_cluster_admin_default,
    check_2_2_no_wildcard_permissions,
    check_3_1_default_deny,
    check_4_1_no_env_secrets,
    check_4_2_secrets_encrypted_etcd,
    check_5_1_no_latest_tag,
    run_benchmark,
)

# ---------------------------------------------------------------------------
# Original baseline tests (kept verbatim)
# ---------------------------------------------------------------------------


class TestPodSecurity:
    def test_privileged_pod_fails(self):
        config = {
            "pods": [
                {
                    "name": "bad",
                    "containers": [{"name": "c1", "securityContext": {"privileged": True}}],
                }
            ]
        }
        findings = run_benchmark(config, section="pod_security")
        priv = next(f for f in findings if f.check_id == "K8S-1.1")
        assert priv.status == "FAIL"

    def test_safe_pod_passes(self):
        config = {
            "pods": [
                {
                    "name": "good",
                    "containers": [
                        {
                            "name": "c1",
                            "securityContext": {
                                "privileged": False,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        },
                    ],
                }
            ]
        }
        findings = run_benchmark(config, section="pod_security")
        assert findings[0].status == "PASS"
        assert findings[3].status == "PASS"

    def test_host_pid_fails(self):
        config = {"pods": [{"name": "bad", "spec": {"hostPID": True}}]}
        findings = run_benchmark(config, section="pod_security")
        pid = next(f for f in findings if f.check_id == "K8S-1.2")
        assert pid.status == "FAIL"

    def test_host_network_fails(self):
        config = {"pods": [{"name": "bad", "spec": {"hostNetwork": True}}]}
        findings = run_benchmark(config, section="pod_security")
        net = next(f for f in findings if f.check_id == "K8S-1.3")
        assert net.status == "FAIL"


class TestRBAC:
    def test_cluster_admin_default_fails(self):
        config = {
            "cluster_role_bindings": [
                {
                    "name": "bad-binding",
                    "roleRef": {"name": "cluster-admin"},
                    "subjects": [{"name": "default", "namespace": "default"}],
                }
            ]
        }
        findings = run_benchmark(config, section="rbac")
        admin = next(f for f in findings if f.check_id == "K8S-2.1")
        assert admin.status == "FAIL"

    def test_wildcard_permissions_fails(self):
        config = {
            "cluster_roles": [
                {"name": "too-broad", "rules": [{"verbs": ["*"], "resources": ["*"]}]}
            ]
        }
        findings = run_benchmark(config, section="rbac")
        wc = next(f for f in findings if f.check_id == "K8S-2.2")
        assert wc.status == "FAIL"


class TestNetwork:
    def test_no_deny_policy_fails(self):
        config = {"namespaces": [{"name": "default", "network_policies": []}]}
        findings = run_benchmark(config, section="network")
        assert findings[0].status == "FAIL"

    def test_deny_policy_passes(self):
        config = {
            "namespaces": [
                {"name": "production", "network_policies": [{"name": "default-deny-ingress"}]}
            ]
        }
        findings = run_benchmark(config, section="network")
        assert findings[0].status == "PASS"


class TestSecrets:
    def test_env_secrets_fails(self):
        config = {
            "pods": [
                {
                    "name": "app",
                    "containers": [
                        {
                            "name": "c1",
                            "env": [
                                {
                                    "name": "DB_PASS",
                                    "valueFrom": {
                                        "secretKeyRef": {"name": "db", "key": "password"}
                                    },
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        findings = run_benchmark(config, section="secrets")
        env = next(f for f in findings if f.check_id == "K8S-4.1")
        assert env.status == "FAIL"

    def test_no_etcd_encryption_fails(self):
        config = {"api_server": {}}
        findings = run_benchmark(config, section="secrets")
        enc = next(f for f in findings if f.check_id == "K8S-4.2")
        assert enc.status == "FAIL"


class TestImages:
    def test_latest_tag_fails(self):
        config = {
            "pods": [{"name": "app", "containers": [{"name": "c1", "image": "nginx:latest"}]}]
        }
        findings = run_benchmark(config, section="images")
        assert findings[0].status == "FAIL"

    def test_pinned_tag_passes(self):
        config = {
            "pods": [
                {"name": "app", "containers": [{"name": "c1", "image": "nginx:1.25.3-alpine"}]}
            ]
        }
        findings = run_benchmark(config, section="images")
        assert findings[0].status == "PASS"


class TestRunner:
    def test_run_all(self):
        config = {"pods": [], "namespaces": [], "api_server": {}}
        findings = run_benchmark(config)
        assert len(findings) == 10
        assert all(isinstance(f, Finding) for f in findings)

    def test_all_have_cis_mapping(self):
        config = {"pods": [{"name": "test", "containers": [{"name": "c", "image": "app:v1"}]}]}
        findings = run_benchmark(config)
        for f in findings:
            assert f.cis_k8s, f"{f.check_id} missing CIS K8s mapping"


# ---------------------------------------------------------------------------
# Edge-case axis 1 — empty input (issue #405)
# ---------------------------------------------------------------------------


_POD_CHECKS = [
    check_1_1_no_privileged_pods,
    check_1_2_no_host_pid,
    check_1_3_no_host_network,
    check_1_4_drop_all_capabilities,
    check_4_1_no_env_secrets,
    check_5_1_no_latest_tag,
]
_RBAC_CHECKS = [
    check_2_1_no_cluster_admin_default,
    check_2_2_no_wildcard_permissions,
]
_OTHER_CHECKS = [
    check_3_1_default_deny,
    check_4_2_secrets_encrypted_etcd,
]
_ALL_CHECKS = _POD_CHECKS + _RBAC_CHECKS + _OTHER_CHECKS


@pytest.mark.parametrize("check_fn", _ALL_CHECKS)
@pytest.mark.parametrize(
    "empty_config",
    [
        {},
        {"pods": []},
        {"namespaces": []},
        {"cluster_role_bindings": [], "cluster_roles": [], "roles": []},
        {"pods": [], "namespaces": [], "api_server": {}},
    ],
    ids=["bare-dict", "empty-pods", "empty-namespaces", "empty-rbac", "all-empty"],
)
class TestEmptyInput:
    """Axis 1: every check returns a Finding with no resources for empty input."""

    def test_returns_finding_with_no_resources(self, check_fn, empty_config):
        f = check_fn(empty_config)
        assert isinstance(f, Finding)
        # 4_2_secrets_encrypted_etcd FAILs on empty (no encryption configured),
        # all others PASS — both are valid; resources should be empty either way.
        assert f.status in {"PASS", "FAIL"}
        assert isinstance(f.resources, list)
        assert f.resources == []
        assert f.check_id.startswith("K8S-")
        assert f.cis_k8s
        assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ---------------------------------------------------------------------------
# Edge-case axis 2 — malformed payload
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_fn", _ALL_CHECKS)
@pytest.mark.parametrize(
    "malformed_config",
    [
        {
            "pods": None,
            "namespaces": None,
            "cluster_role_bindings": None,
            "cluster_roles": None,
            "api_server": None,
        },
        {"pods": "not-a-list"},
        {"pods": [None, 42, "string"]},
        {"pods": [{}]},
        {"pods": [{"spec": None, "containers": None}]},
        {"pods": [{"spec": "string", "containers": "string"}]},
        {"pods": [{"containers": [None, "string", {}]}]},
        {"namespaces": [None, "x", {}]},
        {"cluster_role_bindings": [{"roleRef": None, "subjects": None}]},
        {"cluster_roles": [{"rules": [{"verbs": None, "resources": None}]}]},
    ],
    ids=[
        "fields-None",
        "pods-string",
        "pods-junk",
        "pod-empty",
        "pod-Nones",
        "pod-strings",
        "container-junk",
        "ns-junk",
        "binding-Nones",
        "rule-Nones",
    ],
)
class TestMalformedPayload:
    """Axis 2: malformed input must not crash; returns a structured Finding."""

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
# Edge-case axis 3 — partial pass
# ---------------------------------------------------------------------------


class TestPartialPass:
    """Axis 3: heterogeneous input — failing items surface, passing items don't."""

    def test_privileged_partial(self):
        config = {
            "pods": [
                {
                    "name": "good",
                    "containers": [{"name": "c", "securityContext": {"privileged": False}}],
                },
                {
                    "name": "bad",
                    "containers": [{"name": "c", "securityContext": {"privileged": True}}],
                },
            ]
        }
        f = check_1_1_no_privileged_pods(config)
        assert f.status == "FAIL"
        assert any("bad" in r for r in f.resources)
        assert not any("good" in r for r in f.resources)
        assert len(f.resources) == 1

    def test_host_pid_partial(self):
        config = {
            "pods": [
                {"name": "ok", "spec": {"hostPID": False}},
                {"name": "bad", "spec": {"hostPID": True}},
                {"name": "missing"},  # no spec
            ]
        }
        f = check_1_2_no_host_pid(config)
        assert f.status == "FAIL"
        assert "bad" in f.resources
        assert "ok" not in f.resources
        assert "missing" not in f.resources

    def test_host_network_partial(self):
        config = {
            "pods": [
                {"name": "ok", "spec": {"hostNetwork": False}},
                {"name": "bad", "spec": {"hostNetwork": True}},
            ]
        }
        f = check_1_3_no_host_network(config)
        assert f.status == "FAIL"
        assert "bad" in f.resources
        assert "ok" not in f.resources

    def test_drop_capabilities_partial(self):
        config = {
            "pods": [
                {
                    "name": "good",
                    "containers": [
                        {"name": "c", "securityContext": {"capabilities": {"drop": ["ALL"]}}}
                    ],
                },
                {
                    "name": "bad",
                    "containers": [
                        {"name": "c", "securityContext": {"capabilities": {"drop": ["NET_RAW"]}}}
                    ],
                },
            ]
        }
        f = check_1_4_drop_all_capabilities(config)
        assert f.status == "FAIL"
        assert any("bad" in r for r in f.resources)
        assert not any("good" in r for r in f.resources)

    def test_wildcard_partial(self):
        config = {
            "cluster_roles": [
                {"name": "scoped", "rules": [{"verbs": ["get"], "resources": ["pods"]}]},
                {"name": "broad", "rules": [{"verbs": ["*"], "resources": ["secrets"]}]},
            ]
        }
        f = check_2_2_no_wildcard_permissions(config)
        assert f.status == "FAIL"
        assert "broad" in f.resources
        assert "scoped" not in f.resources

    def test_default_deny_partial(self):
        config = {
            "namespaces": [
                {"name": "locked", "network_policies": [{"name": "default-deny"}]},
                {"name": "open", "network_policies": []},
            ]
        }
        f = check_3_1_default_deny(config)
        assert f.status == "FAIL"
        assert "open" in f.resources
        assert "locked" not in f.resources

    def test_env_secrets_partial(self):
        config = {
            "pods": [
                {
                    "name": "clean",
                    "containers": [{"name": "c", "env": [{"name": "PORT", "value": "8080"}]}],
                },
                {
                    "name": "leaky",
                    "containers": [
                        {
                            "name": "c",
                            "env": [
                                {
                                    "name": "DB_PASS",
                                    "valueFrom": {"secretKeyRef": {"name": "db", "key": "pass"}},
                                }
                            ],
                        }
                    ],
                },
            ]
        }
        f = check_4_1_no_env_secrets(config)
        assert f.status == "FAIL"
        assert any("leaky" in r for r in f.resources)
        assert not any(r.startswith("clean:") for r in f.resources)

    def test_latest_tag_partial(self):
        config = {
            "pods": [
                {"name": "good", "containers": [{"name": "c", "image": "nginx:1.25"}]},
                {"name": "bad", "containers": [{"name": "c", "image": "nginx:latest"}]},
                {"name": "untagged", "containers": [{"name": "c", "image": "nginx"}]},
            ]
        }
        f = check_5_1_no_latest_tag(config)
        assert f.status == "FAIL"
        assert any("bad" in r and ":latest" in r for r in f.resources)
        assert any("untagged" in r for r in f.resources)
        assert not any(r.startswith("good:") for r in f.resources)


# ---------------------------------------------------------------------------
# Edge-case axis 4 — permission-denied / opaque-error encoding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_fn", _ALL_CHECKS)
def test_permission_denied_payload_does_not_crash(check_fn):
    """Axis 4: kubectl 403/Forbidden surfaces in payload — check survives, no resources."""
    payload = {
        "pods": None,
        "namespaces": None,
        "cluster_role_bindings": None,
        "cluster_roles": None,
        "roles": None,
        "api_server": None,
        "error": {"code": 403, "type": "Forbidden", "message": "kubectl: User cannot list pods"},
    }
    f = check_fn(payload)
    assert isinstance(f, Finding)
    assert f.resources == []


# ---------------------------------------------------------------------------
# Edge-case axis 5 — multi-resource happy path
# ---------------------------------------------------------------------------


def test_multi_resource_happy_path_all_pass():
    config = {
        "pods": [
            {
                "name": "api",
                "spec": {"hostPID": False, "hostNetwork": False},
                "containers": [
                    {
                        "name": "api",
                        "image": "registry.example/api:1.2.3",
                        "securityContext": {
                            "privileged": False,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "env": [{"name": "PORT", "value": "8080"}],
                    }
                ],
            },
            {
                "name": "worker",
                "spec": {"hostPID": False, "hostNetwork": False},
                "containers": [
                    {
                        "name": "worker",
                        "image": "registry.example/worker:2.0.0",
                        "securityContext": {
                            "privileged": False,
                            "capabilities": {"drop": ["ALL"]},
                        },
                    }
                ],
            },
        ],
        "namespaces": [
            {"name": "production", "network_policies": [{"name": "default-deny-ingress"}]},
            {"name": "staging", "network_policies": [{"name": "default-deny-all"}]},
        ],
        "cluster_role_bindings": [
            {
                "name": "team-readonly",
                "roleRef": {"name": "view"},
                "subjects": [{"name": "team", "namespace": "production"}],
            },
        ],
        "cluster_roles": [
            {"name": "view", "rules": [{"verbs": ["get", "list"], "resources": ["pods"]}]},
        ],
        "api_server": {"encryption_config": "/etc/k8s/encryption.yaml"},
    }
    findings = run_benchmark(config)
    assert len(findings) == 10
    failed = [(f.check_id, f.detail) for f in findings if f.status == "FAIL"]
    assert not failed, f"unexpected fails: {failed}"
