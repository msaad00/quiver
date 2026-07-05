"""Tests for the eleven Entra IAM teardown steps."""

from __future__ import annotations

import sys

# Stub Azure SDK modules before steps.py imports anything (steps is pure-Python
# but the orchestrator and audit writer pull these in via lazy imports).
sys.modules.setdefault("azure", type(sys)("azure"))
for _mod in (
    "azure.identity",
    "azure.mgmt",
    "azure.mgmt.authorization",
    "azure.cosmos",
    "azure.storage",
    "azure.storage.blob",
    "msgraph",
):
    if _mod not in sys.modules:
        sys.modules[_mod] = type(sys)(_mod)

from function_worker import steps  # type: ignore[import-not-found]  # noqa: E402

OBJECT_ID = "aaaaaaaa-1111-1111-1111-111111111111"


class _StubClient:
    """Records every method call so a test can assert on the audit trail."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        # Defaults — tests override via attribute set.
        self.oauth2_grants: list[dict] = []
        self.user_groups: list[dict] = []
        self.user_directory_roles: list[dict] = []
        self.user_app_role_assignments: list[dict] = []
        self.user_licenses: list[dict] = []
        self.role_assignments: dict[str, list[dict]] = {}

    def _call(self, name: str, **kwargs):
        self.calls.append((name, kwargs))

    def disable_user(self, *, object_id):
        self._call("disable_user", object_id=object_id)

    def revoke_signin_sessions(self, *, object_id):
        self._call("revoke_signin_sessions", object_id=object_id)

    def hard_delete_user(self, *, object_id):
        self._call("hard_delete_user", object_id=object_id)

    def list_oauth2_permission_grants(self, *, principal_id):
        return self.oauth2_grants

    def delete_oauth2_permission_grant(self, *, grant_id):
        self._call("delete_oauth2_permission_grant", grant_id=grant_id)

    def list_user_groups(self, *, object_id):
        return self.user_groups

    def remove_group_member(self, *, group_id, user_id):
        self._call("remove_group_member", group_id=group_id, user_id=user_id)

    def list_user_directory_roles(self, *, object_id):
        return self.user_directory_roles

    def remove_directory_role_member(self, *, role_id, user_id):
        self._call("remove_directory_role_member", role_id=role_id, user_id=user_id)

    def list_user_app_role_assignments(self, *, object_id):
        return self.user_app_role_assignments

    def delete_user_app_role_assignment(self, *, user_id, assignment_id):
        self._call("delete_user_app_role_assignment", user_id=user_id, assignment_id=assignment_id)

    def list_role_assignments(self, *, scope_type, principal_id):
        return self.role_assignments.get(scope_type, [])

    def delete_role_assignment(self, *, assignment_id):
        self._call("delete_role_assignment", assignment_id=assignment_id)

    def list_user_licenses(self, *, object_id):
        return self.user_licenses

    def remove_licenses(self, *, object_id, sku_ids):
        self._call("remove_licenses", object_id=object_id, sku_ids=sku_ids)

    def tag_user(self, *, object_id, tags):
        self._call("tag_user", object_id=object_id, tags=tags)


def test_step_names_match_remediation_steps():
    soft = steps.remediation_steps(hard_delete=False)
    hard = steps.remediation_steps(hard_delete=True)
    assert tuple(name for name, _ in soft) == steps.STEP_NAMES
    assert tuple(name for name, _ in hard) == steps.STEP_NAMES
    # Hard-delete swaps step 11 to the hard variant.
    assert soft[-1][1] is steps._final_delete_user_soft
    assert hard[-1][1] is steps._final_delete_user_hard


def test_disable_user_calls_graph_and_records():
    client = _StubClient()
    actions: list[dict] = []
    steps._disable_user(client, OBJECT_ID, {}, actions)
    assert client.calls == [("disable_user", {"object_id": OBJECT_ID})]
    assert actions[0]["action"] == "disable_user"


def test_revoke_signin_sessions_calls_graph():
    client = _StubClient()
    actions: list[dict] = []
    steps._revoke_signin_sessions(client, OBJECT_ID, {}, actions)
    assert client.calls == [("revoke_signin_sessions", {"object_id": OBJECT_ID})]


def test_delete_oauth2_grants_iterates():
    client = _StubClient()
    client.oauth2_grants = [{"id": "g1"}, {"id": "g2"}]
    actions: list[dict] = []
    steps._delete_oauth2_grants(client, OBJECT_ID, {}, actions)
    deleted = [c for c in client.calls if c[0] == "delete_oauth2_permission_grant"]
    assert {c[1]["grant_id"] for c in deleted} == {"g1", "g2"}


def test_remove_from_groups_iterates():
    client = _StubClient()
    client.user_groups = [{"id": "grp1"}, {"id": "grp2"}]
    actions: list[dict] = []
    steps._remove_from_groups(client, OBJECT_ID, {}, actions)
    removed = [c for c in client.calls if c[0] == "remove_group_member"]
    assert {c[1]["group_id"] for c in removed} == {"grp1", "grp2"}


def test_remove_directory_role_memberships_iterates():
    client = _StubClient()
    client.user_directory_roles = [{"id": "role-a"}]
    actions: list[dict] = []
    steps._remove_directory_role_memberships(client, OBJECT_ID, {}, actions)
    assert any(
        c[0] == "remove_directory_role_member" and c[1]["role_id"] == "role-a" for c in client.calls
    )


def test_delete_app_role_assignments_iterates():
    client = _StubClient()
    client.user_app_role_assignments = [{"id": "a1"}, {"id": "a2"}]
    actions: list[dict] = []
    steps._delete_app_role_assignments(client, OBJECT_ID, {}, actions)
    assert sum(1 for c in client.calls if c[0] == "delete_user_app_role_assignment") == 2


def test_detach_subscription_role_assignments():
    client = _StubClient()
    client.role_assignments["subscription"] = [
        {"id": "/sub/1/ra/x", "scope": "/subscriptions/sub1"}
    ]
    actions: list[dict] = []
    steps._detach_subscription_role_assignments(client, OBJECT_ID, {}, actions)
    assert any(c[0] == "delete_role_assignment" for c in client.calls)
    assert actions[0]["action"] == "detach_subscription_role_assignment"


def test_detach_managementgroup_and_resourcegroup():
    client = _StubClient()
    client.role_assignments["management_group"] = [
        {"id": "/mg/x/ra/m", "scope": "/providers/Microsoft.Management/managementGroups/x"}
    ]
    client.role_assignments["resource_group"] = [
        {"id": "/sub/1/rg/x/ra/r", "scope": "/subscriptions/1/resourceGroups/x"}
    ]
    actions: list[dict] = []
    steps._detach_managementgroup_and_resourcegroup_role_assignments(client, OBJECT_ID, {}, actions)
    targets = {a["target"] for a in actions}
    assert targets == {"/mg/x/ra/m", "/sub/1/rg/x/ra/r"}


def test_detach_assigned_licenses_skips_when_none():
    client = _StubClient()
    actions: list[dict] = []
    steps._detach_assigned_licenses(client, OBJECT_ID, {}, actions)
    assert client.calls == []
    assert actions == []


def test_detach_assigned_licenses_calls_remove():
    client = _StubClient()
    client.user_licenses = [{"skuId": "sku-1"}, {"skuId": "sku-2"}]
    actions: list[dict] = []
    steps._detach_assigned_licenses(client, OBJECT_ID, {}, actions)
    remove_calls = [c for c in client.calls if c[0] == "remove_licenses"]
    assert remove_calls and sorted(remove_calls[0][1]["sku_ids"]) == ["sku-1", "sku-2"]


def test_tag_user_records_audit_extension():
    client = _StubClient()
    actions: list[dict] = []
    entry = {
        "upn": "alice@acme.example",
        "terminated_at": "2026-04-01T00:00:00Z",
        "termination_source": "snowflake",
    }
    steps._tag_user_for_audit(client, OBJECT_ID, entry, actions)
    tag_call = [c for c in client.calls if c[0] == "tag_user"][0]
    assert "extension_audit_remediated_at" in tag_call[1]["tags"]
    assert tag_call[1]["tags"]["extension_audit_employee_upn"] == "alice@acme.example"


def test_soft_delete_does_not_call_graph():
    client = _StubClient()
    actions: list[dict] = []
    steps._final_delete_user_soft(client, OBJECT_ID, {}, actions)
    assert client.calls == []
    assert actions[0]["action"] == "soft_delete_user"
    assert actions[0]["mode"] == "soft"


def test_hard_delete_calls_graph():
    client = _StubClient()
    actions: list[dict] = []
    steps._final_delete_user_hard(client, OBJECT_ID, {}, actions)
    assert client.calls == [("hard_delete_user", {"object_id": OBJECT_ID})]
    assert actions[0]["mode"] == "hard"
