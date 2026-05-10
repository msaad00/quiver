"""Per-skill pytest conftest: delegate sibling-module isolation to the shared helper."""

from tests._pytest_isolation import isolate_skill_src

isolate_skill_src(__file__)
