"""Per-skill pytest conftest: delegate sibling-module isolation to the shared helper.

The repo-root `conftest.py` puts the repo on sys.path so this import resolves;
`tests/_pytest_isolation.py` carries the actual sys.modules + sys.path scrub
logic (formerly duplicated 14 lines per skill).
"""

from tests._pytest_isolation import isolate_skill_src

isolate_skill_src(__file__)
