from __future__ import annotations

import ast
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on Python <3.11
    sys.stderr.write(
        "error: validate_dependency_consistency.py requires Python 3.11+ "
        "(stdlib `tomllib`). Detected Python "
        f"{sys.version_info.major}.{sys.version_info.minor}. "
        'See pyproject.toml `requires-python = ">=3.11"`.\n'
    )
    sys.exit(2)

from skill_validation_common import ROOT

PYPROJECT = ROOT / "pyproject.toml"

IMPORT_TO_PACKAGE = {
    "azure.identity": "azure-identity",
    "azure.mgmt.network": "azure-mgmt-network",
    "azure.mgmt.resource": "azure-mgmt-resource",
    "azure.mgmt.storage": "azure-mgmt-storage",
    "boto3": "boto3",
    "botocore": "boto3",
    "clickhouse_connect": "clickhouse-connect",
    "databricks": "databricks-sql-connector",
    "google.cloud.compute_v1": "google-cloud-compute",
    "google.cloud.iam_admin_v1": "google-cloud-iam",
    "google.cloud.iam_v1": "google-cloud-iam",
    "google.cloud.resourcemanager_v3": "google-cloud-resource-manager",
    "google.cloud.storage": "google-cloud-storage",
    "googleapiclient": "google-api-python-client",
    "httpx": "httpx",
    "moto": "moto",
    "pytest": "pytest",
    "snowflake.connector": "snowflake-connector-python",
}

RUNTIME_ROOTS = (
    *(ROOT / "skills").glob("*/*/src"),
    ROOT / "mcp-server" / "src",
    ROOT / "scripts",
)
TEST_ROOTS = (
    ROOT / "tests",
    ROOT / "mcp-server" / "tests",
)

# Files inside RUNTIME_ROOTS that are test harnesses, not skill runtime
# code. Their imports are matched against the test group, not the
# runtime groups. Listed explicitly so a new genuine `scripts/`
# entrypoint can't silently inherit dev-only deps.
TEST_HARNESS_FILES_INSIDE_RUNTIME_ROOTS = frozenset(
    {
        ROOT / "scripts" / "_runner_e2e_harness.py",
    }
)


def _canonical_package(spec: str) -> str:
    package = spec.split("[", 1)[0]
    for marker in (">=", "<=", "==", "~=", "!=", "<", ">"):
        package = package.split(marker, 1)[0]
    return package


def _load_dependency_groups() -> dict[str, set[str]]:
    """Return each group's directly-owned package set.

    Dependency-group entries may be either a package spec string
    ("httpx>=0.27,<1") or a TOML inline-table that pulls in another
    group ({ include-group = "http-client" }). Only the strings
    contribute packages this group "owns"; includes are resolved by
    uv at install time and must not double-count toward the
    one-group-per-package rule.
    """
    data = tomllib.loads(PYPROJECT.read_text())
    groups = data.get("dependency-groups", {})
    return {
        group: {_canonical_package(spec) for spec in specs if isinstance(spec, str)}
        for group, specs in groups.items()
    }


def _resolve_group(name: str, raw_groups: dict, seen: set[str] | None = None) -> set[str]:
    """Recursively resolve a group's transitive package set, following
    `{ include-group = ... }` references. Used by the runtime / dev
    declaration checks so the one-group-per-package rule can stay
    strict at the spec layer while shared groups (e.g. http-client)
    still satisfy "is this dep declared somewhere?" coverage.
    """
    if seen is None:
        seen = set()
    if name in seen or name not in raw_groups:
        return set()
    seen.add(name)
    out: set[str] = set()
    for spec in raw_groups[name]:
        if isinstance(spec, str):
            out.add(_canonical_package(spec))
        elif isinstance(spec, dict) and "include-group" in spec:
            out.update(_resolve_group(spec["include-group"], raw_groups, seen))
    return out


def _load_raw_groups() -> dict[str, list]:
    raw = tomllib.loads(PYPROJECT.read_text()).get("dependency-groups", {})
    return {str(name): list(specs) for name, specs in raw.items()}


def _iter_python_files(*roots: Path, exclude: frozenset[Path] = frozenset()) -> list[Path]:
    paths: list[Path] = []
    for root in roots:
        if root.is_file():
            if root not in exclude:
                paths.append(root)
            continue
        if root.exists():
            paths.extend(p for p in sorted(root.rglob("*.py")) if p not in exclude)
    return paths


def _extract_imports(path: Path) -> set[str]:
    names: set[str] = set()
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0 or not node.module:
                continue
            names.add(node.module)
            for alias in node.names:
                if alias.name != "*":
                    names.add(f"{node.module}.{alias.name}")
    return names


def _required_packages(paths: list[Path]) -> set[str]:
    imports: set[str] = set()
    for path in paths:
        imports.update(_extract_imports(path))

    packages: set[str] = set()
    for name in imports:
        for prefix, package in IMPORT_TO_PACKAGE.items():
            if name == prefix or name.startswith(f"{prefix}."):
                packages.add(package)
                break
    return packages


def main() -> int:
    groups = _load_dependency_groups()
    errors: list[str] = []

    owners: dict[str, list[str]] = {}
    for group, packages in groups.items():
        for package in packages:
            owners.setdefault(package, []).append(group)
    for package, group_names in sorted(owners.items()):
        if len(group_names) > 1:
            errors.append(
                f"pyproject.toml: package `{package}` is duplicated across dependency groups: "
                f"{', '.join(sorted(group_names))}"
            )

    raw_groups = _load_raw_groups()

    runtime_required = _required_packages(
        _iter_python_files(*RUNTIME_ROOTS, exclude=TEST_HARNESS_FILES_INSIDE_RUNTIME_ROOTS)
    )
    runtime_declared = set().union(
        _resolve_group("aws", raw_groups),
        _resolve_group("gcp", raw_groups),
        _resolve_group("azure", raw_groups),
        _resolve_group("iam_departures", raw_groups),
        _resolve_group("mcp", raw_groups),
        _resolve_group("webhook", raw_groups),
        _resolve_group("mcp-sse", raw_groups),
        _resolve_group("http-runtime", raw_groups),
    )
    for package in sorted(runtime_required - runtime_declared):
        errors.append(f"pyproject.toml: runtime import requires undeclared package `{package}`")

    test_roots = [
        *TEST_ROOTS,
        *(ROOT / "skills").glob("*/*/tests"),
        # Carved-out runtime-rooted test harnesses (see definition above).
        *TEST_HARNESS_FILES_INSIDE_RUNTIME_ROOTS,
    ]
    test_required = _required_packages(_iter_python_files(*test_roots))
    dev_declared = _resolve_group("dev", raw_groups)
    for package in sorted(test_required & {"pytest", "moto"}):
        if package not in dev_declared:
            errors.append(
                f"pyproject.toml: test import requires `{package}` in the dev dependency group"
            )

    if errors:
        print("Dependency consistency validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print("Dependency consistency validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
