"""Generate technical control evidence from discovery-layer inventory artifacts."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "discover-control-evidence"
SUPPORTED_FRAMEWORKS = ("pci", "soc2")
SUPPORTED_OUTPUT_FORMATS = ("native", "ocsf-live-evidence")
SECRET_KEYWORDS = (
    "authorization",
    "client_secret",
    "connection_string",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
)
FRAMEWORK_LABELS = {
    "pci": "PCI DSS 4.0",
    "soc2": "SOC 2 Security",
}


def _load_json(path: str | None) -> dict[str, Any]:
    if path:
        return json.loads(Path(path).read_text())
    return json.load(sys.stdin)


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _secret_like(key: str) -> bool:
    key = key.lower().replace("-", "_")
    return any(fragment in key for fragment in SECRET_KEYWORDS)


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, child in value.items():
            if _secret_like(key):
                continue
            cleaned_child = _sanitize(child)
            if cleaned_child in (None, {}, []):
                continue
            cleaned[key] = cleaned_child
        return cleaned
    if isinstance(value, list):
        cleaned_list = [_sanitize(item) for item in value]
        return [item for item in cleaned_list if item not in (None, {}, [])]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _clean(mapping: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in mapping.items() if value not in (None, "", [], {})}


def _string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_frameworks(frameworks: list[str] | None) -> list[str]:
    if not frameworks:
        return list(SUPPORTED_FRAMEWORKS)
    normalized = []
    for item in frameworks:
        key = item.strip().lower()
        if key not in SUPPORTED_FRAMEWORKS:
            raise ValueError(f"unsupported framework `{item}`; supported values: {', '.join(SUPPORTED_FRAMEWORKS)}")
        if key not in normalized:
            normalized.append(key)
    return normalized


def _time_to_epoch_ms(value: str | None) -> int:
    text = _string(value)
    if not text:
        return 0
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return int(datetime.fromisoformat(text).timestamp() * 1000)
    except ValueError:
        return 0


def _asset_key(asset: dict[str, Any]) -> str:
    provider = _string(asset.get("provider")) or "unknown"
    service = _string(asset.get("service")) or "unknown"
    kind = _string(asset.get("kind")) or "unknown"
    identifier = _string(asset.get("id")) or _string(asset.get("name"))
    if not identifier:
        raise ValueError("normalized asset is missing both `id` and `name`")
    return f"{provider}:{service}:{kind}:{identifier}"


def _normalize_bom(document: dict[str, Any]) -> dict[str, Any]:
    components = document.get("components")
    services = document.get("services")
    if not isinstance(components, list) and not isinstance(services, list):
        raise ValueError("CycloneDX BOM must include `components[]` or `services[]`")

    assets: list[dict[str, Any]] = []
    for component in components or []:
        props = {item.get("name"): item.get("value") for item in component.get("properties", []) if isinstance(item, dict)}
        assets.append(
            _clean(
                {
                    "provider": props.get("cloud-security:provider"),
                    "service": props.get("cloud-security:service"),
                    "kind": props.get("cloud-security:kind") or component.get("type"),
                    "id": component.get("bom-ref"),
                    "name": component.get("name"),
                    "version": component.get("version"),
                }
            )
        )

    for service in services or []:
        props = {item.get("name"): item.get("value") for item in service.get("properties", []) if isinstance(item, dict)}
        assets.append(
            _clean(
                {
                    "provider": props.get("cloud-security:provider"),
                    "service": props.get("cloud-security:service"),
                    "kind": props.get("cloud-security:kind") or "service",
                    "id": service.get("bom-ref"),
                    "name": service.get("name"),
                    "endpoint_url": next(iter(service.get("endpoints", []) or []), None),
                }
            )
        )

    dependencies = [
        {
            "source": item.get("ref"),
            "target": dep,
        }
        for item in document.get("dependencies", []) or []
        if isinstance(item, dict)
        for dep in item.get("dependsOn", []) or []
        if _string(item.get("ref")) and _string(dep)
    ]

    return {
        "source_kind": "cyclonedx-ai-bom",
        "source_id": document.get("serialNumber"),
        "collected_at": ((document.get("metadata") or {}).get("timestamp")),
        "assets": assets,
        "dependencies": dependencies,
    }


def _normalize_graph(document: dict[str, Any]) -> dict[str, Any]:
    nodes = document.get("nodes")
    edges = document.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("environment graph must include `nodes[]` and `edges[]`")

    assets = []
    for node in nodes:
        dimensions = node.get("dimensions", {}) if isinstance(node, dict) else {}
        attrs = node.get("attributes", {}) if isinstance(node, dict) else {}
        if not isinstance(node, dict):
            continue
        assets.append(
            _clean(
                {
                    "provider": dimensions.get("cloud_provider"),
                    "service": dimensions.get("service"),
                    "kind": node.get("entity_type"),
                    "id": node.get("id"),
                    "name": node.get("label"),
                    "arn": attrs.get("arn"),
                    "region": dimensions.get("region"),
                }
            )
        )

    relationships = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source = _string(edge.get("source"))
        target = _string(edge.get("target"))
        if source and target:
            relationships.append({"source": source, "target": target, "relationship": edge.get("relationship")})

    return {
        "source_kind": "environment-graph",
        "source_id": document.get("scan_id"),
        "collected_at": document.get("discovered_at"),
        "assets": assets,
        "dependencies": relationships,
    }


def normalize_source(document: dict[str, Any]) -> dict[str, Any]:
    sanitized = _sanitize(document)
    if sanitized.get("bomFormat") == "CycloneDX":
        return _normalize_bom(sanitized)
    if "nodes" in sanitized and "edges" in sanitized:
        return _normalize_graph(sanitized)
    raise ValueError("input must be a CycloneDX AI BOM or an environment graph snapshot")


def _summaries(normalized: dict[str, Any]) -> dict[str, Any]:
    assets = normalized["assets"]
    dependencies = normalized["dependencies"]

    providers = sorted({_string(asset.get("provider")) or "unknown" for asset in assets})
    services = sorted({_string(asset.get("service")) or "unknown" for asset in assets})
    kinds = Counter((_string(asset.get("kind")) or "unknown") for asset in assets)
    external_services = []
    for asset in assets:
        endpoint = _string(asset.get("endpoint_url"))
        if endpoint:
            external_services.append(
                _clean(
                    {
                        "provider": asset.get("provider"),
                        "service": asset.get("service"),
                        "name": asset.get("name"),
                        "endpoint_url": endpoint,
                    }
                )
            )

    return {
        "providers": providers,
        "services": services,
        "asset_count": len(assets),
        "dependency_count": len(dependencies),
        "kind_counts": dict(sorted(kinds.items())),
        "external_services": sorted(external_services, key=lambda item: json.dumps(item, sort_keys=True)),
    }


def _status(has_enough: bool, has_some: bool) -> str:
    if has_enough:
        return "evidence-ready"
    if has_some:
        return "partial"
    return "missing"


def _control(framework: str, control_id: str, title: str, description: str, evidence: list[dict[str, Any]], gaps: list[str]) -> dict[str, Any]:
    status = _status(not gaps and bool(evidence), bool(evidence))
    return {
        "framework": FRAMEWORK_LABELS[framework],
        "control_id": control_id,
        "title": title,
        "status": status,
        "description": description,
        "evidence": evidence,
        "gaps": gaps,
    }


def build_evidence(document: dict[str, Any], frameworks: list[str] | None = None) -> dict[str, Any]:
    normalized = normalize_source(document)
    selected = _normalize_frameworks(frameworks)
    summary = _summaries(normalized)
    providers = summary["providers"]
    kind_counts = summary["kind_counts"]
    external_services = summary["external_services"]

    base_evidence = [
        {"type": "asset-count", "value": summary["asset_count"]},
        {"type": "providers", "value": providers},
        {"type": "services", "value": summary["services"]},
        {"type": "kind-counts", "value": kind_counts},
        {"type": "dependency-count", "value": summary["dependency_count"]},
    ]

    controls = []
    for framework in selected:
        if framework == "pci":
            controls.extend(
                [
                    _control(
                        framework,
                        "inventory.system-components",
                        "System component inventory evidence",
                        "Evidence package showing inventoried AI and cloud system components relevant to cardholder-data environments or connected services.",
                        base_evidence,
                        [] if summary["asset_count"] else ["No assets were present in the source artifact."],
                    ),
                    _control(
                        framework,
                        "inventory.external-services",
                        "Externally reachable service evidence",
                        "Evidence package listing inventoried externally reachable endpoints and their provider/service context.",
                        [{"type": "external-services", "value": external_services}] if external_services else [],
                        [] if external_services else ["No externally reachable services were identified in the source artifact."],
                    ),
                ]
            )
        if framework == "soc2":
            controls.extend(
                [
                    _control(
                        framework,
                        "system.inventory",
                        "System inventory evidence",
                        "Evidence package describing the systems, providers, and services currently present in the discovery artifact.",
                        base_evidence,
                        [] if summary["asset_count"] else ["No assets were present in the source artifact."],
                    ),
                    _control(
                        framework,
                        "system.dependencies",
                        "Dependency and relationship evidence",
                        "Evidence package summarizing explicit dependencies or graph relationships between inventoried assets.",
                        [{"type": "dependencies", "value": normalized["dependencies"][:20]}] if normalized["dependencies"] else [],
                        [] if normalized["dependencies"] else ["No explicit dependencies or graph relationships were present in the source artifact."],
                    ),
                ]
            )

    source_fingerprint = json.dumps(
        {
            "source_kind": normalized["source_kind"],
            "source_id": normalized["source_id"],
            "frameworks": selected,
            "summary": summary,
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    return {
        "artifact_type": "technical-control-evidence",
        "generated_by": SKILL_NAME,
        "frameworks": [FRAMEWORK_LABELS[item] for item in selected],
        "source_kind": normalized["source_kind"],
        "source_id": normalized["source_id"],
        "collected_at": normalized.get("collected_at"),
        "evidence_id": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, source_fingerprint)}",
        "inventory_summary": summary,
        "controls": controls,
    }


def to_ocsf_live_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    time_ms = _time_to_epoch_ms(evidence.get("collected_at"))
    return {
        "activity_id": 99,
        "activity_name": "Other",
        "category_uid": 5,
        "category_name": "Discovery",
        "class_uid": 5040,
        "class_name": "Live Evidence Info",
        "type_uid": 504099,
        "type_name": "Live Evidence Info: Other",
        "severity_id": 1,
        "severity": "Informational",
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": evidence["evidence_id"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "profiles": ["cloud", "security_control"],
        },
        "message": "Discovery-layer technical control evidence generated from inventory artifacts.",
        "unmapped": {
            "cloud_security_technical_evidence": evidence,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic technical-control evidence from discovery artifacts.")
    parser.add_argument("input", nargs="?", help="Path to a discovery artifact JSON file. Reads stdin when omitted.")
    parser.add_argument("--framework", dest="frameworks", action="append", help="Evidence family to emit: pci or soc2. Defaults to both.")
    parser.add_argument(
        "--output-format",
        choices=SUPPORTED_OUTPUT_FORMATS,
        default="native",
        help="Emit native evidence JSON or an OCSF Live Evidence bridge event.",
    )
    parser.add_argument("-o", "--output", help="Write JSON output to this file instead of stdout.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args(argv)

    try:
        document = _load_json(args.input)
        evidence = build_evidence(document, args.frameworks)
        if args.output_format == "ocsf-live-evidence":
            evidence = to_ocsf_live_evidence(evidence)
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"error: {exc}", file=sys.stderr)
        return 1

    payload = json.dumps(evidence, indent=2 if args.pretty else None, sort_keys=args.pretty)
    if args.pretty:
        payload += "\n"

    if args.output:
        Path(args.output).write_text(payload)
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
