"""Detect Kubernetes privilege escalation patterns in OCSF or native API Activity.

Reads OCSF 1.8 API Activity (class 6003) events or the native enriched
Kubernetes activity shape produced by ingest-k8s-audit-ocsf and emits OCSF 1.8
Detection Findings (class 2004) by default for four K8s privilege-escalation
patterns.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-privilege-escalation-k8s"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
OUTPUT_FORMATS = ("ocsf", "native")

# Detection Finding (2004)
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

# Severity
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5

# MITRE ATT&CK v14
MITRE_VERSION = "v14"

# Rule 1: T1552.007
R1_TACTIC_UID = "TA0006"
R1_TACTIC_NAME = "Credential Access"
R1_TECH_UID = "T1552"
R1_TECH_NAME = "Unsecured Credentials"
R1_SUB_UID = "T1552.007"
R1_SUB_NAME = "Container API"

# Rule 2: T1611
R2_TACTIC_UID = "TA0004"
R2_TACTIC_NAME = "Privilege Escalation"
R2_TECH_UID = "T1611"
R2_TECH_NAME = "Escape to Host"

# Rule 3: T1098
R3_TACTIC_UID = "TA0003"
R3_TACTIC_NAME = "Persistence"
R3_TECH_UID = "T1098"
R3_TECH_NAME = "Account Manipulation"

# Rule 4: T1550.001
R4_TACTIC_UID = "TA0008"
R4_TACTIC_NAME = "Lateral Movement"
R4_TECH_UID = "T1550"
R4_TECH_NAME = "Use Alternate Authentication Material"
R4_SUB_UID = "T1550.001"
R4_SUB_NAME = "Application Access Tokens"

# Rule 1 correlation window (milliseconds)
RULE1_WINDOW_MS = 5 * 60 * 1000

# Admin-like principals that should NOT trigger Rule 3
ADMIN_GROUPS = {"system:masters"}
ADMIN_USERS = {"kubernetes-admin", "kube-admin"}


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _short(s: str) -> str:
    return hashlib.sha256((s or "").encode()).hexdigest()[:8]


def _severity_name(severity_id: int) -> str:
    if severity_id >= SEVERITY_CRITICAL:
        return "critical"
    if severity_id >= SEVERITY_HIGH:
        return "high"
    return "unknown"


def _resource(resources: Any) -> dict[str, Any]:
    values = resources or []
    return values[0] if values else {}


def _group_names(groups: Any) -> tuple[str, ...]:
    names: list[str] = []
    for group in groups or []:
        if isinstance(group, dict):
            name = group.get("name")
        else:
            name = group
        if name:
            names.append(str(name))
    return tuple(names)


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != 6003:
            return None
        actor_user = ((event.get("actor") or {}).get("user")) or {}
        resource = _resource(event.get("resources"))
        return {
            "source_format": "ocsf",
            "provider": str(((event.get("cloud") or {}).get("provider")) or "Kubernetes"),
            "time_ms": _safe_int(event.get("time")),
            "actor_name": str(actor_user.get("name") or ""),
            "actor_type": str(actor_user.get("type") or ""),
            "actor_groups": _group_names(actor_user.get("groups")),
            "operation": str(((event.get("api") or {}).get("operation")) or ""),
            "resource_type": str(resource.get("type") or ""),
            "resource_name": str(resource.get("name") or ""),
            "namespace": str(resource.get("namespace") or ""),
            "subresource": str(resource.get("subresource") or ""),
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"native", "canonical"}:
        return None

    record_type = str(event.get("record_type") or "").strip().lower()
    if record_type and record_type != "api_activity":
        return None

    actor_user = ((event.get("actor") or {}).get("user")) or {}
    resource = _resource(event.get("resources"))
    return {
        "source_format": schema_mode or "native",
        "provider": str(event.get("provider") or event.get("cloud_provider") or "Kubernetes"),
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "actor_name": str(event.get("actor_name") or actor_user.get("name") or ""),
        "actor_type": str(event.get("actor_type") or actor_user.get("type") or ""),
        "actor_groups": _group_names(event.get("actor_groups") or actor_user.get("groups")),
        "operation": str(event.get("operation") or event.get("api_operation") or ""),
        "resource_type": str(event.get("resource_type") or resource.get("type") or ""),
        "resource_name": str(event.get("resource_name") or resource.get("name") or ""),
        "namespace": str(event.get("namespace") or resource.get("namespace") or ""),
        "subresource": str(event.get("subresource") or resource.get("subresource") or ""),
    }


def _normalized_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for event in events:
        item = _normalize_event(event)
        if item is not None:
            normalized.append(item)
    normalized.sort(key=lambda item: item["time_ms"])
    return normalized


def _actor_is_service_account(event: dict[str, Any]) -> bool:
    return event["actor_type"] == "ServiceAccount"


def _build_native_finding(
    *,
    rule_id: str,
    title: str,
    desc: str,
    severity_id: int,
    tactic_uid: str,
    tactic_name: str,
    technique_uid: str,
    technique_name: str,
    sub_technique_uid: str | None,
    sub_technique_name: str | None,
    actor: str,
    target: str,
    first_seen_time: int,
    last_seen_time: int,
    observables: list[dict[str, Any]],
    evidence_count: int,
) -> dict[str, Any]:
    uid = f"det-k8s-{rule_id}-{_short(actor)}-{_short(target)}"
    attack: dict[str, Any] = {
        "version": MITRE_VERSION,
        "tactic_uid": tactic_uid,
        "tactic_name": tactic_name,
        "technique_uid": technique_uid,
        "technique_name": technique_name,
    }
    if sub_technique_uid and sub_technique_name:
        attack["sub_technique_uid"] = sub_technique_uid
        attack["sub_technique_name"] = sub_technique_name

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": uid,
        "event_uid": uid,
        "provider": "Kubernetes",
        "time_ms": last_seen_time or _now_ms(),
        "severity": _severity_name(severity_id),
        "severity_id": severity_id,
        "status": "success",
        "status_id": 1,
        "title": title,
        "description": desc,
        "finding_types": [f"k8s-{rule_id}"],
        "first_seen_time_ms": first_seen_time,
        "last_seen_time_ms": last_seen_time,
        "mitre_attacks": [attack],
        "actor_name": actor,
        "target": target,
        "rule_name": rule_id,
        "observables": observables,
        "evidence_count": evidence_count,
    }


def _render_ocsf_finding(native_finding: dict[str, Any]) -> dict[str, Any]:
    attack = native_finding["mitre_attacks"][0]
    rendered_attack: dict[str, Any] = {
        "version": attack["version"],
        "tactic": {"name": attack["tactic_name"], "uid": attack["tactic_uid"]},
        "technique": {"name": attack["technique_name"], "uid": attack["technique_uid"]},
    }
    if attack.get("sub_technique_uid") and attack.get("sub_technique_name"):
        rendered_attack["sub_technique"] = {
            "name": attack["sub_technique_name"],
            "uid": attack["sub_technique_uid"],
        }

    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": native_finding["severity_id"],
        "status_id": native_finding["status_id"],
        "time": native_finding["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native_finding["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "kubernetes", "privilege-escalation", native_finding["rule_name"]],
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "first_seen_time": native_finding["first_seen_time_ms"],
            "last_seen_time": native_finding["last_seen_time_ms"],
            "attacks": [rendered_attack],
        },
        "observables": native_finding["observables"],
        "evidence": {
            "events_observed": native_finding["evidence_count"],
            "first_seen_time": native_finding["first_seen_time_ms"],
            "last_seen_time": native_finding["last_seen_time_ms"],
            "raw_events": [],
        },
    }


def rule1_secret_enumeration(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """list(secrets) → get(secrets) in the same namespace, same SA, within window."""
    normalized = _normalized_events(events)
    list_events: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = {}

    for event in normalized:
        if not _actor_is_service_account(event):
            continue
        if event["operation"] != "list":
            continue
        if event["resource_type"] != "secrets":
            continue
        list_key = (event["actor_name"], event["namespace"])
        list_events.setdefault(list_key, []).append((event["time_ms"], event))

    seen_findings: set[str] = set()
    for event in normalized:
        if not _actor_is_service_account(event):
            continue
        if event["operation"] != "get":
            continue
        if event["resource_type"] != "secrets":
            continue

        actor = event["actor_name"]
        namespace = event["namespace"]
        get_time = event["time_ms"]
        secret_name = event["resource_name"]

        candidates = list_events.get((actor, namespace), [])
        matching = [(time_ms, item) for time_ms, item in candidates if 0 < get_time - time_ms <= RULE1_WINDOW_MS]
        if not matching:
            continue

        first_list_time = min(time_ms for time_ms, _ in matching)
        key = f"r1|{actor}|{namespace}|{secret_name}"
        if key in seen_findings:
            continue
        seen_findings.add(key)

        target = f"{namespace}/{secret_name}"
        yield _build_native_finding(
            rule_id="r1-secret-enum",
            title="Service account enumerated and read a Kubernetes secret",
            desc=(
                f"Service account '{actor}' performed `list` on secrets in namespace "
                f"'{namespace}' and then `get` on secret '{secret_name}' within the "
                f"{RULE1_WINDOW_MS // 1000}-second correlation window. Workloads that "
                f"need secret data should mount secrets as files, not call the K8s "
                f"API for them — this pattern is a strong signal of a compromised "
                f"pod searching for credentials. (MITRE T1552.007)"
            ),
            severity_id=SEVERITY_HIGH,
            tactic_uid=R1_TACTIC_UID,
            tactic_name=R1_TACTIC_NAME,
            technique_uid=R1_TECH_UID,
            technique_name=R1_TECH_NAME,
            sub_technique_uid=R1_SUB_UID,
            sub_technique_name=R1_SUB_NAME,
            actor=actor,
            target=target,
            first_seen_time=first_list_time,
            last_seen_time=get_time,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "namespace", "type": "Other", "value": namespace},
                {"name": "secret.name", "type": "Other", "value": secret_name},
                {"name": "rule", "type": "Other", "value": "r1-secret-enum"},
            ],
            evidence_count=len(matching) + 1,
        )


def rule2_pod_exec(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """create on pods/exec by a service account."""
    normalized = _normalized_events(events)
    seen: set[str] = set()
    for event in normalized:
        if not _actor_is_service_account(event):
            continue
        if event["operation"] != "create":
            continue
        if event["resource_type"] != "pods" or event["subresource"] != "exec":
            continue

        actor = event["actor_name"]
        pod = event["resource_name"]
        namespace = event["namespace"]
        target = f"{namespace}/{pod}"
        key = f"r2|{actor}|{target}"
        if key in seen:
            continue
        seen.add(key)

        time_ms = event["time_ms"]
        yield _build_native_finding(
            rule_id="r2-pod-exec",
            title="Service account executed a shell inside a pod",
            desc=(
                f"Service account '{actor}' called `create` on pods/exec for pod "
                f"'{pod}' in namespace '{namespace}'. Workloads (as opposed to human "
                f"operators) should never exec into other pods — this is the "
                f"precursor to container escape. (MITRE T1611)"
            ),
            severity_id=SEVERITY_CRITICAL,
            tactic_uid=R2_TACTIC_UID,
            tactic_name=R2_TACTIC_NAME,
            technique_uid=R2_TECH_UID,
            technique_name=R2_TECH_NAME,
            sub_technique_uid=None,
            sub_technique_name=None,
            actor=actor,
            target=target,
            first_seen_time=time_ms,
            last_seen_time=time_ms,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "pod.name", "type": "Other", "value": pod},
                {"name": "namespace", "type": "Other", "value": namespace},
                {"name": "rule", "type": "Other", "value": "r2-pod-exec"},
            ],
            evidence_count=1,
        )


def _is_admin(event: dict[str, Any]) -> bool:
    normalized = _normalize_event(event) or event
    actor = str(normalized.get("actor_name") or "")
    if actor in ADMIN_USERS:
        return True
    groups = normalized.get("actor_groups") or ()
    return bool(set(groups) & ADMIN_GROUPS)


def rule3_rbac_self_grant(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """create on rolebindings or clusterrolebindings by a non-admin."""
    normalized = _normalized_events(events)
    seen: set[str] = set()
    for event in normalized:
        if event["operation"] != "create":
            continue
        resource_type = event["resource_type"]
        if resource_type not in ("rolebindings", "clusterrolebindings"):
            continue
        if _is_admin(event):
            continue

        actor = event["actor_name"]
        binding_name = event["resource_name"]
        namespace = event["namespace"]
        target = f"{resource_type}/{namespace}/{binding_name}"
        key = f"r3|{actor}|{target}"
        if key in seen:
            continue
        seen.add(key)

        time_ms = event["time_ms"]
        yield _build_native_finding(
            rule_id="r3-rbac-self-grant",
            title=f"Non-admin principal created a {resource_type[:-1]}",
            desc=(
                f"Principal '{actor}' created {resource_type[:-1]} '{binding_name}'"
                f"{f' in namespace {namespace}' if namespace else ''}. This principal is not "
                f"in system:masters and is not a recognised admin user — creating "
                f"a binding is the canonical K8s privilege-escalation move after "
                f"initial compromise. (MITRE T1098)"
            ),
            severity_id=SEVERITY_CRITICAL,
            tactic_uid=R3_TACTIC_UID,
            tactic_name=R3_TACTIC_NAME,
            technique_uid=R3_TECH_UID,
            technique_name=R3_TECH_NAME,
            sub_technique_uid=None,
            sub_technique_name=None,
            actor=actor,
            target=target,
            first_seen_time=time_ms,
            last_seen_time=time_ms,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "binding.type", "type": "Other", "value": resource_type},
                {"name": "binding.name", "type": "Other", "value": binding_name},
                {"name": "namespace", "type": "Other", "value": namespace},
                {"name": "rule", "type": "Other", "value": "r3-rbac-self-grant"},
            ],
            evidence_count=1,
        )


def rule4_token_self_grant(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """create on serviceaccounts/token(request) or tokenreviews by a service account."""
    normalized = _normalized_events(events)
    seen: set[str] = set()
    for event in normalized:
        if not _actor_is_service_account(event):
            continue
        if event["operation"] != "create":
            continue
        resource_type = event["resource_type"]
        subresource = event["subresource"]
        hit = (resource_type == "serviceaccounts" and subresource in ("token", "tokenrequest")) or resource_type == "tokenreviews"
        if not hit:
            continue

        actor = event["actor_name"]
        target_sa = event["resource_name"]
        namespace = event["namespace"]
        target = f"{namespace}/{target_sa}"
        key = f"r4|{actor}|{target}"
        if key in seen:
            continue
        seen.add(key)

        time_ms = event["time_ms"]
        yield _build_native_finding(
            rule_id="r4-token-self-grant",
            title="Service account issued itself (or another SA) an API token",
            desc=(
                f"Service account '{actor}' created a token for '{target_sa or 'tokenreview'}' "
                f"in namespace '{namespace}'. Combined with secret access or RBAC "
                f"manipulation this is token-theft in progress. (MITRE T1550.001)"
            ),
            severity_id=SEVERITY_HIGH,
            tactic_uid=R4_TACTIC_UID,
            tactic_name=R4_TACTIC_NAME,
            technique_uid=R4_TECH_UID,
            technique_name=R4_TECH_NAME,
            sub_technique_uid=R4_SUB_UID,
            sub_technique_name=R4_SUB_NAME,
            actor=actor,
            target=target,
            first_seen_time=time_ms,
            last_seen_time=time_ms,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "target.serviceaccount", "type": "Other", "value": target_sa},
                {"name": "namespace", "type": "Other", "value": namespace},
                {"name": "rule", "type": "Other", "value": "r4-token-self-grant"},
            ],
            evidence_count=1,
        )


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    """Run all four rules over an event stream and yield all findings."""
    events_list = list(events)
    native_findings: list[dict[str, Any]] = []
    native_findings.extend(rule1_secret_enumeration(events_list))
    native_findings.extend(rule2_pod_exec(events_list))
    native_findings.extend(rule3_rbac_self_grant(events_list))
    native_findings.extend(rule4_token_self_grant(events_list))

    native_findings.sort(key=lambda finding: finding["time_ms"])
    for native_finding in native_findings:
        if output_format == "native":
            yield native_finding
        else:
            yield _render_ocsf_finding(native_finding)


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=f"skipping line {lineno}: json parse failed: {exc}",
                line=lineno,
            )
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_json_shape",
                message=f"skipping line {lineno}: not a JSON object",
                line=lineno,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect K8s privilege escalation from OCSF or native API Activity events."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF findings or the native enriched finding shape.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        events = list(load_jsonl(in_stream))
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
