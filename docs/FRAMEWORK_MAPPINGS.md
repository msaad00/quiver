# Framework Mappings

This document shows which frameworks are represented in `cloud-ai-security-skills`, where
they appear today, and where coverage is still partial.

For machine-readable source of truth, see
[`docs/framework-coverage.json`](framework-coverage.json). For the policy behind
that file, see [`docs/COVERAGE_MODEL.md`](COVERAGE_MODEL.md).

The repo uses two mapping styles:

- **Event / finding mappings** inside OCSF output, especially `finding_info.attacks[]`
- **Skill-level control mappings** inside benchmark and evaluation skills

The goal is to make coverage explicit instead of forcing reviewers to infer it
from individual `SKILL.md` files.

## Current posture

| Framework | Status | Where it appears |
|---|---|---|
| **OCSF 1.8** | core wire contract | all ingestion, detection, and view flows |
| **MITRE ATT&CK v14** | strong and broader | 86 mapped skills across cloud, identity, Kubernetes, container, MCP, SaaS, Databricks, and remediation paths. Auto-generated rollup in [`docs/FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md); per-skill mapping in [`docs/framework-coverage.json`](framework-coverage.json) |
| **MITRE ATLAS** | partial but real | AI-oriented evaluation, discovery, MCP prompt-injection plus response-layer override and exfiltration detection, and the first AWS + GCP cloud-native model-artifact collection slices |
| **CIS Benchmarks / Controls** | strong | AWS, GCP, Azure, Kubernetes, container evaluation skills |
| **NIST CSF 2.0** | strong | evaluation and some remediation skills |
| **OWASP LLM Top 10** | partial and growing | model-serving controls plus `detect-prompt-injection-mcp-proxy`, `detect-agent-credential-leak-mcp`, `detect-system-prompt-extraction`, `detect-tool-output-policy-bypass`, `detect-tool-output-exfiltration-instructions`, `detect-aws-model-artifact-download`, and `detect-gcp-model-artifact-download` |
| **OWASP MCP Top 10** | partial and growing | `detect-mcp-tool-drift`, `detect-prompt-injection-mcp-proxy`, `detect-agent-credential-leak-mcp`, `detect-system-prompt-extraction`, `detect-tool-output-policy-bypass`, `detect-tool-output-exfiltration-instructions`, and MCP-related repo controls |
| **SOC 2 TSC** | partial | evaluation and remediation mappings |
| **ISO 27001:2022** | partial | CSPM/evaluation mappings |
| **PCI DSS 4.0** | partial | AWS posture mappings today |
| **NIST AI RMF** | real and growing | model-serving security, cloud control evidence, AI BOM, and roadmap items |

## By layer

| Layer | Main frameworks |
|---|---|
| **ingestion/** | OCSF 1.8, vendor schemas, source-specific event contracts |
| **discovery/** | MITRE ATT&CK, MITRE ATLAS, CycloneDX ML-BOM, NIST AI RMF, PCI / SOC 2 evidence support |
| **detection/** | OCSF 1.8, MITRE ATT&CK, MITRE ATLAS, selective OWASP MCP / LLM mappings |
| **evaluation/** | CIS, NIST CSF, ISO, SOC 2, PCI, MITRE ATLAS, OWASP LLM |
| **view/** | OCSF 1.8, SARIF, Mermaid, MITRE ATT&CK labels |
| **remediation/** | MITRE ATT&CK, NIST CSF, CIS Controls, SOC 2 |

## MITRE ATT&CK

Strongest current ATT&CK coverage:

| Skill | Coverage |
|---|---|
| `detect-lateral-movement` | T1021, T1078.004 across AWS role sessions, GCP service-account pivots anchored in IAM Credentials and key-creation events, Azure Activity role/managed-identity pivots, and Azure Entra / Graph application-service-principal credential pivots; AWS IAM-user temporary-credential pivots plus GCP workload-identity federation abuse remain tracked follow-up gaps |
| `detect-aws-access-key-creation` | T1098.001 for successful AWS IAM `CreateAccessKey` operations that add credential material to an IAM user |
| `detect-aws-login-profile-creation` | T1098.001 for successful AWS IAM `CreateLoginProfile` operations that add console-password credential material to an IAM user |
| `detect-gcp-service-account-key-creation` | T1098.001 for successful GCP IAM `CreateServiceAccountKey` operations that add credential material to a service account |
| `detect-aws-enumeration-burst` | T1526 for short-window bursts of high-signal AWS discovery APIs in CloudTrail across IAM, EC2, S3, KMS, Organizations, EKS, Lambda, and CloudTrail |
| `detect-s3-cross-account-copy` | T1537 for successful AWS S3 `CopyObject` calls where the acting principal account differs from the recipient bucket-owner account |
| `detect-aws-model-artifact-download` | T1530 plus ATLAS AML.T0035 for successful AWS S3 `GetObject` downloads of model-weight and checkpoint artifacts |
| `detect-gcp-model-artifact-download` | T1530 plus ATLAS AML.T0035 for successful GCS `storage.objects.get` downloads of model-weight and checkpoint artifacts |
| `detect-okta-mfa-fatigue` | T1621 for repeated Okta Verify push challenge + deny bursts |
| `detect-entra-credential-addition` | T1098.001 for successful Entra application or service-principal credential additions and federated identity credential creation |
| `detect-entra-role-grant-escalation` | T1098.003 for successful Entra app-role assignments that grant additional application permissions to service principals |
| `detect-google-workspace-suspicious-login` | T1110 and T1078 for provider-marked Google Workspace suspicious logins and repeated failure-then-success bursts |
| `detect-cloudtrail-disabled` | T1562.001 for successful AWS CloudTrail `StopLogging` and `DeleteTrail` operations |
| `detect-gcp-audit-logs-disabled` | T1562.001 for successful GCP Cloud Logging `DeleteSink` and `DeleteLog` operations |
| `detect-azure-activity-logs-disabled` | T1562.001 for successful Azure `Microsoft.Insights/diagnosticSettings/delete` operations |
| `detect-prompt-injection-mcp-proxy` | MITRE ATLAS AML.T0051 for explicit prompt-injection and instruction-smuggling language in MCP tool descriptions |
| `detect-system-prompt-extraction` | MITRE ATLAS AML.T0004 / AML.T0041 for explicit system-prompt and hidden-instruction leakage markers in MCP tool-call responses |
| `detect-tool-output-policy-bypass` | MITRE ATLAS AML.T0051 for explicit policy-bypass, approval-evasion, and user-concealment instructions embedded in MCP tool-call responses |
| `detect-tool-output-exfiltration-instructions` | MITRE ATLAS AML.T0051 for explicit exfiltration instructions embedded in MCP tool-call responses |
| `detect-mcp-tool-drift` | T1195.001 |
| `detect-privilege-escalation-k8s` | T1552.007, T1611, T1098, T1550.001 |
| `detect-sensitive-secret-read-k8s` | T1552, T1552.007 |
| `ingest-guardduty-ocsf` | curated ATT&CK tactic/technique extraction |
| `ingest-security-hub-ocsf` | ATT&CK extraction when upstream findings contain MITRE hints |
| `iam-departures-aws` | ATT&CK-linked remediation context |
| `discover-environment` | ATT&CK graph overlay for cloud resources and relationships |

Notes:
- ATT&CK is pinned in the shared OCSF contract.
- ATT&CK mappings belong inside `finding_info.attacks[]` for OCSF 1.8 outputs, not as loose side metadata.
- Cross-cloud logging impairment is now shipped as narrow, high-confidence
  T1562.001 slices across AWS, GCP, and Azure. Broader sink drift, destination
  weakening, and policy-drift depth remain separate follow-on work.
- Current cross-cloud identity depth is strongest in `detect-lateral-movement`; the Azure slice now distinguishes Azure Activity control-plane pivots from Entra / Graph application-service-principal credential pivots.
- The GCP slice in `detect-lateral-movement` is currently pinned to service-account and IAM Credentials anchors; workload-identity federation abuse is tracked separately so the docs do not overstate provider depth.
- `detect-gcp-service-account-key-creation` now ships the first narrow GCP
  service-account credential-creation slice, but workload-identity federation
  abuse and broader token-minting depth remain separate follow-on work.
- The AWS role-session slice stays in `detect-lateral-movement`, while
  `detect-aws-access-key-creation` and
  `detect-aws-login-profile-creation` now cover the first IAM-user
  credential-creation paths. Temporary-credential pivots remain tracked
  separately so the docs do not overstate provider depth.
- The first AWS cloud-discovery slice now ships as
  `detect-aws-enumeration-burst`, but it is intentionally a curated API
  burst detector, not a claim that all AWS discovery behavior is covered.
- The first AWS exfiltration-to-cloud-account slice now ships as
  `detect-s3-cross-account-copy`, but it is intentionally limited to
  successful cross-account `CopyObject` events, not all storage egress.

## OCSF identity normalization

Identity ingestion is broader than cloud control planes now.

| Skill | OCSF scope |
|---|---|
| `ingest-entra-directory-audit-ocsf` | API Activity (6003) for verified Microsoft Entra / Graph `directoryAudit` identity-management events |
| `ingest-google-workspace-login-ocsf` | Authentication (3002) and Account Change (3001) for verified Google Workspace Admin SDK Reports login-audit events |
| `ingest-okta-system-log-ocsf` | Authentication (3002), Account Change (3001), User Access Management (3005) from verified Okta System Log fields, including Okta Verify push and deny event families |
| `ingest-cloudtrail-ocsf` | API Activity (6003) for AWS IAM and control-plane events |
| `ingest-gcp-audit-ocsf` | API Activity (6003) for GCP audit events |
| `ingest-azure-activity-ocsf` | API Activity (6003) for Azure Activity events |

The rule stays the same across vendors:
- verify the real source payload and natural IDs first
- normalize to the narrowest OCSF class that fits cleanly
- keep provider-specific context under `unmapped` instead of losing it
- keep source-specific event families separate instead of pretending Okta, Entra, and Workspace login telemetry are interchangeable

Current identity-vendor detections on top of those streams:
- `detect-okta-mfa-fatigue`
- `detect-entra-credential-addition`
- `detect-entra-role-grant-escalation`
- `detect-google-workspace-suspicious-login`

## MITRE ATLAS

ATLAS is present today, but coverage is narrower than ATT&CK.

| Skill | Coverage |
|---|---|
| `discover-environment` | graph overlay for AI/ML resources and adversarial ML techniques |
| `model-serving-security` | explicit ATLAS coverage plus machine-readable NIST AI RMF section scope in the benchmark metadata |
| `detect-prompt-injection-mcp-proxy` | AI-agent / MCP prompt-injection detection for malicious tool descriptions in `tools/list` responses |
| `detect-system-prompt-extraction` | explicit system-prompt and hidden-instruction leakage detection in MCP `tools/call` responses |
| `detect-tool-output-policy-bypass` | response-layer prompt-injection detection for explicit policy-bypass and approval-evasion instructions in MCP `tools/call` responses |
| `detect-tool-output-exfiltration-instructions` | response-layer prompt-injection detection for explicit data-exfiltration instructions in MCP `tools/call` responses |
| `detect-aws-model-artifact-download` | cloud-native AI artifact collection detection for successful S3 downloads of model weights and checkpoints |
| `detect-gcp-model-artifact-download` | cloud-native AI artifact collection detection for successful GCS downloads of model weights and checkpoints |
| `discover-ai-bom` | inventory artifact plus optional AI BOM policy findings for ATLAS / AI RMF evidence and CI joins |
| `discover-control-evidence` | evidence package that preserves ATLAS / AI RMF context from discovery artifacts |
| `discover-cloud-control-evidence` | cross-cloud evidence package with explicit NIST AI RMF evidence mode, ATT&CK / ATLAS / AI RMF inventory context, and per-provider logging / segmentation / encryption / key-management depth |

Current provider depth in discovery:
- AWS Bedrock / SageMaker
- Google Vertex AI
- Azure ML / Azure AI Foundry

Recommended expansion:
- add a shared table of ATLAS techniques used by AI-oriented skills
- deepen provider-shaped GPU and accelerator evidence beyond the current benchmark input model

## Kubernetes and containers

Kubernetes and container security are currently covered through both benchmark
and threat-model mappings.

| Domain | Frameworks | Current skills |
|---|---|---|
| **Kubernetes detection** | MITRE ATT&CK | `detect-privilege-escalation-k8s`, `detect-sensitive-secret-read-k8s` |
| **Kubernetes posture** | CIS Kubernetes, NIST CSF | `k8s-security-benchmark` |
| **Container posture** | CIS Docker, NIST CSF | `container-security` |
| **Container / workload findings** | MITRE ATT&CK where applicable | detection skills and upstream ingestors |

## GPU and AI infrastructure

AI and GPU security are already in scope, but their framework coverage is less
uniform than classic cloud posture.

| Skill | Frameworks called out today |
|---|---|
| `discover-ai-bom` | CycloneDX ML-BOM, NIST AI RMF, MITRE ATLAS, PCI, SOC 2, optional OCSF 2003 policy findings |
| `discover-control-evidence` | PCI DSS 4.0, SOC 2 TSC, CycloneDX ML-BOM, MITRE ATLAS |
| `discover-cloud-control-evidence` | PCI DSS 4.0, SOC 2 TSC, NIST AI RMF, MITRE ATT&CK, MITRE ATLAS, with provider-scoped logging / segmentation / encryption evidence depth |
| `model-serving-security` | MITRE ATLAS, NIST CSF, NIST AI RMF, OWASP LLM Top 10, SOC 2, provider-specific AI endpoint controls |
| `gpu-cluster-security` | MITRE ATT&CK, MITRE ATLAS, NIST CSF, NIST AI RMF, CIS Controls, CIS Kubernetes |
| `discover-environment` | MITRE ATT&CK, MITRE ATLAS, NIST CSF |

Recommended next step:
- make ATLAS coverage first-class for GPU and model-serving paths
- connect AI BOM and discovery outputs more directly to ATLAS and AI RMF evidence views

## Compliance and control frameworks

| Framework | Skills with explicit mappings today |
|---|---|
| **CIS AWS Foundations** | `cspm-aws-cis-benchmark` |
| **CIS GCP Foundations** | `cspm-gcp-cis-benchmark` |
| **CIS Azure Foundations** | `cspm-azure-cis-benchmark` |
| **CIS Kubernetes** | `k8s-security-benchmark`, `gpu-cluster-security` |
| **CIS Docker** | `container-security` |
| **NIST CSF 2.0** | CSPM skills, K8s/container evaluation, AI-oriented evaluation, remediation |
| **SOC 2 TSC** | AWS evaluation, model-serving, IAM departures remediation |
| **ISO 27001:2022** | AWS/GCP/Azure evaluation |
| **PCI DSS 4.0** | AWS evaluation |
| **NIST AI RMF** | model-serving docs and roadmap expansion |

For procurement-focused mappings to SOC 2 common criteria and ISO/IEC
27001:2022 Annex A, see [COMPLIANCE_MAPPINGS.md](COMPLIANCE_MAPPINGS.md).

## AI BOM

AI BOM is **not** the identity of the repo, but it is now a shipped discovery capability.

Current fit:
- **collection / inventory input** in `discovery/`
- **normalization** into a deterministic CycloneDX-aligned AI BOM artifact
- **technical evidence output** via discovery-layer evidence packaging for PCI and SOC 2 reviews
- **future evaluation joins** against ATLAS, NIST AI RMF, OWASP LLM Top 10, PCI, and SOC 2 evidence pipelines

That keeps AI BOM as one important capability inside a broader cloud + AI security skills repo.

## How to extend mappings safely

When adding or changing framework mappings:

1. update the skill’s `SKILL.md`
2. update `REFERENCES.md` with only official framework or vendor sources
3. add or update tests when mapping logic affects output
4. update this document when the change is material
5. keep ATT&CK / ATLAS / OCSF version pinning consistent with the shared contract
