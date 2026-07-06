# Roadmap

This roadmap turns `cloud-ai-security-skills` into a measurable, cross-cloud security
skills repo for cloud and AI systems.

The operating model is:

- **OCSF-first** where the schema fits
- **deterministic bridge artifacts** where it does not
- **read-only by default**, with write paths gated by HITL approval and dual audit
- **least privilege**: scoped execution identities, short-lived credentials where the platform supports them, manager-injected secrets only where a vendor path still requires them
- **same skill code across CLI, CI, MCP, and persistent/serverless execution**

## Current focus

The current north star is not "more skills" by itself. It is:

- broader framework coverage
- deeper provider and asset coverage
- stronger test and validation coverage
- cleaner interoperability for agents and security teams

### Current shipped progress snapshot

- **ATT&CK depth:** 48 mapped skills in the coverage registry, with the first
  AWS IAM-user credential-creation slices now shipped via access-key and
  login-profile detection, the first GCP service-account-key slice now shipped,
  the first AWS cloud-discovery burst slice now shipped, the first AWS
  exfiltration-to-cloud-account slice now shipped via cross-account S3 copy
  detection, and the first cross-cloud logging-impairment trio now shipped
  across AWS, GCP, and Azure.
- **CIS and posture depth:** 91 shipped benchmark checks across AWS, GCP,
  Azure, Kubernetes, container, GPU, and model-serving surfaces; AWS also has
  the first guarded `--auto-remediate` slice.
- **MITRE ATLAS depth:** AI inventory and evidence, model-serving and GPU
  posture, MCP prompt injection, explicit system-prompt extraction, explicit
  tool-output policy-bypass, explicit tool-output exfiltration-instruction
  detection, and AWS + GCP model-artifact download detection are all shipped.
- **OWASP LLM / MCP depth:** model-serving controls, MCP prompt injection,
  tool drift, credential leak detection, explicit system-prompt extraction,
  explicit tool-output policy-bypass, explicit tool-output exfiltration-
  instruction detection, and MCP tool quarantine are all shipped. The next
  open work is broader AI-native detection depth and stronger closed loops,
  not first presence.

### AI-native status checkpoint

The repo already ships a meaningful AI baseline:

- MCP ingest + detection: `ingest-mcp-proxy-ocsf`, `detect-mcp-tool-drift`, `detect-prompt-injection-mcp-proxy`
- AI inventory and evidence: `discover-ai-bom`, `discover-control-evidence`, `discover-cloud-control-evidence`
- AI posture: `model-serving-security`, `gpu-cluster-security`, `container-security`
- MCP remediation: `remediate-mcp-tool-quarantine`

The next open work is depth, not first presence:

- more AI-native detections across credential leak, model-weight egress, vector poisoning, indirect prompt injection, and tool-result injection
- stronger closed loops for AI-specific remediation
- deeper AI BOM policy coverage beyond the shipped baseline for version pinning, registry trust, provenance, and license flags
- higher explicit MITRE ATLAS and OWASP LLM / MCP coverage in the registry

## Phase 1 — Measured coverage and auditability

Goal: make framework claims measurable instead of implicit.

- ship and maintain [`docs/framework-coverage.json`](framework-coverage.json)
- validate every shipped skill against the coverage registry
- keep framework and asset scope versioned in docs
- expose gaps clearly in docs and issue planning

Exit criteria:

- every shipped skill is present in the coverage registry
- every framework claim in docs is traceable to a concrete skill
- CI validates the registry on every PR

## Phase 2 — ATT&CK and ATLAS depth

Goal: drive toward full mapped coverage for the declared scope.

Priority areas:

- MITRE ATT&CK across AWS, Azure, GCP, Kubernetes, containers, MCP, and identity flows
- MITRE ATLAS across AI endpoints, model serving, datasets, model registries, GPUs, and AI control evidence
- explicit ATT&CK / ATLAS tables per skill family

Exit criteria:

- ATT&CK and ATLAS mappings are explicit in the registry and docs
- AI-oriented skills consistently declare ATLAS coverage where applicable
- detection and evaluation layers show clear ATT&CK / ATLAS traceability

## Phase 3 — Compliance and control framework depth

Goal: increase real technical coverage for control frameworks.

Priority frameworks:

- CIS Benchmarks
- NIST CSF 2.0
- NIST AI RMF
- PCI DSS 4.0
- SOC 2 TSC
- ISO 27001:2022
- OWASP LLM / GenAI guidance where supported by primary sources

Priority work:

- broaden evidence discovery and evaluation coverage
- make provider and asset-class gaps explicit
- keep "mapped", "implemented", and "tested" separate in the registry

## Phase 4 — Provider and asset expansion

Goal: deepen useful coverage across cloud and AI surfaces.

Priority providers and surfaces:

- AWS: IAM, VPC, EKS, Security Hub, GuardDuty, Bedrock, SageMaker
- GCP: IAM, VPC, GKE, SCC, Vertex AI
- Azure: Entra, NSG, Defender, AKS, Azure ML, AI Foundry
- identity vendors: Okta, Entra ID / Graph, Google Workspace, SCIM-capable SaaS audit sources
- current identity-vendor ingesters: Okta System Log, Entra / Graph directoryAudit, and Google Workspace login audit
- current identity-vendor detections: Okta MFA fatigue, Entra credential addition, Entra role-grant escalation, and Google Workspace suspicious login
- shared asset classes:
  - identities
  - compute
  - storage
  - network
  - logging
  - clusters
  - AI endpoints
  - model registries
  - datasets
  - vector stores
  - GPU fleets
  - evidence and inventory artifacts

## Phase 5 — Operational execution paths

Goal: keep the same skills usable in multiple modes without rewriting them.

Supported modes:

- **CLI / just-in-time**
- **CI**
- **MCP**
- **persistent / serverless**

Guardrails:

- read-only skills never silently write
- remediation stays dry-run first
- destructive actions stay HITL-gated
- persistent runners remain explicit edge components, not hidden behavior in core skills

## Near-term delivery order

1. coverage registry and validator
2. framework gap audit against ATT&CK, ATLAS, CIS, NIST, PCI, SOC 2, ISO
3. targeted issues for the biggest framework/provider/asset gaps
4. continued AI service evaluation and detection depth
5. final CI/workflow polish after the coverage program is stable

## Issue design guidance

Open roadmap issues should be:

- provider-scoped
- framework-scoped
- asset-scoped
- measurable

Good examples:

- `ATT&CK gap: Azure Entra and service principal credential detections`
- `ATT&CK gap: AWS IAM-user temporary-credential identity pivots`
- `ATT&CK gap: GCP service accounts, service-account keys, and workload-identity federation abuse detections`
- `ATLAS gap: AI endpoint and model registry evaluation coverage`
- `PCI and SOC 2 gap: remaining cross-cloud evidence depth beyond provider-native logging, segmentation, encryption, and key-management inventory`
- `NIST AI RMF gap: provider-native AI control evidence expansion`

Avoid vague issues like:

- `add more coverage`
- `support AI security better`

## What success looks like

Security teams and engineers should be able to:

- plug the repo into Claude, Codex, Cursor, Windsurf, or Cortex Code CLI
- know which skills are safe to expose to agents
- know which frameworks and providers are covered today
- run the same skill just-in-time or continuously
- submit issues and PRs against explicit gaps instead of implied ones
