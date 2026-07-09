# Reference Terraform skeleton for `remediate-k8s-rbac-revoke`.
# Wire variables to the handler env contract in ../src/handler.py.

terraform {
  required_version = ">= 1.5"
}

variable "worker_name" {
  description = "Deployed worker name for remediate-k8s-rbac-revoke"
  type        = string
  default     = "remediate-k8s-rbac-revoke"
}

variable "audit_lookup_table" {
  description = "Fast audit lookup store"
  type        = string
  default     = "k8s-rbac-revoke-audit"
}

variable "audit_evidence_bucket" {
  description = "KMS-encrypted evidence bucket"
  type        = string
  default     = "k8s-rbac-revoke-evidence"
}

# Operators: add provider blocks (aws/azurerm/google) and a function/Lambda/Job
# resource that packages ../src/handler.py. Keep dry_run the default invocation
# path; route --apply only through approved SOAR playbooks.
