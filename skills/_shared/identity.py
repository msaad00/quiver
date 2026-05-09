"""Single source of truth for vendor / product identity strings.

Skills emit `metadata.product.vendor_name` and `metadata.product.name` on every
OCSF Detection Finding. Hardcoding the strings in each skill's `detect.py` /
`ingest.py` means a fork or org rename has to patch every entrypoint, and
operator deployments inherit upstream identifiers they can't override.

Importing `VENDOR_NAME` and `PRODUCT_NAME` from here keeps both rewriteable in
one place; setting `CLOUD_SECURITY_VENDOR_NAME` or `CLOUD_SECURITY_PRODUCT_NAME`
in the deployment env overrides the defaults at runtime without code changes.
"""

from __future__ import annotations

import os

DEFAULT_VENDOR_NAME = "msaad00/cloud-ai-security-skills"
DEFAULT_PRODUCT_NAME = "cloud-ai-security-skills"
DEFAULT_INFORMATION_URI = "https://github.com/msaad00/cloud-ai-security-skills"


def vendor_name() -> str:
    """Resolve the vendor identifier for emitted findings."""
    override = os.environ.get("CLOUD_SECURITY_VENDOR_NAME", "").strip()
    return override or DEFAULT_VENDOR_NAME


def product_name() -> str:
    """Resolve the product identifier for emitted findings."""
    override = os.environ.get("CLOUD_SECURITY_PRODUCT_NAME", "").strip()
    return override or DEFAULT_PRODUCT_NAME


def information_uri() -> str:
    """Resolve the project URL embedded in SARIF / external metadata."""
    override = os.environ.get("CLOUD_SECURITY_INFORMATION_URI", "").strip()
    return override or DEFAULT_INFORMATION_URI


# Module-level constants resolved once at import. Keep these for skills that
# treat the identifier as a static value; use `vendor_name()` / `product_name()`
# directly when the env override should win even after the skill module is
# already imported (e.g. long-lived MCP processes).
VENDOR_NAME = vendor_name()
PRODUCT_NAME = product_name()
INFORMATION_URI = information_uri()
