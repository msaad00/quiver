# Hardened reference Dockerfile for the MCP SSE / streamable-HTTP runner.
#
# Slice 2 of issue #415 — packages the listener that ships in
# `mcp-server/src/transports/sse.py` (slice 1) for cloud-runner deploys.
#
# Trust posture (matches the webhook-receiver runner):
#
#   * non-root UID 65532   (no privilege escalation)
#   * read-only rootfs friendly (writes only to /tmp + the configurable
#     audit-log mount)
#   * `--cap-drop=ALL`         no Linux capabilities
#   * `--security-opt=no-new-privileges`
#   * default seccomp profile  (Docker / Kubernetes default is fine for
#                                the Starlette + sse-starlette + uvicorn
#                                stack)
#
# Build context is the repo root so the runtime stage can COPY the
# wrapper sources + skill registry. Run from the top of the checkout:
#
#   docker build -t cloud-security-mcp-sse -f runners/mcp-sse/Dockerfile .
#
# Build-deps only (used by CI for the lint-and-deps-resolve smoke):
#
#   docker build --target build-deps -t cloud-security-mcp-sse:build-deps \
#     -f runners/mcp-sse/Dockerfile .
#
# Run (production-shape):
#   docker run --rm -p 8765:8765 \
#     --read-only \
#     --tmpfs /tmp \
#     --cap-drop=ALL \
#     --security-opt=no-new-privileges \
#     --user 65532:65532 \
#     --memory=512m --cpus=1.0 --pids-limit=128 \
#     -e MCP_SSE_BIND=0.0.0.0 \
#     -e MCP_SSE_PORT=8765 \
#     -e MCP_SSE_ALLOW_PUBLIC_BIND=1 \
#     -e MCP_SSE_BEARER_KEYS_FILE=/etc/cloud-security/sse-bearer-keys.json \
#     -e CLOUD_SECURITY_MCP_AUDIT_LOG=/var/log/cloud-security/audit.jsonl \
#     -e CLOUD_SECURITY_AUDIT_HMAC_KEY=$(cat /run/secrets/audit-hmac) \
#     -v $PWD/keys:/etc/cloud-security:ro \
#     -v $PWD/audit:/var/log/cloud-security:rw \
#     cloud-security-mcp-sse
#
# Helm operators: the same flags are encoded under the chart's
# securityContext / resources / volumes. See `templates/helm/`.

# ── Build stage — pip install into an isolated prefix ────────────────
FROM python:3.11-slim AS build-deps

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Pin only the extras the SSE transport actually loads. The wrapper
# itself imports lazily, so cloud-SDK packages are intentionally NOT
# pulled into this image — the SSE runner is the request boundary, not
# a skill executor (skills run as subprocess calls when wired in by the
# operator).
RUN pip install --upgrade pip && pip install --prefix=/install \
        "sse-starlette>=2,<4" \
        "starlette>=1.3.1,<2" \
        "uvicorn[standard]>=0.30,<1" \
        "pyyaml>=6,<7" \
        "httpx>=0.27,<1" \
        "defusedxml>=0.7"


# ── Runtime stage — distroless-friendly, non-root by default ─────────
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/usr/local/lib/python3.11/site-packages

# Create the non-root UID we run as. 65532 matches Google distroless'
# `nonroot` so Helm RunAsUser bindings line up.
RUN groupadd --system --gid 65532 nonroot \
 && useradd --system --uid 65532 --gid 65532 --no-create-home --shell /sbin/nologin nonroot

# Bring deps in from the build stage.
COPY --from=build-deps /install /usr/local

# Copy only what the SSE listener needs at runtime: the wrapper sources
# (server.py, dispatch.py, transports/) and the skill registry. No
# tests, no infra, no docs, no fixtures.
COPY --chown=65532:65532 mcp-server/src                /app/mcp-server/src
COPY --chown=65532:65532 skills                        /app/skills

WORKDIR /app
USER 65532:65532

# Default port for the SSE transport. Override with MCP_SSE_PORT.
EXPOSE 8765

# Healthcheck mirrors the listener's /healthz route. Read-only-rootfs
# operators can still run it because it does not write to disk.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=2).status == 200 else 1)" || exit 1

# Entrypoint runs the SSE listener directly. The transport calls
# `uvicorn.run` internally so we don't need a separate uvicorn CLI line.
CMD ["python", "/app/mcp-server/src/transports/sse.py"]
