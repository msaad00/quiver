# Reference Dockerfile for the webhook-receiver runner.
#
# Build: docker build -t cloud-security-webhook-receiver .
# Run:   docker run -p 8080:8080 \
#          -e WEBHOOK_ALLOWED_SKILLS=ingest-cloudtrail-ocsf \
#          -e WEBHOOK_HMAC_SECRETS='{"ingest-cloudtrail-ocsf":"secret"}' \
#          -e WEBHOOK_SINK_TARGETS=s3,clickhouse \
#          -e CLOUD_SECURITY_MCP_AUDIT_LOG=/var/log/cloud-security/audit.jsonl \
#          cloud-security-webhook-receiver

FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Minimal Python deps. Sink and ingest skills are imported from the
# repo bundle copied below. Adjust this to match the sinks the operator
# actually fans out to.
RUN pip install --upgrade pip && pip install \
        "fastapi>=0.115" \
        "uvicorn[standard]>=0.30" \
        "pyyaml>=6.0" \
        "boto3>=1.34" \
        "snowflake-connector-python>=3.7" \
        "clickhouse-connect>=0.7" \
        "defusedxml>=0.7"

# Copy the repo bundle (skills + mcp-server registry + this runner).
# The receiver resolves the tool registry from this path at runtime.
COPY mcp-server /app/mcp-server
COPY skills /app/skills
COPY runners/webhook-receiver /app/runners/webhook-receiver

EXPOSE 8080

# uvicorn reads the FastAPI app from runners/webhook-receiver/src/server.py
CMD ["uvicorn", "runners.webhook-receiver.src.server:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "2"]
