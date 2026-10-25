# ==============================================================================
# LinuxOps Production Container Image
# Multi-stage hardened non-root container for Fly.io, AWS ECS, GCP Cloud Run, or VPS.
# ==============================================================================

# --- Stage 1: Build & Dependencies ---
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install -r requirements.txt


# --- Stage 2: Runtime Image ---
FROM python:3.11-slim-bookworm AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8501 \
    BIND_ADDRESS=0.0.0.0 \
    LINUXOPS_AUTH_MODE=production \
    LINUXOPS_RECOVERY_DISABLED=1

# Install runtime utilities (curl for health check)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root dedicated service user
RUN groupadd -g 10001 linuxops && \
    useradd -u 10001 -g linuxops -m -s /bin/bash linuxops

WORKDIR /home/linuxops/app

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application files
COPY --chown=linuxops:linuxops app/ app/
COPY --chown=linuxops:linuxops scripts/ scripts/
COPY --chown=linuxops:linuxops .streamlit/ .streamlit/
COPY --chown=linuxops:linuxops requirements.txt .

# Ensure scripts are executable and logs directory exists
RUN chmod +x scripts/*.sh && \
    mkdir -p logs && chown -R linuxops:linuxops logs /home/linuxops/app

USER linuxops

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT}/_stcore/health || exit 1

ENTRYPOINT ["./scripts/run_production.sh"]
