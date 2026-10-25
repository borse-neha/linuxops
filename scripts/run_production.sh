#!/usr/bin/env bash
# ==============================================================================
# LinuxOps Production Service Launcher
# Designed for isolated production environments (Render, Cloud VPS, Docker, K8s).
#
# Production Security Invariants:
# 1. Enforces LINUXOPS_AUTH_MODE=production (fails closed without verified OIDC).
# 2. Enforces LINUXOPS_RECOVERY_DISABLED=1 (real-host recovery disabled).
# 3. Reads platform-assigned $PORT and binds to $BIND_ADDRESS (default 0.0.0.0).
# 4. Streamlit headless mode enabled; usage analytics disabled.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

echo "================================================================================"
echo "STARTING LINUXOPS PRODUCTION SERVICE"
echo "================================================================================"

# 1. Determine Port & Network Binding
PORT="${PORT:-8501}"
BIND_ADDRESS="${BIND_ADDRESS:-0.0.0.0}"

# 2. Security Defaults Enforcement
export LINUXOPS_AUTH_MODE="${LINUXOPS_AUTH_MODE:-production}"
export LINUXOPS_RECOVERY_DISABLED="${LINUXOPS_RECOVERY_DISABLED:-1}"

echo "Operational Mode     : PRODUCTION"
echo "Binding Address      : ${BIND_ADDRESS}:${PORT}"
echo "Authentication Mode  : ${LINUXOPS_AUTH_MODE}"
echo "Recovery Kill-Switch : ${LINUXOPS_RECOVERY_DISABLED} (1 = Real recovery disabled)"

# 3. Locate Streamlit Executable
if [ -f "${PROJECT_ROOT}/.venv/bin/streamlit" ]; then
    STREAMLIT_BIN="${PROJECT_ROOT}/.venv/bin/streamlit"
    echo "Python Environment   : Virtualenv (${PROJECT_ROOT}/.venv)"
elif command -v streamlit >/dev/null 2>&1; then
    STREAMLIT_BIN="$(command -v streamlit)"
    echo "Python Environment   : System PATH (${STREAMLIT_BIN})"
else
    echo "❌ FATAL: Streamlit executable not found. Ensure dependencies are installed."
    exit 1
fi

# 4. Security Sanity Checks
if [ "${LINUXOPS_AUTH_MODE}" != "production" ]; then
    echo "⚠️ WARNING: LINUXOPS_AUTH_MODE is set to '${LINUXOPS_AUTH_MODE}'. In public environments, 'production' is required."
fi

if [ "${LINUXOPS_RECOVERY_DISABLED}" != "1" ]; then
    echo "⚠️ NOTICE: LINUXOPS_RECOVERY_DISABLED is '${LINUXOPS_RECOVERY_DISABLED}'. Ensure state-changing operations are strictly intended."
fi

echo "--------------------------------------------------------------------------------"
echo "🚀 Launching LinuxOps Service..."
echo "--------------------------------------------------------------------------------"

exec "${STREAMLIT_BIN}" run "${PROJECT_ROOT}/app/dashboard.py" \
    --server.address "${BIND_ADDRESS}" \
    --server.port "${PORT}" \
    --server.headless true \
    --browser.gatherUsageStats false
