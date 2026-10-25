#!/usr/bin/env bash
# ==============================================================================
# LinuxOps Local Dashboard Launcher
# Hardens launch to 127.0.0.1:8501 strictly. Never exposes dashboard remotely.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

echo "================================================================================"
echo "STARTING LINUXOPS OPERATIONS CENTER DASHBOARD"
echo "================================================================================"

# 1. Determine Python / Streamlit Runner
if [ -f "${PROJECT_ROOT}/.venv/bin/streamlit" ]; then
    STREAMLIT_BIN="${PROJECT_ROOT}/.venv/bin/streamlit"
    PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"
    echo "Using virtual environment: ${PROJECT_ROOT}/.venv"
elif command -v streamlit >/dev/null 2>&1; then
    STREAMLIT_BIN="$(command -v streamlit)"
    PYTHON_BIN="$(command -v python3)"
    echo "Using system Streamlit: ${STREAMLIT_BIN}"
else
    echo "❌ ERROR: Streamlit executable not found. Run './scripts/setup_env.sh' first."
    exit 1
fi

# 2. Hardening Check: Ensure .streamlit/config.toml binds strictly to 127.0.0.1
CONFIG_TOML="${PROJECT_ROOT}/.streamlit/config.toml"
if [ ! -f "${CONFIG_TOML}" ]; then
    echo "❌ ERROR: Missing '${CONFIG_TOML}'. Refusing unhardened launch."
    exit 1
fi

if ! grep -q 'address = "127.0.0.1"' "${CONFIG_TOML}"; then
    echo "❌ ERROR: .streamlit/config.toml must contain 'address = \"127.0.0.1\"'."
    echo "Refusing to start on unverified network interface."
    exit 1
fi

# 3. Check Port Availability on localhost
PORT=8501
if command -v ss >/dev/null 2>&1; then
    if ss -tlpn | grep -E -q "(127\.0\.0\.1|0\.0\.0\.0|\[::\]):${PORT} "; then
        echo "❌ ERROR: Port ${PORT} is already bound on localhost by another process."
        echo "Check active listeners with: ss -tlpn | grep ${PORT}"
        exit 1
    fi
fi

# 4. Launch Streamlit Bound Strictly to 127.0.0.1
echo "🚀 Launching dashboard on http://127.0.0.1:${PORT} (localhost only)..."
echo "Press Ctrl+C to terminate."
echo "--------------------------------------------------------------------------------"

exec "${STREAMLIT_BIN}" run "${PROJECT_ROOT}/app/dashboard.py" \
    --server.address 127.0.0.1 \
    --server.port "${PORT}" \
    --server.headless true \
    --browser.gatherUsageStats false
