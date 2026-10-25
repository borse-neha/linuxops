#!/usr/bin/env bash
# ==============================================================================
# LinuxOps Local Dashboard Clean Shutdown Script
# Gracefully stops running dashboard instances and confirms port release.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================================"
echo "STOPPING LINUXOPS OPERATIONS CENTER DASHBOARD"
echo "================================================================================"

TARGET_PATTERN="streamlit run.*app/dashboard.py"
PIDS="$(pgrep -f "${TARGET_PATTERN}" || true)"

if [ -z "${PIDS}" ]; then
    echo "ℹ️  No running LinuxOps dashboard process detected."
else
    echo "Stopping dashboard process(es): ${PIDS}"
    kill -SIGTERM ${PIDS} 2>/dev/null || true

    # Wait up to 5 seconds for clean exit
    for i in {1..5}; do
        if ! pgrep -f "${TARGET_PATTERN}" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    # Force kill if still hanging
    REMAINING="$(pgrep -f "${TARGET_PATTERN}" || true)"
    if [ -n "${REMAINING}" ]; then
        echo "⚠️ Forcing termination of remaining process(es): ${REMAINING}"
        kill -SIGKILL ${REMAINING} 2>/dev/null || true
    fi
fi

# Verify port 8501 release
PORT=8501
if command -v ss >/dev/null 2>&1; then
    if ss -tlpn | grep -q ":${PORT} "; then
        echo "⚠️ WARNING: Port ${PORT} is still occupied. Check active listeners with: ss -tlpn | grep ${PORT}"
    else
        echo "✅ Port ${PORT} confirmed released."
    fi
fi

echo "✅ Dashboard shutdown complete."
