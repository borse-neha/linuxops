#!/usr/bin/env bash
# ==============================================================================
# LinuxOps Local Diagnostics and Health Status Tool
# Read-only health probe and service status report.
# ==============================================================================

set -euo pipefail

echo "================================================================================"
echo "               LINUXOPS LOCAL HEALTH & SERVICE STATUS REPORT"
echo "================================================================================"
echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo

echo "1. Streamlit Dashboard Health Endpoint (127.0.0.1:8501):"
if curl -s -f -m 3 http://127.0.0.1:8501/_stcore/health >/dev/null; then
    echo "   ✅ HTTP 200 OK - Healthy"
else
    echo "   ❌ Unreachable / Failed"
fi
echo

echo "2. User Systemd Services:"
echo "   linuxops-dashboard: $(systemctl --user is-active linuxops-dashboard.service || true)"
echo "   linuxops-bridge:    $(systemctl --user is-active linuxops-bridge.service || true)"
echo

echo "3. Active Network Listeners (Port 8501):"
if command -v ss >/dev/null 2>&1; then
    ss -tlpn | grep 8501 || echo "   (No active listeners on port 8501)"
fi
echo

echo "4. WSL eth0 IP Address:"
ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "   (eth0 IP unavailable)"
echo

echo "5. Global Recovery Kill-Switch State:"
PID="$(pgrep -f 'streamlit run.*dashboard.py' | head -1 || true)"
if [ -n "${PID}" ]; then
    echo "   Running Dashboard PID: ${PID}"
    tr '\0' '\n' < "/proc/${PID}/environ" | grep LINUXOPS || echo "   (LINUXOPS_RECOVERY_DISABLED not present in PID ${PID})"
else
    echo "   Dashboard process not currently running."
fi
echo
echo "================================================================================"
