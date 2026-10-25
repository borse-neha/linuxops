#!/usr/bin/env bash
# ==============================================================================
# LinuxOps Master Release Verification Script (make-independent)
# Runs the full automated verification battery: compilation, diff check,
# preflight audit, test suite, pilot cycle stability, and live read-only inspection.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

PYTHON_BIN="python3"
if [ -f "${PROJECT_ROOT}/.venv/bin/python" ]; then
    PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"
fi

echo "================================================================================"
echo "LINUXOPS FULL RELEASE VERIFICATION BATTERY"
echo "Python binary: ${PYTHON_BIN}"
echo "================================================================================"

echo ""
echo "--- 1. BYTECODE COMPILATION AUDIT ---"
"${PYTHON_BIN}" -m compileall -q app scripts tests
echo "✅ Compilation check: ZERO syntax errors."

echo ""
echo "--- 2. GIT DIFF CLEANLINESS AUDIT ---"
git diff --check
echo "✅ Git diff check: ZERO whitespace/patch errors."

echo ""
echo "--- 3. STAGING PREFLIGHT READINESS AUDIT ---"
"${PYTHON_BIN}" "${PROJECT_ROOT}/scripts/staging_preflight.py"

echo ""
echo "--- 4. FULL AUTOMATED TEST SUITE ---"
"${PYTHON_BIN}" -m unittest discover -s tests -p 'test_*.py'

echo ""
echo "--- 5. OPERATIONAL PILOT CYCLES AUDIT ---"
"${PYTHON_BIN}" "${PROJECT_ROOT}/scripts/validate_pilot_cycles.py"

echo ""
echo "--- 6. CONTROLLED BENCHMARK & PERFORMANCE AUDIT ---"
"${PYTHON_BIN}" "${PROJECT_ROOT}/scripts/benchmark_observability.py" --measure-real

echo ""
echo "--- 7. LIVE READ-ONLY HOST AUDIT ---"
"${PYTHON_BIN}" "${PROJECT_ROOT}/scripts/validate_live_readonly.py"

echo ""
echo "================================================================================"
echo "✅ ALL VERIFICATION CHECKS COMPLETED SUCCESSFULLY"
echo "================================================================================"
