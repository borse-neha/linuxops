#!/usr/bin/env bash
# ==============================================================================
# LinuxOps Environment Setup & Bootstrap Script
# Creates an isolated Python virtual environment, installs dependencies,
# validates filesystem paths, and executes the staging preflight audit.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

echo "================================================================================"
echo "LINUXOPS REPRODUCIBLE ENVIRONMENT BOOTSTRAP"
echo "================================================================================"
echo "Project Root: ${PROJECT_ROOT}"

# 1. Verify Python Version (>= 3.10 required)
PYTHON_BIN="${PYTHON:-python3}"
if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    echo "❌ ERROR: Python executable '${PYTHON_BIN}' not found in PATH."
    exit 1
fi

PY_VERSION="$("${PYTHON_BIN}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="$("${PYTHON_BIN}" -c 'import sys; print(sys.version_info.major)')"
PY_MINOR="$("${PYTHON_BIN}" -c 'import sys; print(sys.version_info.minor)')"

if [ "${PY_MAJOR}" -lt 3 ] || ([ "${PY_MAJOR}" -eq 3 ] && [ "${PY_MINOR}" -lt 10 ]); then
    echo "❌ ERROR: Python 3.10 or newer is required. Found Python ${PY_VERSION}."
    exit 1
fi
echo "✅ Python version verified: ${PY_VERSION}"

# 2. Check Podman CLI Availability
if ! command -v podman >/dev/null 2>&1; then
    echo "⚠️ WARNING: 'podman' CLI was not found in PATH. Live container inspection requires Podman."
else
    PODMAN_VER="$(podman --version | head -n1)"
    echo "✅ Podman CLI detected: ${PODMAN_VER}"
fi

# 3. Create or Activate Isolated Virtual Environment
VENV_DIR="${PROJECT_ROOT}/.venv"
if [ ! -d "${VENV_DIR}" ]; then
    echo "📦 Creating isolated virtual environment at '${VENV_DIR}'..."
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

VENV_PYTHON="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"

if [ ! -x "${VENV_PYTHON}" ]; then
    echo "❌ ERROR: Virtualenv python binary missing at '${VENV_PYTHON}'."
    exit 1
fi
echo "✅ Virtual environment ready: ${VENV_DIR}"

# 4. Install Dependencies
INSTALL_DEV=0
if [[ "${1:-}" == "--dev" ]]; then
    INSTALL_DEV=1
fi

echo "📦 Installing Python dependencies into virtual environment..."
"${VENV_PIP}" install --upgrade pip setuptools wheel --quiet

if [ "${INSTALL_DEV}" -eq 1 ] && [ -f "${PROJECT_ROOT}/requirements-dev.txt" ]; then
    echo "📦 Installing development and test dependencies from requirements-dev.txt..."
    "${VENV_PIP}" install -r "${PROJECT_ROOT}/requirements-dev.txt" --quiet
elif [ -f "${PROJECT_ROOT}/requirements.txt" ]; then
    echo "📦 Installing core runtime dependencies from requirements.txt..."
    "${VENV_PIP}" install -r "${PROJECT_ROOT}/requirements.txt" --quiet
else
    echo "❌ ERROR: Neither requirements.txt nor requirements-dev.txt found."
    exit 1
fi
echo "✅ Dependencies installed successfully."

# 5. Ensure Directories & Local Hardening
mkdir -p "${PROJECT_ROOT}/logs" "${PROJECT_ROOT}/.streamlit"
chmod 0755 "${PROJECT_ROOT}/logs" 2>/dev/null || true

# 6. Run Staging Preflight Readiness Audit
echo "🔍 Running staging preflight audit with virtualenv python..."
"${VENV_PYTHON}" "${PROJECT_ROOT}/scripts/staging_preflight.py"

echo "================================================================================"
echo "✅ BOOTSTRAP COMPLETE: Environment is ready."
echo "To activate manually:"
echo "    source .venv/bin/activate"
echo "To start the dashboard bound to localhost:"
echo "    ./scripts/run_dashboard.sh"
echo "================================================================================"
