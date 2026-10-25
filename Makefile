# ==============================================================================
# LinuxOps Platform Automation & Packaging Makefile
# ==============================================================================

SHELL := /usr/bin/env bash
PYTHON ?= python3
VENV ?= .venv
VENV_PYTHON := $(VENV)/bin/python
VENV_PIP := $(VENV)/bin/pip

.PHONY: help venv install install-dev preflight test benchmark validate-pilot validate-live run stop check clean-pyc

help:
	@echo "================================================================================"
	@echo "LinuxOps Operations & Development Automation"
	@echo "================================================================================"
	@echo "Available targets:"
	@echo "  make venv            - Create isolated Python virtual environment (.venv)"
	@echo "  make install         - Install core runtime dependencies from requirements.txt"
	@echo "  make install-dev     - Install development & test dependencies"
	@echo "  make preflight       - Execute 10-point staging readiness preflight audit"
	@echo "  make test            - Execute full automated test suite (350+ tests)"
	@echo "  make benchmark       - Run synthetic load benchmarks (100-1000 containers)"
	@echo "  make validate-pilot  - Run repeated monitoring cycles & pilot stability audit"
	@echo "  make validate-live   - Run read-only live Podman inspection audit"
	@echo "  make run             - Launch Streamlit operations dashboard on 127.0.0.1:8501"
	@echo "  make stop            - Gracefully terminate running localhost dashboard"
	@echo "  make check           - Run bytecode compilation and git diff whitespace checks"
	@echo "  make clean-pyc       - Safely remove compiled bytecode caches (.pyc, __pycache__)"
	@echo "================================================================================"

venv:
	@if [ ! -d "$(VENV)" ]; then \
		echo "Creating virtual environment in $(VENV)..."; \
		$(PYTHON) -m venv $(VENV); \
	else \
		echo "Virtual environment already exists in $(VENV)."; \
	fi

install: venv
	@echo "Installing core runtime dependencies..."
	$(VENV_PIP) install --upgrade pip setuptools wheel --quiet
	$(VENV_PIP) install -r requirements.txt --quiet
	@echo "Dependencies installed."

install-dev: venv
	@echo "Installing development & test dependencies..."
	$(VENV_PIP) install --upgrade pip setuptools wheel --quiet
	$(VENV_PIP) install -r requirements-dev.txt --quiet
	@echo "Development dependencies installed."

preflight:
	@if [ -f "$(VENV_PYTHON)" ]; then \
		$(VENV_PYTHON) scripts/staging_preflight.py; \
	else \
		$(PYTHON) scripts/staging_preflight.py; \
	fi

test:
	@if [ -f "$(VENV_PYTHON)" ]; then \
		$(VENV_PYTHON) -m unittest discover -s tests -p 'test_*.py' -v; \
	else \
		$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v; \
	fi

benchmark:
	@if [ -f "$(VENV_PYTHON)" ]; then \
		$(VENV_PYTHON) scripts/benchmark_observability.py --measure-real; \
	else \
		$(PYTHON) scripts/benchmark_observability.py --measure-real; \
	fi

validate-pilot:
	@if [ -f "$(VENV_PYTHON)" ]; then \
		$(VENV_PYTHON) scripts/validate_pilot_cycles.py; \
	else \
		$(PYTHON) scripts/validate_pilot_cycles.py; \
	fi

validate-live:
	@if [ -f "$(VENV_PYTHON)" ]; then \
		$(VENV_PYTHON) scripts/validate_live_readonly.py; \
	else \
		$(PYTHON) scripts/validate_live_readonly.py; \
	fi

run:
	@./scripts/run_dashboard.sh

stop:
	@./scripts/stop_dashboard.sh

check:
	@echo "Verifying bytecode compilation..."
	$(PYTHON) -m compileall -q app scripts tests
	@echo "Verifying git diff whitespace cleanliness..."
	git diff --check
	@echo "All static integrity checks passed."

clean-pyc:
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.py[cod]" -delete 2>/dev/null || true
	@echo "Cleaned bytecode caches."
