"""
Unit tests for LinuxOps Phase 7 — Packaging, Reproducible Deployment & Release Preparation.
Validates:
- pyproject.toml syntax, metadata, dependency bounds, and Python version constraints
- requirements.txt, requirements-dev.txt, requirements-lock.txt consistency
- .env.example placeholder sanity and secret freedom
- .streamlit/config.toml security hardening (localhost-only binding, CORS/XSRF)
- scripts/ launcher integrity and fail-closed safety
- .gitignore patterns
"""

import os
from pathlib import Path
import re
import tomllib
import unittest

from app.diagnostics_engine import redact_sensitive_text

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestPackagingMetadata(unittest.TestCase):
    """Validate standard packaging declarations and dependency boundaries."""

    def test_pyproject_toml_structure_and_constraints(self):
        pyproject_path = PROJECT_ROOT / "pyproject.toml"
        self.assertTrue(pyproject_path.is_file(), "pyproject.toml must exist in project root")

        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        # Build-system
        self.assertIn("build-system", data)
        self.assertIn("setuptools.build_meta", data["build-system"].get("build-backend", ""))

        # Project metadata
        project = data.get("project", {})
        self.assertEqual(project.get("name"), "linuxops")
        self.assertTrue(project.get("version"), "Version must be specified")
        self.assertEqual(project.get("requires-python"), ">=3.10")

        # Runtime dependencies
        deps = project.get("dependencies", [])
        dep_str = " ".join(deps)
        self.assertIn("pandas", dep_str)
        self.assertIn("streamlit", dep_str)

        # Dev dependencies
        optional_deps = project.get("optional-dependencies", {})
        self.assertIn("dev", optional_deps)
        self.assertTrue(any("pytest" in d for d in optional_deps["dev"]))

    def test_requirements_files_consistency(self):
        req_path = PROJECT_ROOT / "requirements.txt"
        self.assertTrue(req_path.is_file(), "requirements.txt must exist")
        req_content = req_path.read_text(encoding="utf-8")
        self.assertIn("pandas", req_content)
        self.assertIn("streamlit", req_content)

        req_dev_path = PROJECT_ROOT / "requirements-dev.txt"
        self.assertTrue(req_dev_path.is_file(), "requirements-dev.txt must exist")
        dev_content = req_dev_path.read_text(encoding="utf-8")
        self.assertIn("-r requirements.txt", dev_content)
        self.assertIn("pytest", dev_content)

        req_lock_path = PROJECT_ROOT / "requirements-lock.txt"
        self.assertTrue(req_lock_path.is_file(), "requirements-lock.txt must exist")
        lock_content = req_lock_path.read_text(encoding="utf-8")
        self.assertIn("pandas==", lock_content)
        self.assertIn("streamlit==", lock_content)


class TestConfigurationAndSecretsSafety(unittest.TestCase):
    """Validate environment configuration safety, placeholder sanity, and secret absence."""

    def test_env_example_has_no_secrets_and_valid_defaults(self):
        env_example_path = PROJECT_ROOT / ".env.example"
        self.assertTrue(env_example_path.is_file(), ".env.example must exist")
        content = env_example_path.read_text(encoding="utf-8")

        # Secret redaction check: Ensure no real keys, passwords, or credentials
        redacted = redact_sensitive_text(content)
        self.assertNotIn("[REDACTED_AWS_KEY]", redacted)
        self.assertNotIn("[REDACTED_PRIVATE_KEY]", redacted)
        self.assertNotIn("[REDACTED_TOKEN]", redacted)

        # Parse key-values
        env_vars = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip()

        # Check required monitoring thresholds
        for key in ["CPU_WARNING", "CPU_CRITICAL", "MEMORY_WARNING", "MEMORY_CRITICAL", "DISK_WARNING", "DISK_CRITICAL"]:
            self.assertIn(key, env_vars, f"{key} must be declared in .env.example")
            val = float(env_vars[key])
            self.assertTrue(0.0 <= val <= 100.0, f"{key} must be between 0.0 and 100.0")

        self.assertLess(float(env_vars["CPU_WARNING"]), float(env_vars["CPU_CRITICAL"]))
        self.assertLess(float(env_vars["MEMORY_WARNING"]), float(env_vars["MEMORY_CRITICAL"]))
        self.assertLess(float(env_vars["DISK_WARNING"]), float(env_vars["DISK_CRITICAL"]))

        # Recovery disabled kill-switch
        self.assertIn("LINUXOPS_RECOVERY_DISABLED", env_vars)
        self.assertEqual(env_vars["LINUXOPS_RECOVERY_DISABLED"], "0")

    def test_gitignore_covers_sensitive_and_virtualenv_files(self):
        gitignore_path = PROJECT_ROOT / ".gitignore"
        self.assertTrue(gitignore_path.is_file(), ".gitignore must exist")
        content = gitignore_path.read_text(encoding="utf-8")

        self.assertIn(".env", content)
        self.assertIn(".venv/", content)
        self.assertIn("__pycache__/", content)
        self.assertIn("logs/*.jsonl", content)

    def test_streamlit_config_hardened_to_localhost(self):
        config_path = PROJECT_ROOT / ".streamlit" / "config.toml"
        self.assertTrue(config_path.is_file(), ".streamlit/config.toml must exist")

        with open(config_path, "rb") as f:
            cfg = tomllib.load(f)

        server = cfg.get("server", {})
        self.assertEqual(server.get("address"), "127.0.0.1", "Dashboard must be strictly bound to 127.0.0.1")
        self.assertEqual(server.get("port"), 8501)
        self.assertEqual(server.get("headless"), True)
        self.assertEqual(server.get("enableCORS"), True, "CORS protection must be enabled in hardened config")
        self.assertEqual(server.get("enableXsrfProtection"), True)


class TestWorkflowScripts(unittest.TestCase):
    """Validate executable shell scripts and workflow automation."""

    def test_scripts_exist_and_use_safe_shell_modes(self):
        expected_scripts = [
            "scripts/setup_env.sh",
            "scripts/run_dashboard.sh",
            "scripts/stop_dashboard.sh",
            "scripts/run_checks.sh",
        ]
        for script_rel in expected_scripts:
            script_path = PROJECT_ROOT / script_rel
            self.assertTrue(script_path.is_file(), f"{script_rel} must exist")
            content = script_path.read_text(encoding="utf-8")
            self.assertTrue(content.startswith("#!/usr/bin/env bash"), f"{script_rel} must have bash shebang")
            self.assertIn("set -euo pipefail", content, f"{script_rel} must enforce strict error handling")

    def test_run_dashboard_enforces_localhost_flags(self):
        run_script = (PROJECT_ROOT / "scripts/run_dashboard.sh").read_text(encoding="utf-8")
        self.assertIn("--server.address 127.0.0.1", run_script)
        self.assertIn("8501", run_script)
        self.assertIn("address = \"127.0.0.1\"", run_script)

    def test_stop_dashboard_targets_only_streamlit_dashboard(self):
        stop_script = (PROJECT_ROOT / "scripts/stop_dashboard.sh").read_text(encoding="utf-8")
        self.assertIn("app/dashboard.py", stop_script)
        self.assertIn("SIGTERM", stop_script)


if __name__ == "__main__":
    unittest.main()
