#!/usr/bin/env python3

"""Unit tests for Phase 4 Controlled Staging Preflight Tool."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.staging_preflight import (
    DEFAULT_SENTINEL_DATA_PATH,
    check_dashboard_network_binding,
    check_directories_and_permissions,
    check_project_configuration,
    check_protected_workloads_and_data,
    check_python_environment,
    check_recovery_disabled_state,
    run_staging_preflight,
)


class TestStagingPreflight(unittest.TestCase):
    """Test staging preflight checks and safety guardrails."""

    def test_run_staging_preflight_overall_ready(self):
        """Preflight on the repository returns READY with 10 passing checks."""
        report = run_staging_preflight()
        self.assertEqual(report["overall_status"], "READY")
        self.assertEqual(report["summary"]["failed"], 0)
        self.assertEqual(report["summary"]["total_checks"], 10)
        self.assertGreaterEqual(report["summary"]["passed"], 9)

    def test_python_environment_passes(self):
        res = check_python_environment()
        self.assertEqual(res["status"], "PASS")

    def test_project_configuration_passes(self):
        res = check_project_configuration()
        self.assertEqual(res["status"], "PASS")

    def test_dashboard_network_binding_passes(self):
        res = check_dashboard_network_binding()
        self.assertIn(res["status"], {"PASS", "WARN"})

    def test_recovery_disabled_state_passes(self):
        res = check_recovery_disabled_state()
        self.assertEqual(res["status"], "PASS")

    def test_dashboard_binding_rejects_0000(self):
        """Unauthenticated 0.0.0.0 binding fails preflight closed."""
        with tempfile.TemporaryDirectory() as td:
            cfg_dir = Path(td) / ".streamlit"
            cfg_dir.mkdir(parents=True)
            cfg_file = cfg_dir / "config.toml"
            cfg_file.write_text("[server]\naddress = '0.0.0.0'\nport = 8501\n", encoding="utf-8")

            with patch("scripts.staging_preflight.PROJECT_ROOT", Path(td)):
                res = check_dashboard_network_binding()
                self.assertEqual(res["status"], "FAIL")
                self.assertIn("0.0.0.0", res["message"])

    def test_protected_workloads_and_data_isolated_mode_passes(self):
        """Explicit LINUXOPS_SENTINEL_DATA_PATH='isolated' passes and distinguishes sandbox isolation from host integrity."""
        with patch.dict("os.environ", {"LINUXOPS_SENTINEL_DATA_PATH": "isolated"}):
            res = check_protected_workloads_and_data()
            self.assertEqual(res["status"], "PASS")
            self.assertIn("isolated sandbox", res["message"].lower())
            self.assertIn("not host data integrity", res["message"].lower())

    def test_protected_workloads_and_data_isolated_mode_fails_if_leak_detected(self):
        """Explicit isolated mode fails closed if protected host data is unexpectedly present."""
        with patch.dict("os.environ", {"LINUXOPS_SENTINEL_DATA_PATH": "isolated"}):
            with patch.object(Path, "exists", return_value=True):
                res = check_protected_workloads_and_data()
                self.assertEqual(res["status"], "FAIL")
                self.assertIn("Isolation check failed", res["message"])

    def test_protected_workloads_and_data_configured_host_path_passes(self):
        """Configuring an existing directory via LINUXOPS_SENTINEL_DATA_PATH passes with verification."""
        with tempfile.TemporaryDirectory() as td:
            with patch.dict("os.environ", {"LINUXOPS_SENTINEL_DATA_PATH": td}):
                res = check_protected_workloads_and_data()
                self.assertEqual(res["status"], "PASS")
                self.assertIn("configured host data directory", res["message"].lower())
                self.assertIn("verified intact", res["message"].lower())

    def test_protected_workloads_and_data_configured_host_path_fails_closed(self):
        """Configuring a non-existent host data path fails closed."""
        nonexistent = "/nonexistent/cloudops/sentinel/data/path"
        with patch.dict("os.environ", {"LINUXOPS_SENTINEL_DATA_PATH": nonexistent}):
            res = check_protected_workloads_and_data()
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("does not exist on host", res["message"])

    def test_protected_workloads_and_data_host_env_missing_data_fails_closed(self):
        """In a host environment (where /home/neha exists), missing sentinel data fails closed."""
        with patch.dict("os.environ", {}, clear=True):
            orig_exists = Path.exists

            def mock_exists(self_path):
                # /home/neha exists (host environment)
                if str(self_path) == "/home/neha":
                    return True
                # but default sentinel data path does not exist
                if str(self_path) == str(DEFAULT_SENTINEL_DATA_PATH):
                    return False
                return orig_exists(self_path)

            with patch.object(Path, "exists", side_effect=mock_exists, autospec=True):
                res = check_protected_workloads_and_data()
                self.assertEqual(res["status"], "FAIL")
                self.assertIn("does not exist on host", res["message"])


if __name__ == "__main__":
    unittest.main()

