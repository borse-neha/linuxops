#!/usr/bin/env python3

"""
Unit tests for LinuxOps Phase 10 — Isolated Failure-Injection & Remediation Validation Harness.
"""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from scripts.validate_phase10_failure_injection import (
    build_phase10_scenario_plan,
    cleanup_phase10_containers,
    create_phase10_containers,
    generate_run_id,
    get_current_environment_identity,
    is_target_protected,
    verify_environment_isolation,
)


class TestPhase10Harness(unittest.TestCase):
    """Test safety constraints, plan construction, isolation gates, and immunity in Phase 10 harness."""

    def test_protected_workload_immunity(self):
        """Immunity rejects protected container names and IDs."""
        self.assertTrue(is_target_protected("cloudops-floci"))
        self.assertTrue(is_target_protected("linuxops-recovery-ui-test"))
        self.assertTrue(is_target_protected("other", "db80c688e14b"))
        self.assertTrue(is_target_protected("other", "83b65d88a0a9"))
        self.assertTrue(is_target_protected("other", "510d4cfc0d22"))
        self.assertFalse(is_target_protected("linuxops-p10-scen-a-exit42", "abcd1234efgh"))

    def test_build_phase10_scenario_plan_8_scenarios(self):
        """Scenario plan contains all 8 required scenarios A through H with strict resource bounds."""
        run_id = "test_p10"
        plan = build_phase10_scenario_plan(run_id)
        self.assertEqual(len(plan), 8)

        letters = [item["scenario_letter"] for item in plan]
        self.assertEqual(letters, ["A", "B", "C", "D", "E", "F", "G", "H"])

        # Check resource limits: no container may exceed 24m memory or 0.05 cpu
        for item in plan:
            self.assertIn(item["memory"], {"10m", "24m"})
            self.assertEqual(item["cpus"], "0.05")

        # Check scenario names
        scen_names = [item["scenario_name"] for item in plan]
        self.assertIn("nonzero_exit_code", scen_names)
        self.assertIn("dependency_connection_refused", scen_names)
        self.assertIn("repeated_crash_loop", scen_names)
        self.assertIn("failing_health_check", scen_names)
        self.assertIn("memory_exhaustion_oom", scen_names)
        self.assertIn("permission_denied", scen_names)
        self.assertIn("missing_configuration", scen_names)
        self.assertIn("healthy_control", scen_names)

    def test_dry_run_creation_creates_manifest_without_podman(self):
        """Dry-run creation generates an atomic manifest without invoking the podman runner."""
        mock_runner = MagicMock()
        run_id = generate_run_id()
        plan = build_phase10_scenario_plan(run_id)

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / f"manifest_{run_id}.json"
            ok, records, msg = create_phase10_containers(plan, run_id, manifest_path, dry_run=True, runner=mock_runner)

            self.assertTrue(ok)
            self.assertEqual(len(records), 8)
            mock_runner.assert_not_called()
            self.assertTrue(manifest_path.exists())

            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(data["mode"], "DRY_RUN")
            self.assertEqual(len(data["containers"]), 8)

    def test_refuse_to_create_protected_container_name(self):
        """Harness immediately halts if any item targets a protected container name."""
        mock_runner = MagicMock()
        run_id = generate_run_id()
        malicious_plan = [
            {
                "scenario_letter": "X",
                "scenario_name": "malicious",
                "name": "cloudops-floci",
                "memory": "24m",
                "cpus": "0.05",
                "restart": "no",
                "cmd": ["sleep", "1"],
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            ok, records, msg = create_phase10_containers(malicious_plan, run_id, manifest_path, dry_run=False, runner=mock_runner)
            self.assertFalse(ok)
            self.assertIn("Refusing to create protected container", msg)
            mock_runner.assert_not_called()

    def test_cleanup_refuses_to_target_protected_workloads(self):
        """Cleanup removes test containers but skips protected containers."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_data = {
                "run_id": "test_run",
                "containers": [
                    {"name": "cloudops-floci", "full_id": "db80c688e14b", "id": "db80c688e14b"},
                    {"name": "linuxops-recovery-ui-test", "full_id": "83b65d88a0a9", "id": "83b65d88a0a9"},
                    {"name": "linuxops-p10-scen-a", "full_id": "safe_cid_12345", "id": "safe_cid_123"},
                ],
            }
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

            removed, errs = cleanup_phase10_containers(manifest_path=manifest_path, runner=mock_runner)
            self.assertEqual(removed, 1)
            # Only safe_cid_12345 removed
            mock_runner.assert_called_once_with(
                ["podman", "rm", "-f", "safe_cid_12345"],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )

    def test_isolation_check_blocks_on_protected_host(self):
        """verify_environment_isolation blocks execution when run on protected Fedora host."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = "cloudops-floci\nlinuxops-recovery-ui-test\n"

        with patch.dict("os.environ", {"WSL_DISTRO_NAME": "FedoraLinux-44"}):
            is_safe, details, blockers = verify_environment_isolation(runner=mock_runner)
            self.assertFalse(is_safe)
            self.assertTrue(len(blockers) >= 1)
            self.assertTrue(any("Fedora" in b for b in blockers))


if __name__ == "__main__":
    unittest.main()
