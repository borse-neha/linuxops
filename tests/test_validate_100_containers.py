#!/usr/bin/env python3

"""
Unit tests for LinuxOps Phase 9 — Controlled 100-Container Validation Harness.
"""

import json
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from scripts.validate_100_containers import (
    build_scenario_plan,
    check_preflight_readiness,
    cleanup_100_containers,
    create_100_containers,
    generate_run_id,
    is_protected,
    is_protected_data_present,
    main,
    verify_post_cleanup,
    write_manifest_atomically,
)


class TestValidate100Harness(unittest.TestCase):
    """Test safety constraints, plan construction, manifest tracking, and immunity in 100-container harness."""

    def test_protected_workload_immunity(self):
        self.assertTrue(is_protected("cloudops-floci"))
        self.assertTrue(is_protected("linuxops-recovery-ui-test"))
        self.assertTrue(is_protected("random_name", "db80c688e14b"))
        self.assertTrue(is_protected("random_name", "83b65d88a0a9"))
        self.assertFalse(is_protected("linuxops-p9-test-001", "abcdef123456"))

    def test_build_scenario_plan_100_containers(self):
        run_id = "test_run_1"
        plan = build_scenario_plan(run_id=run_id, count=100)
        self.assertEqual(len(plan), 100)

        # Check naming pattern
        self.assertTrue(all(item["name"].startswith("linuxops-p9-test_run_1-") for item in plan))

        # Check scenario distribution
        scenarios = [item["scenario"] for item in plan]
        self.assertEqual(scenarios.count("healthy_running"), 80)
        self.assertEqual(scenarios.count("stopped_normal"), 6)
        self.assertEqual(scenarios.count("nonzero_exit"), 4)
        self.assertEqual(scenarios.count("crash_loop"), 4)
        self.assertEqual(scenarios.count("oom_killed"), 4)
        self.assertEqual(scenarios.count("healthcheck_failing"), 2)

        # Check resource limits
        self.assertTrue(all(item["memory_limit"] in {"6m", "24m"} for item in plan))

    def test_dry_run_creation_does_not_invoke_runner(self):
        mock_runner = MagicMock()
        run_id = generate_run_id()
        plan = build_scenario_plan(run_id=run_id, count=10)

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / f"manifest_{run_id}.json"
            ok, records, msg = create_100_containers(plan, run_id, manifest_path, dry_run=True, runner=mock_runner)

            self.assertTrue(ok)
            self.assertEqual(len(records), 10)
            mock_runner.assert_not_called()
            self.assertTrue(manifest_path.exists())

            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest_data["mode"], "DRY_RUN")
            self.assertEqual(manifest_data["created_count"], 10)

    def test_cleanup_refuses_to_target_protected_containers(self):
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_data = {
                "mode": "LIVE_EXECUTION",
                "containers": [
                    {"name": "cloudops-floci", "full_id": "db80c688e14b", "id": "db80c688e14b"},
                    {"name": "linuxops-p9-run1-001", "full_id": "testcid001", "id": "testcid001"},
                ],
            }
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

            removed, errs = cleanup_100_containers(manifest_path=manifest_path, runner=mock_runner)

            # Only the test container must be removed, floci must be skipped
            self.assertEqual(removed, 1)
            mock_runner.assert_called_once_with(
                ["podman", "rm", "-t", "0", "-f", "testcid001"],
                capture_output=True,
                text=True,
                timeout=25.0,
                check=False,
            )

    def test_preflight_passes_when_protected_resources_absent(self):
        """Preflight passes when memory, disk, and podman are available and protected resources are absent."""
        mock_runner = MagicMock()
        def runner_side_effect(cmd, **kwargs):
            res = MagicMock()
            res.returncode = 0
            if "version" in cmd:
                res.stdout = "4.9.3"
            elif "exists" in cmd:
                res.returncode = 0
            elif "ps" in cmd:
                res.stdout = ""
            return res
        mock_runner.side_effect = runner_side_effect

        with patch("scripts.validate_100_containers.is_protected_data_present", return_value=False):
            ok, details = check_preflight_readiness(runner=mock_runner)
            self.assertTrue(ok)
            self.assertTrue(details["protected_floci_absent"])
            self.assertTrue(details["protected_test_absent"])
            self.assertTrue(details["protected_data_absent"])
            self.assertTrue(details["isolation_verified"])

    def test_preflight_fails_when_protected_container_unexpectedly_present(self):
        """Unexpected presence of cloudops-floci or linuxops-recovery-ui-test causes safe failure."""
        mock_runner = MagicMock()
        # Case A: cloudops-floci is present
        mock_runner.side_effect = lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout="cloudops-floci\n" if "ps" in cmd else ("4.9.3" if "version" in cmd else ""),
        )
        with patch("scripts.validate_100_containers.is_protected_data_present", return_value=False):
            ok, details = check_preflight_readiness(runner=mock_runner)
            self.assertFalse(ok)
            self.assertFalse(details["protected_floci_absent"])
            self.assertTrue(details["protected_test_absent"])
            self.assertFalse(details["isolation_verified"])
            self.assertIn("cloudops-floci", details.get("isolation_error", ""))

        # Case B: linuxops-recovery-ui-test is present
        mock_runner.side_effect = lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout="linuxops-recovery-ui-test\n" if "ps" in cmd else ("4.9.3" if "version" in cmd else ""),
        )
        with patch("scripts.validate_100_containers.is_protected_data_present", return_value=False):
            ok, details = check_preflight_readiness(runner=mock_runner)
            self.assertFalse(ok)
            self.assertTrue(details["protected_floci_absent"])
            self.assertFalse(details["protected_test_absent"])
            self.assertFalse(details["isolation_verified"])

    def test_preflight_fails_when_protected_data_path_or_mount_present(self):
        """Presence or mount of protected data path causes isolation failure."""
        mock_runner = MagicMock()
        mock_runner.side_effect = lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout="4.9.3" if "version" in cmd else "",
        )

        # Case A: is_protected_data_present returns True -> preflight fails
        with patch("scripts.validate_100_containers.is_protected_data_present", return_value=True):
            ok, details = check_preflight_readiness(runner=mock_runner)
            self.assertFalse(ok)
            self.assertFalse(details["protected_data_absent"])
            self.assertFalse(details["isolation_verified"])
            self.assertIn("data_isolation_error", details)

        # Case B: Direct unit tests of is_protected_data_present
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir) / "cloudops-sentinel" / "data"
            test_dir.mkdir(parents=True)
            self.assertTrue(is_protected_data_present(data_path=test_dir))

        with patch("pathlib.Path.read_text", return_value="drvfs /home/neha/cloudops-sentinel/data 9p rw 0 0\n"):
            self.assertTrue(is_protected_data_present(data_path=Path("/nonexistent/data/path")))

    def test_preflight_fails_closed_on_missing_or_failed_inspection(self):
        """Inspection failure or command failure causes preflight to fail closed."""
        mock_runner = MagicMock()

        # Case A: podman ps fails with returncode != 0
        mock_runner.side_effect = lambda cmd, **kwargs: MagicMock(
            returncode=1 if "ps" in cmd else 0,
            stderr="podman daemon unreachable" if "ps" in cmd else "",
            stdout="4.9.3" if "version" in cmd else "",
        )
        with patch("scripts.validate_100_containers.is_protected_data_present", return_value=False):
            ok, details = check_preflight_readiness(runner=mock_runner)
            self.assertFalse(ok)
            self.assertFalse(details["protected_floci_absent"])
            self.assertFalse(details["isolation_verified"])
            self.assertIn("containers_check_error", details)

        # Case B: podman ps raises Exception
        mock_runner.side_effect = Exception("podman execution timeout")
        with patch("scripts.validate_100_containers.is_protected_data_present", return_value=False):
            ok, details = check_preflight_readiness(runner=mock_runner)
            self.assertFalse(ok)
            self.assertIn("containers_check_error", details)

        # Case C: alpine image not present
        mock_runner.side_effect = lambda cmd, **kwargs: MagicMock(
            returncode=1 if "exists" in cmd else 0,
            stdout="4.9.3" if "version" in cmd else "",
        )
        with patch("scripts.validate_100_containers.is_protected_data_present", return_value=False):
            ok, details = check_preflight_readiness(runner=mock_runner)
            self.assertFalse(ok)
            self.assertFalse(details["alpine_image_present"])

    def test_post_cleanup_verification_succeeds_without_fedora_resources(self):
        """Post-cleanup verification validates that test containers were removed without requiring Fedora resources."""
        mock_runner = MagicMock()
        mock_runner.side_effect = lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout="4.9.3" if "version" in cmd else "",
        )

        with patch("scripts.validate_100_containers.is_protected_data_present", return_value=False):
            with tempfile.TemporaryDirectory() as tmpdir:
                manifest_path = Path(tmpdir) / "phase9_manifest_run_test.json"
                all_clean, details = verify_post_cleanup(manifest_path=manifest_path, run_id="run_test", runner=mock_runner)

                self.assertTrue(all_clean)
                self.assertTrue(details["cleanup_complete"])
                self.assertEqual(details["remaining_test_containers"], 0)
                self.assertTrue(details["protected_floci_absent"])
                self.assertTrue(details["protected_test_absent"])
                self.assertTrue(details["protected_data_absent"])
                # Also verify backward-compat aliases and typo fix
                self.assertTrue(details["protected_floci_intac"])
                self.assertTrue(details["protected_floci_intact"])

    def test_post_cleanup_verification_fails_if_test_containers_remain(self):
        """Post-cleanup verification fails if any test containers still exist."""
        mock_runner = MagicMock()
        mock_runner.side_effect = lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout="c101\n" if any("filter" in c for c in cmd) else ("4.9.3" if "version" in cmd else ""),
        )

        with patch("scripts.validate_100_containers.is_protected_data_present", return_value=False):
            with tempfile.TemporaryDirectory() as tmpdir:
                manifest_path = Path(tmpdir) / "manifest.json"
                all_clean, details = verify_post_cleanup(manifest_path=manifest_path, run_id="run_test", runner=mock_runner)
                self.assertFalse(all_clean)
                self.assertFalse(details["cleanup_complete"])
                self.assertEqual(details["remaining_test_containers"], 1)


    def test_initial_manifest_written_before_first_container_creation(self):
        """The initial manifest exists and contains created_count: 0 and containers: [] before first container creation."""
        mock_runner = MagicMock()
        manifest_state_at_call = {}

        def runner_side_effect(cmd, **kwargs):
            nonlocal manifest_state_at_call
            if manifest_path.exists() and not manifest_state_at_call:
                manifest_state_at_call = json.loads(manifest_path.read_text(encoding="utf-8"))
            res = MagicMock()
            res.returncode = 0
            res.stdout = "c123456789012345\n"
            return res

        mock_runner.side_effect = runner_side_effect
        run_id = "test_run_init"
        plan = build_scenario_plan(run_id=run_id, count=2)

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / f"manifest_{run_id}.json"
            ok, records, msg = create_100_containers(plan, run_id, manifest_path, dry_run=False, runner=mock_runner)

            self.assertTrue(ok)
            self.assertEqual(len(records), 2)
            # Verify that before the first runner call, the initial manifest existed with 0 containers
            self.assertIsNotNone(manifest_state_at_call)
            self.assertEqual(manifest_state_at_call.get("mode"), "LIVE_EXECUTION")
            self.assertEqual(manifest_state_at_call.get("created_count"), 0)
            self.assertEqual(manifest_state_at_call.get("containers"), [])

    def test_manifest_durably_updated_after_each_successful_creation(self):
        """The manifest is durably updated on disk after each successful container creation."""
        mock_runner = MagicMock()
        mock_runner.side_effect = lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout=f"cid_{secrets.token_hex(6)}\n",
        )
        run_id = "test_run_updates"
        plan = build_scenario_plan(run_id=run_id, count=3)

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / f"manifest_{run_id}.json"
            ok, records, msg = create_100_containers(plan, run_id, manifest_path, dry_run=False, runner=mock_runner)

            self.assertTrue(ok)
            self.assertEqual(len(records), 3)

            final_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(final_manifest.get("created_count"), 3)
            self.assertEqual(len(final_manifest.get("containers", [])), 3)

    def test_initial_manifest_write_failure_prevents_container_creation(self):
        """Initial manifest-write failure prevents any container creation and returns False."""
        mock_runner = MagicMock()
        run_id = "test_run_fail_init"
        plan = build_scenario_plan(run_id=run_id, count=5)

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / f"manifest_{run_id}.json"
            with patch("scripts.validate_100_containers.write_manifest_atomically", side_effect=OSError("Read-only filesystem")):
                ok, records, msg = create_100_containers(plan, run_id, manifest_path, dry_run=False, runner=mock_runner)
                self.assertFalse(ok)
                self.assertEqual(len(records), 0)
                mock_runner.assert_not_called()
                self.assertIn("Failed initializing manifest", msg)

    def test_manifest_update_failure_stops_further_creation(self):
        """Manifest-update failure stops further creation and returns already-recorded containers."""
        mock_runner = MagicMock()
        mock_runner.side_effect = lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout="cid001\n",
        )
        run_id = "test_run_fail_update"
        plan = build_scenario_plan(run_id=run_id, count=5)

        call_count = 0
        real_write = write_manifest_atomically

        def write_side_effect(path, data):
            nonlocal call_count
            call_count += 1
            if call_count == 2:  # 1st call is init, 2nd call is update after container 1
                raise OSError("Disk quota exceeded during manifest update")
            return real_write(path, data)

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / f"manifest_{run_id}.json"
            with patch("scripts.validate_100_containers.write_manifest_atomically", side_effect=write_side_effect):
                ok, records, msg = create_100_containers(plan, run_id, manifest_path, dry_run=False, runner=mock_runner)
                self.assertFalse(ok)
                # Exactly 1 container attempted and recorded before manifest update failed
                self.assertEqual(len(records), 1)
                self.assertEqual(mock_runner.call_count, 1)
                self.assertIn("Failed updating manifest", msg)

    def test_partial_creation_failure_reports_removed_counts_and_errors(self):
        """Cleanup handles partial creation and reports counts and errors accurately."""
        mock_runner = MagicMock()
        def runner_side_effect(cmd, **kwargs):
            res = MagicMock()
            if "rm" in cmd:
                if "fail_cid" in cmd:
                    res.returncode = 1
                    res.stderr = "device busy"
                else:
                    res.returncode = 0
            return res
        mock_runner.side_effect = runner_side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_data = {
                "mode": "LIVE_EXECUTION",
                "containers": [
                    {"name": "test-c1", "full_id": "good_cid", "id": "good_cid"},
                    {"name": "test-c2", "full_id": "fail_cid", "id": "fail_cid"},
                ],
            }
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

            removed, errs = cleanup_100_containers(manifest_path=manifest_path, runner=mock_runner)
            self.assertEqual(removed, 1)
            self.assertEqual(len(errs), 1)
            self.assertIn("device busy", errs[0])

    def test_cleanup_reconciles_run_id_label_covering_creation_interruption_window(self):
        """Cleanup queries run-id label even if container was interrupted before manifest recording."""
        mock_runner = MagicMock()
        def runner_side_effect(cmd, **kwargs):
            res = MagicMock()
            res.returncode = 0
            if "ps" in cmd:
                # Container cid_unrecorded was created in Podman but interrupted before manifest write
                res.stdout = "cid_recorded test-c1\ncid_unrecorded test-c2\n"
            return res
        mock_runner.side_effect = runner_side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_data = {
                "mode": "LIVE_EXECUTION",
                "containers": [
                    {"name": "test-c1", "full_id": "cid_recorded", "id": "cid_recorded"},
                ],
            }
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

            removed, errs = cleanup_100_containers(manifest_path=manifest_path, run_id="run_interrupted", runner=mock_runner)
            # Both cid_recorded and cid_unrecorded must be reconciled and removed
            self.assertEqual(removed, 2)
            self.assertEqual(len(errs), 0)

    def test_main_creation_failure_aborts_with_nonzero_exit_and_calls_cleanup_and_verify(self):
        """On container creation failure, main() runs cleanup, calls verify_post_cleanup, and exits nonzero."""
        with patch("scripts.validate_100_containers.check_preflight_readiness", return_value=(True, {
            "memory_available_mb": 3000,
            "disk_available_gb": 100,
            "alpine_image_present": True,
            "protected_floci_absent": True,
            "protected_test_absent": True,
            "protected_data_absent": True,
            "isolation_verified": True,
            "podman_version": "4.9.3",
        })):
            with patch("scripts.validate_100_containers.create_100_containers", return_value=(False, [], "Simulated creation failure")):
                with patch("scripts.validate_100_containers.cleanup_100_containers", return_value=(0, [])) as mock_cleanup:
                    with patch("scripts.validate_100_containers.verify_post_cleanup", return_value=(True, {"cleanup_complete": True, "remaining_test_containers": 0})) as mock_verify:
                        with patch("sys.argv", ["validate_100_containers.py", "--execute"]):
                            with self.assertRaises(SystemExit) as cm:
                                main()
                            self.assertEqual(cm.exception.code, 1)
                            mock_cleanup.assert_called_once()
                            mock_verify.assert_called_once()

    def test_main_post_cleanup_failure_exits_nonzero(self):
        """If verify_post_cleanup reports remaining containers, main() exits nonzero."""
        with patch("scripts.validate_100_containers.check_preflight_readiness", return_value=(True, {
            "memory_available_mb": 3000,
            "disk_available_gb": 100,
            "alpine_image_present": True,
            "protected_floci_absent": True,
            "protected_test_absent": True,
            "protected_data_absent": True,
            "isolation_verified": True,
            "podman_version": "4.9.3",
        })):
            with patch("scripts.validate_100_containers.create_100_containers", return_value=(False, [], "Creation error")):
                with patch("scripts.validate_100_containers.cleanup_100_containers", return_value=(1, ["error deleting c2"])):
                    with patch("scripts.validate_100_containers.verify_post_cleanup", return_value=(False, {"cleanup_complete": False, "remaining_test_containers": 1})):
                        with patch("sys.argv", ["validate_100_containers.py", "--execute"]):
                            with self.assertRaises(SystemExit) as cm:
                                main()
    def test_cleanup_running_healthy_and_unhealthy_containers_with_immediate_stop(self):
        """Cleanup removes healthy_running and healthcheck_failing containers using immediate-stop (-t 0 -f) and 25s timeout."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_data = {
                "run_id": "run_test_healthy_unhealthy",
                "mode": "LIVE_EXECUTION",
                "containers": [
                    {"name": "linuxops-p9-run_test-001", "full_id": "cid_healthy_1", "id": "cid_healthy_1", "scenario": "healthy_running"},
                    {"name": "linuxops-p9-run_test-002", "full_id": "cid_healthy_2", "id": "cid_healthy_2", "scenario": "healthy_running"},
                    {"name": "linuxops-p9-run_test-099", "full_id": "cid_unhealthy_99", "id": "cid_unhealthy_99", "scenario": "healthcheck_failing"},
                    {"name": "linuxops-p9-run_test-100", "full_id": "cid_unhealthy_100", "id": "cid_unhealthy_100", "scenario": "healthcheck_failing"},
                ],
            }
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

            removed, errs = cleanup_100_containers(manifest_path=manifest_path, run_id="run_test_healthy_unhealthy", runner=mock_runner)

            self.assertEqual(removed, 4)
            self.assertEqual(len(errs), 0)
            for cid in ["cid_healthy_1", "cid_healthy_2", "cid_unhealthy_99", "cid_unhealthy_100"]:
                mock_runner.assert_any_call(
                    ["podman", "rm", "-t", "0", "-f", cid],
                    capture_output=True,
                    text=True,
                    timeout=25.0,
                    check=False,
                )

    def test_cleanup_stopped_and_failed_containers(self):
        """Cleanup removes stopped_normal, nonzero_exit, crash_loop, and oom_killed containers."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_data = {
                "run_id": "run_test_stopped_failed",
                "mode": "LIVE_EXECUTION",
                "containers": [
                    {"name": "linuxops-p9-test-stopped", "full_id": "cid_stopped", "id": "cid_stopped", "scenario": "stopped_normal"},
                    {"name": "linuxops-p9-test-nonzero", "full_id": "cid_nonzero", "id": "cid_nonzero", "scenario": "nonzero_exit"},
                    {"name": "linuxops-p9-test-crashloop", "full_id": "cid_crashloop", "id": "cid_crashloop", "scenario": "crash_loop"},
                    {"name": "linuxops-p9-test-oom", "full_id": "cid_oom", "id": "cid_oom", "scenario": "oom_killed"},
                ],
            }
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

            removed, errs = cleanup_100_containers(manifest_path=manifest_path, run_id="run_test_stopped_failed", runner=mock_runner)

            self.assertEqual(removed, 4)
            self.assertEqual(len(errs), 0)
            for cid in ["cid_stopped", "cid_nonzero", "cid_crashloop", "cid_oom"]:
                mock_runner.assert_any_call(
                    ["podman", "rm", "-t", "0", "-f", cid],
                    capture_output=True,
                    text=True,
                    timeout=25.0,
                    check=False,
                )

    def test_cleanup_handles_command_timeout_and_removal_failure(self):
        """Cleanup properly records TimeoutExpired exceptions and non-zero podman returncodes without halting remaining cleanups."""
        mock_runner = MagicMock()

        def runner_side_effect(cmd, **kwargs):
            res = MagicMock()
            if "ps" in cmd:
                res.returncode = 0
                res.stdout = ""
                return res
            if "rm" in cmd:
                if "cid_timeout" in cmd:
                    raise subprocess.TimeoutExpired(cmd, 25.0)
                elif "cid_fail" in cmd:
                    res.returncode = 1
                    res.stderr = "Error: container storage lock acquired by another process"
                    return res
                else:
                    res.returncode = 0
                    res.stderr = ""
                    return res
            res.returncode = 0
            return res

        mock_runner.side_effect = runner_side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_data = {
                "run_id": "run_test_failures",
                "mode": "LIVE_EXECUTION",
                "containers": [
                    {"name": "linuxops-p9-test-ok1", "full_id": "cid_ok1", "id": "cid_ok1"},
                    {"name": "linuxops-p9-test-timeout", "full_id": "cid_timeout", "id": "cid_timeout"},
                    {"name": "linuxops-p9-test-fail", "full_id": "cid_fail", "id": "cid_fail"},
                    {"name": "linuxops-p9-test-ok2", "full_id": "cid_ok2", "id": "cid_ok2"},
                ],
            }
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

            removed, errs = cleanup_100_containers(manifest_path=manifest_path, run_id="run_test_failures", runner=mock_runner)

            self.assertEqual(removed, 2)
            self.assertEqual(len(errs), 2)
            self.assertTrue(any("timed out" in e.lower() or "timeout" in e.lower() for e in errs))
            self.assertTrue(any("container storage lock" in e for e in errs))

    def test_post_cleanup_verification_detects_leftovers_and_errors(self):
        """verify_post_cleanup detects leftover test containers and marks cleanup incomplete."""
        mock_runner = MagicMock()

        def runner_side_effect(cmd, **kwargs):
            res = MagicMock()
            res.returncode = 0
            if "version" in cmd:
                res.stdout = "4.9.3"
            elif "exists" in cmd:
                res.returncode = 0
            elif "ps" in cmd and "--filter" in cmd:
                # 3 test containers remained after cleanup
                res.stdout = "cid_leftover_1\ncid_leftover_2\ncid_leftover_3\n"
            elif "ps" in cmd:
                res.stdout = ""
            return res

        mock_runner.side_effect = runner_side_effect

        with patch("scripts.validate_100_containers.is_protected_data_present", return_value=False):
            all_clean, details = verify_post_cleanup(run_id="run_with_leftovers", runner=mock_runner)
            self.assertFalse(all_clean)
            self.assertFalse(details["cleanup_complete"])
            self.assertEqual(details["remaining_test_containers"], 3)

    def test_cleanup_targets_only_specified_run_and_preserves_others(self):
        """Cleanup filters strictly by the target run ID and ignores containers from other runs or untagged workloads."""
        mock_runner = MagicMock()

        def runner_side_effect(cmd, **kwargs):
            res = MagicMock()
            res.returncode = 0
            if "ps" in cmd:
                if "label=linuxops.run-id=run_target" in " ".join(cmd):
                    res.stdout = "cid_target_01 linuxops-p9-run_target-001\ncid_target_02 linuxops-p9-run_target-002\n"
                elif "label=linuxops.run-id=run_other" in " ".join(cmd):
                    res.stdout = "cid_other_01 linuxops-p9-run_other-001\n"
                else:
                    res.stdout = ""
            return res

        mock_runner.side_effect = runner_side_effect

        removed, errs = cleanup_100_containers(run_id="run_target", runner=mock_runner)

        self.assertEqual(removed, 2)
        self.assertEqual(len(errs), 0)

        mock_runner.assert_any_call(
            ["podman", "rm", "-t", "0", "-f", "cid_target_01"],
            capture_output=True,
            text=True,
            timeout=25.0,
            check=False,
        )
        mock_runner.assert_any_call(
            ["podman", "rm", "-t", "0", "-f", "cid_target_02"],
            capture_output=True,
            text=True,
            timeout=25.0,
            check=False,
        )
        for call_args in mock_runner.call_args_list:
            cmd = call_args[0][0]
            self.assertNotIn("cid_other_01", cmd)

    def test_cleanup_handles_malformed_manifest_without_crash(self):
        """Cleanup handles malformed JSON in manifest file and reports error gracefully."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "corrupt_manifest.json"
            manifest_path.write_text("{ malformed json invalid syntax ...", encoding="utf-8")

            removed, errs = cleanup_100_containers(manifest_path=manifest_path, runner=mock_runner)

            self.assertEqual(removed, 0)
            self.assertEqual(len(errs), 1)
            self.assertIn("Error reading manifest", errs[0])
            mock_runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()

