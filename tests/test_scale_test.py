#!/usr/bin/env python3

"""
Unit tests for LinuxOps Safe Scale-Test Harness (Phase 1, Step 1J).

Strict Safety:
All tests use mock runners and temporary directories.
Tests NEVER invoke real Podman container lifecycle operations or modify real systems.
"""

import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from scripts import scale_test


def make_mock_floci_inspect(
    container_id="510d4cfc0d22abcdef123456",
    image="docker.io/floci/floci:latest",
    systemd_unit="cloudops-floci.service",
    mount_source="/home/neha/cloudops-sentinel/data",
    mount_destination="/app/data",
    mounts=None,
):
    """Generate a valid or customized podman inspect response dictionary for cloudops-floci."""
    if mounts is None:
        mounts = [
            {
                "Type": "bind",
                "Source": mount_source,
                "Destination": mount_destination,
                "RW": True,
            }
        ]
    return [{
        "Id": container_id,
        "ImageName": image,
        "Config": {
            "Image": image,
            "Labels": {
                "PODMAN_SYSTEMD_UNIT": systemd_unit,
            },
        },
        "Mounts": mounts,
    }]


def make_default_cli_runner(
    floci_id="510d4cfc0d22abcdef123456",
    recovery_ui_id="83b65d88a0a9abcdef123456",
):
    """Generate a mock runner that satisfies all preflight checks including Floci inspect."""
    mock_runner = MagicMock()
    mock_runner.return_value.returncode = 0

    def side_effect(cmd, **kwargs):
        res = MagicMock()
        res.returncode = 0
        if cmd[1] == "--version":
            res.stdout = "podman version 5.8.4"
        elif cmd[1:3] == ["image", "exists"]:
            res.stdout = ""
        elif cmd[1:4] == ["ps", "-a", "--format"]:
            res.stdout = json.dumps([
                {"Names": ["cloudops-floci"], "Id": floci_id},
                {"Names": ["linuxops-recovery-ui-test"], "Id": recovery_ui_id},
            ])
        elif cmd[1] == "inspect":
            res.stdout = json.dumps(make_mock_floci_inspect(container_id=cmd[2]))
        return res

    mock_runner.side_effect = side_effect
    return mock_runner


class TestHarnessDefaultsAndCLI(unittest.TestCase):
    """Test CLI argument parsing, safe defaults, and count restrictions."""

    def test_default_dry_run_makes_no_changes(self):
        """Executing without arguments defaults to dry-run: no containers created, no manifest written."""
        mock_runner = make_default_cli_runner()

        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_dir = Path(tmp_dir)
            with patch("scripts.scale_test.subprocess.run", mock_runner), \
                 patch("sys.stdout", new_callable=io.StringIO):
                code = scale_test.main(["--manifest-dir", str(manifest_dir)], runner=mock_runner)
                self.assertEqual(code, 0)

            created_files = list(manifest_dir.glob("*.json"))
            self.assertEqual(len(created_files), 0)

            for call_item in mock_runner.call_args_list:
                cmd = call_item[0][0]
                self.assertNotIn("run", cmd)
                self.assertNotIn("rm", cmd)

    def test_refusal_to_execute_without_explicit_flag(self):
        """Even with --count 10, omitting --execute must remain in dry-run mode."""
        mock_runner = make_default_cli_runner()
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_dir = Path(tmp_dir)
            with patch("scripts.scale_test.execute_scale_creation") as mock_exec, \
                 patch("scripts.scale_test.subprocess.run", mock_runner), \
                 patch("sys.stdout", new_callable=io.StringIO):
                code = scale_test.main(["--count", "10", "--manifest-dir", str(manifest_dir)], runner=mock_runner)
                self.assertEqual(code, 0)
                mock_exec.assert_not_called()

    def test_count_restriction_rejects_non_10_counts(self):
        """The harness strictly enforces count == 10 for this version, rejecting any other number."""
        for invalid_count in [0, 1, 5, 9, 11, 20, 50, 100, -1]:
            with self.subTest(count=invalid_count):
                with patch("sys.stderr", new_callable=io.StringIO):
                    code = scale_test.main(["--execute", "--count", str(invalid_count)])
                    self.assertEqual(code, 1)

    def test_dry_run_returns_nonzero_when_preflight_fails(self):
        """When preflight checks fail, dry-run must return a nonzero exit status to fail closed."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps([])  # Missing protected containers!
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_dir = Path(tmp_dir)
            with patch("scripts.scale_test.subprocess.run", mock_runner), \
                 patch("sys.stdout", new_callable=io.StringIO):
                code = scale_test.main(["--manifest-dir", str(manifest_dir)], runner=mock_runner)
                self.assertEqual(code, 1)


class TestIdentitiesAndNaming(unittest.TestCase):
    """Test unique identity generation, naming regex patterns, and protection rules."""

    def test_run_id_format(self):
        """Run ID must be timestamp-based and contain randomized characters."""
        run_id = scale_test.generate_run_id()
        self.assertRegex(run_id, r"^[0-9]{8}_[0-9]{6}_[0-9a-f]{8}$")

    def test_generated_container_names_match_regex(self):
        """Generated container names must match ^linuxops-test-<RUN_ID>-[0-9]{3}$."""
        run_id = "20261020_195500_a1b2c3d4"
        names = scale_test.generate_container_names(run_id, count=10)
        self.assertEqual(len(names), 10)
        self.assertEqual(names[0], f"linuxops-test-{run_id}-001")
        self.assertEqual(names[9], f"linuxops-test-{run_id}-010")

        for name in names:
            self.assertTrue(scale_test.validate_container_name(name, run_id))
            self.assertTrue(scale_test.is_test_container_name(name))

    def test_protected_container_recognition(self):
        """Known protected containers must be identified by name and ID prefix."""
        self.assertTrue(scale_test.is_protected_container("cloudops-floci", "510d4cfc0d221234"))
        self.assertTrue(scale_test.is_protected_container("linuxops-recovery-ui-test", "83b65d88a0a95678"))
        self.assertTrue(scale_test.is_protected_container("other-name", "510d4cfc0d220000"))
        self.assertTrue(scale_test.is_protected_container("cloudops-floci", "different_id"))

        self.assertFalse(scale_test.is_protected_container("linuxops-test-run1-001", "abcdef123456"))


class TestProtectedContainerIdentityVerification(unittest.TestCase):
    """Tests for Phase B/C: validating robust identity and configuration of protected containers."""

    def test_protected_inventory_correct_name_and_id(self):
        """Verification succeeds when all protected containers have expected names and matching IDs."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "510d4cfc0d22abcdef123456"},
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a9abcdef123456"},
        ]
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps(make_mock_floci_inspect("510d4cfc0d22abcdef123456"))
        ok, errors = scale_test.verify_protected_inventory(containers, runner=mock_runner)
        self.assertTrue(ok)
        self.assertEqual(errors, [])

    def test_floci_replacement_new_id_passes(self):
        """Legitimate Floci container with the expected configuration and a new ID passes."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3"},
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a9abcdef123456"},
        ]
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps(make_mock_floci_inspect("db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3"))
        ok, errors = scale_test.verify_protected_inventory(containers, runner=mock_runner)
        self.assertTrue(ok)
        self.assertEqual(errors, [])

    def test_floci_incorrect_image_fails(self):
        """Correct Floci name but incorrect image fails."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3"},
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a9abcdef123456"},
        ]
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps(make_mock_floci_inspect(
            container_id="db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3",
            image="docker.io/library/alpine:latest",
        ))
        ok, errors = scale_test.verify_protected_inventory(containers, runner=mock_runner)
        self.assertFalse(ok)
        self.assertTrue(any("Image mismatch" in e for e in errors))

    def test_floci_incorrect_systemd_label_fails(self):
        """Correct name but incorrect systemd label fails."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3"},
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a9abcdef123456"},
        ]
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps(make_mock_floci_inspect(
            container_id="db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3",
            systemd_unit="wrong.service",
        ))
        ok, errors = scale_test.verify_protected_inventory(containers, runner=mock_runner)
        self.assertFalse(ok)
        self.assertTrue(any("Systemd unit label mismatch" in e for e in errors))

    def test_floci_missing_expected_persistent_mount_fails(self):
        """Missing expected persistent mount fails."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3"},
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a9abcdef123456"},
        ]
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps(make_mock_floci_inspect(
            container_id="db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3",
            mounts=[],
        ))
        ok, errors = scale_test.verify_protected_inventory(containers, runner=mock_runner)
        self.assertFalse(ok)
        self.assertTrue(any("Missing expected persistent mount" in e for e in errors))

    def test_floci_wrong_mount_source_or_destination_fails(self):
        """Wrong mount source or destination fails."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3"},
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a9abcdef123456"},
        ]
        # Case A: Wrong source
        mock_runner_src = MagicMock()
        mock_runner_src.return_value.returncode = 0
        mock_runner_src.return_value.stdout = json.dumps(make_mock_floci_inspect(
            container_id="db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3",
            mount_source="/wrong/source/data",
            mount_destination="/app/data",
        ))
        ok_src, errors_src = scale_test.verify_protected_inventory(containers, runner=mock_runner_src)
        self.assertFalse(ok_src)
        self.assertTrue(any("Mount source mismatch" in e for e in errors_src))

        # Case B: Wrong destination
        mock_runner_dst = MagicMock()
        mock_runner_dst.return_value.returncode = 0
        mock_runner_dst.return_value.stdout = json.dumps(make_mock_floci_inspect(
            container_id="db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3",
            mount_source="/home/neha/cloudops-sentinel/data",
            mount_destination="/wrong/destination",
        ))
        ok_dst, errors_dst = scale_test.verify_protected_inventory(containers, runner=mock_runner_dst)
        self.assertFalse(ok_dst)
        self.assertTrue(any("Missing expected persistent mount" in e for e in errors_dst))

    def test_floci_podman_inspect_failure_or_timeout_fails_closed(self):
        """Podman inspect failure or timeout fails closed."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3"},
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a9abcdef123456"},
        ]
        # Timeout
        mock_runner_timeout = MagicMock(side_effect=scale_test.subprocess.TimeoutExpired(["podman", "inspect"], 10.0))
        ok_timeout, errors_timeout = scale_test.verify_protected_inventory(containers, runner=mock_runner_timeout)
        self.assertFalse(ok_timeout)
        self.assertTrue(any("timed out" in e.lower() or "inspect failed" in e.lower() for e in errors_timeout))

        # Daemon error
        mock_runner_err = MagicMock(side_effect=scale_test.subprocess.CalledProcessError(1, ["podman", "inspect"], stderr="daemon error"))
        ok_err, errors_err = scale_test.verify_protected_inventory(containers, runner=mock_runner_err)
        self.assertFalse(ok_err)
        self.assertTrue(any("inspect failed" in e.lower() for e in errors_err))

    def test_floci_malformed_inspect_json_fails_closed(self):
        """Malformed inspect JSON fails closed."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3"},
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a9abcdef123456"},
        ]
        # Malformed JSON
        mock_runner_malformed = MagicMock()
        mock_runner_malformed.return_value.returncode = 0
        mock_runner_malformed.return_value.stdout = "{not valid json syntax"
        ok_mal, errors_mal = scale_test.verify_protected_inventory(containers, runner=mock_runner_malformed)
        self.assertFalse(ok_mal)
        self.assertTrue(any("inspect failed" in e.lower() or "json" in e.lower() for e in errors_mal))

        # Empty data structure
        mock_runner_empty = MagicMock()
        mock_runner_empty.return_value.returncode = 0
        mock_runner_empty.return_value.stdout = "[]"
        ok_emp, errors_emp = scale_test.verify_protected_inventory(containers, runner=mock_runner_empty)
        self.assertFalse(ok_emp)
        self.assertTrue(any("inspect failed" in e.lower() or "malformed" in e.lower() for e in errors_emp))

    def test_protected_inventory_recovery_ui_unexpected_id(self):
        """Verification fails if recovery UI container ID prefix does not match expected prefix."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "510d4cfc0d22abcdef123456"},
            {"Names": ["linuxops-recovery-ui-test"], "Id": "999999999999abcdef123456"},  # Unexpected ID!
        ]
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps(make_mock_floci_inspect("510d4cfc0d22abcdef123456"))
        ok, errors = scale_test.verify_protected_inventory(containers, runner=mock_runner)
        self.assertFalse(ok)
        self.assertTrue(any("Identity mismatch for 'linuxops-recovery-ui-test'" in e for e in errors))

    def test_protected_inventory_expected_id_wrong_name(self):
        """Verification fails if container ID matches but name is altered."""
        containers = [
            {"Names": ["impostor-floci"], "Id": "510d4cfc0d22abcdef123456"},  # Wrong name!
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a9abcdef123456"},
        ]
        ok, errors = scale_test.verify_protected_inventory(containers)
        self.assertFalse(ok)
        self.assertTrue(any("was not found" in e or "Identity mismatch" in e for e in errors))

    def test_protected_inventory_missing_container(self):
        """Verification fails if any protected container is missing entirely."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "510d4cfc0d22abcdef123456"},
            # linuxops-recovery-ui-test is missing!
        ]
        ok, errors = scale_test.verify_protected_inventory(containers)
        self.assertFalse(ok)
        self.assertTrue(any("linuxops-recovery-ui-test" in e for e in errors))

    def test_protected_inventory_duplicate_identities(self):
        """Verification fails closed if duplicate containers share a protected name."""
        containers = [
            {"Names": ["cloudops-floci"], "Id": "510d4cfc0d22abcdef123456"},
            {"Names": ["cloudops-floci"], "Id": "510d4cfc0d22999999999999"},  # Duplicate name!
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a9abcdef123456"},
        ]
        ok, errors = scale_test.verify_protected_inventory(containers)
        self.assertFalse(ok)
        self.assertTrue(any("duplicate" in e.lower() for e in errors))


class TestPreflightChecks(unittest.TestCase):
    """Test preflight validation gates (Podman responsiveness, images, resources, inventory)."""

    def test_podman_unresponsive_aborts_execution(self):
        """Unresponsive Podman CLI aborts execution."""
        with patch("scripts.scale_test.check_podman_responsive", return_value=(False, "Timeout", 5.0)), \
             patch("sys.stderr", new_callable=io.StringIO):
            code = scale_test.main(["--execute", "--count", "10"])
            self.assertEqual(code, 1)

    def test_missing_local_image_aborts_execution(self):
        """Missing local Alpine image aborts execution without pulling."""
        with patch("scripts.scale_test.check_podman_responsive", return_value=(True, "5.8.4", 0.05)), \
             patch("scripts.scale_test.check_local_image_exists", return_value=(False, "Image not found")), \
             patch("sys.stderr", new_callable=io.StringIO):
            code = scale_test.main(["--execute", "--count", "10"])
            self.assertEqual(code, 1)

    def test_insufficient_memory_aborts_execution(self):
        """Host available memory below 1500 MiB aborts execution."""
        fake_meminfo = "MemTotal:        4000000 kB\nMemAvailable:     800000 kB\n"  # ~781 MiB
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as f:
            f.write(fake_meminfo)
            f.flush()
            passed, details = scale_test.check_system_resources(
                min_mem_mb=1500.0,
                min_disk_gb=20.0,
                proc_meminfo_path=f.name,
            )
            self.assertFalse(passed)
            self.assertFalse(details["mem_ok"])

    def test_insufficient_disk_aborts_execution(self):
        """Host available disk space below 20 GiB aborts execution."""
        from collections import namedtuple
        DiskUsage = namedtuple("DiskUsage", ["total", "used", "free"])
        with patch("shutil.disk_usage", return_value=DiskUsage(100 * 1024**3, 90 * 1024**3, 10 * 1024**3)):  # 10 GiB free
            passed, details = scale_test.check_system_resources(min_disk_gb=20.0)
            self.assertFalse(passed)
            self.assertFalse(details["disk_ok"])

    def test_existing_test_prefix_containers_aborts_execution(self):
        """Any pre-existing test container fails preflight closed."""
        existing = [
            {"Names": ["cloudops-floci"], "Id": "510d4cfc0d221234"},
            {"Names": ["linuxops-recovery-ui-test"], "Id": "83b65d88a0a95678"},
            {"Names": ["linuxops-test-leftover-001"], "Id": "aabbccddeeff"},
        ]
        conflicts = scale_test.check_conflicting_test_containers(existing)
        self.assertEqual(len(conflicts), 1)
        self.assertIn("linuxops-test-leftover-001", conflicts)


class TestCreationAndManifest(unittest.TestCase):
    """Test simulated container creation, command construction, and atomic manifest updates."""

    def test_single_container_creation_command_construction(self):
        """Verifies strict flags: --pull=never, --memory=32m, --memory-swap=32m, --cpus=0.05, labels."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = "c1234567890abcdef"

        ok, cid, err = scale_test.create_single_container(
            name="linuxops-test-r1-001",
            run_id="r1",
            image="docker.io/library/alpine:latest",
            runner=mock_runner,
        )

        self.assertTrue(ok)
        self.assertEqual(cid, "c1234567890abcdef")
        self.assertEqual(err, "")

        mock_runner.assert_called_once()
        cmd = mock_runner.call_args[0][0]
        self.assertEqual(cmd[0], "podman")
        self.assertEqual(cmd[1], "run")
        self.assertIn("-d", cmd)
        self.assertIn("--pull=never", cmd)
        self.assertIn("--name", cmd)
        self.assertIn("linuxops-test-r1-001", cmd)
        self.assertIn("--label", cmd)
        self.assertIn("linuxops.scale-test=true", cmd)
        self.assertIn("linuxops.test-run-id=r1", cmd)
        self.assertIn("--memory=32m", cmd)
        self.assertIn("--memory-swap=32m", cmd)
        self.assertIn("--cpus=0.05", cmd)
        self.assertIn("sleep", cmd)
        self.assertIn("3600", cmd)

    def test_successful_10_container_creation_and_atomic_manifest(self):
        """Creation writes manifest atomically after each container, completing 10 items."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = "cid_mock"

        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_dir = Path(tmp_dir)
            ok, m_path, m_data = scale_test.execute_scale_creation(
                run_id="run_complete",
                count=10,
                manifest_dir=manifest_dir,
                runner=mock_runner,
            )

            self.assertTrue(ok)
            self.assertTrue(m_path.exists())
            self.assertEqual(len(m_data["containers"]), 10)
            self.assertEqual(m_data["status"], "completed")
            self.assertEqual(mock_runner.call_count, 10)

            saved = scale_test.load_manifest(m_path)
            self.assertEqual(saved["target_count"], 10)
            self.assertEqual(len(saved["containers"]), 10)

    def test_creation_failure_stops_immediately_and_preserves_partial_manifest(self):
        """Failure on container 4 halts creation immediately and records partial state."""
        call_count = 0

        def mock_run(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 4:
                raise scale_test.subprocess.CalledProcessError(125, cmd, stderr="Simulated OOM or daemon error")
            res = MagicMock()
            res.returncode = 0
            res.stdout = f"cid_{call_count}"
            return res

        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_dir = Path(tmp_dir)
            ok, m_path, m_data = scale_test.execute_scale_creation(
                run_id="run_partial",
                count=10,
                manifest_dir=manifest_dir,
                runner=mock_run,
            )

            self.assertFalse(ok)
            self.assertEqual(call_count, 4)
            self.assertEqual(len(m_data["containers"]), 4)
            self.assertEqual(m_data["status"], "partial_failure")
            self.assertFalse(m_data["containers"][3]["success"])

            saved = scale_test.load_manifest(m_path)
            self.assertEqual(saved["status"], "partial_failure")
            self.assertEqual(len(saved["containers"]), 4)


class TestInternalCountEnforcement(unittest.TestCase):
    """Tests for Fix 4: execute_scale_creation independently enforces count == 10 and max cap."""

    def test_execute_scale_creation_rejects_counts_below_10(self):
        """Calling execute_scale_creation directly with count < 10 fails before creation."""
        mock_runner = MagicMock()
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_dir = Path(tmp_dir)
            ok, m_path, m_data = scale_test.execute_scale_creation(
                run_id="run_bad_low",
                count=5,
                manifest_dir=manifest_dir,
                runner=mock_runner,
            )
            self.assertFalse(ok)
            self.assertEqual(m_data["status"], "rejected_invalid_count")
            mock_runner.assert_not_called()
            self.assertFalse(m_path.exists())

    def test_execute_scale_creation_rejects_counts_above_10(self):
        """Calling execute_scale_creation directly with count > 10 fails before creation."""
        mock_runner = MagicMock()
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_dir = Path(tmp_dir)
            ok, m_path, m_data = scale_test.execute_scale_creation(
                run_id="run_bad_high",
                count=20,
                manifest_dir=manifest_dir,
                runner=mock_runner,
            )
            self.assertFalse(ok)
            self.assertEqual(m_data["status"], "rejected_invalid_count")
            mock_runner.assert_not_called()
            self.assertFalse(m_path.exists())

    def test_execute_scale_creation_rejects_count_100_programmatically(self):
        """Programmatic attempt to launch 100 containers fails without lifecycle calls."""
        mock_runner = MagicMock()
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_dir = Path(tmp_dir)
            ok, m_path, m_data = scale_test.execute_scale_creation(
                run_id="run_bad_100",
                count=100,
                manifest_dir=manifest_dir,
                runner=mock_runner,
            )
            self.assertFalse(ok)
            self.assertEqual(m_data["status"], "rejected_invalid_count")
            mock_runner.assert_not_called()
            self.assertFalse(m_path.exists())


class TestAtomicWriteFailureHandling(unittest.TestCase):
    """Tests for Fix 5: temporary files cleaned up on failure, existing manifest preserved."""

    def test_atomic_write_cleans_up_temp_file_on_serialization_failure(self):
        """If serialization fails, temp file is deleted and error is raised."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "manifest.json"
            unserializable = {"bad": object()}

            with self.assertRaises(TypeError):
                scale_test.write_manifest_atomically(target, unserializable)

            self.assertFalse(target.exists())
            leftover_tmps = list(Path(tmp_dir).glob("*.tmp*"))
            self.assertEqual(len(leftover_tmps), 0)

    def test_atomic_write_preserves_existing_manifest_on_fsync_failure(self):
        """If fsync fails, original manifest is preserved intact and temp file is cleaned up."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "manifest.json"
            initial_data = {"version": 1, "status": "preserved"}
            scale_test.write_manifest_atomically(target, initial_data)
            self.assertTrue(target.exists())

            # Simulate fsync raising OSError
            with patch("os.fsync", side_effect=OSError("Disk I/O error")):
                with self.assertRaises(OSError):
                    scale_test.write_manifest_atomically(target, {"version": 2})

            # Original manifest must still exist and be intact
            saved = scale_test.load_manifest(target)
            self.assertEqual(saved["version"], 1)
            self.assertEqual(saved["status"], "preserved")

            leftover_tmps = list(Path(tmp_dir).glob("*.tmp*"))
            self.assertEqual(len(leftover_tmps), 0)

    def test_atomic_write_preserves_existing_manifest_on_replace_failure(self):
        """If os.replace fails, original manifest is preserved intact and temp file is cleaned up."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "manifest.json"
            initial_data = {"version": 1, "status": "original"}
            scale_test.write_manifest_atomically(target, initial_data)

            # Simulate os.replace raising PermissionError
            with patch("os.replace", side_effect=PermissionError("Access denied")):
                with self.assertRaises(PermissionError):
                    scale_test.write_manifest_atomically(target, {"version": 2})

            saved = scale_test.load_manifest(target)
            self.assertEqual(saved["version"], 1)

            leftover_tmps = list(Path(tmp_dir).glob("*.tmp*"))
            self.assertEqual(len(leftover_tmps), 0)


class TestManifestPathValidation(unittest.TestCase):
    """Tests for Fix 3: validate_manifest_path enforces logs/ containment and filename pattern."""

    def test_valid_manifest_path_accepted(self):
        """Valid scale_test_manifest_<RUN_ID>.json inside trusted directory is accepted."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            trusted_dir = Path(tmp_dir)
            manifest_file = trusted_dir / "scale_test_manifest_20261020_195500_a1b2c3d4.json"
            manifest_file.write_text('{"run_id": "test"}', encoding="utf-8")

            ok, resolved, err = scale_test.validate_manifest_path(manifest_file, trusted_dir=trusted_dir)
            self.assertTrue(ok)
            self.assertEqual(resolved, manifest_file.resolve())
            self.assertEqual(err, "")

    def test_invalid_filename_pattern_rejected(self):
        """Filenames not matching scale_test_manifest_*.json are rejected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            trusted_dir = Path(tmp_dir)
            bad_file = trusted_dir / "metrics.json"
            bad_file.write_text("{}", encoding="utf-8")

            ok, resolved, err = scale_test.validate_manifest_path(bad_file, trusted_dir=trusted_dir)
            self.assertFalse(ok)
            self.assertIn("Invalid manifest filename", err)

    def test_path_traversal_attempt_rejected(self):
        """Traversal attempts escaping trusted directory are rejected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            trusted_dir = Path(tmp_dir) / "trusted_logs"
            trusted_dir.mkdir()
            outside_file = Path(tmp_dir) / "scale_test_manifest_escape.json"
            outside_file.write_text("{}", encoding="utf-8")

            # Attempt traversal: trusted_logs/../scale_test_manifest_escape.json
            traversal_path = trusted_dir / ".." / "scale_test_manifest_escape.json"
            ok, resolved, err = scale_test.validate_manifest_path(traversal_path, trusted_dir=trusted_dir)
            self.assertFalse(ok)
            self.assertIn("escapes trusted directory", err)

    def test_directory_rejected_as_manifest(self):
        """A directory with matching manifest name is rejected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            trusted_dir = Path(tmp_dir)
            dir_as_manifest = trusted_dir / "scale_test_manifest_fake.json"
            dir_as_manifest.mkdir()

            ok, resolved, err = scale_test.validate_manifest_path(dir_as_manifest, trusted_dir=trusted_dir)
            self.assertFalse(ok)
            self.assertIn("is a directory", err)

    def test_symlink_rejected_as_manifest(self):
        """Symlinks are rejected for safety."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            trusted_dir = Path(tmp_dir)
            real_file = trusted_dir / "real.json"
            real_file.write_text("{}", encoding="utf-8")
            symlink_manifest = trusted_dir / "scale_test_manifest_sym.json"
            try:
                symlink_manifest.symlink_to(real_file)
            except OSError:
                self.skipTest("Symlinks not supported in environment")

            ok, resolved, err = scale_test.validate_manifest_path(symlink_manifest, trusted_dir=trusted_dir)
            self.assertFalse(ok)
            self.assertIn("symlink", err.lower())

    def test_outside_directory_manifest_path_rejected(self):
        """Manifest paths located outside the trusted directory are rejected."""
        with tempfile.TemporaryDirectory() as trusted_tmp, tempfile.TemporaryDirectory() as outside_tmp:
            trusted_dir = Path(trusted_tmp)
            outside_file = Path(outside_tmp) / "scale_test_manifest_20261020_200000_11223344.json"
            outside_file.write_text("{}", encoding="utf-8")

            ok, resolved, err = scale_test.validate_manifest_path(outside_file, trusted_dir=trusted_dir)
            self.assertFalse(ok)
            self.assertIn("escapes trusted directory", err)


class TestManifestSchemaValidation(unittest.TestCase):
    """Tests for Fix 6: validate_manifest_schema rejects malformed manifests fail-closed."""

    def test_valid_manifest_schema_accepted(self):
        """Well-formed manifest passes schema validation."""
        data = {
            "run_id": "20261020_200000_12345678",
            "containers": [
                {
                    "name": "linuxops-test-20261020_200000_12345678-001",
                    "id": "cid1234567890ab",
                    "success": True,
                }
            ],
        }
        ok, err = scale_test.validate_manifest_schema(data)
        self.assertTrue(ok)
        self.assertEqual(err, "")

    def test_non_dict_root_rejected(self):
        """Non-dictionary manifest root is rejected."""
        ok, err = scale_test.validate_manifest_schema(["list", "not", "dict"])
        self.assertFalse(ok)
        self.assertIn("JSON object", err)

    def test_missing_or_invalid_run_id_rejected(self):
        """Missing or malformed run_id is rejected."""
        ok1, err1 = scale_test.validate_manifest_schema({"containers": []})
        self.assertFalse(ok1)
        self.assertIn("missing valid 'run_id'", err1)

        ok2, err2 = scale_test.validate_manifest_schema({"run_id": "invalid_chars!#$", "containers": []})
        self.assertFalse(ok2)
        self.assertIn("format is invalid", err2)

    def test_wrong_container_list_type_rejected(self):
        """Non-list containers field is rejected."""
        ok, err = scale_test.validate_manifest_schema({"run_id": "20261020_200000_12345678", "containers": "not_a_list"})
        self.assertFalse(ok)
        self.assertIn("must be a list", err)

    def test_malformed_entry_rejected(self):
        """Entries missing success, name, or container ID are rejected."""
        data = {
            "run_id": "20261020_200000_12345678",
            "containers": [{"missing_success": True}],
        }
        ok, err = scale_test.validate_manifest_schema(data)
        self.assertFalse(ok)
        self.assertIn("missing boolean 'success'", err)

    def test_duplicate_container_identities_rejected(self):
        """Duplicate container names or IDs within manifest fail closed."""
        run_id = "20261020_200000_12345678"
        # Duplicate name
        data_dup_name = {
            "run_id": run_id,
            "containers": [
                {"name": f"linuxops-test-{run_id}-001", "id": "cid111111111111", "success": True},
                {"name": f"linuxops-test-{run_id}-001", "id": "cid222222222222", "success": True},
            ],
        }
        ok1, err1 = scale_test.validate_manifest_schema(data_dup_name)
        self.assertFalse(ok1)
        self.assertIn("duplicate container name", err1)

        # Duplicate ID
        data_dup_id = {
            "run_id": run_id,
            "containers": [
                {"name": f"linuxops-test-{run_id}-001", "id": "cid111111111111", "success": True},
                {"name": f"linuxops-test-{run_id}-002", "id": "cid111111111111", "success": True},
            ],
        }
        ok2, err2 = scale_test.validate_manifest_schema(data_dup_id)
        self.assertFalse(ok2)
        self.assertIn("duplicate container ID", err2)

    def test_manifest_referencing_protected_container_rejected(self):
        """Manifest referencing cloudops-floci or linuxops-recovery-ui-test fails closed."""
        run_id = "20261020_200000_12345678"
        data_prot = {
            "run_id": run_id,
            "containers": [
                {"name": "cloudops-floci", "id": "510d4cfc0d221234", "success": True},
            ],
        }
        ok, err = scale_test.validate_manifest_schema(data_prot)
        self.assertFalse(ok)
        self.assertTrue(any(term in err for term in ["convention", "protected"]))

    def test_invalid_json_manifest_file_rejected(self):
        """A manifest file containing malformed JSON syntax is rejected without lifecycle calls."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_file = Path(tmp_dir) / "scale_test_manifest_20261020_200000_12345678.json"
            bad_file.write_text("{not valid json syntax", encoding="utf-8")

            mock_runner = MagicMock()
            ok, msgs = scale_test.execute_manifest_cleanup(bad_file, trusted_dir=Path(tmp_dir), runner=mock_runner)
            self.assertFalse(ok)
            self.assertTrue(any("Failed to load manifest" in m for m in msgs))
            mock_runner.assert_not_called()


class TestCleanupWorkflow(unittest.TestCase):
    """Test targeted manifest cleanup, live inspect validation, idempotent retries, and bulk prohibition."""

    def test_cleanup_success_with_matching_manifest(self):
        """Cleanup removes only manifest-listed containers matching exact ID, name, and labels."""
        run_id = "20261020_200000_12345678"
        manifest_data = {
            "run_id": run_id,
            "containers": [
                {"name": f"linuxops-test-{run_id}-001", "id": "cid_001_123456", "success": True},
                {"name": f"linuxops-test-{run_id}-002", "id": "cid_002_123456", "success": True},
            ],
        }

        inspect_responses = {
            "cid_001_123456": [{
                "Id": "cid_001_123456_full",
                "Name": f"/linuxops-test-{run_id}-001",
                "Config": {"Labels": {"linuxops.scale-test": "true", "linuxops.test-run-id": run_id}},
            }],
            "cid_002_123456": [{
                "Id": "cid_002_123456_full",
                "Name": f"/linuxops-test-{run_id}-002",
                "Config": {"Labels": {"linuxops.scale-test": "true", "linuxops.test-run-id": run_id}},
            }],
        }

        def mock_runner(cmd, **kwargs):
            res = MagicMock()
            res.returncode = 0
            if cmd[1] == "inspect":
                cid = cmd[2]
                res.stdout = json.dumps(inspect_responses[cid])
            elif cmd[1] == "rm":
                self.assertEqual(cmd[1:3], ["rm", "-f"])
                self.assertNotIn("-a", cmd)
                res.stdout = cmd[3]
            return res

        with tempfile.TemporaryDirectory() as tmp_dir:
            m_path = Path(tmp_dir) / f"scale_test_manifest_{run_id}.json"
            scale_test.write_manifest_atomically(m_path, manifest_data)

            ok, msgs = scale_test.execute_manifest_cleanup(m_path, trusted_dir=Path(tmp_dir), runner=mock_runner)
            self.assertTrue(ok)
            self.assertEqual(len([m for m in msgs if "Removed test container" in m]), 2)

    def test_cleanup_idempotent_retry_when_earlier_containers_already_absent(self):
        """Cleanup retry continues safely when earlier manifest entries are confirmed absent."""
        run_id = "20261020_200000_12345678"
        manifest_data = {
            "run_id": run_id,
            "containers": [
                {"name": f"linuxops-test-{run_id}-001", "id": "cid_001_123456", "success": True},  # Already deleted
                {"name": f"linuxops-test-{run_id}-002", "id": "cid_002_123456", "success": True},  # Still running
            ],
        }

        inspect_calls = []

        def mock_runner(cmd, **kwargs):
            if cmd[1] == "inspect":
                cid = cmd[2]
                inspect_calls.append(cid)
                if cid == "cid_001_123456":
                    # Simulate Podman reporting container not found
                    raise scale_test.subprocess.CalledProcessError(125, cmd, stderr="Error: no such container cid_001_123456")
                res = MagicMock()
                res.returncode = 0
                res.stdout = json.dumps([{
                    "Id": "cid_002_123456_full",
                    "Name": f"/linuxops-test-{run_id}-002",
                    "Config": {"Labels": {"linuxops.scale-test": "true", "linuxops.test-run-id": run_id}},
                }])
                return res
            elif cmd[1] == "rm":
                res = MagicMock()
                res.returncode = 0
                res.stdout = cmd[3]
                return res
            raise ValueError(f"Unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp_dir:
            m_path = Path(tmp_dir) / f"scale_test_manifest_{run_id}.json"
            scale_test.write_manifest_atomically(m_path, manifest_data)

            ok, msgs = scale_test.execute_manifest_cleanup(m_path, trusted_dir=Path(tmp_dir), runner=mock_runner)
            self.assertTrue(ok)
            # cid_001 was treated as already absent
            self.assertTrue(any("already absent" in m for m in msgs))
            # cid_002 was inspected and removed
            self.assertTrue(any("Removed test container" in m and "002" in m for m in msgs))
            self.assertEqual(inspect_calls, ["cid_001_123456", "cid_002_123456"])

    def test_cleanup_aborts_on_inspection_daemon_error(self):
        """A daemon or permission failure during inspect must NOT be treated as absent."""
        run_id = "20261020_200000_12345678"
        manifest_data = {
            "run_id": run_id,
            "containers": [
                {"name": f"linuxops-test-{run_id}-001", "id": "cid_001_123456", "success": True},
            ],
        }

        def mock_runner(cmd, **kwargs):
            if cmd[1] == "inspect":
                # Daemon communication error, NOT absence
                raise scale_test.subprocess.CalledProcessError(1, cmd, stderr="Error: connection to podman socket refused")
            raise ValueError(f"Unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp_dir:
            m_path = Path(tmp_dir) / f"scale_test_manifest_{run_id}.json"
            scale_test.write_manifest_atomically(m_path, manifest_data)

            ok, msgs = scale_test.execute_manifest_cleanup(m_path, trusted_dir=Path(tmp_dir), runner=mock_runner)
            self.assertFalse(ok)
            self.assertTrue(any("Cannot verify status" in m for m in msgs))

    def test_cleanup_refusal_on_name_mismatch(self):
        """If container name on host does not match manifest, cleanup aborts."""
        run_id = "20261020_200000_12345678"
        manifest_data = {
            "run_id": run_id,
            "containers": [{"name": f"linuxops-test-{run_id}-001", "id": "cid_001_123456", "success": True}],
        }

        inspect_data = [{
            "Id": "cid_001_123456",
            "Name": "/altered-name",
            "Config": {"Labels": {"linuxops.scale-test": "true", "linuxops.test-run-id": run_id}},
        }]

        def mock_runner(cmd, **kwargs):
            res = MagicMock()
            res.returncode = 0
            if cmd[1] == "inspect":
                res.stdout = json.dumps(inspect_data)
            return res

        with tempfile.TemporaryDirectory() as tmp_dir:
            m_path = Path(tmp_dir) / f"scale_test_manifest_{run_id}.json"
            scale_test.write_manifest_atomically(m_path, manifest_data)

            ok, msgs = scale_test.execute_manifest_cleanup(m_path, trusted_dir=Path(tmp_dir), runner=mock_runner)
            self.assertFalse(ok)
            self.assertTrue(any("Name mismatch" in m for m in msgs))

    def test_cleanup_refusal_on_missing_labels(self):
        """If container lacks scale-test label or run-id label, cleanup aborts."""
        run_id = "20261020_200000_12345678"
        manifest_data = {
            "run_id": run_id,
            "containers": [{"name": f"linuxops-test-{run_id}-001", "id": "cid_001_123456", "success": True}],
        }

        inspect_data = [{
            "Id": "cid_001_123456",
            "Name": f"/linuxops-test-{run_id}-001",
            "Config": {"Labels": {"wrong.label": "true"}},
        }]

        def mock_runner(cmd, **kwargs):
            res = MagicMock()
            res.returncode = 0
            if cmd[1] == "inspect":
                res.stdout = json.dumps(inspect_data)
            return res

        with tempfile.TemporaryDirectory() as tmp_dir:
            m_path = Path(tmp_dir) / f"scale_test_manifest_{run_id}.json"
            scale_test.write_manifest_atomically(m_path, manifest_data)

            ok, msgs = scale_test.execute_manifest_cleanup(m_path, trusted_dir=Path(tmp_dir), runner=mock_runner)
            self.assertFalse(ok)
            self.assertTrue(any("lacks label" in m for m in msgs))

    def test_cleanup_removal_failure_and_subsequent_retry(self):
        """A removal failure safely halts cleanup, and a subsequent retry resumes and completes."""
        run_id = "20261020_200000_12345678"
        manifest_data = {
            "run_id": run_id,
            "containers": [
                {"name": f"linuxops-test-{run_id}-001", "id": "cid_001_123456", "success": True},
                {"name": f"linuxops-test-{run_id}-002", "id": "cid_002_123456", "success": True},
            ],
        }

        # Attempt 1: cid_001 removal fails due to a container engine error
        def mock_runner_attempt1(cmd, **kwargs):
            if cmd[1] == "inspect":
                cid = cmd[2]
                res = MagicMock()
                res.returncode = 0
                idx = "001" if cid == "cid_001_123456" else "002"
                res.stdout = json.dumps([{
                    "Id": f"{cid}_full",
                    "Name": f"/linuxops-test-{run_id}-{idx}",
                    "Config": {"Labels": {"linuxops.scale-test": "true", "linuxops.test-run-id": run_id}},
                }])
                return res
            elif cmd[1] == "rm":
                # Simulated removal failure on first container
                raise scale_test.subprocess.CalledProcessError(1, cmd, stderr="device or resource busy")
            raise ValueError(f"Unexpected command: {cmd}")

        # Attempt 2 (Retry): cid_001 succeeds, cid_002 succeeds
        def mock_runner_attempt2(cmd, **kwargs):
            if cmd[1] == "inspect":
                cid = cmd[2]
                res = MagicMock()
                res.returncode = 0
                idx = "001" if cid == "cid_001_123456" else "002"
                res.stdout = json.dumps([{
                    "Id": f"{cid}_full",
                    "Name": f"/linuxops-test-{run_id}-{idx}",
                    "Config": {"Labels": {"linuxops.scale-test": "true", "linuxops.test-run-id": run_id}},
                }])
                return res
            elif cmd[1] == "rm":
                res = MagicMock()
                res.returncode = 0
                res.stdout = cmd[3]
                return res
            raise ValueError(f"Unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp_dir:
            m_path = Path(tmp_dir) / f"scale_test_manifest_{run_id}.json"
            scale_test.write_manifest_atomically(m_path, manifest_data)

            # First attempt fails at container 1
            ok1, msgs1 = scale_test.execute_manifest_cleanup(m_path, trusted_dir=Path(tmp_dir), runner=mock_runner_attempt1)
            self.assertFalse(ok1)
            self.assertTrue(any("Failed to remove" in m and "001" in m for m in msgs1))
            # Container 2 was NOT removed or attempted
            self.assertFalse(any("Removed test container" in m and "002" in m for m in msgs1))

            # Second attempt (retry) succeeds for both
            ok2, msgs2 = scale_test.execute_manifest_cleanup(m_path, trusted_dir=Path(tmp_dir), runner=mock_runner_attempt2)
            self.assertTrue(ok2)
            self.assertTrue(any("Removed test container" in m and "001" in m for m in msgs2))
            self.assertTrue(any("Removed test container" in m and "002" in m for m in msgs2))

    def test_cleanup_refusal_when_manifest_targets_protected_container(self):
        """Manifest containing a protected container ID or name aborts before any removal."""
        run_id = "20261020_200000_12345678"
        manifest_data = {
            "run_id": run_id,
            "containers": [
                {"name": "cloudops-floci", "id": "510d4cfc0d22abcdef", "success": True},
            ],
        }

        mock_runner = MagicMock()
        with tempfile.TemporaryDirectory() as tmp_dir:
            m_path = Path(tmp_dir) / f"scale_test_manifest_{run_id}.json"
            scale_test.write_manifest_atomically(m_path, manifest_data)

            ok, msgs = scale_test.execute_manifest_cleanup(m_path, trusted_dir=Path(tmp_dir), runner=mock_runner)
            self.assertFalse(ok)
            self.assertTrue(any("protected" in m.lower() for m in msgs))
            mock_runner.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
