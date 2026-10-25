
import subprocess
import unittest
from unittest.mock import patch

from app.recovery import restart_container


class TestContainerRecovery(unittest.TestCase):

    @patch("app.recovery.subprocess.run")
    def test_empty_container_name(self, mock_run):
        result = restart_container("")

        self.assertFalse(result["success"])
        self.assertIn("cannot be empty", result["message"])
        mock_run.assert_not_called()

    @patch("app.recovery.subprocess.run")
    def test_start_failure(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="exited\n", stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=1,
                stdout="", stderr="Container not found",
            ),
        ]

        result = restart_container("missing-container")

        self.assertFalse(result["success"])
        self.assertIn("Container not found", result["message"])

    @patch("app.recovery.subprocess.run")
    def test_success_when_container_is_running(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="exited\n", stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="test-container\n", stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="true\n", stderr="",
            ),
        ]

        result = restart_container("test-container")

        self.assertTrue(result["success"])
        self.assertIn("verification succeeded", result["message"])
        self.assertEqual(mock_run.call_count, 3)

    @patch("app.recovery.subprocess.run")
    def test_failure_when_container_exits(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="exited\n", stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="test-container\n", stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="false\n", stderr="",
            ),
        ]

        result = restart_container("test-container")

        self.assertFalse(result["success"])
        self.assertIn("exited or stopped", result["message"])

    @patch("app.recovery.subprocess.run")
    def test_failure_when_state_cannot_be_verified(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="exited\n", stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="test-container\n", stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=1,
                stdout="", stderr="Inspection failed",
            ),
        ]

        result = restart_container("test-container")

        self.assertFalse(result["success"])
        self.assertIn("could not be verified", result["message"])

    @patch("app.recovery.subprocess.run")
    def test_recovery_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["podman", "inspect", "test-container"],
            timeout=15,
        )

        result = restart_container("test-container")

        self.assertFalse(result["success"])
        self.assertIn("timed out", result["message"])

    @patch("app.recovery.subprocess.run")
    def test_invalid_container_name_with_leading_dash(self, mock_run):
        result = restart_container("--all")
        self.assertFalse(result["success"])
        self.assertIn("starting with a dash", result["message"])
        mock_run.assert_not_called()

    @patch("app.recovery.subprocess.run")
    def test_invalid_container_name_with_spaces(self, mock_run):
        result = restart_container("my container")
        self.assertFalse(result["success"])
        self.assertIn("alphanumeric character", result["message"])
        mock_run.assert_not_called()

    @patch("app.recovery.subprocess.run")
    def test_container_already_running(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="running\n", stderr="",
        )

        result = restart_container("test-container")

        self.assertFalse(result["success"])
        self.assertIn("already running", result["message"])
        self.assertEqual(mock_run.call_count, 1)

    @patch("app.recovery.subprocess.run")
    def test_container_unsupported_state(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="paused\n", stderr="",
        )

        result = restart_container("test-container")

        self.assertFalse(result["success"])
        self.assertIn("Automatic start was not attempted", result["message"])
        self.assertEqual(mock_run.call_count, 1)

    @patch("app.recovery.subprocess.run")
    def test_podman_missing(self, mock_run):
        mock_run.side_effect = FileNotFoundError("podman command not found")

        result = restart_container("test-container")

        self.assertFalse(result["success"])
        self.assertIn("Podman command was not found", result["message"])

    @patch("app.recovery.subprocess.run")
    def test_start_timeout(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="exited\n", stderr="",
            ),
            subprocess.TimeoutExpired(
                cmd=["podman", "start", "test-container"],
                timeout=30,
            ),
        ]

        result = restart_container("test-container")

        self.assertFalse(result["success"])
        self.assertIn("start command timed out", result["message"])

    @patch("app.recovery.subprocess.run")
    def test_verify_timeout(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="exited\n", stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="test-container\n", stderr="",
            ),
            subprocess.TimeoutExpired(
                cmd=["podman", "inspect", "test-container"],
                timeout=15,
            ),
        ]

        result = restart_container("test-container")

        self.assertFalse(result["success"])
        self.assertIn("verification timed out", result["message"])

    @patch("app.recovery.subprocess.run")
    def test_permission_error(self, mock_run):
        mock_run.side_effect = PermissionError("access denied")

        result = restart_container("test-container")

        self.assertFalse(result["success"])
        self.assertIn("Permission denied", result["message"])

    @patch("app.recovery.subprocess.run")
    def test_protected_workload_rejected(self, mock_run):
        for protected in ["cloudops-floci", "linuxops-recovery-ui-test", "db80c688e14b", "83b65d88a0a9"]:
            result = restart_container(protected)
            self.assertFalse(result["success"])
            self.assertIn("protected workload", result["message"])
            mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
