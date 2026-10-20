
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


if __name__ == "__main__":
    unittest.main()

