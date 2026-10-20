
import json
import subprocess
import unittest
from unittest.mock import patch

from app.diagnosis import diagnose_container


class TestContainerDiagnosis(unittest.TestCase):

    @patch("app.diagnosis.subprocess.run")
    def test_empty_container_name(self, mock_run):
        result = diagnose_container("")

        self.assertFalse(result["success"])
        self.assertIn("cannot be empty", result["message"])
        mock_run.assert_not_called()

    @patch("app.diagnosis.subprocess.run")
    def test_running_container(self, mock_run):
        details = {
            "name": "test-container",
            "state": "running",
            "exit_code": 0,
            "oom_killed": False,
        }

        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout=json.dumps(details), stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="", stderr="",
            ),
        ]

        result = diagnose_container("test-container")

        self.assertTrue(result["success"])
        self.assertEqual(result["state"], "running")
        self.assertEqual(result["recommendation"], "MONITOR")

    @patch("app.diagnosis.subprocess.run")
    def test_normal_exit(self, mock_run):
        details = {
            "name": "test-container",
            "state": "exited",
            "exit_code": 0,
            "oom_killed": False,
        }

        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout=json.dumps(details), stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="Task completed successfully", stderr="",
            ),
        ]

        result = diagnose_container("test-container")

        self.assertTrue(result["success"])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(
            result["recommendation"],
            "NO_ACTION_UNLESS_SERVICE_EXPECTED",
        )
        self.assertIn("Task completed successfully", result["recent_logs"])

    @patch("app.diagnosis.subprocess.run")
    def test_nonzero_exit(self, mock_run):
        details = {
            "name": "test-container",
            "state": "exited",
            "exit_code": 1,
            "oom_killed": False,
        }

        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout=json.dumps(details), stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="Application error", stderr="",
            ),
        ]

        result = diagnose_container("test-container")

        self.assertTrue(result["success"])
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["recommendation"], "CHECK_LOGS")
        self.assertIn("Application error", result["recent_logs"])

    @patch("app.diagnosis.subprocess.run")
    def test_oom_killed_container(self, mock_run):
        details = {
            "name": "test-container",
            "state": "exited",
            "exit_code": 137,
            "oom_killed": True,
        }

        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout=json.dumps(details), stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="Process killed", stderr="",
            ),
        ]

        result = diagnose_container("test-container")

        self.assertTrue(result["success"])
        self.assertTrue(result["oom_killed"])
        self.assertEqual(result["recommendation"], "HUMAN_REVIEW")

    @patch("app.diagnosis.subprocess.run")
    def test_inspection_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1,
            stdout="", stderr="Container not found",
        )

        result = diagnose_container("missing-container")

        self.assertFalse(result["success"])
        self.assertIn("Container not found", result["message"])
        self.assertEqual(mock_run.call_count, 1)

    @patch("app.diagnosis.subprocess.run")
    def test_diagnosis_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["podman", "inspect", "test-container"],
            timeout=15,
        )

        result = diagnose_container("test-container")

        self.assertFalse(result["success"])
        self.assertIn("timed out", result["message"])


if __name__ == "__main__":
    unittest.main()

