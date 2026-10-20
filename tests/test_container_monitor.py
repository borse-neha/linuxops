import json
import subprocess
import unittest
from unittest.mock import patch

from app import container_monitor


class TestContainerMonitoring(unittest.TestCase):

    @patch("app.container_monitor.subprocess.run")
    def test_running_container(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["podman"],
            returncode=0,
            stdout=json.dumps([
                {
                    "Id": "1234567890123456",
                    "Names": ["web-test"],
                    "Image": "docker.io/library/alpine:latest",
                    "State": "running",
                    "Status": "Up 10 seconds",
                }
            ]),
            stderr="",
        )

        result = container_monitor.collect_container_status()

        self.assertEqual(result["container_count"], 1)
        self.assertEqual(result["running_count"], 1)
        self.assertEqual(result["stopped_count"], 0)
        self.assertEqual(result["containers"][0]["name"], "web-test")
        self.assertEqual(result["containers"][0]["health"], "NORMAL")

    @patch("app.container_monitor.subprocess.run")
    def test_stopped_container(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["podman"],
            returncode=0,
            stdout=json.dumps([
                {
                    "Id": "abcdef1234567890",
                    "Names": ["stopped-test"],
                    "Image": "docker.io/library/alpine:latest",
                    "State": "exited",
                    "Status": "Exited (0)",
                }
            ]),
            stderr="",
        )

        result = container_monitor.collect_container_status()

        self.assertEqual(result["running_count"], 0)
        self.assertEqual(result["stopped_count"], 1)
        self.assertEqual(result["containers"][0]["health"], "WARNING")

    @patch("app.container_monitor.subprocess.run")
    def test_no_containers(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["podman"],
            returncode=0,
            stdout="[]",
            stderr="",
        )

        result = container_monitor.collect_container_status()

        self.assertEqual(result["container_count"], 0)
        self.assertEqual(result["running_count"], 0)
        self.assertEqual(result["stopped_count"], 0)
        self.assertEqual(result["containers"], [])

    @patch("app.container_monitor.subprocess.run")
    def test_podman_command(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["podman"],
            returncode=0,
            stdout="[]",
            stderr="",
        )

        container_monitor.get_containers()

        command = mock_run.call_args.args[0]

        self.assertEqual(
            command,
            ["podman", "ps", "-a", "--format", "json"],
        )
        self.assertTrue(mock_run.call_args.kwargs["check"])

    @patch("app.container_monitor.subprocess.run")
    def test_podman_missing(self, mock_run):
        mock_run.side_effect = FileNotFoundError("podman command not found")

        result = container_monitor.collect_container_status()

        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"])
        self.assertEqual(result["container_count"], 0)
        self.assertEqual(result["containers"], [])

    @patch("app.container_monitor.subprocess.run")
    def test_podman_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["podman", "ps"],
            timeout=15,
        )

        result = container_monitor.collect_container_status()

        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"])
        self.assertEqual(result["container_count"], 0)

    @patch("app.container_monitor.subprocess.run")
    def test_podman_nonzero_exit(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=125,
            cmd=["podman", "ps"],
            stderr="storage configuration error",
        )

        result = container_monitor.collect_container_status()

        self.assertFalse(result["success"])
        self.assertIn("storage configuration error", result["error"])

    @patch("app.container_monitor.subprocess.run")
    def test_podman_malformed_json(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["podman"],
            returncode=0,
            stdout="not-a-valid-json",
            stderr="",
        )

        result = container_monitor.collect_container_status()

        self.assertFalse(result["success"])
        self.assertIn("Malformed container inventory", result["error"])

    @patch("app.container_monitor.subprocess.run")
    def test_podman_dict_instead_of_list(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["podman"],
            returncode=0,
            stdout=json.dumps({"error": "something went wrong"}),
            stderr="",
        )

        result = container_monitor.collect_container_status()

        self.assertFalse(result["success"])
        self.assertIn("expected a JSON list", result["error"])

    @patch("app.container_monitor.subprocess.run")
    def test_malformed_container_record_skipped_or_handled(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["podman"],
            returncode=0,
            stdout=json.dumps([
                None,
                "invalid string record",
                {
                    "Id": None,
                    "Names": None,
                    "State": None,
                    "Status": None,
                },
                {
                    "Id": "123456789012345",
                    "Names": ["healthy-app"],
                    "Image": "alpine:latest",
                    "State": "running",
                    "Status": "Up 5 minutes",
                },
            ]),
            stderr="",
        )

        result = container_monitor.collect_container_status()

        self.assertTrue(result["success"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["container_count"], 2)
        self.assertEqual(result["running_count"], 1)

        # First dict had nulls
        corrupt_rec = result["containers"][0]
        self.assertEqual(corrupt_rec["id"], "unknown")
        self.assertEqual(corrupt_rec["name"], "unknown")
        self.assertEqual(corrupt_rec["health"], "UNKNOWN")

        # Second dict was valid
        valid_rec = result["containers"][1]
        self.assertEqual(valid_rec["name"], "healthy-app")
        self.assertEqual(valid_rec["health"], "NORMAL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
