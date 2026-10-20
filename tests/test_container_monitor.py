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


if __name__ == "__main__":
    unittest.main(verbosity=2)
