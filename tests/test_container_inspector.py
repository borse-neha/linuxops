#!/usr/bin/env python3

"""
Unit tests for LinuxOps Container Observability & Deep Inspection Engine (Phase 2).
Tests cover host identity correlation, metric typing, batch inspection,
fault isolation, stale telemetry detection, and protected workload tagging.
"""

from datetime import datetime, timedelta, timezone
import json
import unittest
from unittest.mock import MagicMock, patch

from app import container_inspector


class TestHostIdentityAndMetricParsing(unittest.TestCase):
    """Test host identity retrieval and metric normalization."""

    def test_get_host_identity(self):
        """Host identity provides machine_id, hostname, and OS metadata."""
        host = container_inspector.get_host_identity()
        self.assertIn("hostname", host)
        self.assertIn("machine_id", host)
        self.assertIn("os", host)
        self.assertIn("kernel", host)
        self.assertIn("arch", host)
        self.assertTrue(len(host["hostname"]) > 0)

    def test_parse_bytes_formats(self):
        """Bytes parser accurately parses various units and formats."""
        self.assertEqual(container_inspector.parse_bytes("100B"), 100)
        self.assertEqual(container_inspector.parse_bytes("10KB"), 10000)
        self.assertEqual(container_inspector.parse_bytes("10KiB"), 10240)
        self.assertEqual(container_inspector.parse_bytes("32MB"), 32000000)
        self.assertEqual(container_inspector.parse_bytes("32MiB"), 33554432)
        self.assertEqual(container_inspector.parse_bytes("2GB"), 2000000000)
        self.assertEqual(container_inspector.parse_bytes("2GiB"), 2147483648)
        self.assertEqual(container_inspector.parse_bytes(1048576), 1048576)
        self.assertIsNone(container_inspector.parse_bytes(None))
        self.assertIsNone(container_inspector.parse_bytes("invalid"))
        self.assertIsNone(container_inspector.parse_bytes(False))

    def test_parse_percentage_formats(self):
        """Percentage parser safely extracts numeric values."""
        self.assertEqual(container_inspector.parse_percentage("12.5%"), 12.5)
        self.assertEqual(container_inspector.parse_percentage("0.0%"), 0.0)
        self.assertEqual(container_inspector.parse_percentage(45.2), 45.2)
        self.assertIsNone(container_inspector.parse_percentage(None))
        self.assertIsNone(container_inspector.parse_percentage("bad"))
        self.assertIsNone(container_inspector.parse_percentage(True))

    def test_metric_value_classification(self):
        """Metric values are formatted with exact status tags."""
        m_ok = container_inspector.format_metric_value(15.4, "%", "ok")
        self.assertEqual(m_ok["status"], "ok")
        self.assertEqual(m_ok["value"], 15.4)

        m_zero = container_inspector.format_metric_value(0.0, "%", "zero")
        self.assertEqual(m_zero["status"], "zero")
        self.assertEqual(m_zero["value"], 0.0)

        m_unavail = container_inspector.format_metric_value(None, "bytes", "unavailable")
        self.assertEqual(m_unavail["status"], "unavailable")
        self.assertIsNone(m_unavail["value"])


class TestStatsParsing(unittest.TestCase):
    """Test container stats parsing and status assignment."""

    def test_running_container_active_stats(self):
        """Running container with metrics returns 'ok' or 'zero' statuses."""
        raw_stat = {
            "id": "c1234567890ab",
            "name": "my-service",
            "cpu_percent": "5.50%",
            "mem_usage": "64MiB / 512MiB",
            "mem_percent": "12.50%",
            "net_io": "1.2KB / 4.5KB",
            "block_io": "0B / 12KB",
            "pids": "14",
        }
        res = container_inspector.parse_stats_entry(raw_stat, is_running=True)
        self.assertEqual(res["cpu_percent"]["status"], "ok")
        self.assertEqual(res["cpu_percent"]["value"], 5.50)
        self.assertEqual(res["memory_usage_bytes"]["status"], "ok")
        self.assertEqual(res["memory_usage_bytes"]["value"], 64 * 1024 * 1024)
        self.assertEqual(res["memory_limit_bytes"]["value"], 512 * 1024 * 1024)
        self.assertEqual(res["pids"]["value"], 14)
        self.assertEqual(res["telemetry_state"], "ok")

    def test_running_container_zero_cpu(self):
        """Verified 0.0% CPU usage is tagged as 'zero' rather than 'unavailable'."""
        raw_stat = {
            "id": "c1234567890ab",
            "cpu_percent": "0.0%",
            "mem_usage": "10MB / 100MB",
        }
        res = container_inspector.parse_stats_entry(raw_stat, is_running=True)
        self.assertEqual(res["cpu_percent"]["status"], "zero")
        self.assertEqual(res["cpu_percent"]["value"], 0.0)

    def test_stopped_container_metrics_unavailable(self):
        """Stopped containers report metrics as 'unavailable' with None values."""
        raw_stat = {"id": "c1234567890ab"}
        res = container_inspector.parse_stats_entry(raw_stat, is_running=False)
        self.assertEqual(res["cpu_percent"]["status"], "unavailable")
        self.assertIsNone(res["cpu_percent"]["value"])
        self.assertEqual(res["memory_usage_bytes"]["status"], "unavailable")
        self.assertEqual(res["telemetry_state"], "unavailable")

    def test_stale_telemetry_detection(self):
        """Samples older than stale threshold are classified as 'stale'."""
        now_ts = 1700000000.0
        old_time = datetime.fromtimestamp(now_ts - 120.0, tz=timezone.utc).isoformat()
        raw_stat = {
            "id": "c1234567890ab",
            "cpu_percent": "1.0%",
            "timestamp": old_time,
        }
        res = container_inspector.parse_stats_entry(
            raw_stat,
            is_running=True,
            stale_threshold=60.0,
            reference_time=now_ts,
        )
        self.assertEqual(res["telemetry_state"], "stale")
        self.assertEqual(res["cpu_percent"]["status"], "stale")


class TestContainerRecordNormalization(unittest.TestCase):
    """Test normalizing raw inspect and stats into deep ContainerRecord."""

    def test_normalize_record_complete_fields(self):
        """Inspect data with ports, mounts, labels, and limits normalizes cleanly."""
        inspect_data = {
            "Id": "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
            "Name": "/production-web-app",
            "ImageName": "docker.io/library/nginx:alpine",
            "Created": "2026-10-20T10:00:00Z",
            "RestartCount": 2,
            "State": {
                "Status": "running",
                "StartedAt": "2026-10-20T10:01:00Z",
                "FinishedAt": "0001-01-01T00:00:00Z",
                "ExitCode": 0,
                "OOMKilled": False,
                "Health": {
                    "Status": "healthy",
                    "FailingStreak": 0,
                },
            },
            "HostConfig": {
                "RestartPolicy": {"Name": "on-failure"},
                "Memory": 104857600,
                "MemorySwap": 104857600,
                "NanoCpus": 500000000,
                "PidsLimit": 100,
                "PortBindings": {
                    "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
                },
            },
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": "/var/www/html",
                    "Destination": "/usr/share/nginx/html",
                    "RW": True,
                    "Mode": "Z",
                }
            ],
            "Config": {
                "Labels": {"app": "web", "env": "prod"},
            },
        }

        rec = container_inspector.normalize_container_record(inspect_data)
        self.assertEqual(rec["name"], "production-web-app")
        self.assertEqual(rec["short_id"], "112233445566")
        self.assertEqual(rec["image"], "docker.io/library/nginx:alpine")
        self.assertEqual(rec["state"], "running")
        self.assertEqual(rec["health_status"], "healthy")
        self.assertEqual(rec["exit_code"], 0)
        self.assertEqual(rec["restart_count"], 2)
        self.assertEqual(rec["restart_policy"], "on-failure")
        self.assertEqual(rec["ports"]["80/tcp"], ["0.0.0.0:8080"])
        self.assertEqual(len(rec["mounts"]), 1)
        self.assertEqual(rec["mounts"][0]["source"], "/var/www/html")
        self.assertEqual(rec["resource_limits"]["memory_bytes"], 104857600)
        self.assertEqual(rec["labels"]["app"], "web")
        self.assertFalse(rec["is_protected"])

    def test_protected_workload_identification(self):
        """Protected workloads are correctly tagged with is_protected=True."""
        floci_inspect = {
            "Id": "db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3",
            "Name": "/cloudops-floci",
            "State": {"Status": "running"},
        }
        rec_floci = container_inspector.normalize_container_record(floci_inspect)
        self.assertTrue(rec_floci["is_protected"])

        ui_inspect = {
            "Id": "83b65d88a0a9ced6761280936b222a2e1d374ec2478fadee2db0f9cb32dbaa22",
            "Name": "/linuxops-recovery-ui-test",
            "State": {"Status": "stopped"},
        }
        rec_ui = container_inspector.normalize_container_record(ui_inspect)
        self.assertTrue(rec_ui["is_protected"])


class TestContainerScannerScaleAndResilience(unittest.TestCase):
    """Test scanner scaling to 100+ containers, batching, and error resilience."""

    def _generate_synthetic_inventory(self, count=100):
        discovered = []
        inspect_map = {}
        for idx in range(1, count + 1):
            cid = f"{idx:064x}"
            name = f"synthetic-worker-{idx:04d}"
            state = "running" if idx % 2 == 1 else "exited"
            discovered.append({
                "Id": cid,
                "Names": [name],
                "Image": "docker.io/library/alpine:latest",
                "State": state,
                "Status": f"Up {idx}m" if state == "running" else "Exited (0)",
            })
            inspect_map[cid] = [{
                "Id": cid,
                "Name": f"/{name}",
                "ImageName": "docker.io/library/alpine:latest",
                "State": {
                    "Status": state,
                    "ExitCode": 0 if state == "running" else (1 if idx % 5 == 0 else 0),
                    "OOMKilled": (idx % 10 == 0),
                    "Health": {"Status": "healthy" if idx % 4 == 0 else "none"},
                },
                "HostConfig": {
                    "Memory": 33554432,
                    "MemorySwap": 33554432,
                },
            }]
        return discovered, inspect_map

    def test_scan_100_synthetic_containers_success(self):
        """Scanner inspects 100 containers with batching, reporting accurate counts."""
        discovered, inspect_map = self._generate_synthetic_inventory(100)

        def mock_runner(cmd, **kwargs):
            res = MagicMock()
            res.returncode = 0
            if cmd[1] == "ps":
                res.stdout = json.dumps(discovered)
            elif cmd[1] == "stats":
                res.stdout = json.dumps([])
            elif cmd[1] == "inspect":
                # cmd[2:] are container IDs
                cids = cmd[2:]
                batch_res = []
                for c in cids:
                    batch_res.extend(inspect_map.get(c, []))
                res.stdout = json.dumps(batch_res)
            return res

        report = container_inspector.scan_containers(
            runner=mock_runner,
            batch_size=25,
            max_workers=4,
            container_inventory=discovered,
        )

        self.assertTrue(report["success"])
        self.assertEqual(report["discovered_count"], 100)
        self.assertEqual(report["inspected_count"], 100)
        self.assertEqual(report["failed_count"], 0)
        self.assertEqual(report["running_count"], 50)
        self.assertEqual(report["stopped_count"], 50)
        self.assertEqual(report["healthy_count"], 25)
        self.assertEqual(len(report["containers"]), 100)
        self.assertTrue(report["scan_duration_ms"] >= 0.0)

    def test_scan_resilience_when_container_disappears(self):
        """When an individual container fails or disappears during batch inspect, scan continues."""
        discovered, inspect_map = self._generate_synthetic_inventory(10)
        # Delete inspect entry for container 4 to simulate concurrent removal
        cid_missing = f"{4:064x}"
        del inspect_map[cid_missing]

        def mock_runner(cmd, **kwargs):
            if cmd[1] == "inspect":
                cids = cmd[2:]
                if cid_missing in cids:
                    # Batch command fails because cid_missing no longer exists in Podman
                    raise subprocess.CalledProcessError(125, cmd, stderr=f"no such container {cid_missing[:12]}")
                # Other batches succeed
                batch_res = []
                for c in cids:
                    batch_res.extend(inspect_map.get(c, []))
                res = MagicMock()
                res.returncode = 0
                res.stdout = json.dumps(batch_res)
                return res
            raise ValueError(f"Unexpected cmd: {cmd}")

        report = container_inspector.scan_containers(
            runner=mock_runner,
            batch_size=5,
            container_inventory=discovered,
        )

        self.assertTrue(report["success"])
        self.assertEqual(report["discovered_count"], 10)
        self.assertEqual(report["inspected_count"], 9)
        self.assertEqual(report["failed_count"], 1)
        self.assertIn(cid_missing, report["errors"])
        # Failed container is recorded with inspection_status='failed'
        failed_entry = next(c for c in report["containers"] if c["id"] == cid_missing)
        self.assertEqual(failed_entry["inspection_status"], "failed")
        self.assertIsNotNone(failed_entry["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
