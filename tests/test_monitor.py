
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import monitor


class TestHealthClassification(unittest.TestCase):

    def test_normal_status(self):
        self.assertEqual(
            monitor.classify_health(40, 70, 90),
            "NORMAL",
        )

    def test_warning_status(self):
        self.assertEqual(
            monitor.classify_health(75, 70, 90),
            "WARNING",
        )

    def test_critical_status(self):
        self.assertEqual(
            monitor.classify_health(95, 70, 90),
            "CRITICAL",
        )

    def test_exact_warning_threshold(self):
        self.assertEqual(
            monitor.classify_health(70, 70, 90),
            "WARNING",
        )

    def test_exact_critical_threshold(self):
        self.assertEqual(
            monitor.classify_health(90, 70, 90),
            "CRITICAL",
        )


class TestThresholds(unittest.TestCase):

    def test_threshold_defaults(self):
        thresholds = monitor.get_thresholds()
        self.assertEqual(thresholds["cpu"], (70.0, 90.0))
        self.assertEqual(thresholds["memory"], (80.0, 90.0))
        self.assertEqual(thresholds["disk"], (80.0, 90.0))

    def test_threshold_invalid_values(self):
        with patch.dict("os.environ", {"CPU_WARNING": "invalid"}):
            thresholds = monitor.get_thresholds()
            self.assertEqual(thresholds["cpu"][0], 70.0)

    def test_threshold_out_of_range(self):
        with patch.dict("os.environ", {"CPU_WARNING": "150", "CPU_CRITICAL": "-5"}):
            thresholds = monitor.get_thresholds()
            self.assertEqual(thresholds["cpu"], (70.0, 90.0))

    def test_threshold_inverted(self):
        with patch.dict("os.environ", {"CPU_WARNING": "95", "CPU_CRITICAL": "80"}):
            thresholds = monitor.get_thresholds()
            self.assertEqual(thresholds["cpu"], (70.0, 90.0))


class TestMonitoring(unittest.TestCase):

    def test_collect_metrics_structure(self):
        metrics = monitor.collect_metrics()

        self.assertIn("timestamp", metrics)
        self.assertIn("hostname", metrics)
        self.assertIn("cpu_usage_percent", metrics)
        self.assertIn("memory", metrics)
        self.assertIn("disk", metrics)
        self.assertIn("health_checks", metrics)
        self.assertIn("overall_status", metrics)

        self.assertIn(
            metrics["overall_status"],
            {"NORMAL", "WARNING", "CRITICAL"},
        )

        self.assertGreaterEqual(
            metrics["cpu_usage_percent"], 0
        )
        self.assertLessEqual(
            metrics["cpu_usage_percent"], 100
        )

    def test_save_metrics_creates_json_record(self):
        metrics = {
            "hostname": "test-host",
            "overall_status": "NORMAL",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            test_log = Path(temp_dir) / "metrics.jsonl"

            with patch.object(monitor, "LOG_FILE", test_log):
                monitor.save_metrics(metrics)

            self.assertTrue(test_log.exists())

            with test_log.open(encoding="utf-8") as file:
                saved_record = json.loads(file.readline())

            self.assertEqual(saved_record, metrics)

    def test_get_memory_usage_zero_total(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_mem = Path(temp_dir) / "meminfo"
            fake_mem.write_text("MemTotal: 0 kB\nMemAvailable: 0 kB\n", encoding="utf-8")
            result = monitor.get_memory_usage(str(fake_mem))
            self.assertEqual(result["total_mb"], 0.0)
            self.assertEqual(result["usage_percent"], 0.0)

    def test_get_memory_usage_fallback_memavailable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_mem = Path(temp_dir) / "meminfo"
            fake_mem.write_text(
                "MemTotal: 1000000 kB\nMemFree: 200000 kB\nBuffers: 100000 kB\nCached: 200000 kB\n",
                encoding="utf-8",
            )
            result = monitor.get_memory_usage(str(fake_mem))
            self.assertEqual(result["usage_percent"], 50.0)

    def test_get_memory_usage_missing_file(self):
        result = monitor.get_memory_usage("/non/existent/path/to/meminfo")
        self.assertEqual(result["total_mb"], 0.0)
        self.assertEqual(result["usage_percent"], 0.0)

    def test_get_disk_usage_zero_total(self):
        from collections import namedtuple
        DiskUsage = namedtuple("DiskUsage", ["total", "used", "free"])
        with patch("shutil.disk_usage", return_value=DiskUsage(0, 0, 0)):
            result = monitor.get_disk_usage("/")
            self.assertEqual(result["total_gb"], 0.0)
            self.assertEqual(result["usage_percent"], 0.0)

    def test_get_disk_usage_os_error(self):
        with patch("shutil.disk_usage", side_effect=OSError("Disk failure")):
            result = monitor.get_disk_usage("/")
            self.assertEqual(result["total_gb"], 0.0)
            self.assertEqual(result["usage_percent"], 0.0)

    def test_get_cpu_usage_zero_delta(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            fake_stat.write_text("cpu  100 20 30 500 10 0 0 0 0 0\n", encoding="utf-8")
            result = monitor.get_cpu_usage(interval=0, proc_stat_path=str(fake_stat))
            self.assertEqual(result, 0.0)

    def test_get_cpu_usage_missing_file(self):
        result = monitor.get_cpu_usage(interval=0, proc_stat_path="/non/existent/stat")
        self.assertEqual(result, 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

