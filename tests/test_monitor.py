
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

    def test_exact_critical_threshold(self):
        self.assertEqual(
            monitor.classify_health(90, 70, 90),
            "CRITICAL",
        )


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


if __name__ == "__main__":
    unittest.main(verbosity=2)

