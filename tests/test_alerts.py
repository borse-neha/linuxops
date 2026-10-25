#!/usr/bin/env python3

"""
Unit tests for LinuxOps Alert Classification and Deduplication (Phase C — Step 2).
"""

import math
import unittest

from app.alerts import (
    classify_alerts,
    classify_container_alerts,
    classify_system_alerts,
    deduplicate_alerts,
    format_alert_rows,
    summarize_alerts,
)


class TestSystemAlertClassification(unittest.TestCase):
    """Test suite for host system resource threshold alert classification."""

    def setUp(self):
        self.healthy_system = {
            "cpu_usage_percent": 35.5,
            "memory": {"usage_percent": 45.0, "total_mb": 8000.0, "used_mb": 3600.0},
            "disk": {"usage_percent": 55.0, "total_gb": 100.0, "used_gb": 55.0},
        }

    def test_system_healthy_no_alerts(self):
        alerts = classify_system_alerts(self.healthy_system)
        self.assertEqual(alerts, [])

    def test_system_cpu_warning(self):
        data = dict(self.healthy_system, cpu_usage_percent=75.0)
        alerts = classify_system_alerts(data)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["id"], "system:cpu")
        self.assertEqual(alert["rule"], "system_cpu_high")
        self.assertEqual(alert["severity"], "WARNING")
        self.assertEqual(alert["target"], "cpu")
        self.assertEqual(alert["current_value"], 75.0)
        self.assertEqual(alert["threshold"], 70.0)

    def test_system_cpu_critical(self):
        data = dict(self.healthy_system, cpu_usage_percent=92.5)
        alerts = classify_system_alerts(data)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["id"], "system:cpu")
        self.assertEqual(alert["rule"], "system_cpu_high")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["current_value"], 92.5)
        self.assertEqual(alert["threshold"], 90.0)

    def test_system_cpu_exact_boundaries(self):
        # Exactly at warning threshold (70.0)
        data_warn = dict(self.healthy_system, cpu_usage_percent=70.0)
        alerts_warn = classify_system_alerts(data_warn)
        self.assertEqual(len(alerts_warn), 1)
        self.assertEqual(alerts_warn[0]["severity"], "WARNING")

        # Exactly at critical threshold (90.0)
        data_crit = dict(self.healthy_system, cpu_usage_percent=90.0)
        alerts_crit = classify_system_alerts(data_crit)
        self.assertEqual(len(alerts_crit), 1)
        self.assertEqual(alerts_crit[0]["severity"], "CRITICAL")

    def test_system_memory_warning(self):
        data = dict(self.healthy_system, memory={"usage_percent": 84.0})
        alerts = classify_system_alerts(data)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["id"], "system:memory")
        self.assertEqual(alert["rule"], "system_memory_high")
        self.assertEqual(alert["severity"], "WARNING")
        self.assertEqual(alert["current_value"], 84.0)

    def test_system_memory_critical(self):
        data = dict(self.healthy_system, memory={"usage_percent": 95.0})
        alerts = classify_system_alerts(data)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["id"], "system:memory")
        self.assertEqual(alert["rule"], "system_memory_high")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["current_value"], 95.0)

    def test_system_disk_warning(self):
        data = dict(self.healthy_system, disk={"usage_percent": 81.5})
        alerts = classify_system_alerts(data)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["id"], "system:disk")
        self.assertEqual(alert["rule"], "system_disk_high")
        self.assertEqual(alert["severity"], "WARNING")
        self.assertEqual(alert["current_value"], 81.5)

    def test_system_disk_critical(self):
        data = dict(self.healthy_system, disk={"usage_percent": 98.0})
        alerts = classify_system_alerts(data)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["id"], "system:disk")
        self.assertEqual(alert["rule"], "system_disk_high")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["current_value"], 98.0)

    def test_system_custom_thresholds(self):
        custom_thresholds = {
            "cpu": (50.0, 75.0),
            "memory": (60.0, 85.0),
            "disk": (65.0, 85.0),
        }
        # 60% CPU is above custom warn (50) but below custom crit (75)
        data = dict(self.healthy_system, cpu_usage_percent=60.0)
        alerts = classify_system_alerts(data, thresholds=custom_thresholds)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "WARNING")
        self.assertEqual(alerts[0]["threshold"], 50.0)

    def test_system_invalid_custom_thresholds_fallback(self):
        # Inverted or invalid thresholds must safely fall back to standard defaults (70, 90)
        bad_thresholds = {"cpu": (95.0, 60.0), "memory": "invalid", "disk": None}
        data = dict(self.healthy_system, cpu_usage_percent=75.0)
        alerts = classify_system_alerts(data, thresholds=bad_thresholds)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "WARNING")
        self.assertEqual(alerts[0]["threshold"], 70.0)

    def test_system_data_missing_or_none(self):
        for bad_input in [None, {}, "invalid", []]:
            alerts = classify_system_alerts(bad_input)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["id"], "system:telemetry_unavailable")
            self.assertEqual(alerts[0]["severity"], "CRITICAL")
            self.assertEqual(alerts[0]["rule"], "system_telemetry_missing")

    def test_system_data_missing_keys_handled_safely(self):
        # Only CPU provided, memory and disk are missing
        partial_data = {"cpu_usage_percent": 40.0}
        alerts = classify_system_alerts(partial_data)
        # Should flag unavailable memory and disk as WARNING
        alert_ids = [a["id"] for a in alerts]
        self.assertIn("system:memory", alert_ids)
        self.assertIn("system:disk", alert_ids)
        for a in alerts:
            self.assertEqual(a["severity"], "WARNING")
            self.assertIsNone(a["current_value"])

    def test_system_data_malformed_metric_values(self):
        # Non-numeric, negative, boolean, and infinity values must be flagged as unavailable
        malformed_data = {
            "cpu_usage_percent": "corrupt_data",
            "memory": {"usage_percent": True},  # Boolean must be rejected
            "disk": {"usage_percent": -10.0},
        }
        alerts = classify_system_alerts(malformed_data)
        self.assertEqual(len(alerts), 3)
        rules = {a["rule"] for a in alerts}
        self.assertEqual(
            rules,
            {"system_cpu_unavailable", "system_memory_unavailable", "system_disk_unavailable"},
        )
        for a in alerts:
            self.assertEqual(a["severity"], "WARNING")


class TestContainerAlertClassification(unittest.TestCase):
    """Test suite for container inventory and container health alert classification."""

    def setUp(self):
        self.healthy_summary = {
            "total": 2,
            "running": 2,
            "stopped": 0,
            "health": "NORMAL",
            "error": None,
        }
        self.healthy_containers = [
            {"name": "web-svc", "id": "c101", "state": "running", "status": "Up 2 hours"},
            {"name": "db-svc", "id": "c102", "state": "running", "status": "Up 2 hours"},
        ]

    def test_container_running_produces_no_alerts(self):
        alerts = classify_container_alerts(self.healthy_summary, self.healthy_containers)
        self.assertEqual(alerts, [])

    def test_container_stopped_and_exited_warning(self):
        containers = [
            {"name": "worker-1", "id": "c201", "state": "exited", "status": "Exited (0) 5m ago"},
            {"name": "worker-2", "id": "c202", "state": "stopped", "status": "Stopped"},
        ]
        alerts = classify_container_alerts(self.healthy_summary, containers)
        self.assertEqual(len(alerts), 2)
        for alert in alerts:
            self.assertEqual(alert["severity"], "WARNING")
            self.assertEqual(alert["rule"], "container_stopped")
        self.assertEqual(alerts[0]["id"], "container:worker-1")
        self.assertEqual(alerts[1]["id"], "container:worker-2")

    def test_container_dead_critical(self):
        containers = [
            {"name": "broken-svc", "id": "c301", "state": "dead", "status": "Dead"},
        ]
        alerts = classify_container_alerts(self.healthy_summary, containers)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["id"], "container:broken-svc")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["rule"], "container_dead")
        self.assertIn("DEAD", alert["message"])

    def test_container_abnormal_states_warning(self):
        abnormal_states = ["paused", "restarting", "created"]
        for st in abnormal_states:
            containers = [{"name": f"test-{st}", "id": "c401", "state": st}]
            alerts = classify_container_alerts(self.healthy_summary, containers)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["severity"], "WARNING")
            self.assertEqual(alerts[0]["rule"], "container_abnormal_state")

    def test_container_unknown_and_missing_states_warning(self):
        # Unknown status must never be presented as healthy
        for bad_state in ["unknown", "", None, "ghost", "bizarre_state"]:
            containers = [{"name": "mystery-svc", "id": "c501", "state": bad_state}]
            alerts = classify_container_alerts(self.healthy_summary, containers)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["severity"], "WARNING")
            self.assertEqual(alerts[0]["rule"], "container_state_unknown")

    def test_container_inventory_failure_critical(self):
        # When container subsystem fails, report CRITICAL container inventory alert
        failing_summary = {
            "total": 0,
            "running": 0,
            "stopped": 0,
            "health": "CRITICAL",
            "error": "Podman daemon not responding: connection refused",
        }
        alerts = classify_container_alerts(failing_summary, [])
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["id"], "container_inventory:podman")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["rule"], "container_inventory_failure")

    def test_container_inventory_missing_warning(self):
        # Both summary and containers None
        alerts = classify_container_alerts(None, None)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["id"], "container_inventory:podman")
        self.assertEqual(alerts[0]["severity"], "WARNING")
        self.assertEqual(alerts[0]["rule"], "container_inventory_missing")

    def test_container_summary_present_containers_none(self):
        alerts = classify_container_alerts(self.healthy_summary, None)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["id"], "container_inventory:missing_containers")
        self.assertEqual(alerts[0]["severity"], "WARNING")

    def test_container_name_and_id_fallback(self):
        # Name is missing / unknown, should fall back to ID
        containers = [
            {"name": "", "id": "c601a7b8c9d0", "state": "exited"},
            {"name": "unknown", "id": "c702b8c9d0e1", "state": "exited"},
            {"name": None, "id": None, "state": "exited"},
        ]
        alerts = classify_container_alerts(self.healthy_summary, containers)
        self.assertEqual(len(alerts), 3)
        self.assertEqual(alerts[0]["id"], "container:c601a7b8c9d0")
        self.assertEqual(alerts[1]["id"], "container:c702b8c9d0e1")
        self.assertEqual(alerts[2]["id"], "container:unknown")

    def test_container_malformed_records(self):
        # Non-dictionary items in containers list
        containers = ["not_a_dict", 42, None, {"name": "valid", "state": "exited"}]
        alerts = classify_container_alerts(self.healthy_summary, containers)
        # 3 malformed warnings + 1 container alert
        self.assertEqual(len(alerts), 4)
        malformed_alerts = [a for a in alerts if a["rule"] == "container_record_malformed"]
        self.assertEqual(len(malformed_alerts), 3)

    def test_container_records_not_a_list(self):
        alerts = classify_container_alerts(self.healthy_summary, "corrupt_string")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["id"], "container_inventory:malformed_data")
        self.assertEqual(alerts[0]["severity"], "WARNING")


class TestDeduplicationAndResolution(unittest.TestCase):
    """Test suite for alert deduplication and active condition resolution."""

    def test_deduplicate_identical_ids(self):
        raw_alerts = [
            {"id": "system:cpu", "severity": "WARNING", "rule": "system_cpu_high"},
            {"id": "system:cpu", "severity": "WARNING", "rule": "system_cpu_high"},
            {"id": "container:api", "severity": "WARNING", "rule": "container_stopped"},
        ]
        deduped = deduplicate_alerts(raw_alerts)
        self.assertEqual(len(deduped), 2)
        ids = {a["id"] for a in deduped}
        self.assertEqual(ids, {"system:cpu", "container:api"})

    def test_deduplicate_severity_elevation_critical_over_warning(self):
        # When duplicate IDs occur with different severities, CRITICAL must win
        raw_alerts = [
            {"id": "system:cpu", "severity": "WARNING", "rule": "system_cpu_high"},
            {"id": "system:cpu", "severity": "CRITICAL", "rule": "system_cpu_high"},
        ]
        deduped = deduplicate_alerts(raw_alerts)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["id"], "system:cpu")
        self.assertEqual(deduped[0]["severity"], "CRITICAL")

        # Reverse order: CRITICAL first, then WARNING
        raw_alerts_rev = [
            {"id": "system:cpu", "severity": "CRITICAL", "rule": "system_cpu_high"},
            {"id": "system:cpu", "severity": "WARNING", "rule": "system_cpu_high"},
        ]
        deduped_rev = deduplicate_alerts(raw_alerts_rev)
        self.assertEqual(len(deduped_rev), 1)
        self.assertEqual(deduped_rev[0]["severity"], "CRITICAL")

    def test_deduplicate_distinct_identities_preserved(self):
        raw_alerts = [
            {"id": "system:cpu", "severity": "WARNING"},
            {"id": "system:memory", "severity": "WARNING"},
            {"id": "system:disk", "severity": "CRITICAL"},
            {"id": "container:web", "severity": "WARNING"},
            {"id": "container:db", "severity": "CRITICAL"},
        ]
        deduped = deduplicate_alerts(raw_alerts)
        self.assertEqual(len(deduped), 5)

    def test_deduplicate_invalid_inputs(self):
        self.assertEqual(deduplicate_alerts(None), [])
        self.assertEqual(deduplicate_alerts("not_a_list"), [])
        # Non-dict and missing/empty ID items are safely skipped
        mixed = [
            None,
            42,
            {},
            {"no_id": True},
            {"id": "", "severity": "WARNING"},
            {"id": 123, "severity": "WARNING"},  # non-string ID
            {"id": "valid:id", "severity": "WARNING"},
        ]
        deduped = deduplicate_alerts(mixed)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["id"], "valid:id")

    def test_resolution_alert_disappears_when_condition_clears(self):
        # Refresh 1: CPU high and container stopped
        report_t1 = {
            "system": {
                "cpu_usage_percent": 95.0,
                "memory": {"usage_percent": 40.0},
                "disk": {"usage_percent": 50.0},
            },
            "container_summary": {"health": "NORMAL"},
            "containers": [{"name": "cache-svc", "id": "c1", "state": "stopped"}],
        }
        alerts_t1 = classify_alerts(report_t1)
        self.assertEqual(len(alerts_t1), 2)
        alert_ids_t1 = {a["id"] for a in alerts_t1}
        self.assertEqual(alert_ids_t1, {"system:cpu", "container:cache-svc"})

        # Refresh 2: CPU dropped to normal and container was restarted to running
        report_t2 = {
            "system": {
                "cpu_usage_percent": 42.0,
                "memory": {"usage_percent": 40.0},
                "disk": {"usage_percent": 50.0},
            },
            "container_summary": {"health": "NORMAL"},
            "containers": [{"name": "cache-svc", "id": "c1", "state": "running"}],
        }
        alerts_t2 = classify_alerts(report_t2)
        # Resolved conditions disappear from the active alert list
        self.assertEqual(alerts_t2, [])

    def test_repeated_evaluation_is_idempotent(self):
        # Evaluating the exact same report repeatedly produces identical, stable alerts
        report = {
            "system": {
                "cpu_usage_percent": 78.0,
                "memory": {"usage_percent": 45.0},
                "disk": {"usage_percent": 50.0},
            },
            "container_summary": {"health": "NORMAL"},
            "containers": [{"name": "web-svc", "id": "c1", "state": "stopped"}],
        }
        eval_1 = classify_alerts(report)
        eval_2 = classify_alerts(report)
        eval_3 = classify_alerts(report)

        self.assertEqual(len(eval_1), len(eval_2))
        self.assertEqual(len(eval_2), len(eval_3))
        self.assertEqual([a["id"] for a in eval_1], [a["id"] for a in eval_2])
        self.assertEqual([a["severity"] for a in eval_1], [a["severity"] for a in eval_2])


class TestClassifyAlertsAndSummary(unittest.TestCase):
    """Test suite for top-level classify_alerts and summarize_alerts."""

    def test_classify_alerts_full_healthy_report(self):
        report = {
            "system": {
                "cpu_usage_percent": 30.0,
                "memory": {"usage_percent": 40.0},
                "disk": {"usage_percent": 50.0},
            },
            "container_summary": {"health": "NORMAL"},
            "containers": [{"name": "web-svc", "id": "c1", "state": "running"}],
        }
        alerts = classify_alerts(report)
        self.assertEqual(alerts, [])
        summary = summarize_alerts(alerts)
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["critical"], 0)
        self.assertEqual(summary["warning"], 0)
        self.assertFalse(summary["has_critical"])
        self.assertFalse(summary["has_warning"])

    def test_classify_alerts_multi_alert_report(self):
        report = {
            "system": {
                "cpu_usage_percent": 95.0,  # CRITICAL
                "memory": {"usage_percent": 85.0},  # WARNING
                "disk": {"usage_percent": 50.0},  # OK
            },
            "container_summary": {"health": "NORMAL"},
            "containers": [
                {"name": "stopped-app", "state": "exited"},  # WARNING
                {"name": "dead-app", "state": "dead"},  # CRITICAL
            ],
        }
        alerts = classify_alerts(report)
        self.assertEqual(len(alerts), 4)

        summary = summarize_alerts(alerts)
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["critical"], 2)
        self.assertEqual(summary["warning"], 2)
        self.assertTrue(summary["has_critical"])
        self.assertTrue(summary["has_warning"])

    def test_classify_alerts_missing_or_empty_report(self):
        for bad_report in [None, {}, "invalid", []]:
            alerts = classify_alerts(bad_report)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["id"], "system:monitoring_unavailable")
            self.assertEqual(alerts[0]["severity"], "CRITICAL")
            self.assertEqual(alerts[0]["rule"], "monitoring_report_missing")

    def test_summarize_alerts_empty_or_malformed(self):
        for bad_alerts in [None, "invalid", 123]:
            summary = summarize_alerts(bad_alerts)
            self.assertEqual(
                summary,
                {"total": 0, "critical": 0, "warning": 0, "has_critical": False, "has_warning": False},
            )

    def test_format_alert_rows(self):
        self.assertEqual(format_alert_rows(None), [])
        self.assertEqual(format_alert_rows("invalid"), [])
        self.assertEqual(format_alert_rows([None, 42]), [])

        sample_alerts = [
            {
                "id": "system:cpu",
                "severity": "CRITICAL",
                "target_type": "system",
                "target": "cpu",
                "rule": "system_cpu_high",
                "message": "CPU is 95%",
                "timestamp": "2026-10-20T12:00:00Z",
            },
            {
                "id": "container:app",
                "severity": "WARNING",
                "target_type": "container",
                "target": "app",
                "rule": "container_stopped",
                "message": "Container is stopped",
                "timestamp": "2026-10-20T12:00:01Z",
            },
        ]
        rows = format_alert_rows(sample_alerts)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["Severity"], "🚨 CRITICAL")
        self.assertEqual(rows[0]["Target"], "system: cpu")
        self.assertEqual(rows[1]["Severity"], "⚠️ WARNING")
        self.assertEqual(rows[1]["Target"], "container: app")


if __name__ == "__main__":
    unittest.main()
