#!/usr/bin/env python3

"""
Unit tests for LinuxOps Operational Analytics & Metric Trends (Phase C — Step 3).
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from app.history import (
    get_policy_decision_stats,
    get_recovery_success_rate,
    record_policy_decision,
    record_recovery_event,
)
from app.monitor import get_metric_trends


class TestPolicyDecisionAnalytics(unittest.TestCase):
    """Test suite for policy decision operational analytics."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.policy_path = Path(self.temp_dir.name) / "policy_history.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_policy_stats_missing_and_empty_file(self):
        # Missing file
        stats = get_policy_decision_stats(history_path=self.policy_path)
        self.assertEqual(stats["total_evaluations"], 0)
        self.assertEqual(stats["allow_count"], 0)
        self.assertEqual(stats["deny_count"], 0)
        self.assertEqual(stats["denial_reasons"], {})
        self.assertIsNone(stats["most_frequent_denial_reason"])
        self.assertEqual(stats["skipped_records"], 0)

        # Empty file
        self.policy_path.touch()
        stats_empty = get_policy_decision_stats(history_path=self.policy_path)
        self.assertEqual(stats_empty["total_evaluations"], 0)
        self.assertEqual(stats_empty["skipped_records"], 0)

    def test_policy_stats_invalid_limit(self):
        # Record one valid decision
        record_policy_decision(
            "app-1",
            {"decision": "ALLOW", "allowed": True, "dry_run": True},
            history_path=self.policy_path,
        )
        for bad_limit in [0, -5, "10", None, False, True, 3.14]:
            stats = get_policy_decision_stats(limit=bad_limit, history_path=self.policy_path)
            self.assertEqual(stats["total_evaluations"], 0)

    def test_policy_stats_allow_and_deny_counts(self):
        # 2 ALLOWs, 3 DENYs
        record_policy_decision(
            "app-1",
            {"decision": "ALLOW", "allowed": True, "dry_run": True, "reason": "Eligible"},
            self.policy_path,
        )
        record_policy_decision(
            "app-2",
            {"decision": "ALLOW", "allowed": True, "dry_run": True, "reason": "Eligible"},
            self.policy_path,
        )
        record_policy_decision(
            "app-3",
            {"decision": "DENY", "allowed": False, "dry_run": True, "reason": "Cooldown active"},
            self.policy_path,
        )
        record_policy_decision(
            "app-4",
            {"decision": "DENY", "allowed": False, "dry_run": True, "reason": "Cooldown active"},
            self.policy_path,
        )
        record_policy_decision(
            "app-5",
            {"decision": "DENY", "allowed": False, "dry_run": True, "reason": "Container running"},
            self.policy_path,
        )

        stats = get_policy_decision_stats(history_path=self.policy_path)
        self.assertEqual(stats["total_evaluations"], 5)
        self.assertEqual(stats["allow_count"], 2)
        self.assertEqual(stats["deny_count"], 3)
        self.assertEqual(stats["skipped_records"], 0)
        self.assertEqual(stats["denial_reasons"]["Cooldown active"], 2)
        self.assertEqual(stats["denial_reasons"]["Container running"], 1)
        self.assertEqual(stats["most_frequent_denial_reason"], "Cooldown active")

    def test_policy_stats_malformed_and_foreign_entries_skipped(self):
        with self.policy_path.open("w", encoding="utf-8") as f:
            f.write("corrupted json line\n")
            f.write(json.dumps("a json string not dict") + "\n")
            f.write(json.dumps({"action": "start_container", "container": "c1"}) + "\n")  # recovery event
            f.write(json.dumps({
                "event_type": "policy_decision",
                "decision": "ALLOW",
                "allowed": False,  # Inconsistent
                "container": "c2",
                "dry_run": True,
            }) + "\n")
            f.write(json.dumps({
                "event_type": "policy_decision",
                "decision": "ALLOW",
                "allowed": True,
                "container": "c3",
                "dry_run": False,  # dry_run not True
            }) + "\n")
            f.write(json.dumps({
                "event_type": "policy_decision",
                "decision": "DENY",
                "allowed": False,
                "container": "valid-app",
                "reason": "Retry limit reached",
                "dry_run": True,
            }) + "\n")

        stats = get_policy_decision_stats(history_path=self.policy_path)
        self.assertEqual(stats["total_evaluations"], 1)
        self.assertEqual(stats["allow_count"], 0)
        self.assertEqual(stats["deny_count"], 1)
        self.assertEqual(stats["denial_reasons"], {"Retry limit reached": 1})
        self.assertEqual(stats["most_frequent_denial_reason"], "Retry limit reached")
        self.assertEqual(stats["skipped_records"], 5)

    def test_policy_stats_bounded_reads(self):
        # Write 20 DENY decisions with different reasons
        for i in range(20):
            reason = "Reason A" if i < 15 else "Reason B"
            record_policy_decision(
                f"app-{i}",
                {"decision": "DENY", "allowed": False, "dry_run": True, "reason": reason},
                self.policy_path,
            )

        # limit=5 should only evaluate the last 5 records (which are all Reason B)
        stats = get_policy_decision_stats(limit=5, history_path=self.policy_path)
        self.assertEqual(stats["total_evaluations"], 5)
        self.assertEqual(stats["deny_count"], 5)
        self.assertEqual(stats["denial_reasons"], {"Reason B": 5})
        self.assertEqual(stats["most_frequent_denial_reason"], "Reason B")


class TestRecoveryExecutionStatistics(unittest.TestCase):
    """Test suite for recovery execution success rate statistics."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.recovery_path = Path(self.temp_dir.name) / "recovery_history.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_recovery_stats_missing_and_empty_file(self):
        stats = get_recovery_success_rate(history_path=self.recovery_path)
        self.assertEqual(stats["total_attempts"], 0)
        self.assertEqual(stats["successful_recoveries"], 0)
        self.assertEqual(stats["failed_recoveries"], 0)
        self.assertEqual(stats["unknown_outcomes"], 0)
        self.assertEqual(stats["success_rate_percent"], 0.0)
        self.assertEqual(stats["denominator"], 0)
        self.assertEqual(stats["skipped_records"], 0)
        self.assertTrue(stats["verified_success_supported"])

    def test_recovery_stats_invalid_limit(self):
        record_recovery_event("app-1", {"success": True}, history_path=self.recovery_path)
        for bad_limit in [0, -1, "5", None, False, True]:
            stats = get_recovery_success_rate(limit=bad_limit, history_path=self.recovery_path)
            self.assertEqual(stats["total_attempts"], 0)

    def test_recovery_stats_success_and_failure_rates(self):
        # 3 successes, 1 failure = 75.0%
        record_recovery_event("app-1", {"success": True}, self.recovery_path)
        record_recovery_event("app-2", {"success": True}, self.recovery_path)
        record_recovery_event("app-3", {"success": False}, self.recovery_path)
        record_recovery_event("app-4", {"success": True}, self.recovery_path)

        stats = get_recovery_success_rate(history_path=self.recovery_path)
        self.assertEqual(stats["total_attempts"], 4)
        self.assertEqual(stats["successful_recoveries"], 3)
        self.assertEqual(stats["failed_recoveries"], 1)
        self.assertEqual(stats["unknown_outcomes"], 0)
        self.assertEqual(stats["denominator"], 4)
        self.assertEqual(stats["success_rate_percent"], 75.0)
        self.assertEqual(stats["skipped_records"], 0)

    def test_recovery_stats_unknown_outcomes(self):
        # When success cannot be determined as boolean, record as unknown outcome
        with self.recovery_path.open("w", encoding="utf-8") as f:
            f.write(json.dumps({
                "action": "start_container",
                "container": "app-1",
                "success": True,
            }) + "\n")
            f.write(json.dumps({
                "action": "start_container",
                "container": "app-2",
                "success": "not_a_bool",  # Unknown outcome
            }) + "\n")
            f.write(json.dumps({
                "action": "start_container",
                "container": "app-3",
                # missing success field
            }) + "\n")

        stats = get_recovery_success_rate(history_path=self.recovery_path)
        self.assertEqual(stats["total_attempts"], 3)
        self.assertEqual(stats["successful_recoveries"], 1)
        self.assertEqual(stats["failed_recoveries"], 0)
        self.assertEqual(stats["unknown_outcomes"], 2)
        self.assertEqual(stats["denominator"], 3)
        # 1 success out of 3 total attempts = 33.33%
        self.assertEqual(stats["success_rate_percent"], 33.33)

    def test_recovery_stats_policy_records_and_malformed_ignored(self):
        with self.recovery_path.open("w", encoding="utf-8") as f:
            f.write("corrupted json\n")
            f.write(json.dumps({"event_type": "policy_decision", "action": "evaluate_policy"}) + "\n")
            f.write(json.dumps({"action": "other_action", "container": "app-1"}) + "\n")
            f.write(json.dumps({"action": "start_container", "container": "app-real", "success": True}) + "\n")

        stats = get_recovery_success_rate(history_path=self.recovery_path)
        self.assertEqual(stats["total_attempts"], 1)
        self.assertEqual(stats["successful_recoveries"], 1)
        self.assertEqual(stats["skipped_records"], 3)

    def test_recovery_stats_bounded_reads(self):
        # Write 10 failures then 10 successes
        for i in range(10):
            record_recovery_event(f"fail-{i}", {"success": False}, self.recovery_path)
        for i in range(10):
            record_recovery_event(f"ok-{i}", {"success": True}, self.recovery_path)

        # limit=5 inspects only the last 5 records (which are all successes)
        stats = get_recovery_success_rate(limit=5, history_path=self.recovery_path)
        self.assertEqual(stats["total_attempts"], 5)
        self.assertEqual(stats["successful_recoveries"], 5)
        self.assertEqual(stats["failed_recoveries"], 0)
        self.assertEqual(stats["success_rate_percent"], 100.0)


class TestMetricTrends(unittest.TestCase):
    """Test suite for bounded metric trend extraction and time-window filtering."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metrics_path = Path(self.temp_dir.name) / "metrics.jsonl"
        self.base_time = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_samples(self, samples):
        with self.metrics_path.open("w", encoding="utf-8") as f:
            for s in samples:
                f.write(json.dumps(s) + "\n")

    def test_metric_trends_missing_and_empty_file(self):
        self.assertEqual(get_metric_trends(metrics_path=self.metrics_path), [])
        self.metrics_path.touch()
        self.assertEqual(get_metric_trends(metrics_path=self.metrics_path), [])

    def test_metric_trends_invalid_limit(self):
        self._write_samples([{"timestamp": self.base_time.isoformat(), "cpu_usage_percent": 10.0}])
        for bad_limit in [0, -1, "10", None, False, True, 4.5]:
            self.assertEqual(get_metric_trends(limit=bad_limit, metrics_path=self.metrics_path), [])

    def test_metric_trends_chronological_ordering(self):
        # Write samples out of order
        t1 = self.base_time
        t2 = self.base_time + timedelta(minutes=5)
        t3 = self.base_time + timedelta(minutes=10)

        samples = [
            {"timestamp": t2.isoformat(), "cpu_usage_percent": 20.0},
            {"timestamp": t1.isoformat(), "cpu_usage_percent": 10.0},
            {"timestamp": t3.isoformat(), "cpu_usage_percent": 30.0},
        ]
        self._write_samples(samples)

        trends = get_metric_trends(metrics_path=self.metrics_path)
        self.assertEqual(len(trends), 3)
        self.assertEqual(trends[0]["timestamp"], t1.isoformat())
        self.assertEqual(trends[1]["timestamp"], t2.isoformat())
        self.assertEqual(trends[2]["timestamp"], t3.isoformat())
        self.assertEqual(trends[0]["cpu_usage_percent"], 10.0)
        self.assertEqual(trends[2]["cpu_usage_percent"], 30.0)

    def test_metric_trends_bounded_samples(self):
        # Write 20 samples
        samples = [
            {"timestamp": (self.base_time + timedelta(minutes=i)).isoformat(), "sample_idx": i}
            for i in range(20)
        ]
        self._write_samples(samples)

        # Request limit=5
        trends = get_metric_trends(limit=5, metrics_path=self.metrics_path)
        self.assertEqual(len(trends), 5)
        # Should return the 5 most recent samples in chronological order: [15, 16, 17, 18, 19]
        self.assertEqual([s["sample_idx"] for s in trends], [15, 16, 17, 18, 19])

    def test_metric_trends_time_window_filtering(self):
        # 6 samples at 0m, 10m, 20m, 30m, 40m, 50m
        samples = [
            {"timestamp": (self.base_time + timedelta(minutes=10 * i)).isoformat(), "idx": i}
            for i in range(6)
        ]
        self._write_samples(samples)

        # Filter window: [15m, 45m] -> should match idx 2 (20m), idx 3 (30m), idx 4 (40m)
        since = self.base_time + timedelta(minutes=15)
        until = self.base_time + timedelta(minutes=45)
        trends = get_metric_trends(since=since, until=until, metrics_path=self.metrics_path)
        self.assertEqual(len(trends), 3)
        self.assertEqual([s["idx"] for s in trends], [2, 3, 4])

    def test_metric_trends_window_boundary_inclusivity(self):
        t_exact_1 = self.base_time + timedelta(minutes=10)
        t_exact_2 = self.base_time + timedelta(minutes=20)

        samples = [
            {"timestamp": t_exact_1.isoformat(), "idx": 1},
            {"timestamp": (self.base_time + timedelta(minutes=15)).isoformat(), "idx": 2},
            {"timestamp": t_exact_2.isoformat(), "idx": 3},
        ]
        self._write_samples(samples)

        # Boundaries match exactly t_exact_1 and t_exact_2
        trends = get_metric_trends(since=t_exact_1, until=t_exact_2, metrics_path=self.metrics_path)
        self.assertEqual(len(trends), 3)
        self.assertEqual([s["idx"] for s in trends], [1, 2, 3])

    def test_metric_trends_utc_normalization_and_offsets(self):
        # Sample with +05:30 offset: 17:30+05:30 is 12:00 UTC
        ts_ist = "2026-10-20T17:30:00+05:30"
        # Sample with -04:00 offset: 08:05-04:00 is 12:05 UTC
        ts_edt = "2026-10-20T08:05:00-04:00"
        # Sample with trailing Z: 12:10:00Z is 12:10 UTC
        ts_z = "2026-10-20T12:10:00Z"

        samples = [
            {"timestamp": ts_ist, "tag": "ist"},
            {"timestamp": ts_edt, "tag": "edt"},
            {"timestamp": ts_z, "tag": "z"},
        ]
        self._write_samples(samples)

        trends = get_metric_trends(metrics_path=self.metrics_path)
        self.assertEqual(len(trends), 3)
        # Verify timestamps are normalized to UTC (+00:00)
        self.assertEqual(trends[0]["timestamp"], "2026-10-20T12:00:00+00:00")
        self.assertEqual(trends[1]["timestamp"], "2026-10-20T12:05:00+00:00")
        self.assertEqual(trends[2]["timestamp"], "2026-10-20T12:10:00+00:00")

    def test_metric_trends_invalid_time_windows(self):
        # since > until
        since = self.base_time + timedelta(hours=2)
        until = self.base_time + timedelta(hours=1)
        self._write_samples([{"timestamp": self.base_time.isoformat()}])
        self.assertEqual(get_metric_trends(since=since, until=until, metrics_path=self.metrics_path), [])

        # Unparseable since or until
        self.assertEqual(get_metric_trends(since="not_a_date", metrics_path=self.metrics_path), [])
        self.assertEqual(get_metric_trends(until="corrupt", metrics_path=self.metrics_path), [])

    def test_metric_trends_malformed_samples_skipped(self):
        with self.metrics_path.open("w", encoding="utf-8") as f:
            f.write("not json\n")
            f.write(json.dumps("just a string") + "\n")
            f.write(json.dumps({"no_timestamp": True}) + "\n")
            f.write(json.dumps({"timestamp": "invalid_date_format"}) + "\n")
            f.write(json.dumps({
                "timestamp": self.base_time.isoformat(),
                "cpu_usage_percent": 45.2,
                "memory": {"usage_percent": 60.0},
                "disk": {"usage_percent": 30.0},
            }) + "\n")

        trends = get_metric_trends(metrics_path=self.metrics_path)
        self.assertEqual(len(trends), 1)
        self.assertEqual(trends[0]["cpu_usage_percent"], 45.2)

    def test_metric_trends_value_preservation(self):
        sample = {
            "timestamp": "2026-10-20T12:00:00Z",
            "hostname": "prod-node-1",
            "operating_system": "Linux",
            "kernel": "6.18.33",
            "cpu_usage_percent": 74.8,
            "memory": {"usage_percent": 82.1, "total_mb": 4096.0, "used_mb": 3362.8},
            "disk": {"usage_percent": 55.4, "total_gb": 128.0, "used_gb": 70.9},
            "health_checks": {"cpu": "WARNING", "memory": "WARNING", "disk": "NORMAL"},
            "overall_status": "WARNING",
        }
        self._write_samples([sample])

        trends = get_metric_trends(metrics_path=self.metrics_path)
        self.assertEqual(len(trends), 1)
        res = trends[0]
        self.assertEqual(res["hostname"], "prod-node-1")
        self.assertEqual(res["cpu_usage_percent"], 74.8)
        self.assertEqual(res["memory"]["usage_percent"], 82.1)
        self.assertEqual(res["disk"]["usage_percent"], 55.4)
        self.assertEqual(res["health_checks"]["cpu"], "WARNING")
        self.assertEqual(res["overall_status"], "WARNING")


if __name__ == "__main__":
    unittest.main()
