#!/usr/bin/env python3

"""
Unit and Integration Test Suite for LinuxOps Phase 12 — Observability & Operational Intelligence.

Verifies:
1. Unified incident timeline extraction, normalization, and multi-dimensional filtering.
2. Reliability metrics calculation (Availability, MTTR, Frequency, Recovery Success).
3. Strict separation of measured values from missing telemetry (no invented data).
4. Advanced operational alerts (persistent outages, crash loops, cooldowns, failed recoveries).
5. Stable alert deduplication across time windows and fingerprints.
6. Explainable diagnostics and safe, non-destructive troubleshooting guidance.
7. Host watchdog supervisor state tracking and cooldown detection.
8. Defensive handling of missing, empty, malformed, or corrupt log files.
9. Secret redaction and security boundaries (zero real subprocesses or container operations).
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from app.analytics import (
    INCIDENT_CATEGORIES,
    classify_incident_category,
    compute_operational_reliability_metrics,
    evaluate_advanced_operational_alerts,
    format_timeline_rows,
    get_explainable_diagnostic_guidance,
    get_unified_incident_timeline,
    get_watchdog_status,
    normalize_severity,
    parse_iso_timestamp,
)


class TestTimestampAndCategoryParsing(unittest.TestCase):
    """Test ISO timestamp normalization and category classification."""

    def test_parse_iso_timestamp_valid_formats(self):
        # Trailing Z
        dt_z = parse_iso_timestamp("2026-10-25T12:00:00Z")
        self.assertIsNotNone(dt_z)
        self.assertEqual(dt_z.tzinfo, timezone.utc)
        self.assertEqual(dt_z.hour, 12)

        # Offset +05:30 -> 12:00 UTC
        dt_ist = parse_iso_timestamp("2026-10-25T17:30:00+05:30")
        self.assertIsNotNone(dt_ist)
        self.assertEqual(dt_ist.astimezone(timezone.utc).hour, 12)

        # Epoch timestamp
        dt_epoch = parse_iso_timestamp(1761393600)
        self.assertIsNotNone(dt_epoch)

    def test_parse_iso_timestamp_invalid(self):
        for bad in [None, "", "not-a-date", True, False, [], {}]:
            self.assertIsNone(parse_iso_timestamp(bad))

    def test_classify_incident_category_rules(self):
        # OOM
        self.assertEqual(classify_incident_category({"exit_code": 137}), "OOM_KILL")
        self.assertEqual(classify_incident_category({"oom_killed": True}), "OOM_KILL")
        self.assertEqual(classify_incident_category({"message": "kernel oom killer invoked"}), "OOM_KILL")

        # Crash loop
        self.assertEqual(classify_incident_category({"message": "rapid crash loop detected"}), "CRASH_LOOP")
        self.assertEqual(classify_incident_category({"rule_id": "restart_count_high"}), "CRASH_LOOP")

        # Probe failure
        self.assertEqual(classify_incident_category({"message": "health probe returned 503"}), "UNHEALTHY_PROBE")

        # Connection failure
        self.assertEqual(classify_incident_category({"message": "dial tcp 127.0.0.1:5432: connection refused"}), "CONNECTION_FAILURE")

        # Policy denial
        self.assertEqual(classify_incident_category({"decision": "DENY"}), "POLICY_DENIAL")

        # Watchdog
        self.assertEqual(classify_incident_category({"source": "watchdog"}), "WATCHDOG_INTERVENTION")

        # General fallback
        self.assertEqual(classify_incident_category({}), "GENERAL_INCIDENT")

    def test_normalize_severity(self):
        self.assertEqual(normalize_severity("CRITICAL"), "CRITICAL")
        self.assertEqual(normalize_severity("critical"), "CRITICAL")
        self.assertEqual(normalize_severity("WARNING"), "WARNING")
        self.assertEqual(normalize_severity("WARN"), "WARNING")
        self.assertEqual(normalize_severity("INFO"), "INFO")
        self.assertEqual(normalize_severity(None, default="WARNING"), "WARNING")


class TestUnifiedIncidentTimeline(unittest.TestCase):
    """Test unified incident timeline correlation, formatting, and filtering."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.incidents_path = Path(self.temp_dir.name) / "incidents.jsonl"
        self.recovery_path = Path(self.temp_dir.name) / "recovery_history.jsonl"
        self.policy_path = Path(self.temp_dir.name) / "policy_history.jsonl"
        self.metrics_path = Path(self.temp_dir.name) / "metrics.jsonl"
        self.base_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_jsonl(self, path: Path, records: list[dict]):
        with path.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    def _get_timeline(self, **kwargs):
        defaults = {
            "incidents_path": self.incidents_path,
            "history_path": self.recovery_path,
            "policy_path": self.policy_path,
            "include_watchdog": False,
        }
        defaults.update(kwargs)
        return get_unified_incident_timeline(**defaults)

    def test_empty_and_missing_files(self):
        timeline = self._get_timeline()
        self.assertEqual(timeline, [])

    def test_malformed_and_corrupt_lines_handled_gracefully(self):
        with self.incidents_path.open("w", encoding="utf-8") as f:
            f.write("corrupted line\n\n{\"broken\": json\n")
            f.write(json.dumps({
                "timestamp": self.base_time.isoformat(),
                "incident_id": "inc-01",
                "container_name": "api-srv",
                "rule_id": "OOM_KILL",
                "resolution_status": "RESOLVED",
                "message": "Recovered from memory pressure",
            }) + "\n")

        timeline = self._get_timeline()
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["incident_id"], "inc-01")
        self.assertEqual(timeline[0]["incident_category"], "OOM_KILL")

    def test_merges_multiple_sources_chronologically(self):
        t1 = self.base_time
        t2 = self.base_time + timedelta(minutes=5)
        t3 = self.base_time + timedelta(minutes=10)

        # 1. Incident resolution
        self._write_jsonl(self.incidents_path, [{
            "timestamp": t1.isoformat(),
            "incident_id": "inc-01",
            "container_name": "worker-1",
            "rule_id": "CRASH_LOOP",
            "resolution_status": "FAILED",
            "message": "Crash loop observed",
        }])

        # 2. Recovery attempt
        self._write_jsonl(self.recovery_path, [{
            "timestamp": t2.isoformat(),
            "container": "worker-1",
            "action": "start_container",
            "success": True,
            "verification_status": "VERIFIED",
            "message": "Container restarted and healthy",
        }])

        # 3. Policy decision
        self._write_jsonl(self.policy_path, [{
            "timestamp": t3.isoformat(),
            "event_type": "policy_decision",
            "container": "worker-2",
            "decision": "DENY",
            "allowed": False,
            "dry_run": True,
            "reason": "Host under high CPU pressure",
        }])

        timeline = self._get_timeline()

        self.assertEqual(len(timeline), 3)
        # Newest first
        self.assertEqual(timeline[0]["component"], "worker-2")
        self.assertEqual(timeline[0]["outcome"], "DENIED")
        self.assertEqual(timeline[1]["component"], "worker-1")
        self.assertEqual(timeline[1]["outcome"], "VERIFIED")
        self.assertEqual(timeline[2]["component"], "worker-1")
        self.assertEqual(timeline[2]["outcome"], "FAILED")

    def test_duration_correlation_between_failure_and_resolution(self):
        t_fail = self.base_time
        t_resolve = self.base_time + timedelta(seconds=75)

        self._write_jsonl(self.incidents_path, [{
            "timestamp": t_fail.isoformat(),
            "incident_id": "inc-oom",
            "container_name": "db-prod",
            "rule_id": "OOM_KILL",
            "resolution_status": "FAILED",
            "message": "OOM kill detected",
        }])

        self._write_jsonl(self.recovery_path, [{
            "timestamp": t_resolve.isoformat(),
            "container": "db-prod",
            "action": "start_container",
            "success": True,
            "verification_status": "VERIFIED",
            "message": "Post-recovery check passed",
        }])

        timeline = self._get_timeline()

        self.assertEqual(len(timeline), 2)
        # Verified event should have correlated 75s duration
        verified_ev = next(e for e in timeline if e["outcome"] == "VERIFIED")
        self.assertEqual(verified_ev["duration_seconds"], 75.0)

    def test_multi_dimensional_filtering(self):
        records = [
            {"timestamp": (self.base_time + timedelta(minutes=i)).isoformat(), "incident_id": f"inc-{i}", "container_name": f"svc-{i % 2}", "rule_id": "OOM_KILL" if i % 2 == 0 else "CONNECTION_FAILURE", "resolution_status": "RESOLVED" if i > 2 else "FAILED", "message": f"Event {i}"}
            for i in range(6)
        ]
        self._write_jsonl(self.incidents_path, records)

        # 1. Category filter
        filtered_cat = self._get_timeline(category_filter="OOM_KILL")
        self.assertTrue(all(e["incident_category"] == "OOM_KILL" for e in filtered_cat))

        # 2. Severity filter
        filtered_sev = self._get_timeline(severity_filter="CRITICAL")
        self.assertTrue(all(e["severity"] == "CRITICAL" for e in filtered_sev))

        # 3. Component search filter
        filtered_comp = self._get_timeline(component_filter="svc-0")
        self.assertTrue(all(e["component"] == "svc-0" for e in filtered_comp))

        # 4. Outcome filter
        filtered_out = self._get_timeline(outcome_filter="RESOLVED")
        self.assertTrue(all(e["outcome"] == "RESOLVED" for e in filtered_out))

        # 5. Time range filter
        since = self.base_time + timedelta(minutes=2)
        until = self.base_time + timedelta(minutes=4)
        filtered_time = self._get_timeline(since=since, until=until)
        self.assertEqual(len(filtered_time), 3)

    def test_secret_redaction_in_timeline_symptoms(self):
        self._write_jsonl(self.incidents_path, [{
            "timestamp": self.base_time.isoformat(),
            "incident_id": "sec-01",
            "container_name": "auth-service",
            "rule_id": "CONFIG_ERROR",
            "resolution_status": "FAILED",
            "message": "Auth failed with password=SuperSecretPassword123 and Bearer eyJhbGciOiJIUzI1NiJ9.test",
        }])

        timeline = self._get_timeline()
        self.assertEqual(len(timeline), 1)
        symptoms = timeline[0]["symptoms"]
        self.assertNotIn("SuperSecretPassword123", symptoms)
        self.assertIn("[REDACTED_SECRET]", symptoms)
        self.assertIn("[REDACTED_TOKEN]", symptoms)


class TestOperationalReliabilityMetrics(unittest.TestCase):
    """Test empirical reliability metrics and strict non-fabrication of missing data."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metrics_path = Path(self.temp_dir.name) / "metrics.jsonl"
        self.base_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_availability_insufficient_data_when_no_samples(self):
        metrics = compute_operational_reliability_metrics(
            timeline_events=[],
            metrics_path=self.metrics_path,
            now=self.base_time,
        )
        self.assertIsNone(metrics["availability"]["percent"])
        self.assertEqual(metrics["availability"]["status"], "INSUFFICIENT_DATA")
        self.assertIn("not fabricated", metrics["availability"]["details"])

    def test_availability_measured_from_samples(self):
        samples = [
            {"timestamp": (self.base_time - timedelta(minutes=i * 10)).isoformat(), "overall_status": "NORMAL"}
            for i in range(9)
        ]
        # Add 1 degraded sample
        samples.append({"timestamp": (self.base_time - timedelta(minutes=90)).isoformat(), "overall_status": "CRITICAL"})

        with self.metrics_path.open("w", encoding="utf-8") as f:
            for s in samples:
                f.write(json.dumps(s) + "\n")

        metrics = compute_operational_reliability_metrics(
            timeline_events=[],
            metrics_path=self.metrics_path,
            window_hours=2.0,
            now=self.base_time,
        )
        self.assertEqual(metrics["availability"]["status"], "MEASURED")
        self.assertEqual(metrics["availability"]["sample_count"], 10)
        self.assertEqual(metrics["availability"]["healthy_samples"], 9)
        self.assertEqual(metrics["availability"]["degraded_samples"], 1)
        self.assertEqual(metrics["availability"]["percent"], 90.0)

    def test_mttr_insufficient_data_when_no_durations(self):
        events = [
            {"timestamp": self.base_time.isoformat(), "outcome": "FAILED", "duration_seconds": None},
        ]
        metrics = compute_operational_reliability_metrics(timeline_events=events, now=self.base_time)
        self.assertEqual(metrics["mttr"]["status"], "INSUFFICIENT_DATA")
        self.assertIsNone(metrics["mttr"]["minutes"])
        self.assertIn("insufficient duration data", metrics["mttr"]["formatted"])

    def test_mttr_measured_accurately_from_durations(self):
        events = [
            {"timestamp": self.base_time.isoformat(), "action_attempted": "start_container", "outcome": "VERIFIED", "duration_seconds": 60.0},
            {"timestamp": self.base_time.isoformat(), "action_attempted": "start_container", "outcome": "VERIFIED", "duration_seconds": 180.0},
        ]
        metrics = compute_operational_reliability_metrics(timeline_events=events, now=self.base_time)
        self.assertEqual(metrics["mttr"]["status"], "MEASURED")
        self.assertEqual(metrics["mttr"]["minutes"], 2.0)  # (60 + 180) / 2 = 120s = 2.0m
        self.assertEqual(metrics["mttr"]["sample_size"], 2)

    def test_incident_frequency_and_recovery_success_rate(self):
        events = [
            {"timestamp": self.base_time.isoformat(), "action_attempted": "start_container", "outcome": "VERIFIED", "severity": "INFO"},
            {"timestamp": self.base_time.isoformat(), "action_attempted": "start_container", "outcome": "FAILED", "severity": "CRITICAL"},
            {"timestamp": self.base_time.isoformat(), "action_attempted": "start_container", "outcome": "VERIFIED", "severity": "INFO"},
        ]
        metrics = compute_operational_reliability_metrics(
            timeline_events=events,
            window_hours=1.0,
            now=self.base_time,
        )
        self.assertEqual(metrics["recoveries"]["restart_attempts"], 3)
        self.assertEqual(metrics["recoveries"]["successful_recoveries"], 2)
        self.assertEqual(metrics["recoveries"]["failed_recoveries"], 1)
        self.assertEqual(metrics["recoveries"]["success_rate_percent"], 66.67)
        self.assertEqual(metrics["incident_frequency"]["total_incidents"], 1)  # only critical/failed counted
        self.assertEqual(metrics["incident_frequency"]["incidents_per_hour"], 1.0)


class TestAdvancedOperationalAlertsAndDeduplication(unittest.TestCase):
    """Test operational alert rules and stable deduplication."""

    def setUp(self):
        self.ref_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    def test_persistent_outage_detection(self):
        containers = [
            {
                "name": "payment-api",
                "state": "exited",
                "exit_code": 1,
                "started_at": (self.ref_time - timedelta(minutes=15)).isoformat(),
                "uptime_seconds": 0,
            }
        ]
        alerts = evaluate_advanced_operational_alerts(
            active_containers=containers,
            outage_threshold_seconds=300.0,
            now=self.ref_time,
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "persistent_workload_outage")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[0]["target"], "payment-api")

    def test_crash_loop_detection_from_restart_count(self):
        containers = [
            {
                "name": "worker-queue",
                "state": "running",
                "restart_count": 5,
                "uptime_seconds": 12.0,
            }
        ]
        alerts = evaluate_advanced_operational_alerts(
            active_containers=containers,
            crash_loop_threshold=3,
            now=self.ref_time,
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "repeated_failures_crash_loop")
        self.assertEqual(alerts[0]["target"], "worker-queue")
        self.assertEqual(alerts[0]["occurrence_count"], 5)

    def test_watchdog_cooldown_alert(self):
        wd_status = {
            "available": True,
            "status": "COOLDOWN",
            "in_cooldown": True,
            "cooldown_until": "2026-10-25T12:05:00+00:00",
            "consecutive_failures": 3,
            "restart_count_in_window": 3,
        }
        alerts = evaluate_advanced_operational_alerts(
            watchdog_status=wd_status,
            now=self.ref_time,
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "restart_cooldown_active")
        self.assertEqual(alerts[0]["severity"], "WARNING")
        self.assertIn("2026-10-25T12:05:00+00:00", alerts[0]["message"])

    def test_alert_deduplication(self):
        # Multiple events with the same failed container
        events = [
            {"timestamp": self.ref_time.isoformat(), "action_attempted": "start_container", "outcome": "FAILED", "component": "cache-redis"},
            {"timestamp": self.ref_time.isoformat(), "action_attempted": "start_container", "outcome": "FAILED", "component": "cache-redis"},
            {"timestamp": self.ref_time.isoformat(), "action_attempted": "start_container", "outcome": "FAILED", "component": "cache-redis"},
        ]
        alerts = evaluate_advanced_operational_alerts(
            timeline_events=events,
            crash_loop_threshold=5,
            now=self.ref_time,
        )
        # Should deduplicate to single alert for cache-redis with occurrence_count 3
        redis_alerts = [a for a in alerts if a["target"] == "cache-redis"]
        self.assertEqual(len(redis_alerts), 1)
        self.assertEqual(redis_alerts[0]["occurrence_count"], 3)


class TestExplainableDiagnosticsGuidance(unittest.TestCase):
    """Test root-cause diagnostics explanations and safe guidance."""

    def test_oom_killer_explanation(self):
        g = get_explainable_diagnostic_guidance({
            "name": "analytics-worker",
            "exit_code": 137,
            "oom_killed": True,
        })
        self.assertEqual(g["category"], "OOM_KILL")
        self.assertIn("cgroup", g["likely_cause"])
        self.assertIn("HIGH", g["certainty"])
        self.assertTrue(len(g["safe_troubleshooting_steps"]) >= 3)
        self.assertTrue(len(g["safe_read_only_commands"]) >= 2)
        self.assertTrue(any("Do NOT" in r for r in g["risky_actions_to_avoid"]))

    def test_connection_refused_explanation(self):
        g = get_explainable_diagnostic_guidance({
            "name": "web-api",
            "message": "dial tcp 127.0.0.1:5432: connection refused",
        })
        self.assertEqual(g["category"], "CONNECTION_FAILURE")
        self.assertIn("upstream dependency", g["likely_cause"])
        self.assertIn("port 5432", g["safe_troubleshooting_steps"][0])

    def test_crash_loop_explanation(self):
        g = get_explainable_diagnostic_guidance({
            "name": "worker-app",
            "message": "repeated crash loop in progress",
        })
        self.assertEqual(g["category"], "CRASH_LOOP")
        self.assertIn("rapid crash-restart thrash", g["likely_cause"])
        self.assertTrue(any("restart policy" in step for step in g["safe_troubleshooting_steps"]))


class TestWatchdogStateReader(unittest.TestCase):
    """Test reading watchdog status with mock and missing files."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_path = Path(self.temp_dir.name) / "watchdog-state.json"
        self.log_path = Path(self.temp_dir.name) / "watchdog.log"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_watchdog_missing_state(self):
        non_existent = Path(self.temp_dir.name) / "does-not-exist.json"
        wd = get_watchdog_status(state_path=non_existent)
        self.assertFalse(wd["available"])
        self.assertEqual(wd["status"], "UNAVAILABLE")

    def test_watchdog_healthy_state(self):
        state_data = {
            "LastProbeTime": "2026-10-25T12:00:00+00:00",
            "LastProbeStatus": "HEALTHY",
            "ConsecutiveFailures": 0,
            "RestartCountInWindow": 0,
            "InCooldown": False,
            "CooldownUntil": None,
            "LastRecoveryAction": None,
        }
        with self.state_path.open("w", encoding="utf-8") as f:
            json.dump(state_data, f)

        wd = get_watchdog_status(state_path=self.state_path)
        self.assertTrue(wd["available"])
        self.assertEqual(wd["status"], "HEALTHY")
        self.assertEqual(wd["consecutive_failures"], 0)

    def test_watchdog_cooldown_state(self):
        state_data = {
            "LastProbeTime": "2026-10-25T12:00:00+00:00",
            "LastProbeStatus": "DEGRADED",
            "ConsecutiveFailures": 3,
            "RestartCountInWindow": 3,
            "InCooldown": True,
            "CooldownUntil": "2026-10-25T12:05:00+00:00",
            "LastRecoveryAction": "2026-10-25T11:59:00+00:00",
        }
        with self.state_path.open("w", encoding="utf-8") as f:
            json.dump(state_data, f)

        wd = get_watchdog_status(state_path=self.state_path)
        self.assertTrue(wd["available"])
        self.assertEqual(wd["status"], "COOLDOWN")
        self.assertTrue(wd["in_cooldown"])


if __name__ == "__main__":
    unittest.main()
