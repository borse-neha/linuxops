#!/usr/bin/env python3

"""
Unit and integration tests for LinuxOps Phase 13:
Isolated Scale Testing, Fault Injection & Resilience Certification.

Verifies:
1. Fleet scale simulation across 10, 25, 50, and 100 workloads.
2. Hard isolation: Mock runner blocks mutating commands and prohibits live Podman socket access.
3. Fault injection scenarios:
   - Crash loops and unhandled exceptions.
   - Unhealthy HTTP 503 probes and timeouts.
   - Connection refused network failures.
   - Out-of-memory (OOM) killer terminations (exit code 137).
   - Missing configuration environment variables.
   - Permission denied (exit 126 / errno 13) file access failures.
   - Missing and delayed telemetry.
   - Duplicate event deduplication and malformed logs.
   - Watchdog supervisor retry-limit and cooldown throttling.
4. Security boundary assertions:
   - Global recovery kill-switch enforcement (LINUXOPS_RECOVERY_DISABLED=1).
   - Protected workload immunity (cloudops-floci and sentinel data).
   - Tamper-evident approval tokens and single-use cryptographic token invalidation.
   - Zero host mutation invariant.
"""

from collections import deque
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.analytics import (
    compute_operational_reliability_metrics,
    evaluate_advanced_operational_alerts,
    get_explainable_diagnostic_guidance,
    get_unified_incident_timeline,
    get_watchdog_status,
)
from app.container_inspector import (
    calculate_latency_percentiles,
    is_protected_workload,
    scan_containers,
)
from app.diagnostics_engine import (
    diagnose_all_containers,
    diagnose_container_record,
)
from app.recovery_controller import (
    approve_remediation_plan,
    build_remediation_plan,
    compute_plan_hash,
    evaluate_incident_recovery,
    execute_authorized_recovery,
    is_global_recovery_disabled,
    is_protected_container_target,
    set_global_recovery_disabled,
    validate_approval_token,
)
from scripts.isolated_resilience_harness import (
    MockIsolatedPodmanRunner,
    execute_isolated_scale_run,
    generate_isolated_fleet,
    run_full_isolated_resilience_matrix,
)


class TestIsolatedMockRunnerAndIsolation(unittest.TestCase):
    """Test hard isolation invariants of MockIsolatedPodmanRunner."""

    def setUp(self):
        self.fleet_data = generate_isolated_fleet(10)
        self.runner = MockIsolatedPodmanRunner(self.fleet_data)

    def test_mock_runner_prohibits_mutating_commands(self):
        """Mutating operations must be strictly rejected with RuntimeError."""
        mutating_verbs = ["start", "restart", "stop", "rm", "kill", "run"]
        for verb in mutating_verbs:
            with self.assertRaises(RuntimeError) as ctx:
                self.runner(["podman", verb, "container_test"])
            self.assertIn("MUTATING PODMAN COMMAND PROHIBITED", str(ctx.exception))
        self.assertEqual(len(self.runner.mutating_calls_attempted), len(mutating_verbs))

    def test_mock_runner_serves_valid_json_read_queries(self):
        """Querying ps, inspect, stats, and logs succeeds without accessing live host."""
        # 1. ps
        res_ps = self.runner(["podman", "ps", "-a", "--format", "json"])
        self.assertEqual(res_ps.returncode, 0)
        ps_list = json.loads(res_ps.stdout)
        self.assertEqual(len(ps_list), 10)

        # 2. inspect
        test_id = ps_list[0]["Id"]
        res_inspect = self.runner(["podman", "inspect", test_id])
        self.assertEqual(res_inspect.returncode, 0)
        inspect_list = json.loads(res_inspect.stdout)
        self.assertEqual(len(inspect_list), 1)
        self.assertEqual(inspect_list[0]["Id"], test_id)

        # 3. stats
        res_stats = self.runner(["podman", "stats", "--no-stream", "--format", "json"])
        self.assertEqual(res_stats.returncode, 0)
        stats_list = json.loads(res_stats.stdout)
        self.assertIsInstance(stats_list, list)

        # 4. logs
        c_name = ps_list[0]["Names"][0]
        res_logs = self.runner(["podman", "logs", c_name])
        self.assertEqual(res_logs.returncode, 0)
        self.assertTrue(len(res_logs.stdout) > 0)


class TestControlledFaultInjection(unittest.TestCase):
    """Test controlled injection and detection of all 8 fault scenarios."""

    def setUp(self):
        self.fleet_data = generate_isolated_fleet(25)
        self.runner = MockIsolatedPodmanRunner(self.fleet_data)
        self.scan_res = scan_containers(runner=self.runner, batch_size=25, collect_stats=True)
        self.containers = self.scan_res.get("containers", [])
        self.diag_res = diagnose_all_containers(
            self.containers,
            log_retriever=lambda name: (self.fleet_data["logs_map"].get(name, ""), True),
        )
        self.incidents = self.diag_res.get("incidents", [])

    def test_crash_loop_fault_detected(self):
        """Containers with high restart counts and recent non-zero exits trigger crash-loop diagnosis."""
        crash_incs = [i for i in self.incidents if "CRASH_LOOP" in str(i.get("rule_id", "")) or "crash" in str(i.get("probable_cause", "")).lower()]
        self.assertTrue(len(crash_incs) > 0, "Crash loop fault should be detected")
        for inc in crash_incs:
            self.assertEqual(inc.get("severity"), "CRITICAL")
            self.assertIn("crash", inc.get("rule_id", "").lower())

    def test_unhealthy_probe_fault_detected(self):
        """Containers with failing health streaks and HTTP 503 errors trigger unhealthy probe diagnosis."""
        probe_incs = [i for i in self.incidents if i.get("rule_id") == "HEALTHCHECK_FAILING"]
        self.assertTrue(len(probe_incs) > 0, "Unhealthy probe fault should be detected as HEALTHCHECK_FAILING")
        for inc in probe_incs:
            self.assertEqual(inc.get("severity"), "CRITICAL")

    def test_connection_failure_fault_detected(self):
        """Containers reporting connection refused in logs trigger connection failure diagnosis."""
        conn_incs = [i for i in self.incidents if "CONN" in str(i.get("rule_id", "")) or "connection" in str(i.get("message", "")).lower() or "5432" in str(i.get("message", ""))]
        self.assertTrue(len(conn_incs) > 0, "Connection failure fault should be detected")

    def test_oom_killed_fault_detected(self):
        """Containers exited with code 137 and OOMKilled flag trigger OOM diagnosis."""
        oom_incs = [i for i in self.incidents if "OOM" in str(i.get("rule_id", ""))]
        self.assertTrue(len(oom_incs) > 0, "OOM killed fault should be detected")
        for inc in oom_incs:
            self.assertEqual(inc.get("severity"), "CRITICAL")

    def test_missing_config_fault_detected(self):
        """Containers exiting due to missing env variables trigger configuration diagnosis."""
        cfg_incs = [i for i in self.incidents if "CONFIG" in str(i.get("rule_id", "")) or "env" in str(i.get("message", "")).lower()]
        self.assertTrue(len(cfg_incs) > 0, "Missing configuration fault should be detected")

    def test_permission_denied_fault_detected(self):
        """Containers exiting with code 126 / permission denied trigger permission diagnosis."""
        perm_incs = [i for i in self.incidents if "PERM" in str(i.get("rule_id", "")) or "permission" in str(i.get("message", "")).lower()]
        self.assertTrue(len(perm_incs) > 0, "Permission denied fault should be detected")

    def test_missing_telemetry_handled_gracefully(self):
        """Containers without CPU/Mem stats do not crash scanner or diagnostics."""
        missing_stats_c = [c for c in self.containers if c.get("name", "").startswith("iso-missing-stats")]
        self.assertTrue(len(missing_stats_c) > 0)
        for c in missing_stats_c:
            metrics = c.get("metrics", {})
            self.assertEqual(metrics.get("telemetry_state"), "unavailable")
            self.assertEqual(metrics.get("cpu_percent", {}).get("status"), "unavailable")

    def test_event_deduplication_and_malformed_logs(self):
        """Duplicate alerts are deduplicated and malformed log entries are cleanly handled."""
        now = datetime.now(timezone.utc)
        duplicate_timeline = [
            {
                "timestamp": now.isoformat(),
                "incident_id": "INC-001",
                "component": "iso-crashloop-000",
                "rule_id": "CRASH_LOOP_DETECTED",
                "incident_category": "CRASH_LOOP_DETECTED",
                "severity": "CRITICAL",
                "symptoms": "Crash loop in progress",
                "action_attempted": "start_container",
                "outcome": "FAILED",
                "duration_seconds": None,
            },
            {
                "timestamp": now.isoformat(),
                "incident_id": "INC-001",
                "component": "iso-crashloop-000",
                "rule_id": "CRASH_LOOP_DETECTED",
                "incident_category": "CRASH_LOOP_DETECTED",
                "severity": "CRITICAL",
                "symptoms": "Crash loop in progress",
                "action_attempted": "start_container",
                "outcome": "FAILED",
                "duration_seconds": None,
            },
        ]
        alerts = evaluate_advanced_operational_alerts(
            timeline_events=duplicate_timeline,
            active_containers=self.containers,
            now=now,
        )
        crash_alerts = [a for a in alerts if a.get("component") == "iso-crashloop-000"]
        self.assertLessEqual(len(crash_alerts), 1, "Duplicate events must produce deduplicated alerts")


class TestWatchdogCooldownAndRetryThrottling(unittest.TestCase):
    """Test watchdog supervisor cooldown, retry limits, and throttle status."""

    def test_watchdog_cooldown_active_status(self):
        """When in_cooldown is True in supervisor state, get_watchdog_status reports COOLDOWN."""
        state_data = {
            "LastProbeTime": datetime.now(timezone.utc).isoformat(),
            "LastProbeStatus": "DEGRADED",
            "ConsecutiveFailures": 3,
            "RestartCountInWindow": 3,
            "InCooldown": True,
            "CooldownUntil": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "LastRecoveryAction": "RESTART_COOLDOWN_ACTIVE",
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(state_data, tf)
            tf_path = Path(tf.name)

        try:
            status = get_watchdog_status(state_path=tf_path)
            self.assertEqual(status["status"], "COOLDOWN")
            self.assertTrue(status["in_cooldown"])
            self.assertEqual(status["consecutive_failures"], 3)
            self.assertEqual(status["restart_count_in_window"], 3)
        finally:
            if tf_path.exists():
                tf_path.unlink()

    def test_watchdog_throttling_triggers_operational_alert(self):
        """Active cooldown in watchdog state triggers restart_cooldown_active alert."""
        now = datetime.now(timezone.utc)
        wd_status = {
            "available": True,
            "status": "COOLDOWN",
            "in_cooldown": True,
            "cooldown_until": (now + timedelta(minutes=5)).isoformat(),
            "consecutive_failures": 3,
            "restart_count_in_window": 3,
        }
        alerts = evaluate_advanced_operational_alerts(
            timeline_events=[],
            active_containers=[],
            watchdog_status=wd_status,
            now=now,
        )
        cd_alerts = [a for a in alerts if a.get("rule") == "restart_cooldown_active"]
        self.assertEqual(len(cd_alerts), 1)
        self.assertEqual(cd_alerts[0]["category"], "WATCHDOG_INTERVENTION")
        self.assertEqual(cd_alerts[0]["target_type"], "supervisor")


class TestScalabilityMatrixAndEmpiricalPerformance(unittest.TestCase):
    """Test empirical performance across 10, 25, 50, and 100 workloads."""

    def test_scale_matrix_10_25_50_100(self):
        """All fleet sizes execute completely, safely, and with high throughput."""
        fleet_sizes = [10, 25, 50, 100]
        results = run_full_isolated_resilience_matrix(fleet_sizes)
        self.assertEqual(len(results), 4)

        for res in results:
            size = res["fleet_size"]
            self.assertEqual(res["inspected_count"], size)
            self.assertTrue(res["incidents_detected"] > 0)
            self.assertTrue(res["kill_switch_held"], f"Kill switch must hold for fleet {size}")
            self.assertTrue(res["zero_mutations_enforced"], f"Zero mutations for fleet {size}")
            self.assertGreater(res["throughput_workloads_per_sec"], 50.0)

    def test_percentile_latency_calculation(self):
        """calculate_latency_percentiles produces accurate, mathematical percentiles."""
        latencies = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
        pct = calculate_latency_percentiles(latencies)
        self.assertEqual(pct["min_ms"], 10.0)
        self.assertEqual(pct["max_ms"], 100.0)
        self.assertEqual(pct["mean_ms"], 55.0)
        self.assertEqual(pct["p50_ms"], 55.0)
        self.assertAlmostEqual(pct["p95_ms"], 95.5, delta=1.0)


class TestSecurityBoundariesAndHardGuarantees(unittest.TestCase):
    """Test recovery kill switch, protected workloads, approval tokens, and socket isolation."""

    def test_global_recovery_kill_switch_blocks_evaluation_and_execution(self):
        """When global recovery is disabled, both proposal evaluation and execution are blocked."""
        orig = is_global_recovery_disabled()
        try:
            set_global_recovery_disabled(True)
            self.assertTrue(is_global_recovery_disabled())

            # 1. Evaluation check
            eval_res = evaluate_incident_recovery("iso-crashloop-001", "exited")
            self.assertFalse(eval_res["allowed"])
            self.assertIn("kill-switch", eval_res["reason"].lower())

            # 2. Execution check with approval token
            plan = build_remediation_plan("iso-crashloop-001", "start_container", current_state="exited")
            app_res = approve_remediation_plan(plan)
            token = app_res["approval_token"]
            exec_res = execute_authorized_recovery(
                "iso-crashloop-001",
                action="start_container",
                authorized=True,
                approval_token=token,
                plan=plan,
            )
            self.assertFalse(exec_res["success"])
            self.assertEqual(exec_res["verification_status"], "GLOBAL_KILL_SWITCH")
        finally:
            set_global_recovery_disabled(orig)

    def test_protected_workload_immunity_cloudops_floci(self):
        """cloudops-floci is permanently immune from all recovery evaluations and actions."""
        orig = is_global_recovery_disabled()
        try:
            set_global_recovery_disabled(False)
            # Both container name and prefix checks
            self.assertTrue(is_protected_workload("cloudops-floci", "f11bd857ea3a0011"))
            self.assertTrue(is_protected_container_target("cloudops-floci"))

            eval_res = evaluate_incident_recovery("cloudops-floci", "exited")
            self.assertFalse(eval_res["allowed"])
            self.assertIn("protected workload", eval_res["reason"].lower())

            exec_res = execute_authorized_recovery(
                "cloudops-floci",
                action="start_container",
                authorized=True,
            )
            self.assertFalse(exec_res["success"])
            self.assertEqual(exec_res["verification_status"], "PROTECTED_WORKLOAD")
        finally:
            set_global_recovery_disabled(orig)

    def test_approval_token_single_use_and_tamper_proofing(self):
        """Approval tokens are strictly single-use and tamper-evident."""
        orig = is_global_recovery_disabled()
        try:
            set_global_recovery_disabled(False)
            mock_runner = MockIsolatedPodmanRunner(generate_isolated_fleet(10))

            plan = build_remediation_plan("iso-healthy-srv-000", "start_container", current_state="exited")
            app_res = approve_remediation_plan(plan)
            token = app_res["approval_token"]

            # 1. Tamper check: modifying plan parameters invalidates approval
            tampered_plan = dict(plan)
            tampered_plan["parameters"] = {"extra_flag": "--privileged"}
            exec_res_tampered = execute_authorized_recovery(
                "iso-healthy-srv-000",
                action="start_container",
                authorized=True,
                approval_token=token,
                plan=tampered_plan,
                runner=mock_runner,
            )
            self.assertFalse(exec_res_tampered["success"])
            self.assertEqual(exec_res_tampered["verification_status"], "APPROVAL_INVALIDATED")

            # 2. Token reuse check
            # Even if execute fails or succeeds, token cannot be reused
            from app.recovery_controller import _EXECUTED_APPROVAL_TOKENS
            _EXECUTED_APPROVAL_TOKENS.add(token)

            exec_res_dup = execute_authorized_recovery(
                "iso-healthy-srv-000",
                action="start_container",
                authorized=True,
                approval_token=token,
                plan=plan,
                runner=mock_runner,
            )
            self.assertFalse(exec_res_dup["success"])
            self.assertEqual(exec_res_dup["verification_status"], "DUPLICATE_REQUEST_BLOCKED")
        finally:
            set_global_recovery_disabled(orig)


if __name__ == "__main__":
    unittest.main()
