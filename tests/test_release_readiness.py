#!/usr/bin/env python3

"""
LinuxOps Phase 5 — Controlled Staging, Performance & Release Readiness Test Suite.

Comprehensive validation covering:
1. Dashboard presentation of real host workloads, unmonitored states, stale telemetry, and pagination
2. Backend enforcement of recovery authorization and policy gates
3. Secret redaction across audit logs (recovery, policy, incident resolutions)
4. Scan cancellation, timeouts, unified timestamps, and metadata caching
5. Repeated monitoring cycles, incident identity stability, and alert deduplication
6. Prevention of arbitrary shell command injection through recovery interfaces
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from app.container_inspector import (
    ContainerMetadataCache,
    clear_container_metadata_cache,
    format_metric_value,
    get_container_metadata_cache,
    get_host_identity,
    normalize_container_record,
    parse_stats_entry,
    scan_containers,
)
from app.dashboard import (
    filter_and_paginate_containers,
    format_container_inventory_rows,
    format_incident_rows,
)
from app.diagnostics_engine import (
    build_incident,
    diagnose_all_containers,
    redact_sensitive_text,
)
from app.history import (
    inspect_audit_log_integrity,
    load_incident_history,
    load_policy_history,
    load_recovery_history,
    record_incident_resolution,
    record_policy_decision,
    record_recovery_event,
)
from app.recovery import validate_container_name
from app.recovery_controller import (
    ALLOWED_RECOVERY_ACTIONS,
    evaluate_incident_recovery,
    execute_authorized_recovery,
    is_global_recovery_disabled,
    is_protected_container_target,
    set_global_recovery_disabled,
)


class TestDashboardPresentationAndSafety(unittest.TestCase):
    """Validates dashboard formatting, unmonitored status preservation, and pagination."""

    def test_real_container_inventory_states(self):
        """Verifies that running unmonitored containers and stopped containers are never mislabeled as healthy."""
        containers = [
            {
                "name": "cloudops-floci",
                "id": "db80c688e14b1b507b96f90dbea3833a5bd79ad27068e678ba7af91fd33650e3",
                "short_id": "db80c688e14b",
                "state": "running",
                "health_status": "running_unmonitored",
                "health": "running_unmonitored",
                "metrics": {"cpu_percent": 0.14, "cpu_percent_status": "ok", "mem_percent": 1.99, "mem_percent_status": "ok"},
                "restart_count": 0,
                "exit_code": 0,
            },
            {
                "name": "linuxops-recovery-ui-test",
                "id": "83b65d88a0a9ced6761280936b222a2e1d374ec2478fadee2db0f9cb32dbaa22",
                "short_id": "83b65d88a0a9",
                "state": "exited",
                "health_status": "stopped",
                "health": "stopped",
                "metrics": {"cpu_percent": None, "cpu_percent_status": "unavailable", "mem_percent": None, "mem_percent_status": "unavailable"},
                "restart_count": 0,
                "exit_code": 0,
            },
        ]
        rows = format_container_inventory_rows(containers)
        self.assertEqual(len(rows), 2)

        # Floci must be Running (Unmonitored), not Healthy
        floci_row = next(r for r in rows if r["Container Name"] == "cloudops-floci")
        self.assertIn("Running (Unmonitored)", floci_row["Health Status"])
        self.assertNotIn("🟢 Healthy", floci_row["Health Status"])

        # Test container must be Stopped
        test_row = next(r for r in rows if r["Container Name"] == "linuxops-recovery-ui-test")
        self.assertIn("Stopped", test_row["Health Status"])
        self.assertNotIn("🟢 Healthy", test_row["Health Status"])

    def test_stale_metrics_and_errors_formatting(self):
        """Stale metrics and runtime failure indicators are visible to operators."""
        containers = [
            {
                "name": "stale-telemetry-svc",
                "id": "aaaabbbbcccc",
                "state": "running",
                "health_status": "running_unmonitored",
                "metrics": {"cpu_percent": 55.4, "cpu_percent_status": "stale", "mem_percent": 80.2, "mem_percent_status": "stale"},
            },
            {
                "name": "failed-inspect-svc",
                "id": "ffffbbbbcccc",
                "state": "unknown",
                "health_status": "unknown",
                "metrics": {"cpu_percent": None, "cpu_percent_status": "failed", "mem_percent": None, "mem_percent_status": "failed"},
            },
        ]
        rows = format_container_inventory_rows(containers)
        stale_row = rows[0]
        self.assertIn("Stale", stale_row["CPU"])
        self.assertIn("Stale", stale_row["Memory"])

        failed_row = rows[1]
        self.assertEqual(failed_row["CPU"], "[failed]")
        self.assertEqual(failed_row["Memory"], "[failed]")

    def test_pagination_100_plus_records(self):
        """Pagination and multi-criteria filtering operate correctly with 150 records."""
        records = [
            {
                "name": f"service-{i:03d}",
                "id": f"id{i:032x}",
                "short_id": f"id{i:010x}",
                "image": "redis:alpine" if i % 3 == 0 else "nginx:alpine",
                "state": "running" if i % 2 == 0 else "exited",
                "health_status": "healthy" if i % 4 == 0 else "none",
            }
            for i in range(150)
        ]

        # Page 1 of size 50
        p1, total, pages = filter_and_paginate_containers(records, page=1, page_size=50)
        self.assertEqual(total, 150)
        self.assertEqual(pages, 3)
        self.assertEqual(len(p1), 50)
        self.assertEqual(p1[0]["name"], "service-000")

        # Page 3 of size 50
        p3, total, pages = filter_and_paginate_containers(records, page=3, page_size=50)
        self.assertEqual(len(p3), 50)
        self.assertEqual(p3[-1]["name"], "service-149")

        # Filter by image
        p_redis, total_redis, _ = filter_and_paginate_containers(records, search_query="redis", page_size=100)
        self.assertEqual(total_redis, 50)


class TestSecurityAndPolicyGates(unittest.TestCase):
    """Validates backend security barriers, recovery authorization, and secret scrubbing."""

    def test_backend_enforces_policy_denial_despite_user_authorization(self):
        """Even if authorized=True is passed, backend rejects crash loops and policy denials."""
        crash_loop_incident = {
            "incident_id": "INC_CRASH_01",
            "container_name": "flapping-worker",
            "rule_id": "CRASH_LOOP_DETECTED",
            "probable_cause": "Process failed repeatedly on startup.",
            "evidence": ["Restarts: 8"],
        }
        res = execute_authorized_recovery(
            container_name="flapping-worker",
            action="start_container",
            incident=crash_loop_incident,
            authorized=True,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "POLICY_DENIED")
        self.assertIn("crash loop", res["message"])

    def test_kill_switch_overrides_authorized_execution(self):
        """Global recovery kill-switch immediately denies any recovery attempt."""
        set_global_recovery_disabled(True)
        try:
            res = execute_authorized_recovery(
                container_name="simple-app",
                action="start_container",
                authorized=True,
            )
            self.assertFalse(res["success"])
            self.assertEqual(res["verification_status"], "GLOBAL_KILL_SWITCH")
        finally:
            set_global_recovery_disabled(False)

    def test_protected_workload_immunity_deep_identity(self):
        """Protected workloads are permanently immune from recovery even if user attempts authorization."""
        res_floci = execute_authorized_recovery(
            container_name="cloudops-floci",
            action="start_container",
            authorized=True,
        )
        self.assertFalse(res_floci["success"])
        self.assertEqual(res_floci["verification_status"], "PROTECTED_WORKLOAD")

        res_test = execute_authorized_recovery(
            container_name="linuxops-recovery-ui-test",
            action="start_container",
            authorized=True,
        )
        self.assertFalse(res_test["success"])
        self.assertEqual(res_test["verification_status"], "PROTECTED_WORKLOAD")

    def test_shell_injection_prevention_in_container_name(self):
        """Arbitrary shell commands and malicious characters in container names are strictly rejected."""
        malicious_names = [
            "app; rm -rf /",
            "app && touch /tmp/pwn",
            "app | cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "-v /:/host:ro",
            "app\nreboot",
        ]
        for bad_name in malicious_names:
            is_valid, _ = validate_container_name(bad_name)
            self.assertFalse(is_valid, f"Container name '{bad_name}' should have been rejected.")

            res = execute_authorized_recovery(
                container_name=bad_name,
                action="start_container",
                authorized=True,
            )
            self.assertFalse(res["success"])
            self.assertEqual(res["verification_status"], "REJECTED")

    def test_secret_scrubbing_in_audit_logs(self):
        """Secrets, credentials, and bearer tokens are redacted prior to audit log writing."""
        tmp_dir = Path("/tmp/linuxops_test_audit_secrets")
        tmp_dir.mkdir(parents=True, exist_ok=True)
        rec_log = tmp_dir / "recovery.jsonl"
        pol_log = tmp_dir / "policy.jsonl"
        inc_log = tmp_dir / "incidents.jsonl"

        secret_raw = "Failed starting: Bearer eyJhbGciOiJIUzI1Ni.secret_token and password=SuperSecretPassword123"

        # 1. Recovery event
        record_recovery_event(
            "auth-svc",
            {"success": False, "message": secret_raw},
            history_path=rec_log,
        )
        content_rec = rec_log.read_text(encoding="utf-8")
        self.assertNotIn("SuperSecretPassword123", content_rec)
        self.assertIn("[REDACTED_SECRET]", content_rec)
        self.assertIn("[REDACTED_TOKEN]", content_rec)

        # 2. Policy decision
        record_policy_decision(
            "auth-svc",
            {
                "decision": "DENY",
                "allowed": False,
                "reason": "Denying container configured with key AKIAIOSFODNN7EXAMPLE on host.",
                "checks": {"cooldown_cleared": False},
                "dry_run": True,
            },
            history_path=pol_log,
        )
        content_pol = pol_log.read_text(encoding="utf-8")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", content_pol)
        self.assertIn("[REDACTED_AWS_KEY]", content_pol)

        # 3. Incident resolution
        record_incident_resolution(
            {"incident_id": "INC_01", "container_name": "auth-svc"},
            "RESOLVED",
            f"Resolved after updating token=SecretTokenValue1234567890",
            incidents_path=inc_log,
        )
        content_inc = inc_log.read_text(encoding="utf-8")
        self.assertNotIn("SecretTokenValue1234567890", content_inc)


class TestOptimizationAndInspectionResilience(unittest.TestCase):
    """Validates scan cancellation, timeouts, metadata caching, and timestamp consistency."""

    def test_container_metadata_cache(self):
        """ContainerMetadataCache safely stores, retrieves, and evicts entries."""
        cache = ContainerMetadataCache(max_entries=10)
        cache.set("cid1", {"image": "alpine:latest", "ports": {}})
        self.assertEqual(cache.get("cid1"), {"image": "alpine:latest", "ports": {}})
        self.assertIsNone(cache.get("cid2"))

        # Invalidate
        cache.invalidate("cid1")
        self.assertIsNone(cache.get("cid1"))

        # Eviction
        for i in range(12):
            cache.set(f"cid_{i}", {"val": i})
        self.assertTrue(len(cache) <= 10)

    def test_scan_cancellation_returns_partial_results(self):
        """Setting cancel_event stops inspection workers and returns partial results."""
        discovered = [{"Id": f"ctr_{i:04d}", "Names": [f"worker-{i}"]} for i in range(30)]
        cancel_evt = threading.Event()

        def slow_runner(cmd, **kwargs):
            if cmd[1] == "inspect":
                time.sleep(0.05)
                # Set cancellation after first batch starts
                cancel_evt.set()
                return MagicMock(returncode=0, stdout=json.dumps([{"Id": cmd[2], "Name": f"worker-0", "State": {"Status": "running"}}]))
            return MagicMock(returncode=0, stdout="[]")

        res = scan_containers(
            runner=slow_runner,
            batch_size=5,
            max_workers=2,
            container_inventory=discovered,
            cancel_event=cancel_evt,
        )
        self.assertTrue(res["partial"])
        self.assertTrue(res["cancelled"])
        self.assertIn("cancelled", res["error"].lower())

    def test_scan_timeout_returns_partial_results(self):
        """Exceeding scan_timeout cancels remaining work and returns partial scan."""
        discovered = [{"Id": f"ctr_{i:04d}", "Names": [f"worker-{i}"]} for i in range(20)]

        def slow_runner(cmd, **kwargs):
            if cmd[1] == "inspect":
                time.sleep(0.05)
                return MagicMock(returncode=0, stdout=json.dumps([{"Id": cmd[2], "Name": f"worker-0", "State": {"Status": "running"}}]))
            return MagicMock(returncode=0, stdout="[]")

        res = scan_containers(
            runner=slow_runner,
            batch_size=5,
            max_workers=2,
            container_inventory=discovered,
            scan_timeout=0.02,
        )
        self.assertTrue(res["partial"])
        self.assertTrue(res["timed_out"])
        self.assertIn("timeout", res["error"].lower())

    def test_unified_scan_timestamp_across_metrics(self):
        """All metrics within a single scan share an identical observation timestamp."""
        discovered = [
            {"Id": "c1", "Names": ["app-1"]},
            {"Id": "c2", "Names": ["app-2"]},
        ]
        inspect_data = [
            {"Id": "c1", "Name": "app-1", "State": {"Status": "running"}},
            {"Id": "c2", "Name": "app-2", "State": {"Status": "running"}},
        ]

        def mock_runner(cmd, **kwargs):
            if cmd[1] == "inspect":
                return MagicMock(returncode=0, stdout=json.dumps(inspect_data))
            return MagicMock(returncode=0, stdout="[]")

        res = scan_containers(runner=mock_runner, container_inventory=discovered)
        self.assertEqual(res["discovered_count"], 2)
        ts1 = res["containers"][0]["metrics"]["cpu_percent"]["observed_at"]
        ts2 = res["containers"][1]["metrics"]["cpu_percent"]["observed_at"]
        self.assertEqual(ts1, ts2)
        self.assertEqual(ts1, res["timestamp"])


class TestContinuousMonitoringLifecycle(unittest.TestCase):
    """Validates incident stability, alert deduplication, and resolution across cycles."""

    def test_incident_stability_across_multiple_scans(self):
        """Unresolved incidents produce identical deterministic IDs across polling cycles without alert churn."""
        stopped_container = {
            "id": "app_exit_001",
            "name": "billing-processor",
            "state": "exited",
            "exit_code": 1,
            "oom_killed": False,
            "restart_count": 0,
            "metrics": {},
        }

        # Cycle 1
        diag_1 = diagnose_all_containers([stopped_container])
        inc_1 = diag_1["incidents"][0]
        id_1 = inc_1["incident_id"]

        # Cycle 2
        diag_2 = diagnose_all_containers([stopped_container])
        inc_2 = diag_2["incidents"][0]
        id_2 = inc_2["incident_id"]

        self.assertEqual(id_1, id_2)
        self.assertTrue(id_1.startswith("INC_CONTAINER_NONZERO_EXIT_"))

    def test_incident_resolution_lifecycle(self):
        """When container becomes running and healthy, previous incident is resolved."""
        # Container previously failed
        failing_ctr = {
            "id": "web_001",
            "name": "web-frontend",
            "state": "exited",
            "exit_code": 1,
            "metrics": {},
        }
        d1 = diagnose_all_containers([failing_ctr])
        self.assertEqual(len(d1["incidents"]), 1)
        inc = d1["incidents"][0]

        # Container successfully resolved
        resolved_ctr = {
            "id": "web_001",
            "name": "web-frontend",
            "state": "running",
            "health_status": "healthy",
            "exit_code": 0,
            "metrics": {},
        }
        d2 = diagnose_all_containers([resolved_ctr])
        # In second scan, no incident for web-frontend
        active_rules = [i["rule_id"] for i in d2["incidents"] if i["container_name"] == "web-frontend"]
        self.assertEqual(active_rules, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
