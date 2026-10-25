#!/usr/bin/env python3

"""
LinuxOps Monitoring Lifecycle, Staging Reliability, & Safety Hardening Tests (Phase 4).

Validates multi-cycle monitoring execution, lifecycle fault isolation,
backend policy gate enforcement, audit log persistence, and deep workload immunity.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from app.container_inspector import (
    DEFAULT_STALE_THRESHOLD_SECONDS,
    parse_stats_entry,
    scan_containers,
)
from app.diagnostics_engine import (
    build_incident,
    diagnose_all_containers,
    diagnose_container_record,
)
from app.history import (
    inspect_audit_log_integrity,
    load_incident_history,
    load_recovery_history,
    record_incident_resolution,
    record_recovery_event,
    rotate_audit_log,
)
from app.recovery_controller import (
    evaluate_incident_recovery,
    execute_authorized_recovery,
    is_protected_container_target,
    set_global_recovery_disabled,
)


class TestMonitoringLifecycle(unittest.TestCase):
    """Test multi-cycle monitoring scenarios, stale metrics, and fault isolation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.history_path = Path(self.temp_dir.name) / "recovery_history.jsonl"
        self.incidents_path = Path(self.temp_dir.name) / "incidents.jsonl"
        set_global_recovery_disabled(False)

    def tearDown(self):
        set_global_recovery_disabled(False)
        self.temp_dir.cleanup()

    def test_stale_metrics_detection_across_cycles(self):
        """Metrics older than stale threshold are classified as 'stale' and trigger diagnostic incident."""
        now = datetime.now(timezone.utc)
        fresh_ts = now.isoformat()
        stale_ts = (now - timedelta(seconds=120)).isoformat()

        # 1. Fresh telemetry
        raw_fresh = {"cpu_percent": "12.5%", "mem_usage": "100MB / 1GB", "timestamp": fresh_ts}
        metrics_fresh = parse_stats_entry(raw_fresh, is_running=True, stale_threshold=60.0, reference_time=now.timestamp())
        self.assertEqual(metrics_fresh["telemetry_state"], "ok")
        self.assertEqual(metrics_fresh["cpu_percent"]["status"], "ok")

        # 2. Stale telemetry (120s old, threshold 60s)
        raw_stale = {"cpu_percent": "12.5%", "mem_usage": "100MB / 1GB", "timestamp": stale_ts}
        metrics_stale = parse_stats_entry(raw_stale, is_running=True, stale_threshold=60.0, reference_time=now.timestamp())
        self.assertEqual(metrics_stale["telemetry_state"], "stale")
        self.assertEqual(metrics_stale["cpu_percent"]["status"], "stale")
        self.assertEqual(metrics_stale["memory_usage_bytes"]["status"], "stale")

        # 3. Verify diagnostics engine flags stale telemetry
        container_rec = {
            "name": "worker-app",
            "id": "c1234",
            "state": "running",
            "health_status": "healthy",
            "metrics": metrics_stale,
        }
        incidents = diagnose_container_record(container_rec)
        stale_incs = [i for i in incidents if i["rule_id"] == "STALE_TELEMETRY"]
        self.assertEqual(len(stale_incs), 1)
        self.assertEqual(stale_incs[0]["severity"], "WARNING")

    def test_disappearing_container_does_not_crash_scan(self):
        """When a container disappears concurrently during batch inspection, scan handles it safely."""
        def mock_runner(cmd, **kwargs):
            class MockCP:
                def __init__(self, rc, stdout, stderr=""):
                    self.returncode = rc
                    self.stdout = stdout
                    self.stderr = stderr

            sub = cmd[1]
            if sub == "ps":
                # Discovers 2 containers
                return MockCP(0, json.dumps([
                    {"Id": "c111", "Names": ["/stable-app"], "State": "running"},
                    {"Id": "c222", "Names": ["/ghost-app"], "State": "running"},
                ]))
            if sub == "inspect":
                # c222 disappeared concurrently!
                if "c222" in cmd:
                    return MockCP(125, "", "Error: no such container c222")
                return MockCP(0, json.dumps([
                    {
                        "Id": "c111",
                        "Name": "/stable-app",
                        "State": {"Status": "running", "Running": True},
                        "Config": {"Image": "docker.io/library/alpine:latest"},
                        "Mounts": [],
                    }
                ]))
            if sub == "stats":
                return MockCP(0, json.dumps([]))
            return MockCP(0, "")

        scan_result = scan_containers(runner=mock_runner)
        self.assertEqual(scan_result["discovered_count"], 2)
        self.assertEqual(scan_result["inspected_count"], 1)
        self.assertEqual(scan_result["failed_count"], 1)
        self.assertEqual(len(scan_result["containers"]), 2)
        self.assertTrue(any("c222" in str(e) for e in scan_result["errors"]))

    def test_incident_lifecycle_unresolved_stability_and_resolution(self):
        """Unresolved incidents retain stable deterministic IDs across polling cycles and can be resolved."""
        # Polling cycle 1: Exited container creates incident
        rec_cycle1 = {
            "name": "payment-api",
            "id": "cid-pay-01",
            "state": "exited",
            "exit_code": 1,
            "oom_killed": False,
            "restart_count": 0,
            "health_status": "none",
        }
        incs_cycle1 = diagnose_container_record(rec_cycle1)
        exited_inc1 = next((i for i in incs_cycle1 if i["rule_id"] == "CONTAINER_NONZERO_EXIT"), None)
        self.assertIsNotNone(exited_inc1)
        stable_id_cycle1 = exited_inc1["incident_id"]
        self.assertTrue(stable_id_cycle1.startswith("INC_CONTAINER_NONZERO_EXIT_"))

        # Polling cycle 2: Container remains exited; incident ID MUST be identical (no duplicate churn)
        incs_cycle2 = diagnose_container_record(rec_cycle1)
        exited_inc2 = next((i for i in incs_cycle2 if i["rule_id"] == "CONTAINER_NONZERO_EXIT"), None)
        self.assertEqual(exited_inc2["incident_id"], stable_id_cycle1)

        # Resolution cycle: Container recovery succeeds and verified healthy
        resolution_rec = record_incident_resolution(
            incident=exited_inc1,
            resolution_status="RESOLVED",
            message="Container successfully started and verified healthy.",
            incidents_path=self.incidents_path,
        )
        self.assertEqual(resolution_rec["incident_id"], stable_id_cycle1)
        self.assertEqual(resolution_rec["resolution_status"], "RESOLVED")

        # Load history and verify audit trail
        history = load_incident_history(incidents_path=self.incidents_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["incident_id"], stable_id_cycle1)
        self.assertEqual(history[0]["resolution_status"], "RESOLVED")


class TestRecoverySafetyHardening(unittest.TestCase):
    """Test backend policy gate enforcement, authorization gates, and deep workload immunity."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.history_path = Path(self.temp_dir.name) / "recovery_history.jsonl"
        self.incidents_path = Path(self.temp_dir.name) / "incidents.jsonl"
        set_global_recovery_disabled(False)

    def tearDown(self):
        set_global_recovery_disabled(False)
        self.temp_dir.cleanup()

    def test_backend_policy_gate_blocks_crash_loop_despite_authorization(self):
        """Even if operator checks authorization checkbox, backend rejects crash-loop recovery."""
        mock_restart = MagicMock()
        incident = {
            "incident_id": "INC-CRASH-01",
            "container_name": "looping-svc",
            "rule_id": "CRASH_LOOP_DETECTED",
            "severity": "CRITICAL",
        }

        res = execute_authorized_recovery(
            container_name="looping-svc",
            action="start_container",
            incident=incident,
            authorized=True,  # UI checked
            history_path=self.history_path,
            incidents_path=self.incidents_path,
            restart_fn=mock_restart,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "POLICY_DENIED")
        self.assertIn("active crash loop", res["message"])
        mock_restart.assert_not_called()

    def test_backend_policy_gate_blocks_missing_mount_despite_authorization(self):
        """Backend rejects recovery when host bind mount is missing."""
        mock_restart = MagicMock()
        incident = {
            "incident_id": "INC-MOUNT-01",
            "container_name": "broken-mount-svc",
            "rule_id": "MISSING_BIND_MOUNT_SOURCE",
            "severity": "CRITICAL",
        }

        res = execute_authorized_recovery(
            container_name="broken-mount-svc",
            action="start_container",
            incident=incident,
            authorized=True,
            history_path=self.history_path,
            incidents_path=self.incidents_path,
            restart_fn=mock_restart,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "POLICY_DENIED")
        self.assertIn("bind mount source directory does not exist", res["message"])
        mock_restart.assert_not_called()

    def test_backend_policy_gate_blocks_port_conflict_despite_authorization(self):
        """Backend rejects recovery when port conflict is unresolved."""
        mock_restart = MagicMock()
        incident = {
            "incident_id": "INC-PORT-01",
            "container_name": "port-conflict-svc",
            "rule_id": "PORT_CONFLICT_DETECTED",
            "severity": "CRITICAL",
        }

        res = execute_authorized_recovery(
            container_name="port-conflict-svc",
            action="start_container",
            incident=incident,
            authorized=True,
            history_path=self.history_path,
            incidents_path=self.incidents_path,
            restart_fn=mock_restart,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "POLICY_DENIED")
        self.assertIn("port conflict", res["message"])
        mock_restart.assert_not_called()

    def test_global_kill_switch_overrides_all_execution_paths(self):
        """Global recovery kill-switch halts execution before any other evaluation."""
        set_global_recovery_disabled(True)
        mock_restart = MagicMock()

        res = execute_authorized_recovery(
            container_name="eligible-svc",
            action="start_container",
            authorized=True,
            history_path=self.history_path,
            incidents_path=self.incidents_path,
            restart_fn=mock_restart,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "GLOBAL_KILL_SWITCH")
        mock_restart.assert_not_called()

    def test_protected_workload_deep_identity_mock_scenarios(self):
        """Workload with new ID and changed name but matching Sentinel data mount or unit label is protected."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps([{
            "Id": "9999888877776666",
            "Name": "/randomized-name-recreated",
            "Config": {
                "Image": "docker.io/library/cloudops-floci:v2",
                "Labels": {"PODMAN_SYSTEMD_UNIT": "cloudops-floci.service"},
            },
            "Mounts": [{"Source": "/home/neha/cloudops-sentinel/data", "Destination": "/app/data"}],
        }])

        # Even with authorized=True and a non-matching target name, deep inspect recognizes Floci
        res = execute_authorized_recovery(
            container_name="randomized-name-recreated",
            action="start_container",
            authorized=True,
            history_path=self.history_path,
            incidents_path=self.incidents_path,
            runner=mock_runner,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "PROTECTED_WORKLOAD")
        self.assertIn("protected workload", res["message"])

    def test_recovery_verification_distinguishes_running_from_app_unhealthy(self):
        """A container that starts but fails healthcheck is classified as FAILED_VERIFICATION."""
        mock_restart = MagicMock(return_value={"success": True, "message": "Container started."})
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps({"running": True, "status": "running", "health": "unhealthy"})

        incident = {"incident_id": "INC-099", "container_name": "flaky-app", "rule_id": "EXITED_UNEXPECTEDLY"}

        res = execute_authorized_recovery(
            container_name="flaky-app",
            action="start_container",
            incident=incident,
            authorized=True,
            history_path=self.history_path,
            incidents_path=self.incidents_path,
            runner=mock_runner,
            restart_fn=mock_restart,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "FAILED_VERIFICATION")
        self.assertIn("UNHEALTHY", res["message"])

        # History audit record must record success: False
        history = load_recovery_history(history_path=self.history_path)
        self.assertEqual(len(history), 1)
        self.assertFalse(history[0]["success"])
        self.assertEqual(history[0]["verification_status"], "FAILED_VERIFICATION")

    def test_audit_log_rotation_and_integrity_audit(self):
        """Audit logs can be verified for integrity and rotated without losing history."""
        test_log = Path(self.temp_dir.name) / "test_audit.jsonl"
        # Write 10 valid records
        for i in range(10):
            record_recovery_event(f"app-{i}", {"success": True, "message": "ok"}, history_path=test_log)

        integ_before = inspect_audit_log_integrity(test_log)
        self.assertTrue(integ_before["is_healthy"])
        self.assertEqual(integ_before["valid_records"], 10)

        # Trigger rotation with low byte threshold
        rot_res = rotate_audit_log(test_log, max_bytes=100)
        self.assertTrue(rot_res["rotated"])
        backup_file = Path(rot_res["archived_to"])
        self.assertTrue(backup_file.exists())

        # Verify archived file still has all 10 records
        integ_archived = inspect_audit_log_integrity(backup_file)
        self.assertEqual(integ_archived["valid_records"], 10)

        # Fresh file exists and is empty
        integ_fresh = inspect_audit_log_integrity(test_log)
        self.assertEqual(integ_fresh["valid_records"], 0)


if __name__ == "__main__":
    unittest.main()
