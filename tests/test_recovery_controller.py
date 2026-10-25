#!/usr/bin/env python3

"""Unit tests for Phase 2 Safe Recovery Controller and Policy Integration."""

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock

from app.recovery_controller import (
    ALLOWED_RECOVERY_ACTIONS,
    clear_container_recovery_policies,
    evaluate_incident_recovery,
    execute_authorized_recovery,
    get_container_recovery_policy,
    is_global_recovery_disabled,
    is_protected_container_target,
    record_incident_resolution,
    set_container_recovery_policy,
    set_global_recovery_disabled,
    verify_post_recovery_health,
)


class TestRecoveryController(unittest.TestCase):
    def setUp(self):
        # Ensure clean state for each test
        set_global_recovery_disabled(False)
        clear_container_recovery_policies()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.history_path = Path(self.temp_dir.name) / "recovery_history.jsonl"
        self.incidents_path = Path(self.temp_dir.name) / "incidents.jsonl"

    def tearDown(self):
        set_global_recovery_disabled(False)
        clear_container_recovery_policies()
        self.temp_dir.cleanup()

    def test_global_recovery_kill_switch(self):
        self.assertFalse(is_global_recovery_disabled())
        set_global_recovery_disabled(True)
        self.assertTrue(is_global_recovery_disabled())
        set_global_recovery_disabled(False)
        self.assertFalse(is_global_recovery_disabled())

    def test_protected_container_targets(self):
        # Known protected names
        self.assertTrue(is_protected_container_target("cloudops-floci"))
        self.assertTrue(is_protected_container_target("/cloudops-floci"))
        self.assertTrue(is_protected_container_target("linuxops-recovery-ui-test"))

        # Protected ID prefixes
        self.assertTrue(is_protected_container_target("some-name", "db80c688e14babcdef"))
        self.assertTrue(is_protected_container_target("other-name", "83b65d88a0a9112233"))
        self.assertTrue(is_protected_container_target("legacy-name", "510d4cfc0d22000000"))

        # Unprotected containers
        self.assertFalse(is_protected_container_target("web-app-1", "aabbccddeeff"))
        self.assertFalse(is_protected_container_target("backend-api", "112233445566"))

    def test_per_container_policies(self):
        set_container_recovery_policy("custom-app", enabled=False)
        policy = get_container_recovery_policy("custom-app")
        self.assertFalse(policy.get("enabled"))

        set_container_recovery_policy("custom-app-2", enabled=True, max_retries=5, cooldown_seconds=120)
        policy2 = get_container_recovery_policy("custom-app-2")
        self.assertEqual(policy2.get("max_retries"), 5)
        self.assertEqual(policy2.get("cooldown_seconds"), 120)

        # Invalid container name should be rejected gracefully
        set_container_recovery_policy("-invalid-name", enabled=False)
        self.assertEqual(get_container_recovery_policy("-invalid-name"), {})

        clear_container_recovery_policies()
        self.assertEqual(get_container_recovery_policy("custom-app"), {})

    def test_evaluate_invalid_name(self):
        res = evaluate_incident_recovery("-invalid", current_state="exited")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["decision"], "DENY")
        self.assertTrue(res["dry_run"])

    def test_evaluate_global_kill_switch_active(self):
        set_global_recovery_disabled(True)
        res = evaluate_incident_recovery("my-worker", current_state="exited")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["decision"], "DENY")
        self.assertIn("kill-switch", res["reason"].lower())

    def test_evaluate_protected_workload_immunity(self):
        res = evaluate_incident_recovery("cloudops-floci", current_state="exited")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["decision"], "DENY")
        self.assertTrue(res["escalated"])
        self.assertIn("immunity", res["reason"].lower())

        res2 = evaluate_incident_recovery("linuxops-recovery-ui-test", current_state="exited")
        self.assertFalse(res2["allowed"])
        self.assertTrue(res2["escalated"])

    def test_evaluate_per_container_disabled(self):
        set_container_recovery_policy("redis-cache", enabled=False)
        res = evaluate_incident_recovery("redis-cache", current_state="exited")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["decision"], "DENY")
        self.assertIn("per-container policy", res["reason"].lower())

    def test_evaluate_incident_oom_escalated(self):
        incident = {"incident_id": "INC-001", "rule_id": "OOM_KILLED", "severity": "CRITICAL"}
        res = evaluate_incident_recovery("memory-hog", current_state="exited", incident=incident)
        self.assertFalse(res["allowed"])
        self.assertEqual(res["decision"], "DENY")
        self.assertTrue(res["escalated"])
        self.assertIn("OOM", res["reason"])

    def test_evaluate_incident_crash_loop_escalated(self):
        incident = {"incident_id": "INC-002", "rule_id": "CRASH_LOOP_DETECTED", "severity": "CRITICAL"}
        res = evaluate_incident_recovery("flapping-service", current_state="restarting", incident=incident)
        self.assertFalse(res["allowed"])
        self.assertEqual(res["decision"], "DENY")
        self.assertTrue(res["escalated"])
        self.assertIn("crash loop", res["reason"])

    def test_evaluate_incident_missing_mount_escalated(self):
        incident = {"incident_id": "INC-003", "rule_id": "MISSING_BIND_MOUNT_SOURCE", "severity": "CRITICAL"}
        res = evaluate_incident_recovery("broken-mount-svc", current_state="exited", incident=incident)
        self.assertFalse(res["allowed"])
        self.assertEqual(res["decision"], "DENY")
        self.assertTrue(res["escalated"])
        self.assertIn("bind mount", res["reason"])

    def test_evaluate_incident_port_conflict_escalated(self):
        incident = {"incident_id": "INC-004", "rule_id": "PORT_CONFLICT_DETECTED", "severity": "CRITICAL"}
        res = evaluate_incident_recovery("web-api", current_state="exited", incident=incident)
        self.assertFalse(res["allowed"])
        self.assertEqual(res["decision"], "DENY")
        self.assertTrue(res["escalated"])
        self.assertIn("port conflict", res["reason"])

    def test_evaluate_allowed_stopped_container(self):
        incident = {"incident_id": "INC-005", "rule_id": "EXITED_UNEXPECTEDLY", "severity": "WARNING"}
        res = evaluate_incident_recovery(
            "worker-pool-1",
            current_state="exited",
            incident=incident,
            history_events=[],
        )
        self.assertTrue(res["allowed"])
        self.assertEqual(res["decision"], "ALLOW")
        self.assertTrue(res["dry_run"])
        self.assertFalse(res["escalated"])
        self.assertEqual(res["incident_id"], "INC-005")

    def test_evaluate_cooldown_and_retries(self):
        now = datetime.now(timezone.utc)
        recent_event = {
            "container": "flaky-worker",
            "timestamp": now.isoformat(),
            "action": "start_container",
            "success": False,
        }
        res = evaluate_incident_recovery(
            "flaky-worker",
            current_state="exited",
            history_events=[recent_event],
            current_time=now,
        )
        self.assertFalse(res["allowed"])
        self.assertGreater(res["cooldown_remaining_seconds"], 0)

        # 3 recent failed events within retry window -> exceeded retries & escalated
        history_3_fails = [
            {"container": "exhausted-worker", "timestamp": now.isoformat(), "action": "start_container", "success": False},
            {"container": "exhausted-worker", "timestamp": now.isoformat(), "action": "start_container", "success": False},
            {"container": "exhausted-worker", "timestamp": now.isoformat(), "action": "start_container", "success": False},
        ]
        res_exceeded = evaluate_incident_recovery(
            "exhausted-worker",
            current_state="exited",
            history_events=history_3_fails,
            current_time=now,
        )
        self.assertFalse(res_exceeded["allowed"])
        self.assertTrue(res_exceeded["escalated"])

    def test_verify_post_recovery_health(self):
        # Case 1: Healthy running container
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps({"running": True, "status": "running", "health": "healthy"})
        ok, msg = verify_post_recovery_health("app-1", runner=mock_runner)
        self.assertTrue(ok)
        self.assertIn("healthy", msg)

        # Case 2: Running unmonitored container (no healthcheck)
        mock_runner.return_value.stdout = json.dumps({"running": True, "status": "running", "health": ""})
        ok, msg = verify_post_recovery_health("app-unmonitored", runner=mock_runner)
        self.assertTrue(ok)
        self.assertIn("none", msg)

        # Case 3: Container failed to start / not running
        mock_runner.return_value.stdout = json.dumps({"running": False, "status": "exited", "health": ""})
        ok, msg = verify_post_recovery_health("app-stopped", runner=mock_runner)
        self.assertFalse(ok)
        self.assertIn("not running", msg)

        # Case 4: Container started but healthcheck is unhealthy
        mock_runner.return_value.stdout = json.dumps({"running": True, "status": "running", "health": "unhealthy"})
        ok, msg = verify_post_recovery_health("app-sick", runner=mock_runner)
        self.assertFalse(ok)
        self.assertIn("UNHEALTHY", msg)

        # Case 5: Inspect command failed
        mock_runner.return_value.returncode = 125
        mock_runner.return_value.stderr = "no such container"
        ok, msg = verify_post_recovery_health("app-missing", runner=mock_runner)
        self.assertFalse(ok)
        self.assertIn("failed", msg)

        # Case 6: Subprocess timeout
        mock_runner.side_effect = subprocess.TimeoutExpired(cmd=["podman", "inspect"], timeout=5.0)
        ok, msg = verify_post_recovery_health("app-timeout", runner=mock_runner)
        self.assertFalse(ok)
        self.assertIn("timed out", msg)

    def test_execute_authorized_recovery_dry_run_unauthorized(self):
        res = execute_authorized_recovery("target-app", authorized=False)
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "AUTHORIZATION_REQUIRED")

    def test_execute_authorized_recovery_global_kill_switch(self):
        set_global_recovery_disabled(True)
        res = execute_authorized_recovery("target-app", authorized=True)
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "GLOBAL_KILL_SWITCH")

    def test_execute_authorized_recovery_forbidden_actions(self):
        for bad_action in ["remove_container", "prune_containers", "kill_container"]:
            res = execute_authorized_recovery("target-app", action=bad_action, authorized=True)
            self.assertFalse(res["success"])
            self.assertEqual(res["verification_status"], "FORBIDDEN_ACTION")

    def test_execute_authorized_recovery_protected_workloads(self):
        res = execute_authorized_recovery("cloudops-floci", authorized=True)
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "PROTECTED_WORKLOAD")

    def test_execute_authorized_recovery_success_flow(self):
        mock_restart = MagicMock(return_value={"success": True, "message": "Container started."})
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps({"running": True, "status": "running", "health": "healthy"})

        incident = {"incident_id": "INC-777", "container_name": "target-app", "rule_id": "EXITED_UNEXPECTEDLY"}

        res = execute_authorized_recovery(
            "target-app",
            action="start_container",
            incident=incident,
            authorized=True,
            history_path=self.history_path,
            incidents_path=self.incidents_path,
            runner=mock_runner,
            restart_fn=mock_restart,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["verification_status"], "VERIFIED")
        mock_restart.assert_called_once_with("target-app")

        # Verify audit history logged
        self.assertTrue(self.history_path.exists())
        with open(self.history_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["container"], "target-app")
        self.assertTrue(lines[0]["success"])

        # Verify incident resolution logged
        self.assertTrue(self.incidents_path.exists())
        with open(self.incidents_path, "r", encoding="utf-8") as f:
            inc_records = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(inc_records), 1)
        self.assertEqual(inc_records[0]["incident_id"], "INC-777")
        self.assertEqual(inc_records[0]["resolution_status"], "RESOLVED")

    def test_execute_authorized_recovery_restart_fails(self):
        mock_restart = MagicMock(return_value={"success": False, "message": "Podman daemon error."})

        res = execute_authorized_recovery(
            "target-app",
            action="start_container",
            authorized=True,
            history_path=self.history_path,
            incidents_path=self.incidents_path,
            restart_fn=mock_restart,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "FAILED")

    def test_execute_authorized_recovery_verification_fails(self):
        mock_restart = MagicMock(return_value={"success": True, "message": "Container started."})
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps({"running": False, "status": "exited", "health": ""})

        incident = {"incident_id": "INC-888", "container_name": "crashing-app", "rule_id": "EXITED_UNEXPECTEDLY"}

        res = execute_authorized_recovery(
            "crashing-app",
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

        # Verify incident marked as FAILED_VERIFICATION
        with open(self.incidents_path, "r", encoding="utf-8") as f:
            inc_records = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(inc_records[0]["resolution_status"], "FAILED_VERIFICATION")

    def test_protected_workload_deep_signals_when_id_changes(self):
        """Identity signals (image, systemd unit label, persistent mount) protect Floci even if ID changes."""
        # 1. Via inspect_data with brand new ID
        floci_new_id_data = {
            "Id": "99998888777766665555",
            "Name": "/random-name",
            "Config": {"Image": "docker.io/floci/floci:latest", "Labels": {"PODMAN_SYSTEMD_UNIT": "cloudops-floci.service"}},
            "Mounts": [{"Source": "/home/neha/cloudops-sentinel/data", "Destination": "/app/data"}],
        }
        self.assertTrue(is_protected_container_target("random-name", "99998888777766665555", inspect_data=floci_new_id_data))

        # 2. Via runner querying live inspect
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps([floci_new_id_data])
        self.assertTrue(is_protected_container_target("random-name", "99998888777766665555", runner=mock_runner))

        # 3. Fail closed on suspected target error
        mock_err_runner = MagicMock(side_effect=subprocess.TimeoutExpired(["podman", "inspect"], 5.0))
        self.assertTrue(is_protected_container_target("cloudops-floci-standin", runner=mock_err_runner))

    def test_execute_authorized_recovery_blocks_deep_protected_container(self):
        """execute_authorized_recovery rejects a container that matches deep Floci identity signals."""
        mock_restart = MagicMock()
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps([{
            "Id": "1111222233334444",
            "Name": "/custom-floci-ctr",
            "Config": {"Image": "floci/floci:v2", "Labels": {}},
        }])

        res = execute_authorized_recovery(
            "custom-floci-ctr",
            action="start_container",
            authorized=True,
            runner=mock_runner,
            restart_fn=mock_restart,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "PROTECTED_WORKLOAD")
        mock_restart.assert_not_called()


if __name__ == "__main__":
    unittest.main()

