#!/usr/bin/env python3

"""
Unit tests for LinuxOps Policy Evaluation Service (Phase B — Steps 3 & 5).

Verifies the integration between monitoring, diagnosis, policy engine,
and policy history auditing, plus end-to-end safety and failure testing.
Uses mocks and temporary files; strictly dry-run.
"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.history import load_policy_history, load_recovery_history, record_recovery_event
from app.policy_service import evaluate_container_policy, evaluate_container_recovery_policy


class TestPolicyService(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.recovery_path = Path(self.temp_dir.name) / "recovery_history.jsonl"
        self.policy_path = Path(self.temp_dir.name) / "policy_history.jsonl"
        self.base_time = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. ALLOW Evaluation & Dry-Run Verification
    @patch("app.recovery.restart_container")
    @patch("app.policy_service.diagnose_container")
    def test_evaluate_stopped_container_allow(self, mock_diag, mock_restart):
        mock_diag.return_value = {
            "success": True,
            "container": "web-svc",
            "state": "exited",
            "exit_code": 0,
            "oom_killed": False,
            "recommendation": "SAFE_TO_RECOVER",
        }

        result = evaluate_container_recovery_policy(
            container_name="web-svc",
            recovery_history_path=self.recovery_path,
            policy_history_path=self.policy_path,
            current_time=self.base_time,
        )

        self.assertTrue(result["allowed"])
        self.assertEqual(result["action"], "ALLOW")
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["container"], "web-svc")
        self.assertEqual(result["current_state"], "exited")

        # Crucial safety check: restart_container must NEVER be called on ALLOW
        mock_restart.assert_not_called()

        # Verify decision was recorded in policy history
        pol_history = load_policy_history(history_path=self.policy_path)
        self.assertEqual(len(pol_history), 1)
        self.assertEqual(pol_history[0]["decision"], "ALLOW")
        self.assertEqual(pol_history[0]["container"], "web-svc")

    # 2. DENY Evaluations & No Recovery Execution
    @patch("app.recovery.restart_container")
    @patch("app.policy_service.diagnose_container")
    def test_evaluate_running_container_deny(self, mock_diag, mock_restart):
        mock_diag.return_value = {
            "success": True,
            "container": "web-svc",
            "state": "running",
            "exit_code": 0,
            "oom_killed": False,
        }

        result = evaluate_container_recovery_policy(
            container_name="web-svc",
            recovery_history_path=self.recovery_path,
            policy_history_path=self.policy_path,
            current_time=self.base_time,
        )

        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertIn("currently running", result["reason"])
        mock_restart.assert_not_called()

        pol_history = load_policy_history(history_path=self.policy_path)
        self.assertEqual(len(pol_history), 1)
        self.assertEqual(pol_history[0]["decision"], "DENY")

    @patch("app.recovery.restart_container")
    @patch("app.policy_service.diagnose_container")
    def test_evaluate_oom_killed_container_deny(self, mock_diag, mock_restart):
        mock_diag.return_value = {
            "success": True,
            "container": "web-svc",
            "state": "exited",
            "exit_code": 137,
            "oom_killed": True,
        }

        result = evaluate_container_recovery_policy(
            container_name="web-svc",
            recovery_history_path=self.recovery_path,
            policy_history_path=self.policy_path,
            current_time=self.base_time,
        )

        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertFalse(result["checks"]["oom_safeguard_satisfied"])
        self.assertIn("Out-Of-Memory", result["reason"])
        mock_restart.assert_not_called()

    # 3. Unknown and Unsupported States
    @patch("app.recovery.restart_container")
    def test_unsupported_states_explicitly_denied(self, mock_restart):
        unsupported = ["paused", "restarting", "created", "dead", "unknown", "configured", None]
        for state in unsupported:
            result = evaluate_container_recovery_policy(
                container_name="web-svc",
                current_state=state,
                record_decision=False,
                recovery_history_path=self.recovery_path,
                policy_history_path=self.policy_path,
                current_time=self.base_time,
            )
            self.assertFalse(result["allowed"])
            self.assertEqual(result["action"], "DENY")
            self.assertFalse(result["checks"]["state_eligible"])
            mock_restart.assert_not_called()

    # 4. Cooldown from Actual Recovery History
    @patch("app.policy_service.diagnose_container")
    def test_evaluate_active_cooldown_from_recovery_history(self, mock_diag):
        mock_diag.return_value = {
            "success": True,
            "container": "web-svc",
            "state": "exited",
            "oom_killed": False,
        }
        # Populate real recovery history with a recent failure (30s ago)
        record_recovery_event(
            "web-svc",
            {"success": False, "message": "Crash"},
            self.recovery_path,
        )

        result = evaluate_container_recovery_policy(
            container_name="web-svc",
            recovery_history_path=self.recovery_path,
            policy_history_path=self.policy_path,
        )

        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertFalse(result["checks"]["cooldown_satisfied"])
        self.assertGreater(result["cooldown_remaining_seconds"], 0.0)

    # 5. Retry Limit Reached
    @patch("app.policy_service.diagnose_container")
    def test_evaluate_retry_limit_reached(self, mock_diag):
        mock_diag.return_value = {
            "success": True,
            "container": "web-svc",
            "state": "exited",
            "oom_killed": False,
        }
        # 3 failures outside cooldown (e.g. 2m, 5m, 8m ago)
        for minutes in [2, 5, 8]:
            event_time = (self.base_time - timedelta(minutes=minutes)).isoformat()
            self.recovery_path.parent.mkdir(parents=True, exist_ok=True)
            with self.recovery_path.open("a", encoding="utf-8") as f:
                import json
                f.write(json.dumps({
                    "timestamp": event_time,
                    "action": "start_container",
                    "container": "web-svc",
                    "success": False,
                    "message": "Crash",
                }) + "\n")

        result = evaluate_container_recovery_policy(
            container_name="web-svc",
            recovery_history_path=self.recovery_path,
            policy_history_path=self.policy_path,
            current_time=self.base_time,
        )

        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertFalse(result["checks"]["within_retry_limit"])
        self.assertTrue(result["checks"]["cooldown_satisfied"])  # 2m > 60s
        self.assertEqual(result["attempts_in_window"], 3)

    # 6. Invalid Container Names
    def test_invalid_container_name_rejected_safely(self):
        for invalid_name in ["", "   ", "--all", "-f", "bad name;rm", "$ENV"]:
            result = evaluate_container_recovery_policy(
                container_name=invalid_name,
                recovery_history_path=self.recovery_path,
                policy_history_path=self.policy_path,
                current_time=self.base_time,
            )
            self.assertFalse(result["allowed"])
            self.assertEqual(result["action"], "DENY")
            self.assertFalse(result["checks"]["name_valid"])

    # 7. Diagnosis and Inventory Failure Handling
    @patch("app.policy_service.diagnose_container")
    @patch("app.policy_service.collect_container_status")
    def test_diagnosis_and_inventory_failure_handled_gracefully(self, mock_collect, mock_diag):
        mock_diag.side_effect = RuntimeError("Podman daemon unavailable")
        mock_collect.side_effect = TimeoutError("Command timed out")

        result = evaluate_container_recovery_policy(
            container_name="web-svc",
            recovery_history_path=self.recovery_path,
            policy_history_path=self.policy_path,
            current_time=self.base_time,
        )

        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertFalse(result["checks"]["state_eligible"])
        self.assertIn("ineligible state 'unknown'", result["reason"])

    # 8. Policy History Write Failure Resilience
    @patch("app.policy_service.record_policy_decision")
    @patch("app.policy_service.diagnose_container")
    def test_policy_history_write_failure_does_not_crash(self, mock_diag, mock_record):
        mock_diag.return_value = {
            "success": True,
            "container": "web-svc",
            "state": "exited",
            "oom_killed": False,
        }
        mock_record.side_effect = OSError("Read-only file system")

        result = evaluate_container_recovery_policy(
            container_name="web-svc",
            recovery_history_path=self.recovery_path,
            policy_history_path=self.policy_path,
            current_time=self.base_time,
        )

        # Decision still computed correctly despite log failure
        self.assertTrue(result["allowed"])
        self.assertEqual(result["action"], "ALLOW")
        self.assertIn("log_error", result)
        self.assertIn("Read-only file system", result["log_error"])

    # 9. Record Decision False Option
    @patch("app.policy_service.diagnose_container")
    def test_record_decision_false_skips_audit_file(self, mock_diag):
        mock_diag.return_value = {
            "success": True,
            "container": "web-svc",
            "state": "exited",
            "oom_killed": False,
        }

        result = evaluate_container_recovery_policy(
            container_name="web-svc",
            record_decision=False,
            recovery_history_path=self.recovery_path,
            policy_history_path=self.policy_path,
            current_time=self.base_time,
        )

        self.assertTrue(result["allowed"])
        self.assertFalse(self.policy_path.exists())

    # 10. Repeated Evaluations Idempotency & Cooldown Protection
    @patch("app.policy_service.diagnose_container")
    def test_multiple_evaluations_do_not_contaminate_cooldown_or_retries(self, mock_diag):
        mock_diag.return_value = {
            "success": True,
            "container": "web-svc",
            "state": "exited",
            "oom_killed": False,
        }

        # Run evaluation 10 times consecutively
        for _ in range(10):
            res = evaluate_container_policy(
                container_name="web-svc",
                recovery_history_path=self.recovery_path,
                policy_history_path=self.policy_path,
                current_time=self.base_time,
            )
            self.assertTrue(res["allowed"])
            self.assertTrue(res["checks"]["cooldown_satisfied"])
            self.assertTrue(res["checks"]["within_retry_limit"])

        # 10 policy audit records written
        pol_history = load_policy_history(history_path=self.policy_path)
        self.assertEqual(len(pol_history), 10)

        # Recovery history remains completely unpolluted (0 records)
        rec_history = load_recovery_history(history_path=self.recovery_path)
        self.assertEqual(len(rec_history), 0)


if __name__ == "__main__":
    unittest.main()
