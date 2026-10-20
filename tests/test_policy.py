#!/usr/bin/env python3

"""
Unit tests for LinuxOps Recovery Policy Engine (Phase B — Step 1).

Tests are completely isolated, using injected time and mock history data.
No live containers or Podman subprocess calls are executed.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.policy import (
    DEFAULT_COOLDOWN_SECONDS,
    DEFAULT_MAX_FAILED_RETRIES,
    DEFAULT_RETRY_WINDOW_SECONDS,
    evaluate_recovery_policy,
)


class TestRecoveryPolicy(unittest.TestCase):

    def setUp(self):
        # Freeze base reference time: 2026-10-20 12:00:00 UTC
        self.base_time = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)

    # 1. State Eligibility
    def test_eligible_stopped_states(self):
        for state in ["exited", "stopped", "EXITED", "STOPPED", "  exited  "]:
            result = evaluate_recovery_policy(
                container_name="web-svc",
                current_state=state,
                current_time=self.base_time,
            )
            self.assertTrue(result["allowed"])
            self.assertEqual(result["action"], "ALLOW")
            self.assertTrue(result["checks"]["state_eligible"])
            self.assertTrue(result["dry_run"])
            self.assertIn("eligible for recovery", result["reason"])

    def test_running_state_denied(self):
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="running",
            current_time=self.base_time,
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertFalse(result["checks"]["state_eligible"])
        self.assertIn("currently running", result["reason"])
        self.assertIn("recovery is not needed", result["reason"])

    def test_other_ineligible_states_denied(self):
        for state in ["paused", "restarting", "created", "dead", "unknown", "configured"]:
            result = evaluate_recovery_policy(
                container_name="web-svc",
                current_state=state,
                current_time=self.base_time,
            )
            self.assertFalse(result["allowed"])
            self.assertEqual(result["action"], "DENY")
            self.assertFalse(result["checks"]["state_eligible"])
            self.assertIn("ineligible state", result["reason"])

    def test_empty_or_none_state_denied(self):
        for state in ["", "   ", None]:
            result = evaluate_recovery_policy(
                container_name="web-svc",
                current_state=state,
                current_time=self.base_time,
            )
            self.assertFalse(result["allowed"])
            self.assertEqual(result["action"], "DENY")
            self.assertFalse(result["checks"]["state_eligible"])
            self.assertIn("empty or missing state", result["reason"])

    # 2. Input Validation
    def test_invalid_container_names_denied(self):
        invalid_names = ["", "   ", "--all", "-f", "my container", "app;rm", "$VAR"]
        for name in invalid_names:
            result = evaluate_recovery_policy(
                container_name=name,
                current_state="exited",
                current_time=self.base_time,
            )
            self.assertFalse(result["allowed"])
            self.assertEqual(result["action"], "DENY")
            self.assertFalse(result["checks"]["name_valid"])

    # 3. Cooldown Safeguard
    def test_cooldown_active(self):
        # Last recovery attempt was 30 seconds ago (cooldown is 60s)
        last_attempt = (self.base_time - timedelta(seconds=30)).isoformat()
        history = [
            {
                "timestamp": last_attempt,
                "action": "start_container",
                "container": "web-svc",
                "success": False,
                "message": "Start failed",
            }
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertFalse(result["checks"]["cooldown_satisfied"])
        self.assertGreater(result["cooldown_remaining_seconds"], 0.0)
        self.assertAlmostEqual(result["cooldown_remaining_seconds"], 30.0, delta=0.5)
        self.assertIn("in cooldown", result["reason"])

    def test_cooldown_expired(self):
        # Last recovery attempt was 75 seconds ago (cooldown is 60s)
        last_attempt = (self.base_time - timedelta(seconds=75)).isoformat()
        history = [
            {
                "timestamp": last_attempt,
                "action": "start_container",
                "container": "web-svc",
                "success": False,
                "message": "Start failed",
            }
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["action"], "ALLOW")
        self.assertTrue(result["checks"]["cooldown_satisfied"])
        self.assertEqual(result["cooldown_remaining_seconds"], 0.0)

    def test_cooldown_boundary_exactly_expired(self):
        # D3-1: Cooldown elapsed exactly 60.0 seconds: cooldown has expired
        last_attempt = (self.base_time - timedelta(seconds=60)).isoformat()
        history = [
            {
                "timestamp": last_attempt,
                "action": "start_container",
                "container": "web-svc",
                "success": False,
            }
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["action"], "ALLOW")
        self.assertTrue(result["checks"]["cooldown_satisfied"])
        self.assertEqual(result["cooldown_remaining_seconds"], 0.0)

    def test_cooldown_boundary_just_active(self):
        # D3-2: Cooldown elapsed 59.9 seconds: cooldown remains active
        last_attempt = (self.base_time - timedelta(seconds=59.9)).isoformat()
        history = [
            {
                "timestamp": last_attempt,
                "action": "start_container",
                "container": "web-svc",
                "success": False,
            }
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertFalse(result["checks"]["cooldown_satisfied"])
        self.assertAlmostEqual(result["cooldown_remaining_seconds"], 0.1, delta=0.05)

    def test_successful_matching_recovery_triggers_cooldown(self):
        # D3-5: Successful matching recovery inside cooldown still triggers cooldown
        history = [
            {
                "timestamp": (self.base_time - timedelta(seconds=20)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": True,
            }
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertFalse(result["checks"]["cooldown_satisfied"])
        # Successful attempts must not increment failed attempts count
        self.assertEqual(result["attempts_in_window"], 0)
        self.assertTrue(result["checks"]["within_retry_limit"])

    # 4. Retry Limit Safeguard
    def test_retry_limit_reached(self):
        # 3 failed attempts in the last 10 minutes (outside cooldown, inside 15m window)
        history = [
            {
                "timestamp": (self.base_time - timedelta(minutes=2)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
                "message": "Fail 1",
            },
            {
                "timestamp": (self.base_time - timedelta(minutes=5)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
                "message": "Fail 2",
            },
            {
                "timestamp": (self.base_time - timedelta(minutes=8)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
                "message": "Fail 3",
            },
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertFalse(result["checks"]["within_retry_limit"])
        self.assertTrue(result["checks"]["cooldown_satisfied"])  # 2m > 60s cooldown
        self.assertEqual(result["attempts_in_window"], 3)
        self.assertIn("maximum failed retry limit (3/3)", result["reason"])

    def test_retry_limit_not_reached(self):
        # 2 failed attempts in the last 10 minutes (limit is 3)
        history = [
            {
                "timestamp": (self.base_time - timedelta(minutes=2)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
                "message": "Fail 1",
            },
            {
                "timestamp": (self.base_time - timedelta(minutes=5)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
                "message": "Fail 2",
            },
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["action"], "ALLOW")
        self.assertTrue(result["checks"]["within_retry_limit"])
        self.assertEqual(result["attempts_in_window"], 2)

    def test_retry_window_exact_boundary_inclusive(self):
        # D3-3: Retry event exactly 900 seconds old remains inside inclusive window
        history = [
            {
                "timestamp": (self.base_time - timedelta(seconds=900)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
            }
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertEqual(result["attempts_in_window"], 1)

    def test_retry_window_exact_boundary_exclusive(self):
        # D3-4: Retry event 901 seconds old is outside the 900-second window
        history = [
            {
                "timestamp": (self.base_time - timedelta(seconds=901)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
            }
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertEqual(result["attempts_in_window"], 0)

    def test_old_failures_outside_window_ignored(self):
        history = [
            {
                "timestamp": (self.base_time - timedelta(minutes=2)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
                "message": "Recent fail",
            },
            {
                "timestamp": (self.base_time - timedelta(minutes=20)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
                "message": "Old fail 1",
            },
            {
                "timestamp": (self.base_time - timedelta(minutes=30)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
                "message": "Old fail 2",
            },
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["attempts_in_window"], 1)

    # 5. Successful Attempts Do Not Count as Failed Retries
    def test_successful_attempts_not_counted_as_failures(self):
        history = [
            {
                "timestamp": (self.base_time - timedelta(minutes=2)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": True,
                "message": "Success 1",
            },
            {
                "timestamp": (self.base_time - timedelta(minutes=5)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": True,
                "message": "Success 2",
            },
            {
                "timestamp": (self.base_time - timedelta(minutes=8)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": True,
                "message": "Success 3",
            },
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["attempts_in_window"], 0)
        self.assertTrue(result["checks"]["within_retry_limit"])

    # 6. Container Isolation in History
    def test_different_containers_history_ignored(self):
        history = [
            {
                "timestamp": (self.base_time - timedelta(minutes=1)).isoformat(),
                "action": "start_container",
                "container": "other-app",
                "success": False,
                "message": "Other container fail",
            }
            for _ in range(5)
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["attempts_in_window"], 0)
        self.assertTrue(result["checks"]["cooldown_satisfied"])

    # 7. OOM Safeguard
    def test_oom_killed_container_denied(self):
        diagnosis = {
            "success": True,
            "container": "web-svc",
            "state": "exited",
            "exit_code": 137,
            "oom_killed": True,
            "recommendation": "HUMAN_REVIEW",
        }
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            diagnosis=diagnosis,
            current_time=self.base_time,
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertFalse(result["checks"]["oom_safeguard_satisfied"])
        self.assertIn("Out-Of-Memory (OOM) event", result["reason"])
        self.assertIn("human review", result["reason"])

    def test_non_oom_exit_137_permitted(self):
        diagnosis = {
            "success": True,
            "container": "web-svc",
            "state": "exited",
            "exit_code": 137,
            "oom_killed": False,
            "recommendation": "INVESTIGATE",
        }
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            diagnosis=diagnosis,
            current_time=self.base_time,
        )
        self.assertTrue(result["allowed"])
        self.assertTrue(result["checks"]["oom_safeguard_satisfied"])

    # 8. Timezone and Offset Parsing (D3-6)
    def test_utc_offsets_and_naive_timestamps(self):
        # base_time: 2026-10-20 12:00:00 UTC
        # +05:30: 17:29:30+05:30 is 11:59:30 UTC (30 seconds ago)
        history_offset = [
            {
                "timestamp": "2026-10-20T17:29:30+05:30",
                "action": "start_container",
                "container": "web-svc",
                "success": False,
            }
        ]
        res_offset = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history_offset,
            current_time=self.base_time,
        )
        self.assertFalse(res_offset["checks"]["cooldown_satisfied"])
        self.assertAlmostEqual(res_offset["cooldown_remaining_seconds"], 30.0, delta=0.5)

        # Naive timestamp string: 2026-10-20T11:59:30 is interpreted as UTC (30s ago)
        history_naive = [
            {
                "timestamp": "2026-10-20T11:59:30",
                "action": "start_container",
                "container": "web-svc",
                "success": False,
            }
        ]
        res_naive = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history_naive,
            current_time=self.base_time,
        )
        self.assertFalse(res_naive["checks"]["cooldown_satisfied"])
        self.assertAlmostEqual(res_naive["cooldown_remaining_seconds"], 30.0, delta=0.5)

    # 9. Future Timestamps (D3-7)
    def test_future_timestamps_ignored(self):
        # Event timestamp is 5 minutes in the future relative to base_time
        history = [
            {
                "timestamp": (self.base_time + timedelta(minutes=5)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
            }
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["action"], "ALLOW")
        self.assertTrue(result["checks"]["cooldown_satisfied"])
        self.assertEqual(result["cooldown_remaining_seconds"], 0.0)
        self.assertEqual(result["attempts_in_window"], 0)

    # 10. Policy Threshold Validation (D3-8)
    def test_threshold_validation_booleans_and_invalid_types(self):
        # Booleans must not be accepted as integers
        res_bool = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            max_failed_retries=True,
            retry_window_seconds=False,
            cooldown_seconds=True,
            current_time=self.base_time,
        )
        self.assertTrue(res_bool["allowed"])

        # Floats must not be silently truncated
        res_float = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            max_failed_retries=3.5,
            retry_window_seconds=900.5,
            cooldown_seconds=60.5,
            current_time=self.base_time,
        )
        self.assertTrue(res_float["allowed"])

        # None and strings fall back safely without TypeError
        res_none = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            max_failed_retries=None,
            retry_window_seconds="invalid",
            cooldown_seconds=None,
            current_time=self.base_time,
        )
        self.assertTrue(res_none["allowed"])

    def test_threshold_validation_negative_and_zero_values(self):
        # Negative or zero max_failed_retries must fall back to default, not cause false denial
        res_neg_retries = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            max_failed_retries=-1,
            current_time=self.base_time,
        )
        self.assertTrue(res_neg_retries["allowed"])

        res_zero_retries = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            max_failed_retries=0,
            current_time=self.base_time,
        )
        self.assertTrue(res_zero_retries["allowed"])

        # Negative or zero retry window must fall back to default
        res_neg_window = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            retry_window_seconds=-60,
            current_time=self.base_time,
        )
        self.assertTrue(res_neg_window["allowed"])

        # Cooldown 0 is valid (disables cooldown), while negative falls back to default
        res_neg_cooldown = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            cooldown_seconds=-10,
            current_time=self.base_time,
        )
        self.assertTrue(res_neg_cooldown["allowed"])

    # 11. Multiple Simultaneous Safeguards Failing (D3-9)
    def test_multiple_simultaneous_safeguard_failures(self):
        # Container running + OOM killed + active cooldown + exceeded retries
        history = [
            {
                "timestamp": (self.base_time - timedelta(seconds=15)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
            },
            {
                "timestamp": (self.base_time - timedelta(minutes=3)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
            },
            {
                "timestamp": (self.base_time - timedelta(minutes=5)).isoformat(),
                "action": "start_container",
                "container": "web-svc",
                "success": False,
            },
        ]
        diagnosis = {
            "success": True,
            "container": "web-svc",
            "state": "running",
            "oom_killed": True,
        }
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="running",
            diagnosis=diagnosis,
            history_events=history,
            current_time=self.base_time,
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["action"], "DENY")
        self.assertTrue(result["checks"]["name_valid"])
        self.assertFalse(result["checks"]["state_eligible"])
        self.assertFalse(result["checks"]["oom_safeguard_satisfied"])
        self.assertFalse(result["checks"]["cooldown_satisfied"])
        self.assertFalse(result["checks"]["within_retry_limit"])
        # Priority reason reports state eligibility
        self.assertIn("currently running", result["reason"])

    # 12. Malformed & Edge Case History Data (D3-10)
    def test_malformed_history_records_handled_gracefully(self):
        history = [
            None,
            "string instead of dict",
            {},
            {"container": "web-svc"},  # missing timestamp & action
            {"container": "web-svc", "action": "start_container", "timestamp": "invalid-time"},
            {"container": "web-svc", "action": "wrong_action", "timestamp": self.base_time.isoformat()},
            {
                "container": "web-svc",
                "action": "start_container",
                "timestamp": (self.base_time - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "success": False,
            },
        ]
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=history,
            current_time=self.base_time,
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["attempts_in_window"], 1)

    # 13. Dry-Run Purity
    def test_dry_run_never_calls_restart_container(self):
        with patch("app.recovery.restart_container") as mock_restart:
            result = evaluate_recovery_policy(
                container_name="web-svc",
                current_state="exited",
                current_time=self.base_time,
            )
            self.assertTrue(result["dry_run"])
            mock_restart.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
