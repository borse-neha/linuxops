"""
Unit tests for LinuxOps Phase 6 — Operational Pilot Validation.
Validates:
- Alert transport layer (MockAlertTransport, dispatch_alert_notifications, fallback, secret scrubbing)
- Operational cycle stability & deterministic incident IDs
- Safety gate enforcement under pilot simulation
"""

import unittest
from datetime import datetime, timezone

from app.alerts import (
    MockAlertTransport,
    dispatch_alert_notifications,
    deduplicate_alerts,
)
from app.recovery_controller import (
    is_protected_container_target,
    ALLOWED_RECOVERY_ACTIONS,
    execute_authorized_recovery,
    set_global_recovery_disabled,
    is_global_recovery_disabled,
    PROTECTED_NAMES,
)
from app.diagnostics_engine import diagnose_container_record, build_incident


class TestAlertTransportLayer(unittest.TestCase):
    """Test the alert transport and notification dispatch capabilities."""

    def setUp(self):
        self.sample_alerts = [
            {
                "id": "ALT_SYS_01",
                "severity": "CRITICAL",
                "rule": "CPU_HIGH",
                "target_type": "system",
                "target": "cpu",
                "message": "Host CPU utilization at 95.5% (threshold: 90.0%)",
                "timestamp": "2026-10-21T12:00:00Z",
            },
            {
                "id": "ALT_CNT_01",
                "severity": "WARNING",
                "rule": "HIGH_RESTART_COUNT",
                "target_type": "container",
                "target": "web-service-app",
                "message": "Container has restarted 4 times. token=secret12345 in env",
                "timestamp": "2026-10-21T12:00:00Z",
            },
        ]

    def test_mock_alert_transport_success(self):
        transport = MockAlertTransport()
        res = transport.send({"test": "data"})
        self.assertEqual(res["status"], "DELIVERED")
        self.assertEqual(len(transport.dispatched_alerts), 1)
        self.assertEqual(transport.dispatched_alerts[0]["test"], "data")

    def test_mock_alert_transport_failure(self):
        transport = MockAlertTransport(should_fail=True, failure_message="Network unreachable")
        with self.assertRaises(ConnectionError) as ctx:
            transport.send({"test": "data"})
        self.assertIn("Network unreachable", str(ctx.exception))
        self.assertEqual(len(transport.dispatched_alerts), 0)

    def test_dispatch_empty_alerts(self):
        res = dispatch_alert_notifications([])
        self.assertEqual(res["status"], "EMPTY")
        self.assertEqual(res["total_alerts"], 0)
        self.assertEqual(res["dispatched"], 0)

        res_none = dispatch_alert_notifications(None)
        self.assertEqual(res_none["status"], "EMPTY")

    def test_dispatch_no_transport_configured(self):
        res = dispatch_alert_notifications(self.sample_alerts, transport=None)
        self.assertEqual(res["status"], "NO_TRANSPORT_CONFIGURED")
        self.assertEqual(res["total_alerts"], 2)
        self.assertEqual(res["dispatched"], 0)
        self.assertIn("not configured", res["message"])

    def test_dispatch_success_with_mock_transport(self):
        transport = MockAlertTransport()
        res = dispatch_alert_notifications(self.sample_alerts, transport=transport, redact_secrets=True)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["total_alerts"], 2)
        self.assertEqual(res["dispatched"], 2)
        self.assertEqual(res["failed"], 0)
        self.assertEqual(len(transport.dispatched_alerts), 2)

        # Check secret scrubbing
        dispatched_cnt = next(a for a in transport.dispatched_alerts if a["id"] == "ALT_CNT_01")
        self.assertNotIn("secret12345", dispatched_cnt["message"])
        self.assertIn("[REDACTED", dispatched_cnt["message"])

    def test_dispatch_with_callable_transport(self):
        delivered = []

        def custom_sink(payload):
            delivered.append(payload)
            return "OK"

        res = dispatch_alert_notifications(self.sample_alerts, transport=custom_sink)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(len(delivered), 2)

    def test_dispatch_partial_failure_isolation(self):
        call_count = [0]

        def flaky_sink(payload):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionResetError("Connection dropped by peer")
            return "OK"

        res = dispatch_alert_notifications(self.sample_alerts, transport=flaky_sink)
        self.assertEqual(res["status"], "PARTIAL")
        self.assertEqual(res["dispatched"], 1)
        self.assertEqual(res["failed"], 1)
        self.assertEqual(res["results"][0]["status"], "FAILED")
        self.assertIn("Connection dropped", res["results"][0]["error"])
        self.assertEqual(res["results"][1]["status"], "DELIVERED")

    def test_dispatch_invalid_transport_type(self):
        res = dispatch_alert_notifications(self.sample_alerts, transport=12345)
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res["failed"], 2)
        self.assertIn("Invalid transport object", res["results"][0]["error"])


class TestPilotSafetyAndStability(unittest.TestCase):
    """Verify safety gates and stability requirements for pilot readiness."""

    def test_deterministic_incident_ids(self):
        """Verify that identical diagnosis triggers generate identical deterministic IDs."""
        cont_state = {
            "id": "c001deadbeef0000000000000000000000000000000000000000000000000001",
            "name": "app-crashloop-pilot",
            "state": "running",
            "restart_count": 12,
            "exit_code": 137,
            "oom_killed": True,
        }
        res1 = diagnose_container_record(cont_state)
        res2 = diagnose_container_record(cont_state)

        incidents1 = [r.get("incident_id") for r in res1]
        incidents2 = [r.get("incident_id") for r in res2]
        self.assertGreater(len(incidents1), 0)
        self.assertEqual(incidents1, incidents2)

    def test_global_kill_switch_denies_recovery(self):
        set_global_recovery_disabled(True)
        try:
            self.assertTrue(is_global_recovery_disabled())
            res = execute_authorized_recovery("test-service", authorized=True)
            self.assertFalse(res["success"])
            self.assertEqual(res["verification_status"], "GLOBAL_KILL_SWITCH")
        finally:
            set_global_recovery_disabled(False)

    def test_unauthorized_operator_denied(self):
        res = execute_authorized_recovery("test-service", authorized=False)
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "AUTHORIZATION_REQUIRED")

    def test_protected_workloads_immune(self):
        for protected in ["cloudops-floci", "linuxops-recovery-ui-test"]:
            self.assertTrue(is_protected_container_target(protected))
            res = execute_authorized_recovery(protected, authorized=True)
            self.assertFalse(res["success"])
            self.assertEqual(res["verification_status"], "PROTECTED_WORKLOAD")

    def test_destructive_actions_forbidden(self):
        for act in ["stop_container", "restart_container", "remove_container", "kill_container", "prune_volumes"]:
            self.assertNotIn(act, ALLOWED_RECOVERY_ACTIONS)
            res = execute_authorized_recovery("test-service", action=act, authorized=True)
            self.assertFalse(res["success"])
            self.assertEqual(res["verification_status"], "FORBIDDEN_ACTION")

        self.assertIn("start_container", ALLOWED_RECOVERY_ACTIONS)

    def test_invalid_and_injection_names_rejected(self):
        for bad_name in ["container; rm -rf /", "app$(whoami)", "-flag", ""]:
            res = execute_authorized_recovery(bad_name, authorized=True)
            self.assertFalse(res["success"])
            self.assertEqual(res["verification_status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
