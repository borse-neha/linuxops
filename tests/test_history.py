#!/usr/bin/env python3

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.history import (
    DEFAULT_HISTORY_PATH,
    DEFAULT_POLICY_HISTORY_PATH,
    format_incident_history_rows,
    inspect_audit_log_integrity,
    load_incident_history,
    load_policy_history,
    load_recovery_history,
    record_incident_resolution,
    record_policy_decision,
    record_recovery_event,
    rotate_audit_log,
)
from app.policy import evaluate_recovery_policy


class TestRecoveryHistory(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.history_path = Path(self.temp_dir.name) / "recovery_history.jsonl"
        self.policy_path = Path(self.temp_dir.name) / "policy_history.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    # --- Existing Recovery History Tests ---

    def test_record_successful_recovery(self):
        event = record_recovery_event(
            "web-service",
            {"success": True, "message": "Container is running."},
            self.history_path,
        )

        self.assertTrue(event["success"])
        self.assertEqual(event["container"], "web-service")
        self.assertEqual(event["action"], "start_container")
        self.assertTrue(self.history_path.exists())

    def test_record_failed_recovery(self):
        record_recovery_event(
            "web-service",
            {"success": False, "message": "Start failed."},
            self.history_path,
        )

        history = load_recovery_history(history_path=self.history_path)

        self.assertEqual(len(history), 1)
        self.assertFalse(history[0]["success"])
        self.assertEqual(history[0]["message"], "Start failed.")

    def test_history_returns_newest_first(self):
        record_recovery_event(
            "first", {"success": True, "message": "First"},
            self.history_path,
        )
        record_recovery_event(
            "second", {"success": False, "message": "Second"},
            self.history_path,
        )

        history = load_recovery_history(history_path=self.history_path)

        self.assertEqual(history[0]["container"], "second")
        self.assertEqual(history[1]["container"], "first")

    def test_history_limit(self):
        for name in ["one", "two", "three"]:
            record_recovery_event(
                name, {"success": True, "message": "OK"},
                self.history_path,
            )

        history = load_recovery_history(
            limit=2, history_path=self.history_path
        )

        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["container"], "three")

    def test_missing_history_returns_empty_list(self):
        history = load_recovery_history(
            history_path=self.history_path
        )

        self.assertEqual(history, [])

    def test_invalid_container_name(self):
        with self.assertRaises(ValueError):
            record_recovery_event(
                "", {"success": True, "message": "OK"},
                self.history_path,
            )

    # --- Phase B Step 2: Policy History Tests ---

    def test_record_policy_decision_allow(self):
        decision_result = {
            "allowed": True,
            "decision": "ALLOW",
            "action": "ALLOW",
            "reason": "Container 'web-service' is eligible for recovery.",
            "checks": {
                "name_valid": True,
                "state_eligible": True,
                "oom_safeguard_satisfied": True,
                "cooldown_satisfied": True,
                "within_retry_limit": True,
            },
            "dry_run": True,
        }
        event = record_policy_decision("web-service", decision_result, self.policy_path)

        self.assertEqual(event["container"], "web-service")
        self.assertEqual(event["event_type"], "policy_decision")
        self.assertEqual(event["action"], "evaluate_policy")
        self.assertEqual(event["decision"], "ALLOW")
        self.assertTrue(event["allowed"])
        self.assertTrue(event["dry_run"])
        self.assertIn("web-service", event["reason"])
        self.assertTrue(event["checks"]["name_valid"])
        self.assertTrue(self.policy_path.exists())

        loaded = load_policy_history(history_path=self.policy_path)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["decision"], "ALLOW")

    def test_record_policy_decision_deny(self):
        decision_result = {
            "allowed": False,
            "decision": "DENY",
            "action": "DENY",
            "reason": "Container 'db-svc' is in cooldown. Please wait 45.0s.",
            "checks": {
                "name_valid": True,
                "state_eligible": True,
                "oom_safeguard_satisfied": True,
                "cooldown_satisfied": False,
                "within_retry_limit": True,
            },
            "dry_run": True,
        }
        event = record_policy_decision("db-svc", decision_result, self.policy_path)

        self.assertEqual(event["container"], "db-svc")
        self.assertEqual(event["decision"], "DENY")
        self.assertFalse(event["allowed"])
        self.assertFalse(event["checks"]["cooldown_satisfied"])
        self.assertTrue(event["dry_run"])

    def test_record_policy_decision_invalid_container_name(self):
        valid_decision = {
            "allowed": True,
            "decision": "ALLOW",
            "dry_run": True,
            "checks": {},
        }
        for invalid_name in ["", "   ", None, 123]:
            with self.assertRaises(ValueError):
                record_policy_decision(invalid_name, valid_decision, self.policy_path)

    def test_record_policy_decision_malformed_payload(self):
        # Non-dict payload
        with self.assertRaises(ValueError):
            record_policy_decision("web-svc", "not a dict", self.policy_path)
        with self.assertRaises(ValueError):
            record_policy_decision("web-svc", None, self.policy_path)

        # Missing decision string
        with self.assertRaises(ValueError):
            record_policy_decision("web-svc", {"allowed": True, "dry_run": True}, self.policy_path)

        # Missing allowed boolean
        with self.assertRaises(ValueError):
            record_policy_decision("web-svc", {"decision": "ALLOW", "dry_run": True}, self.policy_path)

    def test_record_policy_decision_inconsistent_decision_allowed(self):
        # Inconsistent ALLOW with allowed=False
        with self.assertRaises(ValueError):
            record_policy_decision(
                "web-svc",
                {"decision": "ALLOW", "allowed": False, "dry_run": True},
                self.policy_path,
            )

        # Inconsistent DENY with allowed=True
        with self.assertRaises(ValueError):
            record_policy_decision(
                "web-svc",
                {"decision": "DENY", "allowed": True, "dry_run": True},
                self.policy_path,
            )

    def test_record_policy_decision_rejects_dry_run_false(self):
        # Policy records must never be persisted with dry_run=False
        with self.assertRaises(ValueError):
            record_policy_decision(
                "web-svc",
                {"decision": "ALLOW", "allowed": True, "dry_run": False},
                self.policy_path,
            )
        # Missing dry_run must also be rejected
        with self.assertRaises(ValueError):
            record_policy_decision(
                "web-svc",
                {"decision": "ALLOW", "allowed": True},
                self.policy_path,
            )

    def test_load_policy_history_newest_first_and_limit(self):
        for idx in range(5):
            record_policy_decision(
                f"app-{idx}",
                {
                    "decision": "ALLOW",
                    "allowed": True,
                    "reason": f"Allow {idx}",
                    "dry_run": True,
                },
                self.policy_path,
            )

        # Newest first
        all_events = load_policy_history(limit=10, history_path=self.policy_path)
        self.assertEqual(len(all_events), 5)
        self.assertEqual(all_events[0]["container"], "app-4")
        self.assertEqual(all_events[-1]["container"], "app-0")

        # Limit enforcement
        limited = load_policy_history(limit=2, history_path=self.policy_path)
        self.assertEqual(len(limited), 2)
        self.assertEqual(limited[0]["container"], "app-4")
        self.assertEqual(limited[1]["container"], "app-3")

    def test_load_policy_history_missing_file(self):
        history = load_policy_history(history_path=self.policy_path)
        self.assertEqual(history, [])

    def test_load_policy_history_malformed_json_lines(self):
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        with self.policy_path.open("w", encoding="utf-8") as f:
            f.write("corrupt json line 1\n")
            valid_record = {
                "timestamp": "2026-10-20T12:00:00Z",
                "event_type": "policy_decision",
                "action": "evaluate_policy",
                "container": "valid-app",
                "decision": "ALLOW",
                "allowed": True,
                "reason": "OK",
                "checks": {},
                "dry_run": True,
            }
            f.write(json.dumps(valid_record) + "\n")
            f.write("{broken json\n")

        events = load_policy_history(history_path=self.policy_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["container"], "valid-app")

    def test_load_policy_history_invalid_limit(self):
        record_policy_decision(
            "app",
            {"decision": "ALLOW", "allowed": True, "dry_run": True},
            self.policy_path,
        )
        for invalid_limit in [0, -1, -50, "10", None, False]:
            self.assertEqual(load_policy_history(limit=invalid_limit, history_path=self.policy_path), [])

    def test_recovery_and_policy_history_isolation(self):
        # 1. Write a recovery event to recovery_path
        record_recovery_event(
            "web-svc",
            {"success": True, "message": "Started container"},
            self.history_path,
        )

        # 2. Write a policy decision to policy_path
        record_policy_decision(
            "web-svc",
            {"decision": "ALLOW", "allowed": True, "dry_run": True},
            self.policy_path,
        )

        # 3. Verify separation across files
        rec_events = load_recovery_history(history_path=self.history_path)
        pol_events = load_policy_history(history_path=self.policy_path)

        self.assertEqual(len(rec_events), 1)
        self.assertEqual(rec_events[0]["action"], "start_container")

        self.assertEqual(len(pol_events), 1)
        self.assertEqual(pol_events[0]["event_type"], "policy_decision")

        # 4. Even if both records are co-located in the same file:
        shared_path = Path(self.temp_dir.name) / "shared.jsonl"
        record_recovery_event("rec-app", {"success": True}, shared_path)
        record_policy_decision(
            "pol-app",
            {"decision": "ALLOW", "allowed": True, "dry_run": True},
            shared_path,
        )

        rec_from_shared = load_recovery_history(history_path=shared_path)
        pol_from_shared = load_policy_history(history_path=shared_path)

        # load_recovery_history must only return recovery events
        self.assertEqual(len(rec_from_shared), 1)
        self.assertEqual(rec_from_shared[0]["container"], "rec-app")

        # load_policy_history must only return policy decisions
        self.assertEqual(len(pol_from_shared), 1)
        self.assertEqual(pol_from_shared[0]["container"], "pol-app")

    def test_policy_records_ignored_by_recovery_evaluator(self):
        # Feed policy audit records into evaluate_recovery_policy's history_events
        base_time = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)
        recent_policy_event = {
            "timestamp": (base_time - timedelta(seconds=10)).isoformat(),
            "event_type": "policy_decision",
            "action": "evaluate_policy",
            "container": "web-svc",
            "decision": "DENY",
            "allowed": False,
            "dry_run": True,
        }
        # Even with 5 recent DENY policy records, they must NOT count as failed recovery retries
        # or activate cooldown, because their action is "evaluate_policy", not "start_container"
        result = evaluate_recovery_policy(
            container_name="web-svc",
            current_state="exited",
            history_events=[recent_policy_event] * 5,
            current_time=base_time,
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["action"], "ALLOW")
        self.assertTrue(result["checks"]["cooldown_satisfied"])
        self.assertTrue(result["checks"]["within_retry_limit"])
        self.assertEqual(result["attempts_in_window"], 0)

    def test_load_incident_history_and_formatting(self):
        incidents_file = Path(self.temp_dir.name) / "incidents.jsonl"
        # 1. Non-existent file returns []
        self.assertEqual(load_incident_history(incidents_path=incidents_file), [])

        # 2. Write 2 sample incident resolution events
        ev1 = {
            "timestamp": "2026-10-21T10:00:00Z",
            "incident_id": "INC-001",
            "container_name": "worker-1",
            "rule_id": "EXITED_UNEXPECTEDLY",
            "resolution_status": "RESOLVED",
            "message": "Container started and verified healthy.",
        }
        ev2 = {
            "timestamp": "2026-10-21T10:05:00Z",
            "incident_id": "INC-002",
            "container_name": "worker-2",
            "rule_id": "OOM_KILLED",
            "resolution_status": "ESCALATED",
            "message": "Human review required.",
        }
        with open(incidents_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(ev1) + "\n")
            f.write("corrupt line\n")
            f.write(json.dumps(ev2) + "\n")

        loaded = load_incident_history(limit=10, incidents_path=incidents_file)
        self.assertEqual(len(loaded), 2)
        # Newest first
        self.assertEqual(loaded[0]["incident_id"], "INC-002")
        self.assertEqual(loaded[1]["incident_id"], "INC-001")

        # Format rows
        rows = format_incident_history_rows(loaded)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["Incident ID"], "INC-002")
        self.assertEqual(rows[0]["Status"], "ESCALATED")
        self.assertEqual(rows[1]["Incident ID"], "INC-001")
        self.assertEqual(rows[1]["Status"], "RESOLVED")

    def test_record_incident_resolution_persists(self):
        incidents_file = Path(self.temp_dir.name) / "test_incidents.jsonl"
        inc = {
            "incident_id": "INC-999",
            "container_name": "worker-svc",
            "rule_id": "EXITED_UNEXPECTEDLY",
        }
        res = record_incident_resolution(inc, "RESOLVED", "Container successfully recovered and verified.", incidents_path=incidents_file)
        self.assertEqual(res["incident_id"], "INC-999")
        self.assertEqual(res["resolution_status"], "RESOLVED")
        self.assertTrue(incidents_file.exists())

        loaded = load_incident_history(incidents_path=incidents_file)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["incident_id"], "INC-999")
        self.assertEqual(loaded[0]["resolution_status"], "RESOLVED")

    def test_inspect_audit_log_integrity(self):
        log_file = Path(self.temp_dir.name) / "audit_integrity_test.jsonl"
        # 1. Non-existent file
        res_non = inspect_audit_log_integrity(log_file)
        self.assertFalse(res_non["exists"])
        self.assertTrue(res_non["is_healthy"])

        # 2. Populated file with 2 valid lines, 1 empty line, 1 corrupted line
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({"event": 1}) + "\n")
            f.write("\n")
            f.write("corrupted json {not valid\n")
            f.write(json.dumps({"event": 2}) + "\n")

        res = inspect_audit_log_integrity(log_file)
        self.assertTrue(res["exists"])
        self.assertEqual(res["total_lines"], 4)
        self.assertEqual(res["valid_records"], 2)
        self.assertEqual(res["corrupted_records"], 1)
        self.assertEqual(res["empty_lines"], 1)
        self.assertFalse(res["is_healthy"])

    def test_rotate_audit_log(self):
        rot_file = Path(self.temp_dir.name) / "rotate_test.jsonl"
        with open(rot_file, "w", encoding="utf-8") as f:
            f.write("A" * 500)

        # 1. Below threshold does not rotate
        res_no = rotate_audit_log(rot_file, max_bytes=1000)
        self.assertFalse(res_no["rotated"])
        self.assertTrue(rot_file.exists())

        # 2. Above threshold rotates to .1
        res_yes = rotate_audit_log(rot_file, max_bytes=200)
        self.assertTrue(res_yes["rotated"])
        archived = Path(self.temp_dir.name) / "rotate_test.jsonl.1"
        self.assertTrue(archived.exists())
        self.assertEqual(archived.stat().st_size, 500)
        # Fresh file exists
        self.assertTrue(rot_file.exists())
        self.assertEqual(rot_file.stat().st_size, 0)

    def test_malformed_and_partially_written_jsonl(self):
        """Partially written lines do not discard valid records."""
        rec_file = Path(self.temp_dir.name) / "partial_test.jsonl"
        valid_ev = {
            "timestamp": "2026-10-21T12:00:00Z",
            "action": "start_container",
            "container": "app-x",
            "success": True,
            "message": "ok",
        }
        with open(rec_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(valid_ev) + "\n")
            f.write('{"timestamp": "2026-10-21T12:01:00Z", "action": "start_container", "container": "app-truncated\n')
            f.write("\n")
            f.write('{"incomplete": true')

        events = load_recovery_history(history_path=rec_file)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["container"], "app-x")


if __name__ == "__main__":
    unittest.main()
