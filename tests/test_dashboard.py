#!/usr/bin/env python3

"""
Unit tests for LinuxOps Dashboard separable logic (Phase B — Step 4).

Tests data formatting helpers for recovery history and policy audit history,
and validates syntax and imports of the dashboard module.
"""

import py_compile
import unittest
from pathlib import Path

from app.history import format_policy_history_rows, format_recovery_history_rows


class TestDashboardHelpers(unittest.TestCase):

    def test_format_policy_history_rows_empty(self):
        self.assertEqual(format_policy_history_rows([]), [])
        self.assertEqual(format_policy_history_rows(None), [])

    def test_format_policy_history_rows_populated(self):
        events = [
            {
                "timestamp": "2026-10-20T12:00:00Z",
                "container": "web-svc",
                "decision": "allow",
                "reason": "Container is exited and eligible.",
                "dry_run": True,
            },
            {
                "timestamp": "2026-10-20T11:50:00Z",
                "container": "db-svc",
                "decision": "DENY",
                "reason": "Cooldown active.",
                "dry_run": True,
            },
        ]
        rows = format_policy_history_rows(events)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["Container"], "web-svc")
        self.assertEqual(rows[0]["Decision"], "ALLOW")
        self.assertEqual(rows[0]["Dry Run"], "TRUE")

        self.assertEqual(rows[1]["Container"], "db-svc")
        self.assertEqual(rows[1]["Decision"], "DENY")
        self.assertEqual(rows[1]["Dry Run"], "TRUE")

    def test_format_policy_history_rows_malformed_entries(self):
        events = [
            None,
            "corrupt string",
            {},
            {"container": "partial-svc"},
        ]
        rows = format_policy_history_rows(events)
        self.assertEqual(len(rows), 2)  # only dict entries included
        self.assertEqual(rows[0]["Container"], "N/A")
        self.assertEqual(rows[1]["Container"], "partial-svc")

    def test_format_recovery_history_rows_empty(self):
        self.assertEqual(format_recovery_history_rows([]), [])
        self.assertEqual(format_recovery_history_rows(None), [])

    def test_format_recovery_history_rows_populated(self):
        events = [
            {
                "timestamp": "2026-10-20T12:00:00Z",
                "container": "web-svc",
                "success": True,
                "message": "Started",
            },
            {
                "timestamp": "2026-10-20T11:50:00Z",
                "container": "db-svc",
                "success": False,
                "message": "Failed",
            },
        ]
        rows = format_recovery_history_rows(events)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["Status"], "SUCCESS")
        self.assertEqual(rows[1]["Status"], "FAILED")

    def test_dashboard_syntax_and_compilation(self):
        dashboard_path = Path(__file__).resolve().parent.parent / "app" / "dashboard.py"
        self.assertTrue(dashboard_path.exists())
        # Verify py_compile does not raise SyntaxError
        compiled = py_compile.compile(str(dashboard_path), doraise=True)
        self.assertIsNotNone(compiled)


if __name__ == "__main__":
    unittest.main()
