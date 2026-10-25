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


class TestDashboardCaching(unittest.TestCase):

    def test_cached_report_reuse_and_manual_invalidation(self):
        """Test that get_cached_combined_report caches responses and supports explicit .clear()."""
        import logging
        from unittest.mock import patch

        logging.disable(logging.CRITICAL)
        try:
            from app.dashboard import get_cached_combined_report
        finally:
            logging.disable(logging.NOTSET)

        call_count = 0

        def mock_collect():
            nonlocal call_count
            call_count += 1
            return {
                "timestamp": f"2026-10-20T12:00:0{call_count}Z",
                "overall_status": "NORMAL",
                "system": {"cpu_usage_percent": 10.0, "memory": {}, "disk": {}, "health_checks": {"cpu": "NORMAL"}},
                "container_summary": {"total": 1, "running": 1, "stopped": 0, "health": "NORMAL"},
                "containers": [],
            }

        with patch("app.dashboard.collect_combined_report", side_effect=mock_collect):
            get_cached_combined_report.clear()

            # First call: executes underlying collector
            r1 = get_cached_combined_report()
            self.assertEqual(call_count, 1)
            self.assertEqual(r1["timestamp"], "2026-10-20T12:00:01Z")

            # Second call within TTL: returns cached result without re-executing collector
            r2 = get_cached_combined_report()
            self.assertEqual(call_count, 1)
            self.assertEqual(r2["timestamp"], "2026-10-20T12:00:01Z")

            # Manual invalidation: .clear() forces next call to re-execute collector
            get_cached_combined_report.clear()
            r3 = get_cached_combined_report()
            self.assertEqual(call_count, 2)
            self.assertEqual(r3["timestamp"], "2026-10-20T12:00:02Z")

            get_cached_combined_report.clear()

    def test_post_recovery_cache_invalidation_behavior(self):
        """Test that invalidating the cache allows fresh container state to be fetched."""
        import logging
        from unittest.mock import patch

        logging.disable(logging.CRITICAL)
        try:
            from app.dashboard import get_cached_combined_report
        finally:
            logging.disable(logging.NOTSET)

        states = ["stopped", "running"]
        current_idx = 0

        def mock_collect_state():
            return {
                "timestamp": "2026-10-20T12:00:00Z",
                "overall_status": "NORMAL",
                "system": {"cpu_usage_percent": 5.0, "memory": {}, "disk": {}, "health_checks": {"cpu": "NORMAL"}},
                "container_summary": {
                    "total": 1,
                    "running": 1 if states[current_idx] == "running" else 0,
                    "stopped": 1 if states[current_idx] == "stopped" else 0,
                    "health": "NORMAL",
                },
                "containers": [{"name": "app-svc", "state": states[current_idx]}],
            }

        with patch("app.dashboard.collect_combined_report", side_effect=mock_collect_state):
            get_cached_combined_report.clear()
            rep_before = get_cached_combined_report()
            self.assertEqual(rep_before["containers"][0]["state"], "stopped")

            # Simulate recovery succeeding and container state moving to 'running'
            current_idx = 1
            # Before cache clear, still cached as 'stopped'
            self.assertEqual(get_cached_combined_report()["containers"][0]["state"], "stopped")

            # Invalidate cache (as performed in dashboard.py after recovery)
            get_cached_combined_report.clear()
            rep_after = get_cached_combined_report()
            self.assertEqual(rep_after["containers"][0]["state"], "running")

            get_cached_combined_report.clear()

    def test_no_duplicate_recovery_on_refresh_or_rerun(self):
        """Verifies that reading the cached report or refreshing does not invoke restart_container."""
        import logging
        from unittest.mock import patch

        logging.disable(logging.CRITICAL)
        try:
            from app.dashboard import get_cached_combined_report
        finally:
            logging.disable(logging.NOTSET)

        with patch("app.recovery.restart_container") as mock_restart:
            # Querying report or clearing cache does not trigger restart_container
            get_cached_combined_report.clear()
            _ = get_cached_combined_report()
            get_cached_combined_report.clear()
            _ = get_cached_combined_report()
            mock_restart.assert_not_called()

    def test_filter_and_paginate_containers(self):
        """Test search filtering and pagination slicing across container records."""
        from app.dashboard import filter_and_paginate_containers

        containers = [
            {"name": f"worker-{i}", "id": f"id-{i:03d}", "short_id": f"id{i:02d}", "image": "python:3.14", "state": "running" if i % 2 == 0 else "exited", "health": "healthy" if i % 4 == 0 else "none"}
            for i in range(100)
        ]

        # 1. Default pagination (page 1, size 25)
        p1, total, pages = filter_and_paginate_containers(containers, page=1, page_size=25)
        self.assertEqual(total, 100)
        self.assertEqual(pages, 4)
        self.assertEqual(len(p1), 25)
        self.assertEqual(p1[0]["name"], "worker-0")
        self.assertEqual(p1[-1]["name"], "worker-24")

        # 2. Page 2
        p2, total2, pages2 = filter_and_paginate_containers(containers, page=2, page_size=25)
        self.assertEqual(len(p2), 25)
        self.assertEqual(p2[0]["name"], "worker-25")

        # 3. Text search query
        p_search, total_s, _ = filter_and_paginate_containers(containers, search_query="worker-42")
        self.assertEqual(total_s, 1)
        self.assertEqual(p_search[0]["name"], "worker-42")

        # 4. State filter
        p_stopped, total_st, _ = filter_and_paginate_containers(containers, state_filter="exited", page_size=50)
        self.assertEqual(total_st, 50)
        self.assertTrue(all(c["state"] == "exited" for c in p_stopped))

        # 5. Health filter
        p_healthy, total_h, _ = filter_and_paginate_containers(containers, health_filter="healthy")
        self.assertEqual(total_h, 25)

        # 6. Out-of-bounds page clamped safely
        p_oob, _, _ = filter_and_paginate_containers(containers, page=999, page_size=25)
        self.assertEqual(len(p_oob), 25)
        self.assertEqual(p_oob[0]["name"], "worker-75")

    def test_format_container_inventory_rows(self):
        """Test formatting container records and verify health distinction."""
        from app.dashboard import format_container_inventory_rows

        containers = [
            # Running with no healthcheck -> must NOT be reported as healthy
            {
                "name": "unmonitored-svc",
                "id": "1111222233334444",
                "state": "running",
                "health": "none",
                "metrics": {"cpu_percent": 12.5, "cpu_percent_status": "ok", "mem_percent": 45.0, "mem_percent_status": "ok"},
                "restart_count": 0,
                "exit_code": 0,
            },
            # Running with verified healthy healthcheck
            {
                "name": "healthy-svc",
                "id": "2222333344445555",
                "state": "running",
                "health": "healthy",
                "metrics": {"cpu_percent_status": "zero", "mem_percent": 10.0, "mem_percent_status": "ok"},
                "restart_count": 0,
                "exit_code": 0,
            },
            # Stopped container with unavailable metrics
            {
                "name": "stopped-svc",
                "id": "3333444455556666",
                "state": "exited",
                "health": "none",
                "metrics": {"cpu_percent_status": "unavailable", "mem_percent_status": "unavailable"},
                "restart_count": 2,
                "exit_code": 137,
            },
        ]

        rows = format_container_inventory_rows(containers)
        self.assertEqual(len(rows), 3)

        # Crucial requirement: running unmonitored must NOT be called healthy
        self.assertIn("Unmonitored", rows[0]["Health Status"])
        self.assertNotIn("Healthy", rows[0]["Health Status"])
        self.assertEqual(rows[0]["CPU"], "12.5%")

        # Explicitly healthy container
        self.assertIn("Healthy", rows[1]["Health Status"])
        self.assertEqual(rows[1]["CPU"], "0.0%")

        # Stopped container metrics
        self.assertIn("Stopped", rows[2]["Health Status"])
        self.assertEqual(rows[2]["CPU"], "[unavailable]")

    def test_format_incident_rows(self):
        """Test formatting diagnostic incidents for dashboard presentation."""
        from app.dashboard import format_incident_rows

        incidents = [
            {
                "incident_id": "INC-001",
                "severity": "CRITICAL",
                "container_name": "db-prod",
                "rule_id": "OOM_KILLED",
                "probable_cause": "OOM killer terminated container process.",
                "confidence": 0.95,
                "evidence": ["Exit code 137", "OOMKilled flag true"],
                "recommended_action": "INCREASE_MEMORY_LIMIT",
                "verification_status": "OPEN",
                "timestamp": "2026-10-21T12:00:00Z",
            }
        ]

        rows = format_incident_rows(incidents)
        self.assertEqual(len(rows), 1)
        self.assertIn("CRITICAL", rows[0]["Severity"])
        self.assertEqual(rows[0]["Container"], "db-prod")
        self.assertEqual(rows[0]["Confidence"], "95%")
        self.assertIn("Exit code 137", rows[0]["Evidence"])

    def test_cached_container_scan_caching(self):
        """Test caching and invalidation of get_cached_container_scan."""
        import logging
        from unittest.mock import patch

        logging.disable(logging.CRITICAL)
        try:
            from app.dashboard import get_cached_container_scan
        finally:
            logging.disable(logging.NOTSET)

        scan_calls = 0

        def mock_scan():
            nonlocal scan_calls
            scan_calls += 1
            return {
                "containers": [{"name": f"cont-{scan_calls}", "state": "running", "health": "healthy"}],
                "discovered_count": 1,
                "inspected_count": 1,
                "healthy_count": 1,
            }

        with patch("app.dashboard.scan_containers", side_effect=mock_scan), \
             patch("app.dashboard.diagnose_all_containers", return_value=[]):
            get_cached_container_scan.clear()

            s1 = get_cached_container_scan()
            self.assertEqual(scan_calls, 1)

            # Cached
            s2 = get_cached_container_scan()
            self.assertEqual(scan_calls, 1)

            # Invalidate
            get_cached_container_scan.clear()
            s3 = get_cached_container_scan()
            self.assertEqual(scan_calls, 2)

            get_cached_container_scan.clear()


if __name__ == "__main__":
    unittest.main()
