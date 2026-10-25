#!/usr/bin/env python3

"""
Unit and Regression Tests for LinuxOps Phase 8 — Production-Scale Observability & Diagnostics.

Tests cover:
- Latency percentile calculation (p50, p90, p95)
- Bounded metadata cache with eviction, hit/miss tracking, and explicit invalidation
- Empty-running-container stats bypass optimization
- Full scan metrics accounting (freshness, completeness, latency stats, cache stats)
- Partial inspection failure isolation
- Explicit representation of missing vs zero metrics
- Enriched operator guidance schema and deterministic candidate causes
- Secret redaction across all incident fields
- Incident ID stability across repeated evaluations
- Multi-dimensional inventory filtering (severity, label, state, health, search)
- Protected workload immunity in recovery controller
"""

import time
import unittest
from unittest.mock import MagicMock, patch

from app.container_inspector import (
    ContainerMetadataCache,
    calculate_latency_percentiles,
    normalize_container_record,
    query_podman_stats,
    scan_containers,
)
from app.dashboard import filter_and_paginate_containers, format_container_inventory_rows
from app.diagnostics_engine import (
    build_incident,
    diagnose_all_containers,
    diagnose_container_record,
    redact_sensitive_text,
)
from app.recovery_controller import (
    evaluate_incident_recovery,
    is_protected_container_target,
)


class TestLatencyPercentiles(unittest.TestCase):
    """Test percentile latency calculations for inspect chunk latencies."""

    def test_empty_durations(self):
        stats = calculate_latency_percentiles([])
        self.assertEqual(stats["p50_ms"], 0.0)
        self.assertEqual(stats["p95_ms"], 0.0)

    def test_single_duration(self):
        stats = calculate_latency_percentiles([50.0])
        self.assertEqual(stats["min_ms"], 50.0)
        self.assertEqual(stats["max_ms"], 50.0)
        self.assertEqual(stats["p50_ms"], 50.0)
        self.assertEqual(stats["p95_ms"], 50.0)

    def test_multiple_durations_percentiles(self):
        # 100 observations from 1ms to 100ms
        durations = [float(i) for i in range(1, 101)]
        stats = calculate_latency_percentiles(durations)
        self.assertAlmostEqual(stats["min_ms"], 1.0, places=1)
        self.assertAlmostEqual(stats["max_ms"], 100.0, places=1)
        self.assertAlmostEqual(stats["p50_ms"], 50.5, delta=1.5)
        self.assertAlmostEqual(stats["p90_ms"], 90.1, delta=1.5)
        self.assertAlmostEqual(stats["p95_ms"], 95.1, delta=1.5)


class TestMetadataCache(unittest.TestCase):
    """Test ContainerMetadataCache accounting, eviction, and invalidation."""

    def test_cache_hit_miss_and_hit_ratio(self):
        cache = ContainerMetadataCache(max_entries=10)
        self.assertIsNone(cache.get("c1"))  # Miss
        self.assertEqual(cache.stats()["misses"], 1)

        cache.set("c1", {"name": "c1", "image": "redis:alpine"})
        res = cache.get("c1")  # Hit
        self.assertIsNotNone(res)
        stats = cache.stats()
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["misses"], 1)
        self.assertEqual(stats["hit_ratio"], 0.5)
        self.assertEqual(stats["size"], 1)

    def test_cache_bounded_capacity_eviction(self):
        cache = ContainerMetadataCache(max_entries=3)
        cache.set("c1", {"id": "1"})
        cache.set("c2", {"id": "2"})
        cache.set("c3", {"id": "3"})
        cache.set("c4", {"id": "4"})  # Should evict oldest (c1)

        self.assertEqual(cache.stats()["evictions"], 1)
        self.assertIsNone(cache.get("c1"))
        self.assertIsNotNone(cache.get("c4"))
        self.assertEqual(cache.stats()["size"], 3)

    def test_cache_explicit_invalidation(self):
        cache = ContainerMetadataCache(max_entries=10)
        cache.set("c1", {"id": "1"})
        cache.invalidate("c1")
        self.assertIsNone(cache.get("c1"))

        cache.set("c2", {"id": "2"})
        cache.clear()
        self.assertEqual(cache.stats()["size"], 0)
        self.assertIsNone(cache.get("c2"))


class TestStatsOptimization(unittest.TestCase):
    """Test optimization bypassing expensive subprocess stats query when no containers are running."""

    def test_empty_running_ids_bypasses_subprocess(self):
        mock_runner = MagicMock()
        res = query_podman_stats(runner=mock_runner, running_ids=[])
        self.assertEqual(res, {})
        mock_runner.assert_not_called()

    def test_running_ids_invokes_stats_runner(self):
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = '{"ID": "c1", "CPUPerc": "5.0%", "MemUsage": "10MB / 100MB", "MemPerc": "10.0%"}\n'
        res = query_podman_stats(runner=mock_runner, running_ids=["c1"])
        self.assertIn("c1", res)
        mock_runner.assert_called_once()


class TestScanReportingSchema(unittest.TestCase):
    """Test enriched reporting schema and failure accounting in scan_containers."""

    def test_scan_containers_schema(self):
        mock_runner = MagicMock()
        mock_runner.side_effect = [
            # 1. podman ps -a
            MagicMock(returncode=0, stdout='[{"Id": "c1", "Names": ["web"]}]'),
            # 2. podman inspect
            MagicMock(
                returncode=0,
                stdout='[{"Id": "c1", "Name": "web", "State": {"Status": "running", "ExitCode": 0, "OOMKilled": false}}]',
            ),
            # 3. podman stats
            MagicMock(returncode=0, stdout='{"ID": "c1", "CPUPerc": "2.0%", "MemPerc": "5.0%"}\n'),
        ]

        res = scan_containers(runner=mock_runner, collect_stats=True)
        self.assertIn("scan_start_iso", res)
        self.assertIn("scan_completed_iso", res)
        self.assertIn("scan_duration_seconds", res)
        self.assertIn("data_freshness_seconds", res)
        self.assertTrue(res["is_complete"])
        self.assertEqual(res["partial_reasons"], [])
        self.assertIn("latency_stats", res)
        self.assertIn("cache_stats", res)
        self.assertEqual(res["inspected_count"], 1)

    def test_partial_inspection_failure_isolation(self):
        mock_runner = MagicMock()
        mock_runner.side_effect = [
            # 1. podman ps -a returns 1 container
            MagicMock(returncode=0, stdout='[{"Id": "c_fail", "Names": ["bad-container"]}]'),
            # 2. podman inspect fails with exit code 125
            MagicMock(returncode=125, stdout="", stderr="Error: no such container"),
        ]

        res = scan_containers(runner=mock_runner, collect_stats=False)
        self.assertFalse(res["is_complete"])
        self.assertTrue(len(res["partial_reasons"]) > 0)
        self.assertEqual(res["failed_count"], 1)
        self.assertEqual(res["containers"][0]["inspection_status"], "failed")


class TestMetricIntegrity(unittest.TestCase):
    """Test that missing or stale metrics are never presented as zero."""

    def test_missing_metrics_not_zero(self):
        raw_inspect = {
            "Id": "c_stopped",
            "Name": "/stopped-app",
            "State": {"Status": "exited", "ExitCode": 0, "OOMKilled": False},
        }
        # Normalized with no stats
        norm = normalize_container_record(raw_inspect, stats_map=None)
        cpu_stat = norm["metrics"]["cpu_percent"]["status"]
        mem_stat = norm["metrics"]["memory_percent"]["status"]
        self.assertEqual(cpu_stat, "unavailable")
        self.assertEqual(mem_stat, "unavailable")

        rows = format_container_inventory_rows([norm])
        self.assertEqual(rows[0]["CPU"], "[unavailable]")
        self.assertEqual(rows[0]["Memory"], "[unavailable]")


class TestOperatorGuidanceDiagnostics(unittest.TestCase):
    """Test that incidents provide the full 7-question operator guidance schema."""

    def test_operator_guidance_fields_populated(self):
        inc = build_incident(
            container_name="db-prod",
            container_id="c100",
            rule_id="OOM_KILLED",
            category="resource",
            severity="CRITICAL",
            probable_cause="Container killed by OOM killer.",
            confidence=1.0,
            evidence=["State.OOMKilled=True"],
            recommended_action="Increase memory limit.",
        )

        required_fields = [
            "incident_id",
            "container_name",
            "container_id",
            "rule_id",
            "severity",
            "severity_reason",
            "symptoms",
            "first_seen",
            "last_seen",
            "probable_cause",
            "candidate_causes",
            "confidence",
            "confidence_explanation",
            "alternative_explanations",
            "evidence",
            "suggested_investigation_steps",
            "investigation_commands",
            "recommended_action",
            "action_reason",
            "risks_and_prerequisites",
            "expected_outcome",
            "post_action_verification",
            "escalation_guidance",
            "correlated_containers",
        ]
        for f in required_fields:
            self.assertIn(f, inc, f"Missing operator guidance field: {f}")

        # Check candidate cause classification
        self.assertEqual(inc["candidate_causes"][0]["type"], "CONFIRMED")
        self.assertEqual(inc["candidate_causes"][0]["confidence"], 1.0)

    def test_secret_redaction_in_guidance(self):
        inc = build_incident(
            container_name="app",
            container_id="c1",
            rule_id="CRASH_LOOP",
            category="lifecycle",
            severity="CRITICAL",
            probable_cause="Failed with token=secret_token_1234567890",
            confidence=0.9,
            evidence=["password=my_secret_password_123"],
            recommended_action="Update API key AKIAIOSFODNN7EXAMPLE",
            symptoms=["Crash with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"],
            investigation_commands=["podman logs app --tail 50 # key=AKIAIOSFODNN7EXAMPLE"],
        )

        self.assertNotIn("secret_token_1234567890", inc["probable_cause"])
        self.assertNotIn("my_secret_password_123", str(inc["evidence"]))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", inc["recommended_action"])
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz", str(inc["symptoms"]))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", str(inc["investigation_commands"]))

    def test_incident_id_stability(self):
        inc1 = build_incident("web", "c1", "OOM_KILLED", "resource", "CRITICAL", "OOM", 1.0, [], "Action")
        inc2 = build_incident("web", "c1", "OOM_KILLED", "resource", "CRITICAL", "OOM", 1.0, [], "Action")
        self.assertEqual(inc1["incident_id"], inc2["incident_id"])


class TestDashboardFiltering(unittest.TestCase):
    """Test dashboard multi-dimensional filtering by search, severity, labels, and state."""

    def test_multi_filter_pagination(self):
        containers = [
            {"name": "api-1", "id": "1", "state": "running", "health": "healthy", "labels": {"tier": "backend"}},
            {"name": "api-2", "id": "2", "state": "exited", "health": "none", "labels": {"tier": "backend"}},
            {"name": "frontend", "id": "3", "state": "running", "health": "none", "labels": {"tier": "frontend"}},
        ]
        incidents = [
            {"container_name": "api-2", "severity": "CRITICAL"},
        ]

        # Filter by severity CRITICAL
        res, count, _ = filter_and_paginate_containers(
            containers=containers,
            severity_filter="CRITICAL",
            incidents=incidents,
        )
        self.assertEqual(count, 1)
        self.assertEqual(res[0]["name"], "api-2")

        # Filter by label 'frontend'
        res_lbl, count_lbl, _ = filter_and_paginate_containers(
            containers=containers,
            label_filter="frontend",
        )
        self.assertEqual(count_lbl, 1)
        self.assertEqual(res_lbl[0]["name"], "frontend")


class TestProtectedWorkloadSafeguards(unittest.TestCase):
    """Test that protected workloads remain immune under all circumstances."""

    def test_protected_workloads_immune(self):
        self.assertTrue(is_protected_container_target("cloudops-floci"))
        self.assertTrue(is_protected_container_target("linuxops-recovery-ui-test"))
        self.assertFalse(is_protected_container_target("ephemeral-worker"))

        # Evaluate recovery against protected container
        res = evaluate_incident_recovery("cloudops-floci", current_state="exited")
        self.assertFalse(res["allowed"])
        self.assertTrue(res["escalated"])
        self.assertIn("PROTECTED", res["reason"].upper())


if __name__ == "__main__":
    unittest.main()
