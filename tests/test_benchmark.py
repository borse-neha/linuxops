#!/usr/bin/env python3

"""Unit tests for Phase 2 Synthetic Scale & Observability Benchmark Harness."""

import json
import unittest

from scripts.benchmark_observability import (
    generate_synthetic_dataset,
    measure_real_podman_latency,
    run_benchmark_for_scale,
    verify_benchmark_accounting,
)


class TestBenchmarkObservability(unittest.TestCase):
    """Test synthetic load generation, scale execution, and benchmark metrics."""

    def test_generate_synthetic_dataset_counts(self):
        dataset_100 = generate_synthetic_dataset(100)
        self.assertEqual(len(dataset_100["ps_inventory"]), 100)
        self.assertIn("ground_truth", dataset_100)

        gt = dataset_100["ground_truth"]
        self.assertEqual(gt["protected"], 2)
        self.assertGreater(gt["oom_killed"], 0)
        self.assertGreater(gt["crash_loop"], 0)
        self.assertGreater(gt["disappearing"], 0)

        # Inspect map should have 100 - disappearing records
        expected_inspect = 100 - gt["disappearing"]
        self.assertEqual(len(dataset_100["inspect_by_id"]), expected_inspect)

    def test_benchmark_100_containers_scale(self):
        """Run 100-container benchmark and verify all measurements and safeguards."""
        res = run_benchmark_for_scale(100)

        self.assertEqual(res["record_count"], 100)
        self.assertEqual(res["discovered_count"], 100)
        self.assertEqual(res["inspected_count"], 95)
        self.assertEqual(res["failed_count"], 5)  # 5 disappearing containers
        self.assertEqual(res["expected_simulated_failures"], 5)
        self.assertEqual(res["unexpected_failures"], 0)

        # Verify safeguards and fault isolation
        self.assertTrue(res["disappearing_containers_isolated"])
        self.assertTrue(res["protected_workloads_immune"])
        self.assertTrue(res["oom_safeguards_enforced"])
        self.assertTrue(res["crash_loop_safeguards_enforced"])

        # Diagnostic accuracy against ground truth
        self.assertEqual(res["diagnostic_accuracy_percent"], 100.0)

        # Performance measurements & breakdown
        self.assertGreater(res["throughput_containers_per_sec"], 500.0)
        self.assertGreater(res["synthetic_total_throughput_cps"], 500.0)
        self.assertGreater(res["inspection_pipeline_throughput_cps"], 1000.0)
        self.assertGreater(res["diagnostics_throughput_cps"], 1000.0)
        self.assertLess(res["wall_duration_seconds"], 2.0)
        self.assertGreater(res["incidents_detected"], 0)

        # Accounting assertion
        ok, msg = verify_benchmark_accounting(res)
        self.assertTrue(ok)
        self.assertIn("passed", msg)

    def test_benchmark_250_containers_scale(self):
        """Run 250-container benchmark and verify fault isolation."""
        res = run_benchmark_for_scale(250)

        self.assertEqual(res["record_count"], 250)
        self.assertEqual(res["discovered_count"], 250)
        self.assertTrue(res["disappearing_containers_isolated"])
        self.assertTrue(res["protected_workloads_immune"])
        self.assertTrue(res["oom_safeguards_enforced"])
        self.assertEqual(res["diagnostic_accuracy_percent"], 100.0)
        self.assertLess(res["wall_duration_seconds"], 5.0)

    def test_verify_benchmark_accounting_failures(self):
        """verify_benchmark_accounting detects accounting discrepancies."""
        # 1. Unexpected failures
        bad_res1 = {
            "unexpected_failures": 2,
            "diagnostic_accuracy_percent": 100.0,
            "protected_workloads_immune": True,
            "disappearing_containers_isolated": True,
        }
        ok, msg = verify_benchmark_accounting(bad_res1)
        self.assertFalse(ok)
        self.assertIn("Unexpected failures detected", msg)

        # 2. Low accuracy
        bad_res2 = {
            "unexpected_failures": 0,
            "diagnostic_accuracy_percent": 80.0,
            "protected_workloads_immune": True,
            "disappearing_containers_isolated": True,
        }
        ok, msg = verify_benchmark_accounting(bad_res2)
        self.assertFalse(ok)
        self.assertIn("Diagnostic accuracy is 80.0%", msg)

        # 3. Protected workload immunity breach
        bad_res3 = {
            "unexpected_failures": 0,
            "diagnostic_accuracy_percent": 100.0,
            "protected_workloads_immune": False,
            "disappearing_containers_isolated": True,
        }
        ok, msg = verify_benchmark_accounting(bad_res3)
        self.assertFalse(ok)
        self.assertIn("Protected workloads were not verified immune", msg)

    def test_measure_real_podman_latency_structure(self):
        """Real Podman measurement returns correct read-only schema."""
        real_data = measure_real_podman_latency()
        self.assertEqual(real_data["mode"], "REAL_HOST_PODMAN")
        self.assertIn("real_container_count", real_data)
        self.assertIn("real_scan_duration_seconds", real_data)
        self.assertIn("real_throughput_containers_per_sec", real_data)
        self.assertIn("real_latency_ms_per_container", real_data)
        self.assertIn("real_failed_count", real_data)


if __name__ == "__main__":
    unittest.main()
