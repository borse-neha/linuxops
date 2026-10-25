
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app import monitor


class TestHealthClassification(unittest.TestCase):

    def test_normal_status(self):
        self.assertEqual(
            monitor.classify_health(40, 70, 90),
            "NORMAL",
        )

    def test_warning_status(self):
        self.assertEqual(
            monitor.classify_health(75, 70, 90),
            "WARNING",
        )

    def test_critical_status(self):
        self.assertEqual(
            monitor.classify_health(95, 70, 90),
            "CRITICAL",
        )

    def test_exact_warning_threshold(self):
        self.assertEqual(
            monitor.classify_health(70, 70, 90),
            "WARNING",
        )

    def test_exact_critical_threshold(self):
        self.assertEqual(
            monitor.classify_health(90, 70, 90),
            "CRITICAL",
        )


class TestThresholds(unittest.TestCase):

    def test_threshold_defaults(self):
        thresholds = monitor.get_thresholds()
        self.assertEqual(thresholds["cpu"], (70.0, 90.0))
        self.assertEqual(thresholds["memory"], (80.0, 90.0))
        self.assertEqual(thresholds["disk"], (80.0, 90.0))

    def test_threshold_invalid_values(self):
        with patch.dict("os.environ", {"CPU_WARNING": "invalid"}):
            thresholds = monitor.get_thresholds()
            self.assertEqual(thresholds["cpu"][0], 70.0)

    def test_threshold_out_of_range(self):
        with patch.dict("os.environ", {"CPU_WARNING": "150", "CPU_CRITICAL": "-5"}):
            thresholds = monitor.get_thresholds()
            self.assertEqual(thresholds["cpu"], (70.0, 90.0))

    def test_threshold_inverted(self):
        with patch.dict("os.environ", {"CPU_WARNING": "95", "CPU_CRITICAL": "80"}):
            thresholds = monitor.get_thresholds()
            self.assertEqual(thresholds["cpu"], (70.0, 90.0))


class TestMonitoring(unittest.TestCase):

    def test_collect_metrics_structure(self):
        metrics = monitor.collect_metrics()

        self.assertIn("timestamp", metrics)
        self.assertIn("hostname", metrics)
        self.assertIn("cpu_usage_percent", metrics)
        self.assertIn("memory", metrics)
        self.assertIn("disk", metrics)
        self.assertIn("health_checks", metrics)
        self.assertIn("overall_status", metrics)

        self.assertIn(
            metrics["overall_status"],
            {"NORMAL", "WARNING", "CRITICAL"},
        )

        cpu_val = metrics["cpu_usage_percent"]
        self.assertTrue(
            cpu_val is None or (isinstance(cpu_val, (int, float)) and 0 <= cpu_val <= 100),
            f"cpu_usage_percent must be None or numeric within [0, 100], got {cpu_val!r}",
        )
        if cpu_val is not None:
            self.assertGreaterEqual(cpu_val, 0)
            self.assertLessEqual(cpu_val, 100)

    def test_save_metrics_creates_json_record(self):
        metrics = {
            "hostname": "test-host",
            "overall_status": "NORMAL",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            test_log = Path(temp_dir) / "metrics.jsonl"

            with patch.object(monitor, "LOG_FILE", test_log):
                monitor.save_metrics(metrics)

            self.assertTrue(test_log.exists())

            with test_log.open(encoding="utf-8") as file:
                saved_record = json.loads(file.readline())

            self.assertEqual(saved_record, metrics)

    def test_get_memory_usage_zero_total(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_mem = Path(temp_dir) / "meminfo"
            fake_mem.write_text("MemTotal: 0 kB\nMemAvailable: 0 kB\n", encoding="utf-8")
            result = monitor.get_memory_usage(str(fake_mem))
            self.assertEqual(result["total_mb"], 0.0)
            self.assertEqual(result["usage_percent"], 0.0)

    def test_get_memory_usage_fallback_memavailable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_mem = Path(temp_dir) / "meminfo"
            fake_mem.write_text(
                "MemTotal: 1000000 kB\nMemFree: 200000 kB\nBuffers: 100000 kB\nCached: 200000 kB\n",
                encoding="utf-8",
            )
            result = monitor.get_memory_usage(str(fake_mem))
            self.assertEqual(result["usage_percent"], 50.0)

    def test_get_memory_usage_missing_file(self):
        result = monitor.get_memory_usage("/non/existent/path/to/meminfo")
        self.assertEqual(result["total_mb"], 0.0)
        self.assertEqual(result["usage_percent"], 0.0)

    def test_get_disk_usage_zero_total(self):
        from collections import namedtuple
        DiskUsage = namedtuple("DiskUsage", ["total", "used", "free"])
        with patch("shutil.disk_usage", return_value=DiskUsage(0, 0, 0)):
            result = monitor.get_disk_usage("/")
            self.assertEqual(result["total_gb"], 0.0)
            self.assertEqual(result["usage_percent"], 0.0)

    def test_get_disk_usage_os_error(self):
        with patch("shutil.disk_usage", side_effect=OSError("Disk failure")):
            result = monitor.get_disk_usage("/")
            self.assertEqual(result["total_gb"], 0.0)
            self.assertEqual(result["usage_percent"], 0.0)

    def test_get_cpu_usage_zero_delta(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            fake_stat.write_text("cpu  100 20 30 500 10 0 0 0 0 0\n", encoding="utf-8")
            result = monitor.get_cpu_usage(interval=0, proc_stat_path=str(fake_stat))
            self.assertEqual(result, 0.0)

    def test_get_cpu_usage_missing_file(self):
        result = monitor.get_cpu_usage(interval=0, proc_stat_path="/non/existent/stat")
        self.assertEqual(result, 0.0)


class TestCpuUsageSampling(unittest.TestCase):
    def setUp(self):
        with monitor._CPU_LOCK:
            monitor._LAST_CPU_SAMPLE.clear()

    def tearDown(self):
        with monitor._CPU_LOCK:
            monitor._LAST_CPU_SAMPLE.clear()
            init_times = monitor._read_cpu_times("/proc/stat")
            if init_times and len(init_times) >= 4:
                monitor._LAST_CPU_SAMPLE["/proc/stat"] = (init_times, time.monotonic())

    def test_initial_sample_warmup(self):
        """First call with no prior sample returns None (warm-up state) without sleeping."""
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            fake_stat.write_text("cpu  100 20 30 500 10 0 0 0 0 0\n", encoding="utf-8")
            result = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
            self.assertIsNone(result)

    def test_two_samples_calculation(self):
        """Second call with a subsequent sample calculates correct CPU utilization percentage."""
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            # Sample 1: total = 100+20+30+500+10 = 660, idle = 500+10 = 510
            fake_stat.write_text("cpu  100 20 30 500 10 0 0 0 0 0\n", encoding="utf-8")
            res1 = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
            self.assertIsNone(res1)

            # Sample 2: total increases by 100, idle increases by 50 -> usage = 50.0%
            fake_stat.write_text("cpu  150 20 30 550 10 0 0 0 0 0\n", encoding="utf-8")
            res2 = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
            self.assertIsNotNone(res2)
            self.assertEqual(res2, 50.0)

    def test_sample_reuse_successive_calls(self):
        """Successive calls update state and compute deltas from the immediate previous sample."""
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            fake_stat.write_text("cpu  100 0 0 900 0 0 0 0 0 0\n", encoding="utf-8")
            monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))

            # Delta 1: total=100, idle=80 -> usage=20%
            fake_stat.write_text("cpu  120 0 0 980 0 0 0 0 0 0\n", encoding="utf-8")
            r1 = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
            self.assertEqual(r1, 20.0)

            # Delta 2: total=100, idle=100 -> usage=0%
            fake_stat.write_text("cpu  120 0 0 1080 0 0 0 0 0 0\n", encoding="utf-8")
            r2 = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
            self.assertEqual(r2, 0.0)

    def test_zero_delta_handling(self):
        """When proc_stat does not change between calls, return None (unavailable) without division by zero."""
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            fake_stat.write_text("cpu  100 0 0 900 0 0 0 0 0 0\n", encoding="utf-8")
            monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))

            # Identical content -> total delta = 0 -> returns None (unavailable)
            r = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
            self.assertIsNone(r)

    def test_counter_reset_and_subsequent_sample(self):
        """Counter reset returns None, resets baseline, and next sample calculates correct percentage."""
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            fake_stat.write_text("cpu  1000 0 0 9000 0 0 0 0 0 0\n", encoding="utf-8")
            monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))

            # Counter reset: lower values -> returns None and resets baseline
            fake_stat.write_text("cpu  100 0 0 900 0 0 0 0 0 0\n", encoding="utf-8")
            r_reset = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
            self.assertIsNone(r_reset)

            # Next valid sample after reset: total increases by 100, idle increases by 50 -> 50.0%
            fake_stat.write_text("cpu  150 0 0 950 0 0 0 0 0 0\n", encoding="utf-8")
            r_next = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
            self.assertIsNotNone(r_next)
            self.assertEqual(r_next, 50.0)

    def test_impossible_idle_delta_handling(self):
        """When idle delta exceeds total delta, return None (unavailable) rather than invalid or clamped values."""
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            fake_stat.write_text("cpu  100 0 0 900 0 0 0 0 0 0\n", encoding="utf-8")
            monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))

            # Impossible: total increases by 50, but idle increases by 100
            fake_stat.write_text("cpu  50 0 0 1000 0 0 0 0 0 0\n", encoding="utf-8")
            r = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
            self.assertIsNone(r)

    def test_missing_and_malformed_proc_stat(self):
        """Missing or malformed proc stat file returns None (unavailable) safely in stateful mode."""
        r_missing = monitor.get_cpu_usage(interval=None, proc_stat_path="/non/existent/path")
        self.assertIsNone(r_missing)

        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            fake_stat.write_text("invalid cpu line text\n", encoding="utf-8")
            r_malformed = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
            self.assertIsNone(r_malformed)

    def test_explicit_interval_backward_compatibility(self):
        """Explicit interval parameter triggers two-sample sleep without altering stateful mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            fake_stat.write_text("cpu  100 0 0 900 0 0 0 0 0 0\n", encoding="utf-8")
            # Using interval=0.001 to test explicit interval execution
            r = monitor.get_cpu_usage(interval=0.001, proc_stat_path=str(fake_stat))
            self.assertEqual(r, 0.0)

    def test_concurrent_sampling_safety(self):
        """Multiple threads calling get_cpu_usage simultaneously do not crash or corrupt state."""
        import threading
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_stat = Path(temp_dir) / "stat"
            fake_stat.write_text("cpu  100 0 0 900 0 0 0 0 0 0\n", encoding="utf-8")

            results = []
            def worker():
                for _ in range(20):
                    res = monitor.get_cpu_usage(interval=None, proc_stat_path=str(fake_stat))
                    results.append(res)

            threads = [threading.Thread(target=worker) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(results), 100)
            for val in results:
                self.assertTrue(val is None or (isinstance(val, (int, float)) and 0.0 <= val <= 100.0))

    def test_unavailable_cpu_alerts_and_health_classification(self):
        """Unavailable CPU data is classified as UNKNOWN and triggers WARNING alert, not treated as healthy zero."""
        from app.alerts import classify_system_alerts

        # Health classification returns UNKNOWN, not NORMAL
        self.assertEqual(monitor.classify_health(None, 70.0, 90.0), "UNKNOWN")

        # Alerts engine produces WARNING alert for unavailable CPU
        system_payload = {"cpu_usage_percent": None, "memory": {"usage_percent": 20.0}, "disk": {"usage_percent": 10.0}}
        alerts = classify_system_alerts(system_payload)
        cpu_alerts = [a for a in alerts if a["target"] == "cpu"]
        self.assertEqual(len(cpu_alerts), 1)
        self.assertEqual(cpu_alerts[0]["severity"], "WARNING")
        self.assertEqual(cpu_alerts[0]["rule"], "system_cpu_unavailable")

    def test_concurrent_sampling_prevents_stale_baseline_overwrite(self):
        """Verify that _read_cpu_times and baseline updates are serialized so older samples cannot overwrite newer ones."""
        import threading
        fake_path = "/fake/proc/stat_race"
        t1_in_read = threading.Event()
        t2_in_read = threading.Event()
        t1_allow_finish = threading.Event()
        t1_lock_held = []

        sample_older = [100, 0, 0, 900]
        sample_newer = [200, 0, 0, 1000]

        call_count = 0

        def mock_read(path):
            nonlocal call_count
            if path == fake_path:
                call_count += 1
                if call_count == 1:
                    # Thread 1: reading older sample
                    t1_lock_held.append(monitor._CPU_LOCK.locked())
                    t1_in_read.set()
                    # Wait for test driver before finishing read
                    t1_allow_finish.wait(timeout=2.0)
                    return sample_older
                elif call_count == 2:
                    # Thread 2: reading newer sample
                    t2_in_read.set()
                    return sample_newer
            return monitor._read_cpu_times(path)

        with patch.object(monitor, "_read_cpu_times", side_effect=mock_read):
            t1 = threading.Thread(
                target=monitor.get_cpu_usage,
                kwargs={"interval": None, "proc_stat_path": fake_path},
            )
            t2 = threading.Thread(
                target=monitor.get_cpu_usage,
                kwargs={"interval": None, "proc_stat_path": fake_path},
            )

            # 1. Start Thread 1 (older sample)
            t1.start()
            self.assertTrue(t1_in_read.wait(timeout=2.0), "Thread 1 did not reach proc_stat read")

            # 2. Thread 1 is currently in mock_read holding _CPU_LOCK.
            # In corrected code, Thread 2 must block and cannot enter mock_read until Thread 1 finishes.
            t2.start()

            # Verify Thread 2 cannot enter mock_read while Thread 1 holds the lock
            t2_entered = t2_in_read.wait(timeout=0.05)
            self.assertFalse(t2_entered, "Thread 2 must not enter proc_stat read while Thread 1 holds _CPU_LOCK")

            # 3. Allow Thread 1 to finish
            t1_allow_finish.set()
            t1.join(timeout=2.0)

            # 4. Now Thread 1 has finished; Thread 2 unblocks, reads newer sample, and updates baseline
            self.assertTrue(t2_in_read.wait(timeout=2.0), "Thread 2 did not proceed after Thread 1 released lock")
            t2.join(timeout=2.0)

            # Verify lock was held by Thread 1 during proc_stat read
            self.assertTrue(t1_lock_held and t1_lock_held[0], "_CPU_LOCK must be held during proc_stat read")

            # Final baseline must be the newer sample from Thread 2, never overwritten by Thread 1's older sample
            with monitor._CPU_LOCK:
                final_entry = monitor._LAST_CPU_SAMPLE.get(fake_path)
            self.assertIsNotNone(final_entry)
            self.assertEqual(
                final_entry[0],
                sample_newer,
                "Stale sample must not overwrite newer baseline in _LAST_CPU_SAMPLE",
            )

    def test_stale_timestamp_sample_rejected_as_baseline(self):
        """Defense-in-depth: sample with older timestamp than current baseline cannot overwrite it."""
        fake_path = "/fake/proc/stat_timestamp_order"
        # Seed a baseline with timestamp 200.0
        with monitor._CPU_LOCK:
            monitor._LAST_CPU_SAMPLE[fake_path] = ([200, 0, 0, 1000], 200.0)

        # Attempt to run with mock time returning older 100.0
        with patch.object(monitor, "_read_cpu_times", return_value=[150, 0, 0, 950]):
            with patch("time.monotonic", return_value=100.0):
                res = monitor.get_cpu_usage(interval=None, proc_stat_path=fake_path)
                self.assertIsNone(res)

        # Baseline must still be the newer sample at timestamp 200.0
        with monitor._CPU_LOCK:
            entry = monitor._LAST_CPU_SAMPLE.get(fake_path)
        self.assertIsNotNone(entry)
        self.assertEqual(entry[0], [200, 0, 0, 1000])
        self.assertEqual(entry[1], 200.0)



if __name__ == "__main__":
    unittest.main(verbosity=2)

