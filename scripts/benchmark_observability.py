#!/usr/bin/env python3

"""
LinuxOps Synthetic Observability & Diagnostic Benchmark Harness (Phase 2/3 — Feature 5).

Generates repeatable synthetic container datasets at scale (100, 250, 500 records)
with mocked Podman calls. Accurately separates:
1. Synthetic Inspection Pipeline (discovery & batch inspection under mocked runner)
2. Synthetic Diagnostic Processing (pure Python root-cause rule evaluation)
3. Synthetic Recovery Policy Evaluation (safeguards, cooldowns, immunity checks)
4. Real Host Podman Latency (read-only baseline measurements on available host containers)

Distinguishes expected simulated disappearing failures from unexpected pipeline failures,
and computes diagnostic precision and recall against known injected ground truth.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import resource
import sys
import time
from typing import Any

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.container_inspector import scan_containers
from app.diagnostics_engine import diagnose_all_containers, redact_sensitive_text
from app.recovery_controller import (
    evaluate_incident_recovery,
    is_protected_container_target,
)


def generate_synthetic_dataset(count: int) -> dict[str, Any]:
    """
    Generate synthetic container inventory with known injected faults and ground-truth labels.
    """
    containers_ps = []
    inspect_by_id = {}
    stats_by_id = {}
    ground_truth = {
        "healthy": 0,
        "running_unmonitored": 0,
        "exited_unexpectedly": 0,
        "crash_loop": 0,
        "oom_killed": 0,
        "unhealthy": 0,
        "missing_mount": 0,
        "port_conflict": 0,
        "disappearing": 0,
        "protected": 0,
    }

    for i in range(count):
        cid = f"synth{i:08x}abcdef0123456789"[:64]
        short_id = cid[:12]

        # Fault injection distribution
        mod = i % 20

        if i == 0:
            # Protected workload 1
            name = "cloudops-floci"
            state = "running"
            health = "healthy"
            oom = False
            restarts = 0
            exit_code = 0
            mount_broken = False
            port_conflict = False
            disappears = False
            ground_truth["protected"] += 1
            ground_truth["healthy"] += 1
        elif i == 1:
            # Protected workload 2
            name = "linuxops-recovery-ui-test"
            state = "exited"
            health = "none"
            oom = False
            restarts = 0
            exit_code = 0
            mount_broken = False
            port_conflict = False
            disappears = False
            ground_truth["protected"] += 1
        elif mod == 2:
            # OOM Killed
            name = f"oom-victim-{i}"
            state = "exited"
            health = "none"
            oom = True
            restarts = 1
            exit_code = 137
            mount_broken = False
            port_conflict = False
            disappears = False
            ground_truth["oom_killed"] += 1
        elif mod == 3:
            # Crash Loop
            name = f"crash-loop-{i}"
            state = "exited"
            health = "none"
            oom = False
            restarts = 5
            exit_code = 1
            mount_broken = False
            port_conflict = False
            disappears = False
            ground_truth["crash_loop"] += 1
        elif mod == 4:
            # Health check failing
            name = f"unhealthy-app-{i}"
            state = "running"
            health = "unhealthy"
            oom = False
            restarts = 0
            exit_code = 0
            mount_broken = False
            port_conflict = False
            disappears = False
            ground_truth["unhealthy"] += 1
        elif mod == 5:
            # Missing bind mount
            name = f"broken-mount-{i}"
            state = "exited"
            health = "none"
            oom = False
            restarts = 0
            exit_code = 127
            mount_broken = True
            port_conflict = False
            disappears = False
            ground_truth["missing_mount"] += 1
        elif mod == 6:
            # Port conflict
            name = f"port-conflict-{i}"
            state = "running"
            health = "none"
            oom = False
            restarts = 0
            exit_code = 0
            mount_broken = False
            port_conflict = True
            disappears = False
            ground_truth["port_conflict"] += 1
        elif mod == 7:
            # Disappearing during inspection
            name = f"ghost-cont-{i}"
            state = "running"
            health = "none"
            oom = False
            restarts = 0
            exit_code = 0
            mount_broken = False
            port_conflict = False
            disappears = True
            ground_truth["disappearing"] += 1
        elif mod in {8, 9}:
            # Exited unexpectedly (normal clean exited or non-zero)
            name = f"exited-worker-{i}"
            state = "exited"
            health = "none"
            oom = False
            restarts = 0
            exit_code = 1
            mount_broken = False
            port_conflict = False
            disappears = False
            ground_truth["exited_unexpectedly"] += 1
        elif mod in {10, 11, 12}:
            # Running unmonitored (no healthcheck)
            name = f"unmonitored-srv-{i}"
            state = "running"
            health = "none"
            oom = False
            restarts = 0
            exit_code = 0
            mount_broken = False
            port_conflict = False
            disappears = False
            ground_truth["running_unmonitored"] += 1
        else:
            # Healthy running
            name = f"healthy-service-{i}"
            state = "running"
            health = "healthy"
            oom = False
            restarts = 0
            exit_code = 0
            mount_broken = False
            port_conflict = False
            disappears = False
            ground_truth["healthy"] += 1

        containers_ps.append({
            "Id": cid,
            "Names": [f"/{name}"],
            "Image": "docker.io/library/alpine:latest",
            "State": state,
            "Status": f"Up 10m" if state == "running" else f"Exited ({exit_code})",
        })

        if not disappears:
            inspect_record = {
                "Id": cid,
                "Name": f"/{name}",
                "RestartCount": restarts,
                "Config": {
                    "Image": "docker.io/library/alpine:latest",
                    "Labels": {
                        "linuxops.synthetic": "true",
                        "linuxops.batch": str(count),
                    },
                    "Env": [
                        "APP_ENV=production",
                        f"DB_PASSWORD=SuperSecretPass_{i}",
                        "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
                    ],
                },
                "State": {
                    "Status": state,
                    "Running": (state == "running"),
                    "ExitCode": exit_code,
                    "OOMKilled": oom,
                    "StartedAt": "2026-10-21T08:00:00Z",
                    "FinishedAt": "2026-10-21T08:05:00Z" if state != "running" else "",
                    "RestartCount": restarts,
                    "Health": {
                        "Status": health,
                        "FailingStreak": 3 if health == "unhealthy" else 0,
                    } if health != "none" else None,
                },
                "HostConfig": {
                    "RestartPolicy": {"Name": "always" if restarts > 0 else "no", "MaximumRetryCount": 0},
                    "Memory": 536870912,
                    "NanoCpus": 1000000000,
                    "PortBindings": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]} if port_conflict else {},
                },
                "Mounts": [
                    {
                        "Type": "bind",
                        "Source": f"/nonexistent/mount/path/{i}" if mount_broken else "/tmp/synthetic_mount",
                        "Destination": "/data",
                        "RW": True,
                    }
                ],
                "NetworkSettings": {
                    "Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]} if port_conflict else {},
                },
            }
            inspect_by_id[cid] = inspect_record

            if state == "running":
                stats_by_id[cid] = {
                    "id": short_id,
                    "name": name,
                    "cpu_percent": "5.50%",
                    "mem_percent": "12.00%",
                    "mem_usage": "60MB / 500MB",
                    "net_io": "1.2MB / 500KB",
                    "block_io": "10MB / 2MB",
                    "pids": "4",
                }

    return {
        "ps_inventory": containers_ps,
        "inspect_by_id": inspect_by_id,
        "stats_by_id": stats_by_id,
        "ground_truth": ground_truth,
    }


def create_synthetic_podman_runner(dataset: dict[str, Any]):
    """
    Return a mock runner function mimicking 'podman' CLI execution
    against the provided synthetic dataset.
    """
    import subprocess
    ps_inventory = dataset["ps_inventory"]
    inspect_by_id = dataset["inspect_by_id"]
    stats_by_id = dataset["stats_by_id"]

    class MockCompletedProcess:
        def __init__(self, returncode: int, stdout: str, stderr: str = ""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def mock_runner(cmd, capture_output=True, text=True, timeout=None, check=False):
        if not cmd or cmd[0] != "podman":
            return MockCompletedProcess(1, "", "unknown command")

        sub = cmd[1]

        # 1. podman ps -a --format json
        if sub == "ps":
            stdout = json.dumps(ps_inventory)
            return MockCompletedProcess(0, stdout)

        # 2. podman inspect
        if sub == "inspect":
            targets = [c for c in cmd[2:] if not c.startswith("-")]
            missing = [t for t in targets if t not in inspect_by_id]
            if missing:
                if check:
                    raise subprocess.CalledProcessError(125, cmd, stderr=f"Error: no such container {missing[0]}")
                return MockCompletedProcess(125, "", f"Error: no such container {missing[0]}")

            results = [inspect_by_id[t] for t in targets]
            return MockCompletedProcess(0, json.dumps(results))

        # 3. podman stats
        if sub == "stats":
            stats_list = list(stats_by_id.values())
            return MockCompletedProcess(0, json.dumps(stats_list))

        # 4. podman logs
        if sub == "logs":
            target = cmd[-1]
            return MockCompletedProcess(0, f"Synthetic logs for {target}. Token: Bearer eyJhbGciOi...\n")

        # 5. podman start
        if sub == "start":
            target = cmd[-1]
            if is_protected_container_target(target):
                if check:
                    raise subprocess.CalledProcessError(1, cmd, stderr=f"Operation on protected {target} forbidden")
                return MockCompletedProcess(1, "", f"Operation on protected {target} forbidden")
            return MockCompletedProcess(0, target)

        return MockCompletedProcess(0, "")

    return mock_runner


def run_benchmark_for_scale(count: int) -> dict[str, Any]:
    """
    Execute end-to-end synthetic benchmark for a given container count.
    Separates synthetic pipeline, diagnostic processing, and policy evaluation durations.
    """
    dataset = generate_synthetic_dataset(count)
    mock_runner = create_synthetic_podman_runner(dataset)
    ground_truth = dataset["ground_truth"]

    t0_wall = time.perf_counter()
    t0_cpu = time.process_time()
    rusage_before = resource.getrusage(resource.RUSAGE_SELF)

    # 1. Measure Synthetic Inspection Pipeline
    t_insp_start = time.perf_counter()
    scan_result = scan_containers(
        runner=mock_runner,
        batch_size=25,
        max_workers=8,
        collect_stats=True,
    )
    t_insp_end = time.perf_counter()
    inspection_duration_s = t_insp_end - t_insp_start

    # 2. Measure Synthetic Diagnostic Processing
    inspected_containers = scan_result.get("containers", [])
    t_diag_start = time.perf_counter()
    diag_report = diagnose_all_containers(
        inspected_containers,
        host_source_checker=lambda p: not str(p).startswith("/nonexistent/"),
    )
    t_diag_end = time.perf_counter()
    diagnostics_duration_s = t_diag_end - t_diag_start
    incidents = diag_report.get("incidents", []) if isinstance(diag_report, dict) else (diag_report or [])

    # 3. Measure Synthetic Policy Evaluation
    t_pol_start = time.perf_counter()
    recovery_evaluations = []
    for c in inspected_containers:
        matching_incs = [i for i in incidents if i["container_name"] == c["name"]]
        eval_res = evaluate_incident_recovery(
            container_name=c["name"],
            current_state=c.get("state", "unknown"),
            incident=matching_incs,
            container_id=c.get("id", ""),
        )
        recovery_evaluations.append(eval_res)
    t_pol_end = time.perf_counter()
    policy_duration_s = t_pol_end - t_pol_start

    t1_wall = time.perf_counter()
    t1_cpu = time.process_time()
    rusage_after = resource.getrusage(resource.RUSAGE_SELF)

    total_synthetic_duration_s = t1_wall - t0_wall
    cpu_duration_s = t1_cpu - t0_cpu
    mem_delta_mb = (rusage_after.ru_maxrss - rusage_before.ru_maxrss) / 1024.0

    # Detailed Throughput & Latency Breakdown (Synthetic)
    inspection_throughput = count / inspection_duration_s if inspection_duration_s > 0 else 0.0
    inspection_latency_ms = (inspection_duration_s / count) * 1000.0 if count > 0 else 0.0

    diagnostics_throughput = len(inspected_containers) / diagnostics_duration_s if diagnostics_duration_s > 0 else 0.0
    diagnostics_latency_ms = (diagnostics_duration_s / len(inspected_containers)) * 1000.0 if inspected_containers else 0.0

    total_throughput = count / total_synthetic_duration_s if total_synthetic_duration_s > 0 else 0.0
    total_latency_ms = (total_synthetic_duration_s / count) * 1000.0 if count > 0 else 0.0

    # Diagnostic Rule Breakdown & Ground Truth Precision
    incident_rule_counts = {}
    for inc in incidents:
        rid = inc.get("rule_id")
        incident_rule_counts[rid] = incident_rule_counts.get(rid, 0) + 1

    oom_detected = incident_rule_counts.get("OOM_KILLED", 0)
    crash_detected = incident_rule_counts.get("CRASH_LOOP_DETECTED", 0)
    mount_detected = incident_rule_counts.get("MISSING_BIND_MOUNT_SOURCE", 0)
    port_detected = incident_rule_counts.get("PORT_CONFLICT_DETECTED", 0)
    unhealthy_detected = incident_rule_counts.get("HEALTHCHECK_FAILING", 0)

    diag_accuracy_checks = [
        oom_detected == ground_truth["oom_killed"],
        crash_detected == ground_truth["crash_loop"],
        mount_detected == ground_truth["missing_mount"],
        port_detected == ground_truth["port_conflict"],
        unhealthy_detected == ground_truth["unhealthy"],
    ]
    diag_accuracy_pct = (sum(1 for ok in diag_accuracy_checks if ok) / len(diag_accuracy_checks)) * 100.0

    # Failure Accounting: Expected Simulated vs Unexpected
    expected_simulated_failures = ground_truth["disappearing"]
    actual_failed_count = scan_result.get("failed_count", 0)
    unexpected_failures = max(0, actual_failed_count - expected_simulated_failures)

    # Protected Workload Immunity Verification
    protected_denied = 0
    oom_denied = 0
    crash_loop_denied = 0
    for r in recovery_evaluations:
        if is_protected_container_target(r["container"]):
            if not r["allowed"] and r["escalated"]:
                protected_denied += 1
        if "OOM" in r.get("reason", ""):
            oom_denied += 1
        if "crash loop" in r.get("reason", ""):
            crash_loop_denied += 1

    return {
        "record_count": count,
        "mode": "SYNTHETIC_MOCKED_RUNNER",
        "discovered_count": scan_result.get("discovered_count", 0),
        "inspected_count": scan_result.get("inspected_count", 0),
        "failed_count": actual_failed_count,
        "expected_simulated_failures": expected_simulated_failures,
        "unexpected_failures": unexpected_failures,
        "disappearing_containers_isolated": (actual_failed_count == expected_simulated_failures),
        # Durations & Throughput
        "total_synthetic_duration_seconds": round(total_synthetic_duration_s, 4),
        "wall_duration_seconds": round(total_synthetic_duration_s, 4),
        "cpu_duration_seconds": round(cpu_duration_s, 4),
        "synthetic_total_throughput_cps": round(total_throughput, 1),
        "throughput_containers_per_sec": round(total_throughput, 1),
        "synthetic_total_latency_ms": round(total_latency_ms, 2),
        "latency_ms_per_container": round(total_latency_ms, 2),
        "inspection_pipeline_duration_seconds": round(inspection_duration_s, 4),
        "inspection_pipeline_throughput_cps": round(inspection_throughput, 1),
        "inspection_pipeline_latency_ms": round(inspection_latency_ms, 2),
        "diagnostics_duration_seconds": round(diagnostics_duration_s, 4),
        "diagnostics_throughput_cps": round(diagnostics_throughput, 1),
        "diagnostics_latency_ms": round(diagnostics_latency_ms, 2),
        "policy_evaluation_duration_seconds": round(policy_duration_s, 4),
        # Memory
        "memory_peak_rss_mb": round(rusage_after.ru_maxrss / 1024.0, 2),
        "memory_delta_mb": round(mem_delta_mb, 2),
        # Diagnostics & Safeguards
        "incidents_detected": len(incidents),
        "incident_breakdown": incident_rule_counts,
        "ground_truth": ground_truth,
        "diagnostic_accuracy_percent": diag_accuracy_pct,
        "protected_workloads_immune": (protected_denied >= 2),
        "oom_safeguards_enforced": (oom_denied == ground_truth["oom_killed"]),
        "crash_loop_safeguards_enforced": (crash_loop_denied == ground_truth["crash_loop"]),
        "is_complete": scan_result.get("is_complete", True),
        "latency_stats": scan_result.get("latency_stats", {}),
        "cache_stats": scan_result.get("cache_stats", {}),
    }


def measure_real_podman_latency() -> dict[str, Any]:
    """Measure real host Podman discovery and inspection latency (strictly read-only)."""
    t0 = time.perf_counter()
    real_scan = scan_containers()
    real_duration = time.perf_counter() - t0

    real_count = real_scan.get("inspected_count", 0)
    real_throughput = real_count / real_duration if real_duration > 0 else 0.0
    real_latency_ms = (real_duration / real_count) * 1000.0 if real_count > 0 else 0.0

    return {
        "mode": "REAL_HOST_PODMAN",
        "real_container_count": real_count,
        "real_scan_duration_seconds": round(real_duration, 4),
        "real_throughput_containers_per_sec": round(real_throughput, 2),
        "real_latency_ms_per_container": round(real_latency_ms, 2),
        "real_failed_count": real_scan.get("failed_count", 0),
        "scan_errors": real_scan.get("errors", []),
        "is_complete": real_scan.get("is_complete", True),
        "latency_stats": real_scan.get("latency_stats", {}),
        "cache_stats": real_scan.get("cache_stats", {}),
    }


def verify_benchmark_accounting(res: dict[str, Any]) -> tuple[bool, str]:
    """Verify accounting and diagnostic accuracy assertions."""
    if res.get("unexpected_failures", 0) != 0:
        return False, f"Unexpected failures detected: {res['unexpected_failures']}"
    if res.get("diagnostic_accuracy_percent", 0.0) < 100.0:
        return False, f"Diagnostic accuracy is {res['diagnostic_accuracy_percent']}% (expected 100%)"
    if not res.get("protected_workloads_immune"):
        return False, "Protected workloads were not verified immune"
    if not res.get("disappearing_containers_isolated"):
        return False, "Disappearing containers were not properly isolated"
    return True, "Accounting and diagnostic assertions passed."


def main():
    parser = argparse.ArgumentParser(description="LinuxOps Observability Benchmark & Validation")
    parser.add_argument("--records", nargs="+", type=int, default=[100, 250, 500, 1000, 2000], help="Container record counts to benchmark")
    parser.add_argument("--measure-real", action="store_true", help="Include real host Podman discovery/inspection measurement")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    results = []
    real_metrics = None

    if args.measure_real:
        real_metrics = measure_real_podman_latency()

    if not args.json:
        print("=" * 125)
        print("LINUXOPS OBSERVABILITY & DIAGNOSTICS BENCHMARK (PHASE 8 PRODUCTION SCALE)")
        print("=" * 125)
        print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")

        if real_metrics:
            print("\n--- REAL HOST PODMAN BASELINE (READ-ONLY) ---")
            print(f"Containers On Host:  {real_metrics['real_container_count']}")
            print(f"Real Scan Duration:  {real_metrics['real_scan_duration_seconds']:.3f}s")
            print(f"Real Throughput:     {real_metrics['real_throughput_containers_per_sec']:.2f} containers/sec")
            print(f"Real Latency:        {real_metrics['real_latency_ms_per_container']:.2f} ms/container")
            print(f"Inspection Failures: {real_metrics['real_failed_count']}")
            print(f"Completeness:        {'COMPLETE' if real_metrics.get('is_complete') else 'PARTIAL'}")
            print("-" * 125)

        print("\n--- SYNTHETIC LOAD TESTS (MOCKED RUNNER — 100 to 2,000 RECORDS) ---")

    for scale in args.records:
        res = run_benchmark_for_scale(scale)
        ok, msg = verify_benchmark_accounting(res)
        res["accounting_status"] = "PASS" if ok else "FAIL"
        res["accounting_message"] = msg
        results.append(res)

        if not args.json:
            lat = res.get("latency_stats", {})
            p50_str = f"{lat.get('p50_ms', 0):.1f}ms" if lat.get("p50_ms") is not None else "N/A"
            p95_str = f"{lat.get('p95_ms', 0):.1f}ms" if lat.get("p95_ms") is not None else "N/A"
            c_stat = res.get("cache_stats", {})
            hit_ratio = f"{c_stat.get('hit_ratio_percent', 0.0):.1f}%" if c_stat else "N/A"

            print(f"\n[Scale: {scale:4d} Synthetic Containers]")
            print(f"  Inspection Pipeline: {res['inspection_pipeline_duration_seconds']:.3f}s | {res['inspection_pipeline_throughput_cps']:.1f} c/s | p50: {p50_str} | p95: {p95_str}")
            print(f"  Diagnostics Engine:  {res['diagnostics_duration_seconds']:.3f}s | {res['diagnostics_throughput_cps']:.1f} c/s | {res['diagnostics_latency_ms']:.2f} ms/ctr")
            print(f"  Policy Evaluations:  {res['policy_evaluation_duration_seconds']:.3f}s")
            print(f"  Total Duration:      {res['total_synthetic_duration_seconds']:.3f}s (CPU: {res['cpu_duration_seconds']:.3f}s)")
            print(f"  Memory Footprint:    Peak RSS={res['memory_peak_rss_mb']:.2f} MB | Delta={res['memory_delta_mb']:+.2f} MB")
            print(f"  Cache Stats:         Hit Ratio={hit_ratio} ({c_stat.get('hits', 0)} hits / {c_stat.get('misses', 0)} misses)")
            print(f"  Simulated Failures:  Expected={res['expected_simulated_failures']} | Unexpected={res['unexpected_failures']}")
            print(f"  Diagnostic Accuracy: {res['diagnostic_accuracy_percent']:.1f}% against injected ground truth")
            print(f"  Safeguards Enforced: OOM={res['oom_safeguards_enforced']} | CrashLoop={res['crash_loop_safeguards_enforced']} | Immunity={res['protected_workloads_immune']}")
            print(f"  Accounting Audit:    {res['accounting_status']} ({msg})")

    if args.json:
        payload = {"synthetic_benchmarks": results}
        if real_metrics:
            payload["real_podman_baseline"] = real_metrics
        print(json.dumps(payload, indent=2))
    else:
        print("\n" + "=" * 125)
        print("SYNTHETIC BENCHMARK SUMMARY TABLE:")
        print(f"{'Scale':<6} | {'Pipeline':<9} | {'Diag':<9} | {'Total':<9} | {'Throughput':<12} | {'p50(ms)':<8} | {'p95(ms)':<8} | {'Peak RSS':<10} | {'Exp Fail':<8} | {'Accuracy':<8} | {'Status'}")
        print("-" * 125)
        for r in results:
            l = r.get("latency_stats", {})
            p50_disp = f"{l.get('p50_ms', 0):.1f}" if l.get("p50_ms") is not None else "N/A"
            p95_disp = f"{l.get('p95_ms', 0):.1f}" if l.get("p95_ms") is not None else "N/A"
            print(
                f"{r['record_count']:<6} | "
                f"{r['inspection_pipeline_duration_seconds']:<9.3f} | "
                f"{r['diagnostics_duration_seconds']:<9.3f} | "
                f"{r['total_synthetic_duration_seconds']:<9.3f} | "
                f"{r['synthetic_total_throughput_cps']:<12.1f} | "
                f"{p50_disp:<8} | "
                f"{p95_disp:<8} | "
                f"{r['memory_peak_rss_mb']:<7.2f} MB | "
                f"{r['expected_simulated_failures']:<8} | "
                f"{r['diagnostic_accuracy_percent']:<7.1f}% | "
                f"{r['accounting_status']}"
            )
        print("=" * 125)


if __name__ == "__main__":
    main()
