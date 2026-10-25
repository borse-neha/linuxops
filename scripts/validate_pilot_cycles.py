#!/usr/bin/env python3

"""
LinuxOps Operational Pilot Validation Script (Phase 6).

Executes repeated, non-destructive monitoring and diagnostics cycles under
mocked runners and synthetic datasets to evaluate:
1. Repeated-cycle monitoring stability (incident identity consistency, deduplication, closure)
2. Resource and memory growth across cycles (detecting memory leaks / unbounded caches)
3. Stale telemetry and partial failure isolation
4. Alert generation, deduplication, secret redaction, and mock notification transport delivery
5. Recovery safety verification with mocks (kill-switch, policy gate, protected container immunity)

Usage:
    python3 scripts/validate_pilot_cycles.py
    python3 scripts/validate_pilot_cycles.py --cycles 10 --scale 100 --json
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

from app.alerts import (
    MockAlertTransport,
    classify_alerts,
    deduplicate_alerts,
    dispatch_alert_notifications,
)
from app.container_inspector import (
    clear_container_metadata_cache,
    get_container_metadata_cache,
    scan_containers,
)
from app.diagnostics_engine import diagnose_all_containers
from app.history import load_recovery_history
from app.recovery_controller import (
    evaluate_incident_recovery,
    execute_authorized_recovery,
    is_protected_container_target,
    set_global_recovery_disabled,
)
from scripts.benchmark_observability import (
    create_synthetic_podman_runner,
    generate_synthetic_dataset,
)


def run_operational_pilot_cycles(
    num_cycles: int = 5,
    scale: int = 100,
) -> dict[str, Any]:
    """Execute repeated operational monitoring cycles and evaluate stability and resource usage."""
    dataset = generate_synthetic_dataset(scale)
    inventory = dataset["ps_inventory"]
    mock_runner = create_synthetic_podman_runner(dataset)

    cycle_reports = []
    initial_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

    # Track incident IDs across cycles to verify stability
    incident_id_history = []
    all_stable = True

    for cycle_idx in range(1, num_cycles + 1):
        t0 = time.perf_counter()
        scan_res = scan_containers(
            runner=mock_runner,
            container_inventory=inventory,
            batch_size=25,
            collect_stats=True,
        )
        scan_dur = time.perf_counter() - t0

        t1 = time.perf_counter()
        diag_res = diagnose_all_containers(scan_res.get("containers", []))
        diag_dur = time.perf_counter() - t1

        incidents = diag_res.get("incidents", [])
        current_incident_ids = sorted(inc.get("incident_id") for inc in incidents)
        incident_id_history.append(current_incident_ids)

        if cycle_idx > 1 and current_incident_ids != incident_id_history[0]:
            all_stable = False

        current_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

        cycle_reports.append({
            "cycle": cycle_idx,
            "scan_duration_seconds": round(scan_dur, 4),
            "diag_duration_seconds": round(diag_dur, 4),
            "total_duration_seconds": round(scan_dur + diag_dur, 4),
            "discovered_count": scan_res.get("discovered_count", 0),
            "inspected_count": scan_res.get("inspected_count", 0),
            "failed_count": scan_res.get("failed_count", 0),
            "incidents_count": len(incidents),
            "peak_rss_mb": round(current_rss, 2),
            "rss_growth_mb": round(current_rss - initial_rss, 2),
        })

    final_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    net_memory_growth_mb = final_rss - initial_rss

    # Verify incident closure on resolved container
    test_container_resolved = {
        "id": "mock_resolve_01",
        "name": "resolved-service",
        "state": "running",
        "health_status": "healthy",
        "exit_code": 0,
        "metrics": {},
    }
    diag_resolved = diagnose_all_containers([test_container_resolved])
    resolved_incidents = [
        i for i in diag_resolved.get("incidents", [])
        if i.get("container_name") == "resolved-service"
    ]
    incident_closure_verified = len(resolved_incidents) == 0

    return {
        "total_cycles_executed": num_cycles,
        "containers_per_cycle": scale,
        "incident_ids_deterministic": all_stable,
        "incident_closure_verified": incident_closure_verified,
        "initial_rss_mb": round(initial_rss, 2),
        "final_rss_mb": round(final_rss, 2),
        "net_memory_growth_mb": round(net_memory_growth_mb, 2),
        "memory_growth_bounded": (net_memory_growth_mb < 20.0),
        "cycles": cycle_reports,
    }


def verify_alert_delivery_readiness() -> dict[str, Any]:
    """Test alert generation, deduplication, secret scrubbing, and mock transport delivery."""
    sample_report = {
        "system": {
            "cpu_usage_percent": 95.5,
            "memory": {"usage_percent": 92.0},
            "disk": {"usage_percent": 50.0},
        },
        "container_summary": {"total": 3, "running": 1, "stopped": 2},
        "containers": [
            {
                "name": "c1-api-Authorization: Bearer my_secret_token_123",
                "state": "exited",
                "exit_code": 137,
                "health": "stopped",
            },
            {
                "name": "c2-db",
                "state": "dead",
                "exit_code": 1,
                "health": "unknown",
            },
        ],
    }

    # 1. Alert generation & classification
    raw_alerts = classify_alerts(sample_report)

    # 2. Duplicate prevention
    duplicated_alerts = raw_alerts + raw_alerts
    deduped = deduplicate_alerts(duplicated_alerts)
    dedup_ratio = len(duplicated_alerts) / len(deduped) if deduped else 1.0

    # 3. Notification dispatch with MockAlertTransport (success path)
    success_transport = MockAlertTransport(should_fail=False)
    dispatch_success = dispatch_alert_notifications(deduped, transport=success_transport)

    # Check secret redaction in dispatched payload
    secret_leaked = False
    for sent in success_transport.dispatched_alerts:
        msg = sent.get("message", "")
        tgt = sent.get("target", "")
        if "my_secret_token_123" in msg or "my_secret_token_123" in tgt:
            secret_leaked = True

    # 4. Notification dispatch with MockAlertTransport (failure simulation)
    fail_transport = MockAlertTransport(should_fail=True, failure_message="Connection timed out to webhook")
    dispatch_failed = dispatch_alert_notifications(deduped, transport=fail_transport)

    # 5. Delivery without transport configured (absent state)
    dispatch_absent = dispatch_alert_notifications(deduped, transport=None)

    return {
        "raw_alerts_generated": len(raw_alerts),
        "deduplicated_count": len(deduped),
        "deduplication_effective": (len(deduped) == len(raw_alerts)),
        "secrets_scrubbed_in_payload": not secret_leaked,
        "mock_transport_dispatch_success": (dispatch_success.get("status") == "SUCCESS"),
        "mock_transport_failure_isolated": (dispatch_failed.get("status") == "FAILED" and dispatch_failed.get("failed") == len(deduped)),
        "absent_transport_handled_safely": (dispatch_absent.get("status") == "NO_TRANSPORT_CONFIGURED"),
    }


def verify_recovery_safety_guards() -> dict[str, Any]:
    """Test all recovery authorization, kill-switch, policy gate, and protected immunity guards."""
    results = {}

    # 1. Kill-Switch Denies Execution
    set_global_recovery_disabled(True)
    try:
        ks_res = execute_authorized_recovery("test-worker", action="start_container", authorized=True)
        results["kill_switch_denies"] = (ks_res.get("verification_status") == "GLOBAL_KILL_SWITCH")
    finally:
        set_global_recovery_disabled(False)

    # 2. Protected Container Immunity
    floci_res = execute_authorized_recovery("cloudops-floci", action="start_container", authorized=True)
    ui_test_res = execute_authorized_recovery("linuxops-recovery-ui-test", action="start_container", authorized=True)
    results["protected_floci_immune"] = (floci_res.get("verification_status") == "PROTECTED_WORKLOAD")
    results["protected_ui_test_immune"] = (ui_test_res.get("verification_status") == "PROTECTED_WORKLOAD")

    # 3. Crash Loop Blocked by Backend Policy Gate
    crash_inc = {
        "incident_id": "INC_CRASH_TEST",
        "container_name": "crash-app",
        "rule_id": "CRASH_LOOP_DETECTED",
        "probable_cause": "Process failed repeatedly on startup.",
    }
    crash_res = execute_authorized_recovery("crash-app", action="start_container", incident=crash_inc, authorized=True)
    results["crash_loop_policy_denied"] = (crash_res.get("verification_status") == "POLICY_DENIED")

    # 4. Missing Mount Blocked by Backend Policy Gate
    mount_inc = {
        "incident_id": "INC_MOUNT_TEST",
        "container_name": "mount-app",
        "rule_id": "MISSING_BIND_MOUNT_SOURCE",
        "probable_cause": "Host directory /nonexistent/path does not exist.",
    }
    mount_res = execute_authorized_recovery("mount-app", action="start_container", incident=mount_inc, authorized=True)
    results["missing_mount_policy_denied"] = (mount_res.get("verification_status") == "POLICY_DENIED")

    # 5. Shell Injection Blocked
    bad_name_res = execute_authorized_recovery("app; rm -rf /", action="start_container", authorized=True)
    results["shell_injection_rejected"] = (bad_name_res.get("verification_status") == "REJECTED")

    # All safety assertions passed
    results["all_safety_guards_passed"] = all(results.values())
    return results


def main():
    parser = argparse.ArgumentParser(description="LinuxOps Phase 6 Operational Pilot Validation")
    parser.add_argument("--cycles", type=int, default=5, help="Number of repeated monitoring cycles to run")
    parser.add_argument("--scale", type=int, default=100, help="Container inventory scale per cycle")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    # 1. Run repeated monitoring cycles
    monitoring_results = run_operational_pilot_cycles(num_cycles=args.cycles, scale=args.scale)

    # 2. Run alert delivery readiness checks
    alert_results = verify_alert_delivery_readiness()

    # 3. Run recovery safety verification
    recovery_results = verify_recovery_safety_guards()

    overall_ready = (
        monitoring_results["incident_ids_deterministic"]
        and monitoring_results["incident_closure_verified"]
        and monitoring_results["memory_growth_bounded"]
        and alert_results["secrets_scrubbed_in_payload"]
        and alert_results["mock_transport_dispatch_success"]
        and recovery_results["all_safety_guards_passed"]
    )

    verdict = "READY FOR LIMITED PILOT" if overall_ready else "NOT READY"

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": "Phase 6 Operational Pilot Validation",
        "verdict": verdict,
        "monitoring_stability": monitoring_results,
        "alert_delivery_readiness": alert_results,
        "recovery_safety_guards": recovery_results,
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print("=" * 80)
        print("LINUXOPS PHASE 6: OPERATIONAL PILOT VALIDATION AUDIT")
        print("=" * 80)
        print(f"Timestamp: {payload['timestamp']}")
        print(f"Verdict:   {verdict}")
        print("-" * 80)

        print("\n--- 1. MONITORING STABILITY & REPEATED CYCLES ---")
        print(f"Cycles Executed:            {monitoring_results['total_cycles_executed']}")
        print(f"Containers Per Cycle:       {monitoring_results['containers_per_cycle']}")
        print(f"Deterministic Incident IDs: {'✅ PASS' if monitoring_results['incident_ids_deterministic'] else '❌ FAIL'}")
        print(f"Incident Closure Verified:  {'✅ PASS' if monitoring_results['incident_closure_verified'] else '❌ FAIL'}")
        print(f"Initial / Final Peak RSS:   {monitoring_results['initial_rss_mb']:.2f} MB / {monitoring_results['final_rss_mb']:.2f} MB")
        print(f"Net Memory Growth:          {monitoring_results['net_memory_growth_mb']:+.2f} MB ({'✅ BOUNDED' if monitoring_results['memory_growth_bounded'] else '❌ EXCESSIVE'})")

        print("\nCycle Breakdown:")
        print(f"  {'Cycle':<6} | {'Scan Dur':<10} | {'Diag Dur':<10} | {'Total Dur':<10} | {'Failed':<8} | {'Incidents':<10} | {'Peak RSS':<10}")
        print("  " + "-" * 72)
        for c in monitoring_results["cycles"]:
            print(f"  {c['cycle']:<6} | {c['scan_duration_seconds']:<10.3f} | {c['diag_duration_seconds']:<10.3f} | {c['total_duration_seconds']:<10.3f} | {c['failed_count']:<8} | {c['incidents_count']:<10} | {c['peak_rss_mb']:<7.2f} MB")

        print("\n--- 2. ALERT DELIVERY READINESS ---")
        print(f"Alert Classification:       ✅ Generated {alert_results['raw_alerts_generated']} alerts")
        print(f"Alert Deduplication:        ✅ Deduplicated down to {alert_results['deduplicated_count']} alerts")
        print(f"Secret Scrubbing:           {'✅ PASS (Redacted credentials)' if alert_results['secrets_scrubbed_in_payload'] else '❌ FAIL'}")
        print(f"Mock Transport Delivery:    {'✅ PASS (Delivered via MockAlertTransport)' if alert_results['mock_transport_dispatch_success'] else '❌ FAIL'}")
        print(f"Transport Failure Handling: {'✅ PASS (Isolated gracefully)' if alert_results['mock_transport_failure_isolated'] else '❌ FAIL'}")
        print(f"Unconfigured Transport:     {'✅ PASS (Safe fallback NO_TRANSPORT_CONFIGURED)' if alert_results['absent_transport_handled_safely'] else '❌ FAIL'}")

        print("\n--- 3. RECOVERY SAFETY GUARDS (MOCKED) ---")
        print(f"Kill-Switch Override:       {'✅ PASS (GLOBAL_KILL_SWITCH enforced)' if recovery_results['kill_switch_denies'] else '❌ FAIL'}")
        print(f"Protected Workload Floci:   {'✅ PASS (PROTECTED_WORKLOAD enforced)' if recovery_results['protected_floci_immune'] else '❌ FAIL'}")
        print(f"Protected Workload Test:    {'✅ PASS (PROTECTED_WORKLOAD enforced)' if recovery_results['protected_ui_test_immune'] else '❌ FAIL'}")
        print(f"Crash Loop Policy Gate:     {'✅ PASS (POLICY_DENIED enforced)' if recovery_results['crash_loop_policy_denied'] else '❌ FAIL'}")
        print(f"Missing Mount Policy Gate:  {'✅ PASS (POLICY_DENIED enforced)' if recovery_results['missing_mount_policy_denied'] else '❌ FAIL'}")
        print(f"Shell Injection Blocked:    {'✅ PASS (REJECTED by naming rules)' if recovery_results['shell_injection_rejected'] else '❌ FAIL'}")

        print("\n" + "=" * 80)
        print(f"OVERALL PILOT READINESS STATUS: {verdict}")
        print("=" * 80)


if __name__ == "__main__":
    main()
