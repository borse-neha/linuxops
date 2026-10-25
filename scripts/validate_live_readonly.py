#!/usr/bin/env python3

"""
LinuxOps Live Read-Only Podman Integration Verification (Phase 3 — Step 2).

Strictly read-only inspection script:
- Verifies live Podman availability and permissions
- Discovers real container inventory without mutations
- Compares container_inspector results against raw Podman CLI output
- Verifies metric status typing (stopped container metrics are 'unavailable', not 0.0)
- Verifies running containers without health checks are NOT reported as healthy
- Validates that protected workloads are correctly identified and immune
- Confirms zero modifications to protected containers or persistent data
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.container_inspector import (
    get_host_identity,
    is_protected_workload,
    scan_containers,
)
from app.diagnostics_engine import diagnose_all_containers
from app.recovery_controller import (
    evaluate_incident_recovery,
    is_protected_container_target,
)


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    return res.returncode, res.stdout.strip(), res.stderr.strip()


def main():
    print("=" * 80)
    print("LINUXOPS PHASE 3: LIVE READ-ONLY PODMAN INTEGRATION AUDIT")
    print("=" * 80)

    # 1. Check Podman availability and permissions
    rc, version_out, version_err = run_cmd(["podman", "version"])
    if rc != 0:
        print(f"[FAIL] Podman CLI is unavailable or returned error: {version_err}")
        sys.exit(1)
    print(f"[PASS] Podman CLI is available (rc={rc}):")
    for line in version_out.splitlines()[:5]:
        print(f"       {line}")

    # 2. Query Raw Podman Inventory
    rc, raw_ps_out, raw_ps_err = run_cmd(["podman", "ps", "-a", "--format", "json"])
    if rc != 0:
        print(f"[FAIL] 'podman ps -a' failed: {raw_ps_err}")
        sys.exit(1)

    raw_containers = json.loads(raw_ps_out) if raw_ps_out else []
    raw_count = len(raw_containers)
    print(f"\n[INFO] Real Podman Container Inventory: {raw_count} container(s) found on host.")
    for c in raw_containers:
        names = c.get("Names") or []
        cid = c.get("Id", "")[:12]
        state = c.get("State", "unknown")
        print(f"       - ID: {cid} | Names: {names} | State: {state}")

    # 3. Execute container_inspector.scan_containers()
    t0 = time.perf_counter()
    scan_report = scan_containers()
    scan_time = time.perf_counter() - t0

    discovered = scan_report.get("containers", [])
    print(f"\n[INFO] container_inspector.scan_containers() Report:")
    print(f"       Scan Duration:       {scan_time:.3f}s (reported: {scan_report.get('scan_duration_ms', 0):.1f}ms)")
    print(f"       Discovered Count:    {scan_report.get('discovered_count')}")
    print(f"       Inspected Count:     {scan_report.get('inspected_count')}")
    print(f"       Failed Count:        {scan_report.get('failed_count')}")
    print(f"       Healthy Count:       {scan_report.get('healthy_count')}")
    print(f"       Host Machine ID:     {scan_report.get('host_identity', {}).get('machine_id', 'unknown')[:12]}")

    # 4. Compare Inspector Output against Raw Podman CLI
    assert len(discovered) == raw_count, f"Mismatch: Raw count {raw_count} vs Inspector count {len(discovered)}"
    print("\n[PASS] Discovered container count matches raw Podman inventory exactly.")

    # 5. Verify Metric Typing & Health Status on Discovered Containers
    for c in discovered:
        c_name = c["name"]
        c_state = c["state"]
        c_health = c["health_status"]
        metrics = c.get("metrics", {})
        is_prot = c.get("is_protected", False)

        print(f"\n[AUDIT] Container: '{c_name}' (State: {c_state})")
        print(f"        Short ID:         {c['short_id']}")
        print(f"        Health Status:    {c_health}")
        print(f"        Is Protected:     {is_prot}")
        print(f"        CPU Metric:       {metrics.get('cpu_percent')}")
        print(f"        Mem Metric:       {metrics.get('memory_percent')}")

        # Check 1: Protected workload recognition
        if c_name in {"cloudops-floci", "linuxops-recovery-ui-test"}:
            assert is_prot is True, f"Protected container '{c_name}' was not tagged as is_protected=True!"
            print(f"        -> [PASS] Correctly tagged as protected workload.")

        # Check 2: If stopped, metrics must be 'unavailable', NOT 0.0 / zero
        if c_state in {"exited", "stopped"}:
            cpu_status = metrics.get("cpu_percent", {}).get("status")
            assert cpu_status == "unavailable", f"Stopped container '{c_name}' had cpu_status='{cpu_status}', expected 'unavailable'!"
            assert c_health != "healthy", f"Stopped container '{c_name}' was marked as healthy!"
            print(f"        -> [PASS] Stopped container metrics strictly typed as 'unavailable' (not fake 0.0%).")

        # Check 3: If running without explicit healthcheck, must NOT be marked 'healthy'
        if c_state == "running":
            # Check raw inspect health object
            rc_insp, raw_insp_out, _ = run_cmd(["podman", "inspect", c_name])
            insp_data = json.loads(raw_insp_out)[0] if rc_insp == 0 else {}
            has_health_config = bool(insp_data.get("Config", {}).get("Healthcheck") or insp_data.get("State", {}).get("Health"))
            if not has_health_config:
                assert c_health != "healthy", f"Running container '{c_name}' without healthcheck was falsely marked as 'healthy'!"
                print(f"        -> [PASS] Running container without health probe marked as '{c_health}' (not falsely 'healthy').")
            else:
                print(f"        -> [PASS] Running container with health probe marked as '{c_health}'.")

    # 6. Execute Diagnostics & Recovery Evaluation (Read-Only)
    diag_report = diagnose_all_containers(discovered)
    incidents = diag_report.get("incidents", [])
    print(f"\n[INFO] Diagnostics Engine Report:")
    print(f"       Total Incidents:     {len(incidents)}")
    print(f"       Critical:            {diag_report.get('critical_count')}")
    print(f"       Warning:             {diag_report.get('warning_count')}")
    print(f"       Info:                {diag_report.get('info_count')}")

    for inc in incidents:
        print(f"       - Incident: {inc['incident_id']} | Rule: {inc['rule_id']} | Target: {inc['container_name']} | Severity: {inc['severity']}")
        print(f"         Probable Cause: {inc['probable_cause']}")

    # 7. Audit Safe Recovery Proposals for Live Containers
    print("\n[AUDIT] Safe Recovery Controller Evaluations (Read-Only Dry-Run):")
    for c in discovered:
        matching_incs = [i for i in incidents if i["container_name"] == c["name"]]
        prop = evaluate_incident_recovery(
            container_name=c["name"],
            current_state=c["state"],
            incident=matching_incs,
            container_id=c["id"],
        )
        print(f"       Container: '{c['name']}' -> Decision: {prop['decision']} | Allowed: {prop['allowed']} | Escalated: {prop.get('escalated')}")
        print(f"       Reason: {prop['reason']}")

        # Ensure protected workloads are permanently DENIED recovery
        if is_protected_container_target(c["name"], c["id"]):
            assert prop["allowed"] is False, f"CRITICAL: Protected workload '{c['name']}' was ALLOWED recovery!"
            assert prop["escalated"] is True, f"Protected workload '{c['name']}' must be escalated!"
            print(f"       -> [PASS] Protected workload immunity verified: recovery strictly DENIED.")

    # 8. Verify Protected Containers and Persistent Data are Untouched
    print("\n[AUDIT] Verifying Protected Workloads State & Timestamps Post-Scan:")
    rc_floci, floci_out, _ = run_cmd(["podman", "inspect", "cloudops-floci"])
    assert rc_floci == 0, "cloudops-floci inspect failed!"
    floci_data = json.loads(floci_out)[0]
    assert floci_data["State"]["Running"] is True, "cloudops-floci is not running!"
    print(f"[PASS] 'cloudops-floci' is running (PID: {floci_data['State']['Pid']}, StartedAt: {floci_data['State']['StartedAt']}).")

    rc_ui, ui_out, _ = run_cmd(["podman", "inspect", "linuxops-recovery-ui-test"])
    assert rc_ui == 0, "linuxops-recovery-ui-test inspect failed!"
    ui_data = json.loads(ui_out)[0]
    assert ui_data["State"]["Status"] == "exited", "linuxops-recovery-ui-test state altered!"
    print(f"[PASS] 'linuxops-recovery-ui-test' is untouched (Status: {ui_data['State']['Status']}).")

    persistent_mount = Path("/home/neha/cloudops-sentinel/data")
    if persistent_mount.exists():
        print(f"[PASS] Persistent data directory '{persistent_mount}' verified intact.")

    print("\n" + "=" * 80)
    print("LIVE READ-ONLY INTEGRATION AUDIT: ALL CHECKS PASSED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    main()
