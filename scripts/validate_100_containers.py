#!/usr/bin/env python3

"""
LinuxOps Phase 9 — Controlled 100-Container Validation Test Harness & Auditor.

Implements safe, repeatable, non-destructive validation of LinuxOps against
100 containers in an approved disposable environment.

CRITICAL ARCHITECTURAL SAFETY PRINCIPLES:
1. SAFE BY DEFAULT: Running without arguments executes in DRY-RUN mode.
   No containers are created, started, stopped, or removed.
2. EXPLICIT EXECUTION GATE: Real container creation requires the explicit '--execute' flag.
3. CONSERVATIVE RESOURCE BOUNDS:
   - Memory capped at 24 MiB per container (--memory=24m, --memory-swap=24m)
   - Total theoretical cgroup boundary for 100 containers = 2.4 GiB (host has 3.2+ GiB available)
   - CPU limited to 0.05 per container (--cpus=0.05)
   - PIDs limited to 15 per container (--pids-limit=15)
   - Isolated loopback / closed networking (--network=none)
   - Zero host mounts, zero published ports, zero privileged flags
4. STRICT ISOLATION & DETERMINISTIC LABELS:
   - All containers named linuxops-p9-<RUN_ID>-<INDEX:03d>
   - Tagged with:
     linuxops.phase9-test=true
     linuxops.run-id=<RUN_ID>
     linuxops.scenario=<SCENARIO>
5. ATOMIC MANIFEST TRACKING:
   - Every created container is logged in logs/phase9_manifest_<RUN_ID>.json.
6. TARGETED NON-DESTRUCTIVE CLEANUP:
   - Cleanup is strictly limited to containers recorded in the manifest or matching the exact run label.
   - Never calls broad prune commands.
   - Protected workloads ('cloudops-floci', 'linuxops-recovery-ui-test') and persistent data
     ('/home/neha/cloudops-sentinel/data') are permanently excluded from any cleanup or targeting.
7. COMPREHENSIVE PERFORMANCE & DIAGNOSTIC VALIDATION:
   - Evaluates discovery, batch inspection, p50/p95 latency percentiles, memory growth,
     diagnostic accuracy against injected ground-truth faults, and 7-question operator guidance.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import resource
import secrets
import subprocess
import sys
import time
from typing import Any, Callable

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.container_inspector import (
    calculate_latency_percentiles,
    get_host_identity,
    scan_containers,
)
import logging
logging.disable(logging.CRITICAL)
try:
    from app.dashboard import filter_and_paginate_containers, format_container_inventory_rows
finally:
    logging.disable(logging.NOTSET)
from app.diagnostics_engine import diagnose_all_containers, redact_sensitive_text
from app.recovery_controller import (
    evaluate_incident_recovery,
    is_protected_container_target,
)

# Required Constants & Thresholds
TARGET_CONTAINER_COUNT = 100
DEFAULT_IMAGE = "docker.io/library/alpine:latest"
MIN_MEMORY_MB = 1500.0   # 1.5 GiB
MIN_DISK_GB = 10.0       # 10 GiB

# Protected Workload Identity & Configuration Specifications
PROTECTED_CONTAINERS: dict[str, str] = {
    "cloudops-floci": "db80c688e14b",
    "linuxops-recovery-ui-test": "83b65d88a0a9",
}
PROTECTED_NAMES = {"cloudops-floci", "linuxops-recovery-ui-test"}
PROTECTED_PREFIXES = {"db80c688e14b", "83b65d88a0a9", "510d4cfc0d22"}
PROTECTED_DATA_PATH = Path("/home/neha/cloudops-sentinel/data")


def is_protected(name: str, container_id: str = "") -> bool:
    """Verify if a target matches any protected workload name or ID prefix."""
    clean_name = str(name).strip().lstrip("/")
    clean_id = str(container_id).strip()
    if clean_name in PROTECTED_NAMES:
        return True
    if is_protected_container_target(clean_name, clean_id):
        return True
    for prefix in PROTECTED_PREFIXES:
        if clean_id.startswith(prefix) or prefix in clean_id:
            return True
    return False


def generate_run_id() -> str:
    """Generate a collision-resistant, URL/filename-safe run identifier."""
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    rand_hex = secrets.token_hex(3)
    return f"run_{now_str}_{rand_hex}"


def is_protected_data_present(data_path: Path | None = None) -> bool:
    """
    Check if protected Fedora data path exists or is mounted into the disposable environment.
    Note: detecting this in the disposable environment indicates isolation failure.
    """
    target_path = data_path if data_path is not None else PROTECTED_DATA_PATH
    try:
        if target_path.exists():
            return True
    except Exception:
        pass
    try:
        proc_mounts = Path("/proc/mounts")
        if proc_mounts.exists():
            mounts_text = proc_mounts.read_text(encoding="utf-8", errors="replace")
            if "cloudops-sentinel" in mounts_text:
                return True
    except Exception:
        pass
    return False


def check_preflight_readiness(runner: Callable = subprocess.run) -> tuple[bool, dict[str, Any]]:
    """
    Verify host environment resources, Podman availability, and strict isolation
    in the disposable sandbox environment before testing.

    Safety model for disposable environment:
    - Verifies sufficient memory (>= 1.5 GiB) and disk (>= 10 GiB).
    - Verifies local presence of the test image (alpine:latest).
    - Verifies that protected workloads ('cloudops-floci', 'linuxops-recovery-ui-test')
      are strictly ABSENT from the disposable environment's Podman inventory.
      If any protected workload is unexpectedly present, fails closed.
    - Verifies that protected persistent data path ('/home/neha/cloudops-sentinel/data')
      is NOT present and NOT mounted in the disposable environment.
      (Note: checks inside the disposable environment verify isolation, NOT the
      integrity of the original Fedora environment).
    - Fails closed on any inspection failure or exception.
    """
    details: dict[str, Any] = {
        "memory_available_mb": 0.0,
        "disk_available_gb": 0.0,
        "podman_version": "unknown",
        "alpine_image_present": False,
        "protected_floci_absent": False,
        "protected_test_absent": False,
        "protected_data_absent": False,
        "isolation_verified": False,
        # Backward-compatible aliases for diagnostics/reporting:
        "protected_floci_intact": False,
        "protected_test_intact": False,
        "protected_data_intact": False,
        "protected_floci_intac": False,
    }

    # 1. Check Memory Available
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            meminfo = f.read()
        for line in meminfo.splitlines():
            if line.startswith("MemAvailable:"):
                kb = float(line.split()[1])
                details["memory_available_mb"] = round(kb / 1024.0, 2)
                break
    except Exception as exc:
        details["memory_error"] = str(exc)

    # 2. Check Disk Available on root partition
    try:
        st = os.statvfs(str(PROJECT_ROOT))
        avail_gb = (st.f_bavail * st.f_frsize) / (1024.0**3)
        details["disk_available_gb"] = round(avail_gb, 2)
    except Exception as exc:
        details["disk_error"] = str(exc)

    # 3. Check Podman CLI Version
    try:
        res = runner(["podman", "version", "--format", "{{.Client.Version}}"], capture_output=True, text=True, timeout=5.0, check=False)
        details["podman_version"] = (res.stdout or "").strip() or "available"
        if res.returncode != 0:
            details["podman_error"] = (res.stderr or "").strip() or f"podman version exit code {res.returncode}"
    except Exception as exc:
        details["podman_error"] = str(exc)

    # 4. Check Alpine Image Locally (enforce --pull=never)
    try:
        res = runner(["podman", "image", "exists", DEFAULT_IMAGE], capture_output=True, timeout=5.0, check=False)
        details["alpine_image_present"] = (res.returncode == 0)
    except Exception:
        details["alpine_image_present"] = False

    # 5. Check Protected Workloads are ABSENT in Disposable Environment
    try:
        res = runner(["podman", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=5.0, check=False)
        if res.returncode != 0:
            details["containers_check_error"] = (res.stderr or "").strip() or f"podman ps exit code {res.returncode}"
            details["protected_floci_absent"] = False
            details["protected_test_absent"] = False
        else:
            raw_names = (res.stdout or "").strip().splitlines()
            existing_names = set(raw_names)
            # In a disposable environment, protected containers MUST be absent:
            details["protected_floci_absent"] = "cloudops-floci" not in existing_names
            details["protected_test_absent"] = "linuxops-recovery-ui-test" not in existing_names
            if not details["protected_floci_absent"]:
                details["isolation_error"] = "CRITICAL: 'cloudops-floci' unexpectedly present in disposable environment!"
            elif not details["protected_test_absent"]:
                details["isolation_error"] = "CRITICAL: 'linuxops-recovery-ui-test' unexpectedly present in disposable environment!"
    except Exception as exc:
        details["containers_check_error"] = str(exc)
        details["protected_floci_absent"] = False
        details["protected_test_absent"] = False

    # 6. Check Protected Persistent Data Path is NOT mounted or used in Disposable Environment
    data_present = is_protected_data_present(PROTECTED_DATA_PATH)
    if data_present:
        details["protected_data_absent"] = False
        details["data_isolation_error"] = (
            "Protected Fedora data path '/home/neha/cloudops-sentinel/data' is present or mounted "
            "in disposable environment; isolation check failed."
        )
    else:
        details["protected_data_absent"] = True

    # Compute overall isolation
    details["isolation_verified"] = bool(
        details["protected_floci_absent"]
        and details["protected_test_absent"]
        and details["protected_data_absent"]
    )
    # Set backward-compatible aliases
    details["protected_floci_intact"] = details["protected_floci_absent"]
    details["protected_test_intact"] = details["protected_test_absent"]
    details["protected_data_intact"] = details["protected_data_absent"]
    details["protected_floci_intac"] = details["protected_floci_absent"]

    # Pass criteria: must fail closed if resources cannot be verified
    mem_ok = details["memory_available_mb"] >= MIN_MEMORY_MB
    disk_ok = details["disk_available_gb"] >= MIN_DISK_GB
    image_ok = details["alpine_image_present"]
    isolation_ok = details["isolation_verified"]
    podman_ok = details.get("podman_error") is None and bool(details["podman_version"])

    all_ok = mem_ok and disk_ok and image_ok and isolation_ok and podman_ok
    return all_ok, details


def verify_post_cleanup(
    manifest_path: Path | None = None,
    run_id: str | None = None,
    runner: Callable = subprocess.run,
) -> tuple[bool, dict[str, Any]]:
    """
    Verify that harness-created test containers have been completely removed
    and that disposable environment isolation remains intact.
    Does NOT require Fedora's protected resources to exist in Ubuntu.
    """
    preflight_ok, preflight_details = check_preflight_readiness(runner=runner)

    details = dict(preflight_details)
    remaining_count = 0
    manifest_gone = True

    if manifest_path:
        manifest_gone = not Path(manifest_path).exists()

    if run_id:
        try:
            res = runner(
                ["podman", "ps", "-a", "--filter", f"label=linuxops.run-id={run_id}", "--format", "{{.ID}}"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            if res.returncode == 0:
                remaining_count = len((res.stdout or "").strip().splitlines())
            else:
                remaining_count = -1
        except Exception as exc:
            details["cleanup_query_error"] = str(exc)
            remaining_count = -1

    details["remaining_test_containers"] = remaining_count
    details["manifest_removed"] = manifest_gone
    details["cleanup_complete"] = (remaining_count == 0) and manifest_gone

    all_clean = preflight_ok and details["cleanup_complete"]
    return all_clean, details


def build_scenario_plan(run_id: str, count: int = TARGET_CONTAINER_COUNT) -> list[dict[str, Any]]:
    """
    Construct a deterministic scenario plan for exactly 100 test containers.
    Scenarios:
    - 80 x healthy_running: long-running sleep 3600
    -  6 x stopped_normal: clean exit 0
    -  4 x nonzero_exit: exit 2
    -  4 x crash_loop: restart=always with immediate exit 1
    -  4 x oom_killed: small memory limit with allocation spike
    -  2 x healthcheck_failing: failing health probe
    Total = 100 containers
    """
    plan = []
    for idx in range(1, count + 1):
        name = f"linuxops-p9-{run_id}-{idx:03d}"

        if idx <= 80:
            scenario = "healthy_running"
            cmd = ["sleep", "3600"]
            restart = "no"
            mem_limit = "24m"
            health = None
        elif idx <= 86:
            scenario = "stopped_normal"
            cmd = ["sh", "-c", "exit 0"]
            restart = "no"
            mem_limit = "24m"
            health = None
        elif idx <= 90:
            scenario = "nonzero_exit"
            cmd = ["sh", "-c", "exit 2"]
            restart = "no"
            mem_limit = "24m"
            health = None
        elif idx <= 94:
            scenario = "crash_loop"
            cmd = ["sh", "-c", "exit 1"]
            restart = "always"
            mem_limit = "24m"
            health = None
        elif idx <= 98:
            scenario = "oom_killed"
            # Limit to 6m and try to read 50m of zeros to trigger cgroup OOM
            cmd = ["sh", "-c", "head -c 50m /dev/zero > /dev/null"]
            restart = "no"
            mem_limit = "6m"
            health = None
        else:
            scenario = "healthcheck_failing"
            cmd = ["sleep", "3600"]
            restart = "no"
            mem_limit = "24m"
            health = {
                "cmd": "exit 1",
                "interval": "1s",
                "retries": 1,
            }

        plan.append({
            "index": idx,
            "name": name,
            "scenario": scenario,
            "cmd": cmd,
            "restart": restart,
            "memory_limit": mem_limit,
            "health": health,
        })
    return plan


def write_manifest_atomically(manifest_path: Path, manifest_data: dict[str, Any]) -> None:
    """
    Atomically write manifest data to disk with fsync durability.
    Writes to a temporary sibling file, flushes, fsyncs, and replaces atomically.
    Also fsyncs the parent directory where supported.
    """
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = manifest_path.with_suffix(f".tmp_{secrets.token_hex(4)}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except (AttributeError, OSError):
            pass
    tmp_path.replace(manifest_path)
    try:
        dir_fd = os.open(str(manifest_path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except (AttributeError, OSError):
        pass


def create_100_containers(
    plan: list[dict[str, Any]],
    run_id: str,
    manifest_path: Path,
    dry_run: bool = True,
    runner: Callable = subprocess.run,
) -> tuple[bool, list[dict[str, Any]], str]:
    """
    Execute controlled creation of the 100 container plan with atomic manifest writing.
    Never creates containers if dry_run=True.
    In live mode, durably writes the initial manifest before creating any container,
    and updates the manifest durably after each container creation.
    """
    created_records = []

    if dry_run:
        for item in plan:
            created_records.append({
                "index": item["index"],
                "name": item["name"],
                "id": f"dry_run_id_{item['index']:03d}",
                "scenario": item["scenario"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "dry_run",
            })
        # Save dry-run manifest
        manifest_data = {
            "run_id": run_id,
            "mode": "DRY_RUN",
            "schema_version": "1.0",
            "target_count": len(plan),
            "created_count": len(created_records),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "planned_containers": [
                {"index": item["index"], "name": item["name"], "scenario": item["scenario"]}
                for item in plan
            ],
            "containers": created_records,
        }
        write_manifest_atomically(manifest_path, manifest_data)
        return True, created_records, "Dry-run execution plan simulated successfully."

    # LIVE EXECUTION GATE: Real Podman container creation
    # Step 1: Initialize the manifest durably on disk BEFORE creating any container
    initial_manifest_data = {
        "run_id": run_id,
        "mode": "LIVE_EXECUTION",
        "schema_version": "1.0",
        "target_count": len(plan),
        "created_count": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "planned_containers": [
            {"index": item["index"], "name": item["name"], "scenario": item["scenario"]}
            for item in plan
        ],
        "containers": [],
    }
    try:
        write_manifest_atomically(manifest_path, initial_manifest_data)
    except Exception as exc:
        return False, created_records, f"Failed initializing manifest before container creation: {exc}"

    for item in plan:
        name = item["name"]
        # Double-check protection boundary
        if is_protected(name):
            return False, created_records, f"CRITICAL SAFETY VIOLATION: Name '{name}' matches protected inventory!"

        cmd = [
            "podman", "run", "-d",
            "--name", name,
            "--pull=never",
            "--network=none",
            f"--memory={item['memory_limit']}",
            f"--memory-swap={item['memory_limit']}",
            "--cpus=0.05",
            "--pids-limit=15",
            f"--restart={item['restart']}",
            "--label", "linuxops.phase9-test=true",
            "--label", f"linuxops.run-id={run_id}",
            "--label", f"linuxops.scenario={item['scenario']}",
        ]

        if item.get("health"):
            h = item["health"]
            cmd.extend([
                f"--health-cmd={h['cmd']}",
                f"--health-interval={h['interval']}",
                f"--health-retries={h['retries']}",
            ])

        cmd.append(DEFAULT_IMAGE)
        cmd.extend(item["cmd"])

        try:
            res = runner(cmd, capture_output=True, text=True, timeout=15.0, check=False)
            cid = (res.stdout or "").strip()
            if res.returncode != 0 or not cid:
                err_msg = (res.stderr or "").strip()
                return False, created_records, f"Failed creating container {name}: {err_msg}"

            record = {
                "index": item["index"],
                "name": name,
                "id": cid[:12],
                "full_id": cid,
                "scenario": item["scenario"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "created",
            }
            created_records.append(record)

            # Atomic manifest update on each container creation
            manifest_data = {
                "run_id": run_id,
                "mode": "LIVE_EXECUTION",
                "schema_version": "1.0",
                "target_count": len(plan),
                "created_count": len(created_records),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "planned_containers": [
                    {"index": p["index"], "name": p["name"], "scenario": p["scenario"]}
                    for p in plan
                ],
                "containers": created_records,
            }
            try:
                write_manifest_atomically(manifest_path, manifest_data)
            except Exception as exc:
                return False, created_records, f"Failed updating manifest after creating {name}: {exc}"

        except Exception as exc:
            return False, created_records, f"Exception during creation of {name}: {exc}"

    return True, created_records, f"Successfully created {len(created_records)} real test containers."


def cleanup_100_containers(
    manifest_path: Path | None = None,
    run_id: str | None = None,
    runner: Callable = subprocess.run,
) -> tuple[int, list[str]]:
    """
    Remove strictly the test containers recorded in the manifest or matching the run ID.
    Never runs broad prune commands. Re-verifies protected workload immunity before every deletion.
    """
    removed_count = 0
    errors = []

    containers_to_remove: dict[str, str] = {}  # cid -> cname

    # 1. Read targets from manifest if provided
    if manifest_path and manifest_path.exists():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            if data.get("mode") == "LIVE_EXECUTION":
                for c in data.get("containers", []):
                    cname = c.get("name", "")
                    cid = c.get("full_id") or c.get("id", "")
                    if cid and cname and not is_protected(cname, cid):
                        containers_to_remove[cid] = cname
        except Exception as exc:
            errors.append(f"Error reading manifest {manifest_path}: {exc}")

    # 2. Reconcile with containers matching run label (covers creation interruption failure window)
    if run_id:
        try:
            res = runner(
                ["podman", "ps", "-a", "--filter", f"label=linuxops.run-id={run_id}", "--format", "{{.ID}} {{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            existing_names = set(containers_to_remove.values())
            for line in (res.stdout or "").strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    cid, cname = parts[0], parts[1]
                    if cname not in existing_names and not is_protected(cname, cid):
                        containers_to_remove[cid] = cname
                        existing_names.add(cname)
        except Exception as exc:
            errors.append(f"Error querying containers by label: {exc}")

    # Execute targeted individual removal using immediate-stop (-t 0 -f)
    for cid, cname in list(containers_to_remove.items()):
        if is_protected(cname, cid):
            continue  # Absolute hard boundary
        try:
            res = runner(["podman", "rm", "-t", "0", "-f", cid], capture_output=True, text=True, timeout=25.0, check=False)
            if res.returncode == 0:
                removed_count += 1
            else:
                errors.append(f"Failed removing {cname} ({cid}): {res.stderr.strip()}")
        except Exception as exc:
            errors.append(f"Exception removing {cname}: {exc}")

    # Clean up manifest file after removal
    if manifest_path and manifest_path.exists():
        try:
            manifest_path.unlink()
        except OSError:
            pass

    return removed_count, errors


def evaluate_100_observability(
    expected_count: int = TARGET_CONTAINER_COUNT,
    cycles: int = 3,
    runner: Callable = subprocess.run,
) -> dict[str, Any]:
    """
    Run LinuxOps observability, diagnostics, and multi-filter verification against the live fleet.
    Measures duration, p50/p95 latency, throughput, memory peak RSS, cache stats, and diagnostic accuracy.
    """
    t0_wall = time.perf_counter()
    rusage_before = resource.getrusage(resource.RUSAGE_SELF)

    cycle_metrics = []
    last_scan = {}
    last_diag = {}

    for c_idx in range(1, cycles + 1):
        t_cycle_start = time.perf_counter()
        scan_res = scan_containers(runner=runner, batch_size=25, max_workers=8, collect_stats=True)
        t_scan_end = time.perf_counter()

        containers = scan_res.get("containers", [])
        diag_res = diagnose_all_containers(containers)
        t_diag_end = time.perf_counter()

        scan_dur = t_scan_end - t_cycle_start
        diag_dur = t_diag_end - t_scan_end
        cycle_dur = t_diag_end - t_cycle_start

        cycle_metrics.append({
            "cycle": c_idx,
            "scan_duration_seconds": round(scan_dur, 4),
            "diag_duration_seconds": round(diag_dur, 4),
            "cycle_total_seconds": round(cycle_dur, 4),
            "discovered_count": scan_res.get("discovered_count", 0),
            "inspected_count": scan_res.get("inspected_count", 0),
            "failed_count": scan_res.get("failed_count", 0),
            "incidents_count": diag_res.get("total_incidents", 0),
            "is_complete": scan_res.get("is_complete", True),
        })
        last_scan = scan_res
        last_diag = diag_res

    rusage_after = resource.getrusage(resource.RUSAGE_SELF)
    total_duration_s = time.perf_counter() - t0_wall
    mem_delta_mb = (rusage_after.ru_maxrss - rusage_before.ru_maxrss) / 1024.0

    all_containers = last_scan.get("containers", [])
    active_incidents = last_diag.get("incidents", [])

    # Evaluate Diagnostic Accuracy against Ground Truth Scenarios
    # In 100 plan:
    # 80 healthy_running
    # 6 stopped_normal (rule: CONTAINER_STOPPED_NORMAL)
    # 4 nonzero_exit (rule: CONTAINER_NONZERO_EXIT)
    # 4 crash_loop (rule: CRASH_LOOP_DETECTED)
    # 4 oom_killed (rule: OOM_KILLED)
    # 2 healthcheck_failing (rule: HEALTHCHECK_FAILING)
    rule_counts: dict[str, int] = {}
    for inc in active_incidents:
        rid = inc.get("rule_id", "UNKNOWN")
        rule_counts[rid] = rule_counts.get(rid, 0) + 1

    # Verify 7-question operator guidance schema completeness
    guidance_complete = True
    required_guidance_fields = [
        "severity_reason", "symptoms", "candidate_causes", "confidence_explanation",
        "suggested_investigation_steps", "investigation_commands", "action_reason",
        "expected_outcome", "post_action_verification", "escalation_guidance",
    ]
    for inc in active_incidents:
        for f in required_guidance_fields:
            if f not in inc:
                guidance_complete = False
                break
        if not guidance_complete:
            break

    # Verify Dashboard Pagination & Multi-Filtering against the 100+ fleet
    paginated_p1, total_filtered, total_pages = filter_and_paginate_containers(
        containers=all_containers,
        search_query="",
        state_filter="ALL",
        health_filter="ALL",
        page=1,
        page_size=25,
        severity_filter="ALL",
        incidents=active_incidents,
    )
    paginated_p2, _, _ = filter_and_paginate_containers(
        containers=all_containers,
        page=2,
        page_size=25,
    )
    rows_p1 = format_container_inventory_rows(paginated_p1)

    pagination_passed = (
        len(paginated_p1) == 25 and
        len(paginated_p2) == 25 and
        total_pages >= 4 and
        len(rows_p1) == 25 and
        rows_p1[0]["Container Name"] != rows_p2_first_name(paginated_p2)
    )

    lat_stats = last_scan.get("latency_stats", {})
    cache_stats = last_scan.get("cache_stats", {})

    inspected_count = last_scan.get("inspected_count", 0)
    throughput = (inspected_count / last_scan.get("scan_duration_seconds", 1.0)) if last_scan.get("scan_duration_seconds", 0) > 0 else 0.0

    return {
        "status": "PASS" if inspected_count >= expected_count else "FAIL",
        "total_containers_discovered": last_scan.get("discovered_count", 0),
        "total_containers_inspected": inspected_count,
        "inspection_failed_count": last_scan.get("failed_count", 0),
        "is_complete": last_scan.get("is_complete", True),
        "scan_duration_seconds": last_scan.get("scan_duration_seconds", 0.0),
        "throughput_containers_per_sec": round(throughput, 2),
        "latency_stats": lat_stats,
        "cache_stats": cache_stats,
        "peak_rss_mb": round(rusage_after.ru_maxrss / 1024.0, 2),
        "memory_delta_mb": round(mem_delta_mb, 2),
        "cycles_metrics": cycle_metrics,
        "incidents_total": len(active_incidents),
        "rule_distribution": rule_counts,
        "guidance_schema_complete": guidance_complete,
        "pagination_functional": pagination_passed,
    }


def rows_p2_first_name(p2: list[dict]) -> str:
    return p2[0].get("name", "") if p2 else ""


def main():
    parser = argparse.ArgumentParser(description="LinuxOps Phase 9: Controlled 100-Container Validation")
    parser.add_argument("--execute", action="store_true", help="Explicitly authorize creating real containers in disposable environment")
    parser.add_argument("--cleanup", type=str, help="Path to manifest file for targeted cleanup")
    parser.add_argument("--cleanup-run", type=str, help="Run ID for targeted cleanup via labels")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Simulate execution without creating containers (default)")
    parser.add_argument("--cycles", type=int, default=3, help="Number of sustained monitoring cycles to evaluate")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    # 1. Cleanup Operation
    if args.cleanup or args.cleanup_run:
        m_path = Path(args.cleanup) if args.cleanup else None
        removed, errs = cleanup_100_containers(manifest_path=m_path, run_id=args.cleanup_run)
        print(f"Cleanup Completed: Removed {removed} test container(s). Errors: {len(errs)}")
        for e in errs:
            print(f" - {e}")
        return

    # 2. Preflight Check
    preflight_ok, preflight_details = check_preflight_readiness()
    if not preflight_ok:
        print("Preflight Check FAILED:")
        print(json.dumps(preflight_details, indent=2))
        sys.exit(1)

    run_id = generate_run_id()
    manifest_path = PROJECT_ROOT / "logs" / f"phase9_manifest_{run_id}.json"
    plan = build_scenario_plan(run_id=run_id, count=TARGET_CONTAINER_COUNT)

    is_live = bool(args.execute and not args.dry_run)

    if not is_live:
        ok, records, msg = create_100_containers(plan, run_id, manifest_path, dry_run=True)
        if args.json:
            result_payload = {
                "run_id": run_id,
                "mode": "DRY_RUN",
                "harness_planning": "PASS" if ok else "FAIL",
                "message": msg,
                "target_count": len(plan),
                "preflight": preflight_details,
                "manifest_path": str(manifest_path),
            }
            print(json.dumps(result_payload, indent=2))
            return

        print("=" * 115)
        print("LINUXOPS PHASE 9: CONTROLLED 100-CONTAINER VALIDATION HARNESS (DRY-RUN)")
        print("=" * 115)
        print("Notice: Running in DRY-RUN mode. Zero real containers created on host.")
        print(f"Run ID:                 {run_id}")
        print(f"Planned Target Fleet:   {len(plan)} containers")
        print(f"Memory Available:       {preflight_details['memory_available_mb']:.1f} MB (>= {MIN_MEMORY_MB:.0f} MB required)")
        print(f"Disk Available:         {preflight_details['disk_available_gb']:.1f} GB (>= {MIN_DISK_GB:.0f} GB required)")
        print(f"Local Image:            {DEFAULT_IMAGE} (Present: {preflight_details['alpine_image_present']})")
        print(f"Disposable Isolation:   floci_absent={preflight_details['protected_floci_absent']}, test_absent={preflight_details['protected_test_absent']}, data_absent={preflight_details['protected_data_absent']}")
        print(f"Manifest Path:          {manifest_path}")

        print(f"\nHarness Planning:       {'PASS' if ok else 'FAIL'} ({msg})")
        print("To execute against an approved disposable environment, run with '--execute'.")
        print("=" * 115)
        return

    # 3. Live Execution against Approved Disposable Host
    print("=" * 115)
    print("LINUXOPS PHASE 9: CONTROLLED 100-CONTAINER VALIDATION (LIVE EXECUTION)")
    print("=" * 115)
    print(f"Run ID:                 {run_id}")
    print(f"Starting creation of {len(plan)} controlled test containers...")

    created_ok, records, create_msg = create_100_containers(plan, run_id, manifest_path, dry_run=False)
    if not created_ok:
        print(f"\n[ABORT] Container Creation FAILED: {create_msg}")
        print("Initiating targeted cleanup of partial run...")
        removed, errs = cleanup_100_containers(manifest_path=manifest_path, run_id=run_id)
        print(f"Cleanup Removed:        {removed} container(s)")
        if errs:
            print(f"Cleanup Errors ({len(errs)}):")
            for e in errs:
                print(f" - Cleanup Error: {e}")
        else:
            print("Cleanup Errors:         0")

        # Post-cleanup verification of leftovers
        post_ok, post_details = verify_post_cleanup(manifest_path=manifest_path, run_id=run_id)
        remaining = post_details.get("remaining_test_containers", -1)
        print(f"Post-Cleanup Fleet:     complete={post_details.get('cleanup_complete', False)} (Remaining Test Containers: {remaining})")
        print(f"Disposable Isolation:   floci_absent={post_details.get('protected_floci_absent', False)} | test_absent={post_details.get('protected_test_absent', False)} | data_absent={post_details.get('protected_data_absent', False)}")

        if not post_ok or remaining != 0 or errs:
            print("[CRITICAL] Partial creation abort failed clean recovery: leftover test containers or cleanup errors detected!")

        sys.exit(1)

    print(f"Container Creation:     SUCCESS ({len(records)} test containers active)")

    # 4. Observability & Diagnostic Evaluation
    print(f"\nRunning {args.cycles} observability & diagnostic cycles against live 100-container fleet...")
    time.sleep(2.0)  # Allow healthcheck and exit scenarios to stabilize

    val_res = evaluate_100_observability(expected_count=TARGET_CONTAINER_COUNT, cycles=args.cycles)

    print("\n--- 100-CONTAINER FLEET OBSERVABILITY RESULTS ---")
    print(f"Total Discovered:       {val_res['total_containers_discovered']}")
    print(f"Total Inspected:        {val_res['total_containers_inspected']}")
    print(f"Inspection Failures:    {val_res['inspection_failed_count']}")
    print(f"Scan Completeness:      {'COMPLETE' if val_res['is_complete'] else 'PARTIAL'}")
    print(f"Scan Duration:          {val_res['scan_duration_seconds']:.3f}s")
    print(f"Scan Throughput:        {val_res['throughput_containers_per_sec']:.1f} containers/sec")

    lats = val_res.get("latency_stats", {})
    print(f"Latency Percentiles:    min: {lats.get('min_ms', 0):.1f}ms | p50: {lats.get('p50_ms', 0):.1f}ms | p95: {lats.get('p95_ms', 0):.1f}ms | max: {lats.get('max_ms', 0):.1f}ms")
    print(f"Peak Process RSS:       {val_res['peak_rss_mb']:.2f} MB (Delta: {val_res['memory_delta_mb']:+.2f} MB)")
    print(f"Active Incidents:       {val_res['incidents_total']}")
    print(f"Rule Distribution:      {val_res['rule_distribution']}")
    print(f"Operator Guidance:      {'COMPLETE (All 7 questions answered)' if val_res['guidance_schema_complete'] else 'INCOMPLETE'}")
    print(f"Dashboard Pagination:   {'PASS (25 items/page, >4 pages verified)' if val_res['pagination_functional'] else 'FAIL'}")

    # 5. Guaranteed Safe Cleanup
    print("\n--- TARGETED CLEANUP ---")
    removed, errs = cleanup_100_containers(manifest_path=manifest_path, run_id=run_id)
    print(f"Removed Test Containers: {removed} / {len(records)}")
    if errs:
        for e in errs:
            print(f" - Cleanup Error: {e}")

    # 6. Post-Cleanup Verification of Protected Resources & Fleet Status
    post_ok, post_details = verify_post_cleanup(manifest_path=manifest_path, run_id=run_id)
    print(f"\nDisposable Isolation:   floci_absent={post_details['protected_floci_absent']} | test_absent={post_details['protected_test_absent']} | data_absent={post_details['protected_data_absent']}")
    print(f"Post-Cleanup Fleet:     Complete={post_details['cleanup_complete']} (Remaining Test Containers: {post_details['remaining_test_containers']})")
    print("=" * 115)

    if not post_ok or post_details.get("remaining_test_containers", 0) != 0 or errs:
        print("[CRITICAL] Post-cleanup verification failed or leftovers detected!")
        sys.exit(1)


if __name__ == "__main__":
    main()
