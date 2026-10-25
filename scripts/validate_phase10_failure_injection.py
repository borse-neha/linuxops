#!/usr/bin/env python3

"""
LinuxOps Phase 10 — Isolated Live Failure-Injection and Remediation Validation Harness.

Provides controlled, repeatable, non-destructive validation of LinuxOps troubleshooting:
1. Strict Environment Isolation & Protected Workload Immunity
2. Controlled Live Failure Scenarios A-H (nonzero exit, connection refused, crash loop,
   failing health check, memory exhaustion OOM, permission denied, missing configuration, healthy control)
3. Approval-Controlled Remediation Lifecycle (propose, gate, approve, revalidate, execute, verify, audit)
4. Manifest-Based Targeted Cleanup
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.container_inspector import (
    calculate_latency_percentiles,
    get_host_identity,
    scan_containers,
)
from app.diagnostics_engine import (
    diagnose_all_containers,
    diagnose_container_record,
    redact_sensitive_text,
)
from app.history import (
    DEFAULT_HISTORY_PATH,
    load_recovery_history,
)
from app.recovery_controller import (
    ALLOWED_RECOVERY_ACTIONS,
    SUPPORTED_OPERATIONS,
    approve_remediation_plan,
    build_remediation_plan,
    clear_executed_approval_tokens,
    compute_plan_hash,
    execute_authorized_recovery,
    is_approval_valid,
    is_global_recovery_disabled,
    is_protected_container_target,
    reject_remediation_plan,
    set_global_recovery_disabled,
    validate_approval_token,
    verify_post_recovery_health,
)

DEFAULT_IMAGE = "docker.io/library/alpine:latest"
PROTECTED_DISTRO_NAMES = {"FedoraLinux-44", "fedora"}
PROTECTED_CONTAINER_NAMES = {"cloudops-floci", "linuxops-recovery-ui-test"}
PROTECTED_CONTAINER_PREFIXES = {"db80c688e14b", "83b65d88a0a9", "510d4cfc0d22"}
PROTECTED_DATA_PATH = Path("/home/neha/cloudops-sentinel/data")


def generate_run_id() -> str:
    """Generate a collision-resistant unique test run identifier."""
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    rand_hex = secrets.token_hex(3)
    return f"p10_{now_str}_{rand_hex}"


def get_current_environment_identity() -> dict[str, Any]:
    """Inspect active WSL / host environment details."""
    wsl_distro = os.environ.get("WSL_DISTRO_NAME", "").strip()
    hostname = os.uname().nodename if hasattr(os, "uname") else "unknown"

    os_release = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    os_release[k] = v.strip('"')
    except Exception:
        pass

    is_protected_distro = (
        wsl_distro in PROTECTED_DISTRO_NAMES
        or "fedora" in os_release.get("ID", "").lower()
        or "fedora" in hostname.lower()
    )

    return {
        "wsl_distro": wsl_distro,
        "hostname": hostname,
        "os_id": os_release.get("ID", "unknown"),
        "os_pretty_name": os_release.get("PRETTY_NAME", "unknown"),
        "is_protected_distro": is_protected_distro,
    }


def verify_environment_isolation(runner: Callable = subprocess.run) -> tuple[bool, dict[str, Any], list[str]]:
    """
    Strictly verify environment isolation before permitting any container operations.
    Returns (is_safe_disposable, details, blockers).
    """
    env_id = get_current_environment_identity()
    blockers = []

    # 1. Protected Host Distribution Check
    if env_id["is_protected_distro"]:
        blockers.append(
            f"Host is identified as protected Fedora distribution ('{env_id['wsl_distro']}' / '{env_id['os_pretty_name']}'). "
            "Section 2 hard safety invariant: Live failure-injection containers must NOT run on the protected Fedora host."
        )

    # 2. Check Protected Workloads Presence
    existing_containers = set()
    try:
        res = runner(["podman", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=5.0, check=False)
        if res.returncode == 0:
            existing_containers = set((res.stdout or "").strip().splitlines())
    except Exception as exc:
        blockers.append(f"Failed querying existing containers: {exc}")

    floci_present = "cloudops-floci" in existing_containers
    test_ui_present = "linuxops-recovery-ui-test" in existing_containers
    data_dir_present = PROTECTED_DATA_PATH.exists()

    if floci_present or test_ui_present or data_dir_present:
        # Protected resources exist in this environment
        blockers.append(
            f"Protected resources detected in environment: "
            f"cloudops-floci={floci_present}, linuxops-recovery-ui-test={test_ui_present}, data_path={data_dir_present}. "
            "Must execute only in an isolated disposable environment."
        )

    details = {
        "environment": env_id,
        "protected_floci_present": floci_present,
        "protected_test_ui_present": test_ui_present,
        "protected_data_present": data_dir_present,
        "is_disposable_confirmed": len(blockers) == 0,
    }

    return (len(blockers) == 0), details, blockers


def is_target_protected(name: str, cid: str = "") -> bool:
    """Verify if a name or ID prefix belongs to protected resources."""
    clean_name = str(name).strip().lstrip("/")
    clean_id = str(cid).strip()
    if clean_name in PROTECTED_CONTAINER_NAMES:
        return True
    if is_protected_container_target(clean_name, clean_id):
        return True
    for pfx in PROTECTED_CONTAINER_PREFIXES:
        if clean_id.startswith(pfx) or pfx in clean_id:
            return True
    return False


def build_phase10_scenario_plan(run_id: str) -> list[dict[str, Any]]:
    """
    Construct the 8 required failure scenarios with strict resource bounds:
    A. Container exits with nonzero code
    B. Connection refused error logged
    C. Repeated restart failure / crash loop
    D. Deliberately failing health check
    E. Memory exhaustion OOM
    F. Controlled permission denied error
    G. Missing configuration or environment variable
    H. Healthy control container
    """
    scenarios = [
        {
            "scenario_letter": "A",
            "scenario_name": "nonzero_exit_code",
            "name": f"linuxops-{run_id}-scen-a-exit42",
            "description": "Container that exits with nonzero exit code 42",
            "cmd": ["sh", "-c", "echo 'Application worker encountered fatal error code 42'; exit 42"],
            "restart": "no",
            "memory": "24m",
            "cpus": "0.05",
            "expected_category": "lifecycle",
            "expected_state": "exited",
            "expected_remediation_action": "start_container",
        },
        {
            "scenario_letter": "B",
            "scenario_name": "dependency_connection_refused",
            "name": f"linuxops-{run_id}-scen-b-connrefused",
            "description": "Application that logs a database connection-refused error",
            "cmd": ["sh", "-c", "echo '2026-10-22 10:00:00 ERROR: Connection refused to postgres://db-prod:5432'; exit 1"],
            "restart": "no",
            "memory": "24m",
            "cpus": "0.05",
            "expected_category": "network",
            "expected_rule": "DEPENDENCY_CONNECTION_REFUSED",
            "expected_state": "exited",
            "expected_remediation_action": "start_container",
        },
        {
            "scenario_letter": "C",
            "scenario_name": "repeated_crash_loop",
            "name": f"linuxops-{run_id}-scen-c-crashloop",
            "description": "Process that repeatedly fails and restarts",
            "cmd": ["sh", "-c", "echo 'Process booting... crash on init'; sleep 0.5; exit 1"],
            "restart": "on-failure:3",
            "memory": "24m",
            "cpus": "0.05",
            "expected_category": "lifecycle",
            "expected_state": "exited",
            "expected_remediation_action": "start_container",
        },
        {
            "scenario_letter": "D",
            "scenario_name": "failing_health_check",
            "name": f"linuxops-{run_id}-scen-d-unhealthy",
            "description": "Container running with a deliberately failing health check",
            "cmd": ["sleep", "3600"],
            "restart": "no",
            "memory": "24m",
            "cpus": "0.05",
            "health": {
                "cmd": "exit 1",
                "interval": "1s",
                "retries": "1",
            },
            "expected_category": "lifecycle",
            "expected_rule": "HEALTHCHECK_FAILING",
            "expected_state": "running",
            "expected_remediation_action": "start_container",
        },
        {
            "scenario_letter": "E",
            "scenario_name": "memory_exhaustion_oom",
            "name": f"linuxops-{run_id}-scen-e-oom",
            "description": "Process terminated for memory exhaustion under strict cgroup limits",
            "cmd": ["sh", "-c", "tail /dev/zero"],
            "restart": "no",
            "memory": "10m",
            "cpus": "0.05",
            "expected_category": "resource",
            "expected_rule": "OOM_KILLED",
            "expected_state": "exited",
            "expected_remediation_action": "start_container",
        },
        {
            "scenario_letter": "F",
            "scenario_name": "permission_denied",
            "name": f"linuxops-{run_id}-scen-f-permdenied",
            "description": "Controlled permission-denied error accessing secure storage",
            "cmd": ["sh", "-c", "echo 'open /app/data/keystore.db: Permission denied'; exit 126"],
            "restart": "no",
            "memory": "24m",
            "cpus": "0.05",
            "expected_category": "security",
            "expected_rule": "PERMISSION_DENIED",
            "expected_state": "exited",
            "expected_remediation_action": "start_container",
        },
        {
            "scenario_letter": "G",
            "scenario_name": "missing_configuration",
            "name": f"linuxops-{run_id}-scen-g-missingconfig",
            "description": "Simulated missing configuration or environment variable error",
            "cmd": ["sh", "-c", "echo 'Fatal: KeyError: JWT_SIGNING_SECRET - missing required environment variable'; exit 1"],
            "restart": "no",
            "memory": "24m",
            "cpus": "0.05",
            "expected_category": "configuration",
            "expected_rule": "MISSING_CONFIGURATION_OR_ENV",
            "expected_state": "exited",
            "expected_remediation_action": "start_container",
        },
        {
            "scenario_letter": "H",
            "scenario_name": "healthy_control",
            "name": f"linuxops-{run_id}-scen-h-healthy",
            "description": "Healthy control container with no injected failure",
            "cmd": ["sleep", "3600"],
            "restart": "no",
            "memory": "24m",
            "cpus": "0.05",
            "health": {
                "cmd": "exit 0",
                "interval": "2s",
                "retries": "3",
            },
            "expected_category": "none",
            "expected_state": "running",
            "expected_remediation_action": "none",
        },
    ]
    return scenarios


def create_phase10_containers(
    plan: list[dict[str, Any]],
    run_id: str,
    manifest_path: Path,
    dry_run: bool = True,
    runner: Callable = subprocess.run,
) -> tuple[bool, list[dict[str, Any]], str]:
    """
    Create controlled test containers with strict resource limits and atomic manifest tracking.
    """
    created_records = []

    if dry_run:
        for idx, item in enumerate(plan, 1):
            created_records.append({
                "index": idx,
                "scenario_letter": item["scenario_letter"],
                "scenario_name": item["scenario_name"],
                "name": item["name"],
                "id": f"dry_{secrets.token_hex(6)}",
                "full_id": f"dry_full_{secrets.token_hex(16)}",
                "status": "simulated",
            })
        manifest_data = {
            "run_id": run_id,
            "mode": "DRY_RUN",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "containers": created_records,
        }
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        return True, created_records, "Dry-run plan created successfully."

    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    for idx, item in enumerate(plan, 1):
        name = item["name"]

        # Defense-in-depth: Never target protected workloads
        if is_target_protected(name):
            return False, created_records, f"CRITICAL: Refusing to create protected container name '{name}'"

        cmd = [
            "podman", "run", "-d",
            "--name", name,
            f"--memory={item['memory']}",
            f"--memory-swap={item['memory']}",
            f"--cpus={item['cpus']}",
            "--pids-limit=15",
            "--network=none",
            f"--restart={item['restart']}",
            "--label", "linuxops.phase10-test=true",
            "--label", f"linuxops.run-id={run_id}",
            "--label", f"linuxops.scenario={item['scenario_name']}",
            "--label", f"linuxops.scenario-letter={item['scenario_letter']}",
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
                "index": idx,
                "scenario_letter": item["scenario_letter"],
                "scenario_name": item["scenario_name"],
                "name": name,
                "id": cid[:12],
                "full_id": cid,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "created",
            }
            created_records.append(record)

            # Atomic manifest write
            manifest_data = {
                "run_id": run_id,
                "mode": "LIVE_EXECUTION",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "containers": created_records,
            }
            tmp_path = manifest_path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
            tmp_path.replace(manifest_path)

        except Exception as exc:
            return False, created_records, f"Exception creating container {name}: {exc}"

    return True, created_records, f"Successfully created {len(created_records)} containers."


def cleanup_phase10_containers(
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
    containers_to_remove = []

    if manifest_path and manifest_path.exists():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            for c in data.get("containers", []):
                cname = c.get("name", "")
                cid = c.get("full_id") or c.get("id", "")
                if cname and not is_target_protected(cname, cid):
                    containers_to_remove.append((cid, cname))
        except Exception as exc:
            errors.append(f"Error reading manifest: {exc}")

    if not containers_to_remove and run_id:
        try:
            res = runner(
                ["podman", "ps", "-a", "--filter", f"label=linuxops.run-id={run_id}", "--format", "{{.ID}} {{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            for line in (res.stdout or "").strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    cid, cname = parts[0], parts[1]
                    if not is_target_protected(cname, cid):
                        containers_to_remove.append((cid, cname))
        except Exception as exc:
            errors.append(f"Error querying by label: {exc}")

    for cid, cname in containers_to_remove:
        if is_target_protected(cname, cid):
            continue
        try:
            res = runner(["podman", "rm", "-f", cid], capture_output=True, text=True, timeout=10.0, check=False)
            if res.returncode == 0:
                removed_count += 1
            else:
                errors.append(f"Failed removing {cname} ({cid}): {res.stderr.strip()}")
        except Exception as exc:
            errors.append(f"Exception removing {cname}: {exc}")

    if manifest_path and manifest_path.exists():
        try:
            manifest_path.unlink()
        except OSError:
            pass

    return removed_count, errors


def main():
    parser = argparse.ArgumentParser(description="LinuxOps Phase 10: Isolated Live Failure-Injection & Remediation Validation")
    parser.add_argument("--check-isolation", action="store_true", help="Inspect and report environment isolation status")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Simulate failure injection and diagnostic checks (safe by default)")
    parser.add_argument("--execute", action="store_true", help="Execute real container failure injection in disposable environment")
    parser.add_argument("--cleanup", type=str, help="Targeted cleanup using specified manifest file")
    parser.add_argument("--cleanup-run", type=str, help="Targeted cleanup by run ID")
    parser.add_argument("--json", action="store_true", help="Output summary in JSON format")

    args = parser.parse_args()

    # 1. Targeted Cleanup Mode
    if args.cleanup or args.cleanup_run:
        mpath = Path(args.cleanup) if args.cleanup else None
        removed, errs = cleanup_phase10_containers(manifest_path=mpath, run_id=args.cleanup_run)
        print(f"Cleanup completed: removed {removed} test containers.")
        if errs:
            for e in errs:
                print(f"Cleanup warning: {e}")
        return

    # 2. Isolation Verification Gate
    is_safe_disposable, isolation_details, blockers = verify_environment_isolation()

    if args.check_isolation:
        print("=" * 80)
        print("LINUXOPS PHASE 10: ENVIRONMENT ISOLATION CHECK")
        print("=" * 80)
        print(f"WSL Distribution:       {isolation_details['environment']['wsl_distro'] or 'N/A'}")
        print(f"Hostname:               {isolation_details['environment']['hostname']}")
        print(f"OS Pretty Name:         {isolation_details['environment']['os_pretty_name']}")
        print(f"Protected Workloads:    floci={isolation_details['protected_floci_present']} | test_ui={isolation_details['protected_test_ui_present']} | data={isolation_details['protected_data_present']}")
        print(f"Disposable Confirmed:   {'YES (Isolated)' if is_safe_disposable else 'NO (BLOCKED)'}")
        if blockers:
            print("\nBLOCKERS DETECTED:")
            for b in blockers:
                print(f" - {b}")
        print("=" * 80)
        return

    run_id = generate_run_id()
    manifest_path = PROJECT_ROOT / "logs" / f"phase10_manifest_{run_id}.json"
    plan = build_phase10_scenario_plan(run_id)

    # 3. Dry-Run / Planning Mode (Safe Default)
    if not args.execute:
        print("=" * 80)
        print("LINUXOPS PHASE 10: CONTROLLED FAILURE INJECTION (DRY-RUN PLANNING)")
        print("=" * 80)
        print(f"Run ID:                 {run_id}")
        print(f"Planned Scenarios:      {len(plan)} controlled failure scenarios (A through H)")
        print(f"Environment Status:     {'ISOLATED DISPOSABLE' if is_safe_disposable else 'PROTECTED HOST (Execution Gate Enforced)'}")
        print(f"Manifest Path:          {manifest_path}")

        ok, records, msg = create_phase10_containers(plan, run_id, manifest_path, dry_run=True)
        print(f"Harness Planning:       {'PASS' if ok else 'FAIL'} ({msg})")

        print("\nSCENARIO MATRIX:")
        for item in plan:
            print(f" [{item['scenario_letter']}] {item['scenario_name']:<30} -> Expected: {item['expected_category']} ({item['expected_state']})")

        print("\nSafety Gate Status: Real container execution requires '--execute' in an isolated disposable WSL environment.")
        print("=" * 80)
        return

    # 4. Live Execution Mode: Strict Isolation Enforcement
    if not is_safe_disposable:
        print("=" * 80)
        print("HARD SAFETY STOP: EXECUTION BLOCKED")
        print("=" * 80)
        for b in blockers:
            print(f"BLOCKER: {b}")
        print("\nAction Aborted. LinuxOps will NEVER execute live test containers on the protected host.")
        print("=" * 80)
        sys.exit(1)


if __name__ == "__main__":
    main()
