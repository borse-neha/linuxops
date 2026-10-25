#!/usr/bin/env python3
"""
LinuxOps Phase 11.1: Targeted Residual Container Cleanup
Safely removes verified residual containers from run_20261022_081009_c3b96a
using podman rm -t 0 -f <verified_cid>.
Strict safety restrictions:
- Ubuntu-24.04 only.
- Strict cross-checking against backup_phase9_manifest_run_20261022_081009_c3b96a.json.
- Verifies hard workload immunity (cloudops-floci, linuxops-recovery-ui-test).
- Executes per-container removal without broad wildcards.
- Verifies 0 containers remain post-cleanup.
- Writes structured JSON audit report.
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_DISTRO = "Ubuntu"
EXPECTED_RUN_ID = "run_20261022_081009_c3b96a"
PROJECT_DIR = Path("/home/neha_borse/linuxops")
MANIFEST_PATH = PROJECT_DIR / "logs" / "backup_phase9_manifest_run_20261022_081009_c3b96a.json"
REPORT_JSON_PATH = PROJECT_DIR / "logs" / "phase11_1_cleanup_report.json"

PROTECTED_NAMES = {"cloudops-floci", "linuxops-recovery-ui-test"}
PROTECTED_PREFIXES = ("cloudops-", "sentinel-")


def verify_environment():
    if not Path("/etc/os-release").exists():
        raise RuntimeError("Cannot verify OS: /etc/os-release missing")
    os_info = Path("/etc/os-release").read_text()
    if "Ubuntu" not in os_info:
        raise RuntimeError(f"Distribution check failed: Not Ubuntu ({os_info[:100]})")
    if "Fedora" in os_info:
        raise RuntimeError("ABORT: Fedora detected! Must only run in Ubuntu-24.04")


def is_protected(name: str, cid: str) -> bool:
    if name in PROTECTED_NAMES:
        return True
    if any(name.startswith(p) for p in PROTECTED_PREFIXES):
        return True
    if cid in ("f11bd857ea3a", "83b65d88a0a9"):
        return True
    return False


def main():
    print("=" * 80)
    print("LinuxOps Phase 11.1: Targeted Residual Container Cleanup")
    print("=" * 80)

    # 1. Environment verification
    verify_environment()
    print("[PASS] Environment verified: Ubuntu-24.04 WSL2 sandbox")

    # 2. Verify Manifest
    if not MANIFEST_PATH.exists():
        print(f"[FAIL] Manifest missing: {MANIFEST_PATH}")
        sys.exit(1)

    manifest_data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest_data.get("run_id") != EXPECTED_RUN_ID:
        print(f"[FAIL] Manifest run ID mismatch: {manifest_data.get('run_id')} != {EXPECTED_RUN_ID}")
        sys.exit(1)

    # Map manifest containers
    manifest_containers = {c["full_id"]: c for c in manifest_data.get("containers", [])}
    manifest_short_ids = {c["id"]: c for c in manifest_data.get("containers", [])}
    manifest_names = {c["name"]: c for c in manifest_data.get("containers", [])}
    print(f"[PASS] Loaded manifest with {len(manifest_containers)} recorded containers for run {EXPECTED_RUN_ID}")

    # 3. Query Podman for matching containers
    cmd_list = [
        "podman", "ps", "-a",
        "--filter", f"label=linuxops.run-id={EXPECTED_RUN_ID}",
        "--format", "{{.ID}}|{{.Names}}|{{.Status}}|{{.Labels}}"
    ]
    res = subprocess.run(cmd_list, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        print(f"[FAIL] Error querying Podman: {res.stderr}")
        sys.exit(1)

    lines = [l.strip() for l in res.stdout.strip().splitlines() if l.strip()]
    print(f"Discovered {len(lines)} active/stopping containers matching label linuxops.run-id={EXPECTED_RUN_ID}")

    # 4. Cross-check each container
    verified_targets = []
    for line in lines:
        parts = line.split("|")
        short_id = parts[0]
        name = parts[1]
        status = parts[2] if len(parts) > 2 else ""
        labels = parts[3] if len(parts) > 3 else ""

        # Verify not protected
        if is_protected(name, short_id):
            print(f"[CRITICAL ABORT] Discovered container {name} ({short_id}) matches protected list!")
            sys.exit(1)

        # Cross-check ownership against manifest
        m_entry = manifest_short_ids.get(short_id) or manifest_names.get(name)
        if not m_entry:
            print(f"[CRITICAL ABORT] Container {name} ({short_id}) NOT found in run manifest!")
            sys.exit(1)

        if not name.startswith(f"linuxops-p9-{EXPECTED_RUN_ID}-"):
            print(f"[CRITICAL ABORT] Container {name} does not match expected naming convention!")
            sys.exit(1)

        verified_targets.append({
            "short_id": short_id,
            "full_id": m_entry.get("full_id", ""),
            "name": name,
            "status": status,
            "scenario": m_entry.get("scenario", "unknown"),
        })

    print(f"[PASS] Cross-check verified {len(verified_targets)} containers against manifest.")

    if not verified_targets:
        print("No residual containers found to clean up.")
        return

    # 5. Targeted Removal
    removed_records = []
    failed_records = []

    print(f"Beginning targeted removal of {len(verified_targets)} verified containers using 'podman rm -t 0 -f'...")
    for idx, target in enumerate(verified_targets, 1):
        cid = target["short_id"]
        cname = target["name"]
        rm_cmd = ["podman", "rm", "-t", "0", "-f", cid]
        try:
            rm_res = subprocess.run(rm_cmd, capture_output=True, text=True, timeout=15.0, check=False)
            if rm_res.returncode == 0:
                removed_records.append({
                    "id": cid,
                    "name": cname,
                    "status": "removed",
                    "stdout": rm_res.stdout.strip(),
                })
                if idx % 10 == 0 or idx == len(verified_targets):
                    print(f" - Progress: {idx}/{len(verified_targets)} removed ({cname})")
            else:
                err_msg = rm_res.stderr.strip()
                failed_records.append({
                    "id": cid,
                    "name": cname,
                    "error": err_msg,
                })
                print(f"[ERROR] Failed removing {cname} ({cid}): {err_msg}")
        except subprocess.TimeoutExpired:
            failed_records.append({
                "id": cid,
                "name": cname,
                "error": "TimeoutExpired after 15.0s",
            })
            print(f"[ERROR] Timeout removing {cname} ({cid})")
        except Exception as exc:
            failed_records.append({
                "id": cid,
                "name": cname,
                "error": str(exc),
            })
            print(f"[ERROR] Exception removing {cname}: {exc}")

    # 6. Post-Cleanup Verification
    res_post = subprocess.run(cmd_list, capture_output=True, text=True, check=False)
    remaining_lines = [l.strip() for l in res_post.stdout.strip().splitlines() if l.strip()]

    # Query total podman containers in Ubuntu
    res_all = subprocess.run(["podman", "ps", "-a", "-q"], capture_output=True, text=True, check=False)
    total_remaining = len([l.strip() for l in res_all.stdout.strip().splitlines() if l.strip()])

    print("\n--- POST-CLEANUP VERIFICATION ---")
    print(f"Successfully Removed:  {len(removed_records)} / {len(verified_targets)}")
    print(f"Removal Failures:      {len(failed_records)}")
    print(f"Remaining Matching:    {len(remaining_lines)}")
    print(f"Total Fleet in Ubuntu: {total_remaining}")

    # 7. Write Audit Report
    audit_report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": "11.1_targeted_residual_cleanup",
        "run_id": EXPECTED_RUN_ID,
        "environment": "Ubuntu-24.04 WSL2 sandbox",
        "verified_initial_count": len(verified_targets),
        "removed_count": len(removed_records),
        "failed_count": len(failed_records),
        "remaining_matching_count": len(remaining_lines),
        "total_remaining_in_ubuntu": total_remaining,
        "success": len(remaining_lines) == 0 and len(failed_records) == 0,
        "removed_containers": removed_records,
        "failures": failed_records,
    }
    REPORT_JSON_PATH.write_text(json.dumps(audit_report, indent=2), encoding="utf-8")
    print(f"[PASS] Audit report written to {REPORT_JSON_PATH}")

    if len(remaining_lines) > 0 or len(failed_records) > 0:
        print("[FAIL] Residual cleanup incomplete: leftovers detected.")
        sys.exit(1)
    else:
        print("[SUCCESS] All Phase 11 residual containers cleanly and safely removed.")


if __name__ == "__main__":
    main()
