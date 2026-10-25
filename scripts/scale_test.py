#!/usr/bin/env python3

"""
LinuxOps Safe Scale-Test Harness (Phase 1, Step 1J).

Provides an auditable, isolated harness for preparing a future 10-container
LinuxOps scale test on Fedora Linux with rootless Podman.

CRITICAL ARCHITECTURAL SAFETY PRINCIPLES:
1. SAFE BY DEFAULT: Running this script without arguments executes in DRY-RUN mode.
   No containers are created, started, stopped, or removed. No manifests or logs are written.
2. EXPLICIT EXECUTION GATE: Real container creation requires the explicit '--execute' flag.
3. FIXED INITIAL COUNT: Creation is strictly restricted to exactly 10 containers.
   Any requested count other than 10 is rejected to prevent accidental scale-up.
   Enforced both at CLI boundary and internally inside execute_scale_creation().
4. NO-PULL LOCAL IMAGE POLICY: Container creation requires the local Alpine image to be
   already present locally and enforces '--pull=never'. Image acquisition must be approved
   separately.
5. STRICT IDENTITY ENFORCEMENT: Every container is assigned a unique name matching
   ^linuxops-test-<RUN_ID>-[0-9]{3}$ and tagged with 'linuxops.scale-test=true' and
   'linuxops.test-run-id=<RUN_ID>'.
6. FAIL-CLOSED PREFLIGHT: Prior to any creation, preflight checks verify host memory (>=1500 MiB),
   disk space (>=20 GiB), Podman responsiveness, image presence, protected container integrity
   (both exact names AND expected ID prefixes), and the absence of any conflicting or ambiguous test containers.
7. ATOMIC SYNCHRONOUS MANIFEST: Each created container is recorded in a run-specific manifest
   immediately upon creation via atomic file replacement before attempting the next container.
   Temporary files are safely cleaned up on failure without endangering existing manifests.
8. ISOLATED TARGETED CLEANUP: Cleanup is a separate explicit operation (--cleanup <manifest>)
   that validates manifest containment in logs/, checks schema, and validates each container's
   full ID, exact name, and labels via live inspect immediately before removal.
   Confirmed absent containers are treated idempotently on retries. Bulk deletion is strictly forbidden.
9. PROTECTED INVENTORY IMMUNITY: Pre-existing containers ('cloudops-floci', 'linuxops-recovery-ui-test')
   are permanently excluded from any creation or cleanup target set.

NOTE ON CONTAINER MEMORY LIMITS:
Configured container memory limits (--memory=32m, --memory-swap=32m) apply to the container's
cgroup runtime boundary. They DO NOT guarantee total host memory consumption. Additional host
resources are consumed by per-container conmon monitor processes (~3-5 MiB each), kernel page tables,
storage overlay mounts, and socket buffers.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
from typing import Any, Callable

# Target Scale Limits
EXACT_CONTAINER_COUNT = 10
MAX_CONTAINER_CAP = 10

# Resource Limits
DEFAULT_IMAGE = "docker.io/library/alpine:latest"
WORKLOAD_CMD = ["sleep", "3600"]
MEMORY_LIMIT = "32m"
MEMORY_SWAP_LIMIT = "32m"
CPU_LIMIT = "0.05"

# Required Labels
LABEL_SCALE_TEST = "linuxops.scale-test=true"
LABEL_RUN_ID_KEY = "linuxops.test-run-id"

# Preflight Thresholds
MIN_MEMORY_MB = 1500.0  # ~1.46 GiB
MIN_DISK_GB = 20.0      # 20 GiB

# Protected Workload Identity & Configuration Specifications
FLOCI_CONTAINER_NAME = "cloudops-floci"
FLOCI_EXPECTED_IMAGE = "docker.io/floci/floci:latest"
FLOCI_SYSTEMD_UNIT_LABEL = "cloudops-floci.service"
FLOCI_MOUNT_SOURCE = "/home/neha/cloudops-sentinel/data"
FLOCI_MOUNT_DESTINATION = "/app/data"

RECOVERY_UI_CONTAINER_NAME = "linuxops-recovery-ui-test"
RECOVERY_UI_EXPECTED_ID_PREFIX = "83b65d88a0a9"

# Protected Containers (Must never be altered or targeted)
PROTECTED_CONTAINERS: dict[str, str] = {
    FLOCI_CONTAINER_NAME: "510d4cfc0d22",
    RECOVERY_UI_CONTAINER_NAME: RECOVERY_UI_EXPECTED_ID_PREFIX,
}
PROTECTED_CONTAINER_NAMES: set[str] = {
    FLOCI_CONTAINER_NAME,
    RECOVERY_UI_CONTAINER_NAME,
}
PROTECTED_CONTAINER_ID_PREFIXES: set[str] = {
    "510d4cfc0d22",
    "db80c688e14b",
    RECOVERY_UI_EXPECTED_ID_PREFIX,
}
_DYNAMIC_PROTECTED_IDS: set[str] = set()


def register_protected_container_id(container_id: str) -> None:
    """Register a verified live container ID into the dynamic protected inventory."""
    clean_id = container_id.strip()
    if clean_id:
        _DYNAMIC_PROTECTED_IDS.add(clean_id)
        if len(clean_id) >= 12:
            _DYNAMIC_PROTECTED_IDS.add(clean_id[:12])


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST_DIR = PROJECT_ROOT / "logs"


def generate_run_id() -> str:
    """Generate a collision-resistant, URL/filename-safe run identifier."""
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    rand_hex = secrets.token_hex(4)
    return f"{now_str}_{rand_hex}"


def generate_container_names(run_id: str, count: int = EXACT_CONTAINER_COUNT) -> list[str]:
    """Generate deterministic container names following ^linuxops-test-<RUN_ID>-[0-9]{3}$."""
    return [f"linuxops-test-{run_id}-{idx:03d}" for idx in range(1, count + 1)]


def validate_container_name(name: str, run_id: str) -> bool:
    """Check whether a name matches the required regex pattern for the given run_id."""
    pattern = rf"^linuxops-test-{re.escape(run_id)}-[0-9]{{3}}$"
    return bool(re.match(pattern, name))


def is_test_container_name(name: str) -> bool:
    """Check if a container name carries the scale-test naming prefix."""
    return name.startswith("linuxops-test-")


def is_protected_container(name: str, container_id: str) -> bool:
    """Determine whether a container is a protected production or verification workload."""
    clean_name = name.strip().lstrip("/")
    clean_id = container_id.strip()
    if clean_name and clean_name in PROTECTED_CONTAINER_NAMES:
        return True
    if clean_id:
        for prefix in (PROTECTED_CONTAINER_ID_PREFIXES | _DYNAMIC_PROTECTED_IDS):
            if clean_id.startswith(prefix) or (len(clean_id) >= 12 and prefix.startswith(clean_id[:12])):
                return True
    return False


# ---------------------------------------------------------------------------
# Preflight & Subprocess Inspection Helpers
# ---------------------------------------------------------------------------

def check_podman_responsive(
    timeout: float = 5.0,
    runner: Callable = subprocess.run,
) -> tuple[bool, str, float]:
    """Verify that the Podman CLI is installed, responsive, and queryable."""
    start_time = time.monotonic()
    try:
        res = runner(
            ["podman", "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        elapsed = time.monotonic() - start_time
        version_str = res.stdout.strip()
        return True, version_str, elapsed
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        elapsed = time.monotonic() - start_time
        return False, f"Podman responsiveness check failed: {exc}", elapsed


def check_local_image_exists(
    image: str = DEFAULT_IMAGE,
    timeout: float = 5.0,
    runner: Callable = subprocess.run,
) -> tuple[bool, str]:
    """Verify that the requested container image is already stored locally without pulling."""
    try:
        res = runner(
            ["podman", "image", "exists", image],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if res.returncode == 0:
            return True, f"Image '{image}' is present in local Podman storage."
        return False, f"Image '{image}' is NOT present locally. Network image pulls are prohibited."
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return False, f"Image check error for '{image}': {exc}"


def check_system_resources(
    min_mem_mb: float = MIN_MEMORY_MB,
    min_disk_gb: float = MIN_DISK_GB,
    proc_meminfo_path: str = "/proc/meminfo",
    mount_path: str = "/",
) -> tuple[bool, dict[str, Any]]:
    """Verify host available memory and free disk space against safety thresholds."""
    available_mem_mb = 0.0
    try:
        with open(proc_meminfo_path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        available_mem_mb = float(parts[1]) / 1024.0
                    break
    except (OSError, ValueError):
        available_mem_mb = 0.0

    available_disk_gb = 0.0
    try:
        disk_usage = shutil.disk_usage(mount_path)
        available_disk_gb = disk_usage.free / (1024.0 ** 3)
    except (OSError, ValueError):
        available_disk_gb = 0.0

    mem_ok = available_mem_mb >= min_mem_mb
    disk_ok = available_disk_gb >= min_disk_gb
    passed = mem_ok and disk_ok

    details = {
        "passed": passed,
        "available_mem_mb": round(available_mem_mb, 2),
        "min_mem_mb": min_mem_mb,
        "mem_ok": mem_ok,
        "available_disk_gb": round(available_disk_gb, 2),
        "min_disk_gb": min_disk_gb,
        "disk_ok": disk_ok,
    }
    return passed, details


def get_existing_containers(
    timeout: float = 15.0,
    runner: Callable = subprocess.run,
) -> tuple[bool, list[dict[str, Any]], str]:
    """Retrieve full existing Podman container inventory."""
    try:
        res = runner(
            ["podman", "ps", "-a", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        raw = res.stdout.strip()
        if not raw:
            return True, [], ""
        data = json.loads(raw)
        if not isinstance(data, list):
            return False, [], "Unexpected podman ps output format (expected JSON list)."
        return True, data, ""
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        return False, [], f"Failed to list containers: {exc}"


def inspect_floci_container(
    container_id: str,
    runner: Callable = subprocess.run,
    timeout: float = 10.0,
) -> tuple[bool, dict[str, Any], str]:
    """
    Read-only podman inspect of cloudops-floci.
    Fails closed on timeouts, process errors, malformed JSON, or missing metadata.
    """
    try:
        res = runner(
            ["podman", "inspect", container_id],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        data = json.loads(res.stdout)
        if not isinstance(data, list) or not data or not isinstance(data[0], dict):
            return False, {}, "Malformed or incomplete inspect data for 'cloudops-floci'."
        return True, data[0], ""
    except subprocess.CalledProcessError as exc:
        err = (exc.stderr or "").strip()
        return False, {}, f"podman inspect failed (exit code {exc.returncode}): {err}"
    except subprocess.TimeoutExpired:
        return False, {}, "podman inspect timed out."
    except json.JSONDecodeError as exc:
        return False, {}, f"Failed to parse podman inspect JSON: {exc}"
    except (FileNotFoundError, OSError) as exc:
        return False, {}, f"Inspection error: {exc}"


def verify_floci_configuration(meta: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Validate cloudops-floci configuration against required security and operational properties:
    1. Image == docker.io/floci/floci:latest
    2. PODMAN_SYSTEMD_UNIT label == cloudops-floci.service
    3. Mount Source == /home/neha/cloudops-sentinel/data, Destination == /app/data
    """
    errors: list[str] = []

    # 1. Image check
    image_name = meta.get("ImageName") or meta.get("Config", {}).get("Image") or ""
    if not isinstance(image_name, str) or image_name.strip() != FLOCI_EXPECTED_IMAGE:
        errors.append(
            f"Image mismatch for 'cloudops-floci': expected '{FLOCI_EXPECTED_IMAGE}', found '{image_name}'."
        )

    # 2. Systemd unit label check
    config = meta.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict):
        labels = meta.get("Labels") if isinstance(meta.get("Labels"), dict) else {}

    unit_label = labels.get("PODMAN_SYSTEMD_UNIT") if isinstance(labels, dict) else None
    if unit_label != FLOCI_SYSTEMD_UNIT_LABEL:
        errors.append(
            f"Systemd unit label mismatch for 'cloudops-floci': expected '{FLOCI_SYSTEMD_UNIT_LABEL}', found '{unit_label}'."
        )

    # 3. Mounts check
    mounts = meta.get("Mounts")
    if not isinstance(mounts, list):
        errors.append("Malformed inspect data: 'Mounts' field is missing or not a list.")
    else:
        found_expected_mount = False
        matching_dest_sources = []
        for m in mounts:
            if not isinstance(m, dict):
                continue
            src = str(m.get("Source", "")).rstrip("/")
            dst = str(m.get("Destination", "")).rstrip("/")
            if dst == FLOCI_MOUNT_DESTINATION:
                matching_dest_sources.append(src)
                if src == FLOCI_MOUNT_SOURCE:
                    found_expected_mount = True

        if not matching_dest_sources:
            errors.append(
                f"Missing expected persistent mount for 'cloudops-floci': destination '{FLOCI_MOUNT_DESTINATION}' not found."
            )
        elif not found_expected_mount:
            errors.append(
                f"Mount source mismatch for 'cloudops-floci' at destination '{FLOCI_MOUNT_DESTINATION}': "
                f"expected '{FLOCI_MOUNT_SOURCE}', found {matching_dest_sources}."
            )

    return len(errors) == 0, errors


def verify_protected_inventory(
    existing_containers: list[dict[str, Any]],
    protected_specs: dict[str, str] | None = None,
    runner: Callable = subprocess.run,
) -> tuple[bool, list[str]]:
    """
    Confirm that known protected workloads ('cloudops-floci' and 'linuxops-recovery-ui-test')
    are present, untampered, and meet exact security and identity requirements.

    Floci verification:
    - Exactly one container named 'cloudops-floci'
    - Read-only inspect verifies image is docker.io/floci/floci:latest
    - PODMAN_SYSTEMD_UNIT label matches cloudops-floci.service
    - Persistent mount matches /home/neha/cloudops-sentinel/data -> /app/data
    - Accepts legitimate replacement container ID after full configuration verification

    Recovery UI verification:
    - Exactly one container named 'linuxops-recovery-ui-test'
    - ID prefix strictly matches '83b65d88a0a9'
    """
    errors: list[str] = []

    name_to_containers: dict[str, list[dict[str, Any]]] = {}
    id_to_names: dict[str, list[str]] = {}

    for item in existing_containers:
        name_val = item.get("Names") or item.get("names") or ""
        if isinstance(name_val, list):
            name_val = name_val[0] if name_val else ""
        clean_name = str(name_val).strip().lstrip("/")

        raw_id = str(item.get("Id") or item.get("id") or "").strip()
        if not clean_name or not raw_id:
            continue

        name_to_containers.setdefault(clean_name, []).append(item)
        id_to_names.setdefault(raw_id, []).append(clean_name)

    # 1. Verify cloudops-floci
    floci_matches = name_to_containers.get(FLOCI_CONTAINER_NAME, [])
    if not floci_matches:
        errors.append(f"Protected container '{FLOCI_CONTAINER_NAME}' was not found in active inventory.")
    elif len(floci_matches) > 1:
        f_ids = [c.get("Id") for c in floci_matches]
        errors.append(f"Ambiguous identity: duplicate containers named '{FLOCI_CONTAINER_NAME}' found: {f_ids}.")
    else:
        floci_item = floci_matches[0]
        floci_id = str(floci_item.get("Id") or floci_item.get("id") or "").strip()
        if not floci_id:
            errors.append(f"Protected container '{FLOCI_CONTAINER_NAME}' has empty or invalid container ID.")
        else:
            inspect_ok, meta, inspect_err = inspect_floci_container(floci_id, runner=runner)
            if not inspect_ok:
                errors.append(
                    f"Protected container '{FLOCI_CONTAINER_NAME}' inspect failed: {inspect_err}"
                )
            else:
                cfg_ok, cfg_errs = verify_floci_configuration(meta)
                if not cfg_ok:
                    errors.extend(cfg_errs)
                else:
                    register_protected_container_id(floci_id)

    # 2. Verify linuxops-recovery-ui-test
    recovery_ui_matches = name_to_containers.get(RECOVERY_UI_CONTAINER_NAME, [])
    if not recovery_ui_matches:
        errors.append(f"Protected container '{RECOVERY_UI_CONTAINER_NAME}' was not found in active inventory.")
    elif len(recovery_ui_matches) > 1:
        ui_ids = [c.get("Id") for c in recovery_ui_matches]
        errors.append(f"Ambiguous identity: duplicate containers named '{RECOVERY_UI_CONTAINER_NAME}' found: {ui_ids}.")
    else:
        ui_item = recovery_ui_matches[0]
        actual_id = str(ui_item.get("Id") or ui_item.get("id") or "").strip()
        exp_prefix = RECOVERY_UI_EXPECTED_ID_PREFIX
        if not actual_id.startswith(exp_prefix) and not exp_prefix.startswith(actual_id[:12]):
            errors.append(
                f"Identity mismatch for '{RECOVERY_UI_CONTAINER_NAME}': expected ID prefix '{exp_prefix}', found actual ID '{actual_id}'."
            )
        else:
            register_protected_container_id(actual_id)

    # 3. Check for any container on host with the Recovery UI prefix under a different name
    exp_prefix = RECOVERY_UI_EXPECTED_ID_PREFIX
    for raw_id, c_names in id_to_names.items():
        if raw_id.startswith(exp_prefix) or exp_prefix.startswith(raw_id[:12]):
            for c_name in c_names:
                if c_name != RECOVERY_UI_CONTAINER_NAME:
                    errors.append(
                        f"Identity mismatch for prefix '{exp_prefix}': expected name '{RECOVERY_UI_CONTAINER_NAME}', found actual name '{c_name}'."
                    )

    return len(errors) == 0, errors


def check_conflicting_test_containers(
    existing_containers: list[dict[str, Any]],
) -> list[str]:
    """Enumerate any pre-existing containers carrying the scale-test prefix or label."""
    conflicts = []
    for item in existing_containers:
        name_val = item.get("Names") or item.get("names") or ""
        if isinstance(name_val, list):
            name_val = name_val[0] if name_val else ""
        clean_name = str(name_val).strip().lstrip("/")

        labels = item.get("Labels") or item.get("labels") or {}
        has_label = False
        if isinstance(labels, dict):
            has_label = labels.get("linuxops.scale-test") == "true"

        if is_test_container_name(clean_name) or has_label:
            conflicts.append(clean_name or str(item.get("Id", "unknown")))
    return conflicts


# ---------------------------------------------------------------------------
# Atomic Manifest Operations & Path Validation
# ---------------------------------------------------------------------------

def validate_manifest_path(
    manifest_path_input: str | Path,
    trusted_dir: Path | None = None,
) -> tuple[bool, Path | None, str]:
    """
    Validate that a cleanup manifest path:
    1. Has a filename strictly matching scale_test_manifest_<RUN_ID>.json.
    2. Resolves strictly inside the trusted logs directory without escaping.
    3. Is a regular file and not an unexpected symlink or directory.
    """
    if not manifest_path_input:
        return False, None, "Manifest path cannot be empty."

    raw_path = Path(manifest_path_input)
    trusted_root = (trusted_dir or DEFAULT_MANIFEST_DIR).resolve()

    # 1. Filename pattern check
    filename = raw_path.name
    manifest_pattern = r"^scale_test_manifest_[A-Za-z0-9_.-]+\.json$"
    if not re.match(manifest_pattern, filename):
        return (
            False,
            None,
            f"Invalid manifest filename '{filename}'. Filename must match 'scale_test_manifest_<RUN_ID>.json'.",
        )

    # 2. Path containment check
    resolved_path = raw_path.resolve()
    try:
        rel = resolved_path.relative_to(trusted_root)
        if len(rel.parts) != 1:
            return False, None, f"Manifest path must reside directly inside trusted directory '{trusted_root}'."
    except ValueError:
        return False, None, f"Manifest path '{raw_path}' escapes trusted directory '{trusted_root}'."

    # 3. File existence and type checks
    if not resolved_path.exists():
        return False, None, f"Manifest file does not exist: {resolved_path}"

    if raw_path.is_symlink() or resolved_path.is_symlink():
        return False, None, f"Manifest path '{raw_path}' is a symlink. Symlinks are rejected for safety."

    if resolved_path.is_dir():
        return False, None, f"Manifest path '{resolved_path}' is a directory, not a regular file."

    if not resolved_path.is_file():
        return False, None, f"Manifest path '{resolved_path}' is not a regular file."

    return True, resolved_path, ""


def write_manifest_atomically(manifest_path: Path, data: dict[str, Any]) -> None:
    """
    Persist manifest JSON atomically using a sibling temporary file and os.replace.
    Cleans up temporary file on any error while preserving any existing manifest.
    """
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = manifest_path.with_name(f"{manifest_path.name}.tmp_{secrets.token_hex(4)}")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, manifest_path)
    except Exception:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass
        raise


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    """Read manifest JSON from file."""
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Manifest at {manifest_path} is malformed (expected JSON object).")
    return data


def validate_manifest_schema(data: Any) -> tuple[bool, str]:
    """
    Validate top-level manifest schema, run ID format, container list, and entry identities.
    Fails closed on malformed entries, duplicates, or contradictory identities.
    """
    if not isinstance(data, dict):
        return False, "Manifest root must be a JSON object (dict)."

    run_id = data.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        return False, "Manifest missing valid 'run_id'."
    if not re.match(r"^[0-9]{8}_[0-9]{6}_[0-9a-f]{8}$", run_id):
        return False, f"Manifest 'run_id' format is invalid: '{run_id}'."

    containers = data.get("containers")
    if not isinstance(containers, list):
        return False, "Manifest 'containers' field must be a list."
    if len(containers) == 0:
        return False, "Manifest contains no container records."

    seen_names: set[str] = set()
    seen_ids: set[str] = set()

    for idx, entry in enumerate(containers):
        if not isinstance(entry, dict):
            return False, f"Manifest entry {idx} is not an object."

        name = entry.get("name")
        cid = entry.get("id")
        name_str = str(name or "").strip()
        cid_str = str(cid or "").strip()

        if is_protected_container(name_str, cid_str):
            return False, f"Manifest illegally references protected container '{name_str}' ({cid_str})."

        success = entry.get("success")
        if not isinstance(success, bool):
            return False, f"Manifest entry {idx} missing boolean 'success' field."

        if success:
            if not isinstance(name, str) or not validate_container_name(name, run_id):
                return False, f"Manifest entry {idx} name '{name}' does not match expected convention for run_id '{run_id}'."

            if not isinstance(cid, str) or not cid.strip() or len(cid.strip()) < 12:
                return False, f"Manifest entry {idx} container ID is missing or too short: '{cid}'."

            clean_cid = cid.strip()
            if name in seen_names:
                return False, f"Manifest contains duplicate container name '{name}'."
            seen_names.add(name)

            if clean_cid in seen_ids:
                return False, f"Manifest contains duplicate container ID '{clean_cid}'."
            seen_ids.add(clean_cid)

    return True, ""


# ---------------------------------------------------------------------------
# Creation Workflow (Execution Mode Only)
# ---------------------------------------------------------------------------

def create_single_container(
    name: str,
    run_id: str,
    image: str = DEFAULT_IMAGE,
    runner: Callable = subprocess.run,
) -> tuple[bool, str, str]:
    """
    Execute podman run for a single container under strict resource caps.
    Returns (success, container_id_or_error, raw_error).
    """
    cmd = [
        "podman", "run", "-d",
        "--pull=never",
        "--name", name,
        "--label", LABEL_SCALE_TEST,
        "--label", f"{LABEL_RUN_ID_KEY}={run_id}",
        f"--memory={MEMORY_LIMIT}",
        f"--memory-swap={MEMORY_SWAP_LIMIT}",
        f"--cpus={CPU_LIMIT}",
        image,
    ] + WORKLOAD_CMD

    try:
        res = runner(cmd, capture_output=True, text=True, timeout=15.0, check=True)
        cid = res.stdout.strip()
        return True, cid, ""
    except subprocess.CalledProcessError as exc:
        err = (exc.stderr or "").strip()
        return False, "", f"Exit code {exc.returncode}: {err}"
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, "", str(exc)


def execute_scale_creation(
    run_id: str,
    count: int = EXACT_CONTAINER_COUNT,
    image: str = DEFAULT_IMAGE,
    manifest_dir: Path = DEFAULT_MANIFEST_DIR,
    runner: Callable = subprocess.run,
) -> tuple[bool, Path, dict[str, Any]]:
    """
    Execute controlled creation of exactly `count` containers with atomic per-container manifest updates.
    Independently enforces count == EXACT_CONTAINER_COUNT and count <= MAX_CONTAINER_CAP.
    Stops immediately upon any failure without deleting containers blindly.
    """
    manifest_path = manifest_dir / f"scale_test_manifest_{run_id}.json"

    # Strict internal count enforcement (cannot be bypassed programmatically)
    if count != EXACT_CONTAINER_COUNT or count > MAX_CONTAINER_CAP or count <= 0:
        error_manifest: dict[str, Any] = {
            "run_id": run_id,
            "status": "rejected_invalid_count",
            "error": f"Requested count {count} is invalid. Execution count must be exactly {EXACT_CONTAINER_COUNT} (max cap: {MAX_CONTAINER_CAP}).",
            "containers": [],
        }
        return False, manifest_path, error_manifest

    names = generate_container_names(run_id, count)

    manifest_data: dict[str, Any] = {
        "run_id": run_id,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target_count": count,
        "image": image,
        "workload": WORKLOAD_CMD,
        "resource_limits": {
            "memory": MEMORY_LIMIT,
            "memory_swap": MEMORY_SWAP_LIMIT,
            "cpus": CPU_LIMIT,
        },
        "status": "in_progress",
        "containers": [],
    }

    write_manifest_atomically(manifest_path, manifest_data)

    success_all = True
    for name in names:
        ok, cid, err = create_single_container(name, run_id, image=image, runner=runner)
        entry = {
            "name": name,
            "id": cid if ok else None,
            "success": ok,
            "error": err if not ok else None,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        manifest_data["containers"].append(entry)
        if not ok:
            manifest_data["status"] = "partial_failure"
            write_manifest_atomically(manifest_path, manifest_data)
            success_all = False
            break
        write_manifest_atomically(manifest_path, manifest_data)

    if success_all:
        manifest_data["status"] = "completed"
        write_manifest_atomically(manifest_path, manifest_data)

    return success_all, manifest_path, manifest_data


# ---------------------------------------------------------------------------
# Cleanup Workflow (Execution Mode Only)
# ---------------------------------------------------------------------------

def inspect_container_metadata(
    container_id: str,
    runner: Callable = subprocess.run,
) -> tuple[str, dict[str, Any], str]:
    """
    Query live container metadata via podman inspect.
    Returns (status, metadata_dict, error_message), where status is:
    - 'EXISTS': container was found and metadata parsed successfully.
    - 'ABSENT': container was confirmed not to exist on host.
    - 'ERROR': a daemon failure, timeout, permission error, or unexpected output occurred.
    """
    try:
        res = runner(
            ["podman", "inspect", container_id],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=True,
        )
        data = json.loads(res.stdout)
        if isinstance(data, list) and data:
            return "EXISTS", data[0], ""
        return "ERROR", {}, "podman inspect returned empty data structure."
    except subprocess.CalledProcessError as exc:
        stderr_text = (exc.stderr or "").strip().lower()
        absence_patterns = [
            "no such container",
            "no container with name or id",
            "could not find",
            "not found",
            "does not exist",
            "failed to find container",
        ]
        if any(pattern in stderr_text for pattern in absence_patterns):
            return "ABSENT", {}, f"Container confirmed absent: {exc.stderr.strip()}"
        return "ERROR", {}, f"Podman command error (exit code {exc.returncode}): {exc.stderr.strip()}"
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
        return "ERROR", {}, f"Inspection failure: {exc}"


def remove_single_container(
    container_id: str,
    runner: Callable = subprocess.run,
) -> tuple[bool, str]:
    """Remove a single container explicitly. Bulk commands are never used."""
    try:
        runner(
            ["podman", "rm", "-f", container_id],
            capture_output=True,
            text=True,
            timeout=15.0,
            check=True,
        )
        return True, ""
    except subprocess.CalledProcessError as exc:
        err = (exc.stderr or "").strip()
        return False, f"Exit code {exc.returncode}: {err}"
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, str(exc)


def execute_manifest_cleanup(
    manifest_path: Path,
    trusted_dir: Path | None = None,
    runner: Callable = subprocess.run,
) -> tuple[bool, list[str]]:
    """
    Remove only manifest-listed containers where ID, exact name, and labels strictly match.
    Validates manifest path containment and schema first.
    Treats confirmed absent containers idempotently on retry runs.
    Fails closed and aborts on any identity mismatch or daemon error.
    """
    log_messages: list[str] = []

    # 1. Path validation
    path_ok, resolved_manifest, path_err = validate_manifest_path(manifest_path, trusted_dir=trusted_dir)
    if not path_ok or resolved_manifest is None:
        return False, [f"Manifest path rejection: {path_err}"]

    # 2. Load and validate schema
    try:
        manifest = load_manifest(resolved_manifest)
    except Exception as exc:
        return False, [f"Failed to load manifest: {exc}"]

    schema_ok, schema_err = validate_manifest_schema(manifest)
    if not schema_ok:
        return False, [f"Manifest schema validation rejection: {schema_err}"]

    run_id = manifest["run_id"]
    containers = manifest["containers"]

    for entry in containers:
        if isinstance(entry, dict):
            c_name = str(entry.get("name") or "").strip()
            c_id = str(entry.get("id") or "").strip()
            if is_protected_container(c_name, c_id):
                return False, [f"Manifest targets protected container '{c_name}' ({c_id}). Aborting cleanup immediately."]

    cleanup_targets: list[tuple[str, str]] = [
        (entry["id"], entry["name"])
        for entry in containers
        if entry.get("success") and entry.get("id") and entry.get("name")
    ]

    all_removed = True
    for cid, expected_name in cleanup_targets:
        status, meta, err = inspect_container_metadata(cid, runner=runner)

        if status == "ABSENT":
            log_messages.append(
                f"Container '{expected_name}' ({cid[:12]}) is already absent on host (cleaned up previously). Continuing."
            )
            continue

        if status == "ERROR":
            log_messages.append(
                f"Cannot verify status for container {cid} ({expected_name}): {err}. Aborting cleanup."
            )
            all_removed = False
            break

        # status == "EXISTS" -> validate live identity
        actual_name = str(meta.get("Name") or "").strip().lstrip("/")
        actual_id = str(meta.get("Id") or "").strip()
        labels = meta.get("Config", {}).get("Labels") or {}

        if actual_name != expected_name:
            log_messages.append(f"Name mismatch for {cid}: expected '{expected_name}', found '{actual_name}'. Aborting.")
            all_removed = False
            break

        if not actual_id.startswith(cid) and not cid.startswith(actual_id):
            log_messages.append(f"ID mismatch for {cid}: actual ID is '{actual_id}'. Aborting.")
            all_removed = False
            break

        if labels.get("linuxops.scale-test") != "true":
            log_messages.append(f"Container {cid} lacks label 'linuxops.scale-test=true'. Aborting.")
            all_removed = False
            break

        if labels.get(LABEL_RUN_ID_KEY) != run_id:
            log_messages.append(f"Container {cid} has run ID '{labels.get(LABEL_RUN_ID_KEY)}' != expected '{run_id}'. Aborting.")
            all_removed = False
            break

        if is_protected_container(actual_name, actual_id):
            log_messages.append(f"FATAL: Live container {cid} ({actual_name}) matches protected workload! Aborting.")
            all_removed = False
            break

        rm_ok, rm_err = remove_single_container(cid, runner=runner)
        if not rm_ok:
            log_messages.append(f"Failed to remove {expected_name} ({cid}): {rm_err}. Aborting.")
            all_removed = False
            break
        log_messages.append(f"Removed test container '{expected_name}' ({cid[:12]}).")

    return all_removed, log_messages


# ---------------------------------------------------------------------------
# Dry-Run Presentation
# ---------------------------------------------------------------------------

def run_dry_run_plan(
    run_id: str,
    count: int = EXACT_CONTAINER_COUNT,
    image: str = DEFAULT_IMAGE,
    manifest_dir: Path = DEFAULT_MANIFEST_DIR,
    runner: Callable = subprocess.run,
) -> int:
    """Print the proposed dry-run execution plan. Never mutates system or writes files."""
    names = generate_container_names(run_id, count)
    manifest_path = manifest_dir / f"scale_test_manifest_{run_id}.json"

    print("=" * 72)
    print(" LinuxOps Scale-Test Harness — DRY-RUN INSPECTION (Read-Only)")
    print("=" * 72)
    print(f"Generated Run ID:             {run_id}")
    print(f"Proposed Container Count:     {count} (Strict initial limit)")
    print(f"Proposed Image:               {image} (Enforcing --pull=never)")
    print(f"Workload:                     {' '.join(WORKLOAD_CMD)}")
    print(f"Per-Container Limits:         Memory: {MEMORY_LIMIT}, Swap: {MEMORY_SWAP_LIMIT}, CPUs: {CPU_LIMIT}")
    print(f"Proposed Manifest Target:     {manifest_path}")
    print("\n[PROPOSED CONTAINER NAMES (NOT CREATED)]")
    for idx, name in enumerate(names, start=1):
        print(f"  {idx:02d}. {name}")

    print("\n[PREFLIGHT CHECKS AUDIT]")
    # 1. Podman
    pod_ok, pod_ver, pod_lat = check_podman_responsive(runner=runner)
    status_pod = "PASS" if pod_ok else "FAIL"
    print(f"  1. Podman CLI Status:        [{status_pod}] {pod_ver} ({pod_lat:.3f}s)")

    # 2. Local Image
    img_ok, img_msg = check_local_image_exists(image, runner=runner)
    status_img = "PASS" if img_ok else "FAIL"
    print(f"  2. Local Image Status:       [{status_img}] {img_msg}")

    # 3. System Resources
    res_ok, res_det = check_system_resources()
    status_res = "PASS" if res_ok else "FAIL"
    print(f"  3. Memory Capacity:          [{'PASS' if res_det['mem_ok'] else 'FAIL'}] {res_det['available_mem_mb']} MiB available (req >= {res_det['min_mem_mb']} MiB)")
    print(f"  4. Disk Capacity:            [{'PASS' if res_det['disk_ok'] else 'FAIL'}] {res_det['available_disk_gb']} GiB available (req >= {res_det['min_disk_gb']} GiB)")

    # 4. Inventory
    inv_ok, existing, inv_err = get_existing_containers(runner=runner)
    prot_ok = False
    prot_errs: list[str] = []
    conf_ok = False
    conflicts: list[str] = []

    if inv_ok:
        prot_ok, prot_errs = verify_protected_inventory(existing, runner=runner)
        status_prot = "PASS" if prot_ok else "FAIL"
        print(f"  5. Protected Workloads:      [{status_prot}] cloudops-floci & linuxops-recovery-ui-test verified")
        if prot_errs:
            for pe in prot_errs:
                print(f"     ! {pe}")

        conflicts = check_conflicting_test_containers(existing)
        conf_ok = len(conflicts) == 0
        status_conf = "PASS" if conf_ok else "FAIL"
        print(f"  6. Prior Scale Containers:   [{status_conf}] {len(conflicts)} conflicting test container(s) found")
        if conflicts:
            for cf in conflicts:
                print(f"     ! Conflicting container found: {cf}")
    else:
        print(f"  5. Container Inventory:      [FAIL] {inv_err}")

    all_preflight_passed = bool(
        pod_ok and img_ok and res_ok and inv_ok and prot_ok and conf_ok
    )

    print("\n[SAFETY NOTICE]")
    print("  * This dry-run made ZERO Podman lifecycle calls, pulled NO images, and wrote NO manifests.")
    print("  * Execution requires explicit '--execute' flag with exactly 10 containers.")
    if all_preflight_passed:
        print("  * Preflight audit status: PASS (Environment verified; ready for execution with '--execute').")
    else:
        print("  * Preflight audit status: FAIL (One or more preflight checks failed; execution blocked).")
    print("=" * 72)
    return 0 if all_preflight_passed else 1


# ---------------------------------------------------------------------------
# CLI Argument Parser & Entry Point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="LinuxOps Safe Scale-Test Harness (Dry-Run by Default)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Explicit flag required to create containers. Defaults to False (Dry-Run).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=EXACT_CONTAINER_COUNT,
        help=f"Number of containers to create. Strictly locked to {EXACT_CONTAINER_COUNT} for this version.",
    )
    parser.add_argument(
        "--cleanup",
        type=str,
        default=None,
        metavar="MANIFEST_PATH",
        help="Path to scale_test_manifest_<RUN_ID>.json to safely remove manifest-listed test containers.",
    )
    parser.add_argument(
        "--image",
        type=str,
        default=DEFAULT_IMAGE,
        help=f"Local container image to use (default: {DEFAULT_IMAGE}).",
    )
    parser.add_argument(
        "--manifest-dir",
        type=str,
        default=str(DEFAULT_MANIFEST_DIR),
        help=f"Directory for saving manifests (default: {DEFAULT_MANIFEST_DIR}).",
    )
    return parser


def main(argv: list[str] | None = None, runner: Callable = subprocess.run) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    run_id = generate_run_id()
    manifest_dir = Path(args.manifest_dir)

    # 1. Cleanup Mode (Explicit)
    if args.cleanup:
        path_ok, manifest_path, path_err = validate_manifest_path(args.cleanup, manifest_dir)
        if not path_ok or manifest_path is None:
            print(f"ABORT: {path_err}", file=sys.stderr)
            return 1

        print(f"Initiating verified cleanup for manifest: {manifest_path}")
        ok, msgs = execute_manifest_cleanup(manifest_path, trusted_dir=manifest_dir, runner=runner)
        for m in msgs:
            print(f"  {m}")
        if ok:
            print("Cleanup completed successfully.")
            return 0
        print("Cleanup encountered errors or safety stops.", file=sys.stderr)
        return 1

    # 2. Execution Mode (Requires explicit --execute and exact count)
    if args.execute:
        if args.count != EXACT_CONTAINER_COUNT:
            print(f"ERROR: Execution count must be exactly {EXACT_CONTAINER_COUNT}. Requested: {args.count}.", file=sys.stderr)
            return 1

        # Run preflight checks before any execution
        pod_ok, pod_msg, _ = check_podman_responsive(runner=runner)
        if not pod_ok:
            print(f"ABORT: {pod_msg}", file=sys.stderr)
            return 1

        img_ok, img_msg = check_local_image_exists(args.image, runner=runner)
        if not img_ok:
            print(f"ABORT: {img_msg}", file=sys.stderr)
            return 1

        res_ok, res_det = check_system_resources()
        if not res_ok:
            print(f"ABORT: Insufficient system resources: {res_det}", file=sys.stderr)
            return 1

        inv_ok, existing, inv_err = get_existing_containers(runner=runner)
        if not inv_ok:
            print(f"ABORT: Cannot verify existing container inventory: {inv_err}", file=sys.stderr)
            return 1

        prot_ok, prot_errs = verify_protected_inventory(existing, runner=runner)
        if not prot_ok:
            print(f"ABORT: Protected container inventory verification failed: {prot_errs}", file=sys.stderr)
            return 1

        conflicts = check_conflicting_test_containers(existing)
        if conflicts:
            print(f"ABORT: Found pre-existing conflicting scale-test containers: {conflicts}", file=sys.stderr)
            return 1

        print(f"Preflight passed. Beginning execution of run {run_id} ({args.count} containers)...")
        ok, m_path, m_data = execute_scale_creation(
            run_id=run_id,
            count=args.count,
            image=args.image,
            manifest_dir=manifest_dir,
            runner=runner,
        )
        print(f"Manifest written: {m_path}")
        if ok:
            print(f"Successfully created {args.count} containers under run ID {run_id}.")
            return 0
        print(f"Execution failed or halted partially. Check manifest for details: {m_path}", file=sys.stderr)
        return 1

    # 3. Default Mode: DRY-RUN (safe, no changes)
    return run_dry_run_plan(
        run_id=run_id,
        count=args.count,
        image=args.image,
        manifest_dir=manifest_dir,
        runner=runner,
    )


if __name__ == "__main__":
    sys.exit(main())
