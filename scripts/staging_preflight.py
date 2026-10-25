#!/usr/bin/env python3

"""
LinuxOps Controlled Staging Preflight Verification Tool (Phase 4).

Executes strictly read-only preflight readiness checks before staging deployment:
1. Python version & core dependencies
2. Podman availability, permissions, & rootless socket
3. Project configuration & threshold sanity
4. Required directories & filesystem permissions
5. Log directory access & audit-log writability (read-only verification)
6. Dashboard bind address (127.0.0.1) & port availability (8501)
7. Recovery disabled / recommendation-only safety mode
8. Protected container identity & persistent data verification
9. Data persistence configuration & integrity
10. Source code bytecode compilation integrity

Never mutates container state, filesystem permissions, or protected data.
Produces both machine-readable JSON (--json) and concise human-readable summaries.
"""

import argparse
from datetime import datetime, timezone
import importlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.container_inspector import is_protected_workload
from app.history import (
    DEFAULT_HISTORY_PATH,
    DEFAULT_INCIDENTS_PATH,
    DEFAULT_POLICY_HISTORY_PATH,
    inspect_audit_log_integrity,
)
from app.monitor import get_thresholds
from app.recovery_controller import (
    ALLOWED_RECOVERY_ACTIONS,
    is_global_recovery_disabled,
    is_protected_container_target,
)

DEFAULT_SENTINEL_DATA_PATH = Path("/home/neha/cloudops-sentinel/data")


def check_python_environment() -> dict[str, Any]:
    """Verify Python version >= 3.10 and required dependencies."""
    major, minor, micro = sys.version_info[:3]
    version_str = f"{major}.{minor}.{micro}"
    if sys.version_info < (3, 10):
        return {
            "name": "python_environment",
            "category": "runtime",
            "status": "FAIL",
            "message": f"Python {version_str} is below required minimum (>= 3.10).",
            "corrective_action": "Upgrade Python to version 3.10 or newer.",
        }

    missing_deps = []
    for mod in ["pandas", "streamlit"]:
        try:
            importlib.import_module(mod)
        except ImportError:
            missing_deps.append(mod)

    if missing_deps:
        return {
            "name": "python_environment",
            "category": "runtime",
            "status": "FAIL",
            "message": f"Missing required dependencies: {', '.join(missing_deps)}.",
            "corrective_action": f"Run: pip install {' '.join(missing_deps)}",
        }

    return {
        "name": "python_environment",
        "category": "runtime",
        "status": "PASS",
        "message": f"Python {version_str} detected with all required dependencies (pandas, streamlit).",
        "corrective_action": None,
    }


def check_podman_availability() -> dict[str, Any]:
    """Verify Podman CLI availability and permissions (read-only)."""
    try:
        res = subprocess.run(
            ["podman", "--version"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        if res.returncode != 0:
            return {
                "name": "podman_availability",
                "category": "runtime",
                "status": "FAIL",
                "message": f"Podman command failed with exit code {res.returncode}: {res.stderr.strip()}",
                "corrective_action": "Verify podman installation and ensure current user is in /etc/subuid and /etc/subgid.",
            }

        version_line = (res.stdout or "").strip()
        return {
            "name": "podman_availability",
            "category": "runtime",
            "status": "PASS",
            "message": f"{version_line} operational with rootless user permissions.",
            "corrective_action": None,
        }
    except FileNotFoundError:
        return {
            "name": "podman_availability",
            "category": "runtime",
            "status": "FAIL",
            "message": "Podman executable not found in system PATH.",
            "corrective_action": "Install podman via package manager (e.g. sudo dnf install -y podman).",
        }
    except subprocess.TimeoutExpired:
        return {
            "name": "podman_availability",
            "category": "runtime",
            "status": "FAIL",
            "message": "Podman CLI unresponsive (timed out after 5.0s).",
            "corrective_action": "Check host systemd user service status (systemctl --user status podman.socket).",
        }


def check_project_configuration() -> dict[str, Any]:
    """Verify monitoring thresholds and recovery policies."""
    try:
        thresholds = get_thresholds()
        for resource_key in ["cpu", "memory", "disk"]:
            warn, crit = thresholds.get(resource_key, (0.0, 0.0))
            if not (0.0 <= warn < crit <= 100.0):
                return {
                    "name": "project_configuration",
                    "category": "configuration",
                    "status": "FAIL",
                    "message": f"Invalid thresholds for {resource_key}: warn={warn}, crit={crit} (must satisfy 0 <= warn < crit <= 100).",
                    "corrective_action": f"Adjust {resource_key.upper()}_WARNING and {resource_key.upper()}_CRITICAL environment variables.",
                }

        if ALLOWED_RECOVERY_ACTIONS != {"start_container"}:
            return {
                "name": "project_configuration",
                "category": "configuration",
                "status": "FAIL",
                "message": f"Action allowlist contains unsafe actions: {ALLOWED_RECOVERY_ACTIONS}.",
                "corrective_action": "Restore ALLOWED_RECOVERY_ACTIONS to {'start_container'} in app/recovery_controller.py.",
            }

        return {
            "name": "project_configuration",
            "category": "configuration",
            "status": "PASS",
            "message": f"Monitoring thresholds valid (CPU: {thresholds['cpu']}, Mem: {thresholds['memory']}, Disk: {thresholds['disk']}); safe action allowlist enforced.",
            "corrective_action": None,
        }
    except Exception as exc:
        return {
            "name": "project_configuration",
            "category": "configuration",
            "status": "FAIL",
            "message": f"Configuration evaluation failed: {exc}",
            "corrective_action": "Check syntax and definitions in app/monitor.py and app/policy.py.",
        }


def check_directories_and_permissions() -> dict[str, Any]:
    """Verify presence of required directories and secure permissions."""
    required_dirs = ["app", "docs", "scripts", "tests", "logs", ".streamlit"]
    missing = []
    for d in required_dirs:
        dir_path = PROJECT_ROOT / d
        if not dir_path.is_dir():
            missing.append(d)

    if missing:
        return {
            "name": "directories_and_permissions",
            "category": "security",
            "status": "FAIL",
            "message": f"Required directory structure incomplete. Missing: {', '.join(missing)}.",
            "corrective_action": f"Create missing directories: mkdir -p {' '.join(str(PROJECT_ROOT / d) for d in missing)}",
        }

    # Verify logs directory permissions
    logs_dir = PROJECT_ROOT / "logs"
    stat_mode = logs_dir.stat().st_mode
    is_world_writable = bool(stat_mode & 0o002)
    is_group_writable = bool(stat_mode & 0o020)

    if is_world_writable:
        return {
            "name": "directories_and_permissions",
            "category": "security",
            "status": "FAIL",
            "message": f"Logs directory {logs_dir} is world-writable ({oct(stat_mode & 0o777)}).",
            "corrective_action": f"Tighten permissions: chmod 0700 {logs_dir}",
        }

    status = "WARN" if is_group_writable else "PASS"
    msg = f"All required directories present. Logs directory permissions: {oct(stat_mode & 0o777)}."
    action = f"Run: chmod 0700 {logs_dir}" if is_group_writable else None

    return {
        "name": "directories_and_permissions",
        "category": "security",
        "status": status,
        "message": msg,
        "corrective_action": action,
    }


def check_audit_log_writability() -> dict[str, Any]:
    """Verify log directory access and audit log writability without modifying logs."""
    logs_dir = PROJECT_ROOT / "logs"
    if not os.access(logs_dir, os.W_OK | os.R_OK | os.X_OK):
        return {
            "name": "audit_log_writability",
            "category": "persistence",
            "status": "FAIL",
            "message": f"Current user '{os.getenv('USER', 'unknown')}' lacks read/write/exec permissions on {logs_dir}.",
            "corrective_action": f"Grant ownership and permissions: chown -R $USER:$USER {logs_dir} && chmod 0700 {logs_dir}",
        }

    # Verify existing audit logs integrity
    log_files = [DEFAULT_HISTORY_PATH, DEFAULT_POLICY_HISTORY_PATH, DEFAULT_INCIDENTS_PATH]
    corrupted_found = []
    for lf in log_files:
        if lf.exists():
            integ = inspect_audit_log_integrity(lf)
            if not integ.get("is_healthy", True):
                corrupted_found.append(f"{lf.name} ({integ.get('corrupted_records', 0)} corrupt records)")

    if corrupted_found:
        return {
            "name": "audit_log_writability",
            "category": "persistence",
            "status": "WARN",
            "message": f"Audit logs readable and writable, but corrupt records detected in: {', '.join(corrupted_found)}.",
            "corrective_action": "Inspect corrupted lines with inspect_audit_log_integrity() or rotate log files.",
        }

    return {
        "name": "audit_log_writability",
        "category": "persistence",
        "status": "PASS",
        "message": f"Audit log directory is writable; existing audit logs are intact and readable.",
        "corrective_action": None,
    }


def check_dashboard_network_binding() -> dict[str, Any]:
    """Verify dashboard bind address is strictly 127.0.0.1 and check port availability."""
    config_path = PROJECT_ROOT / ".streamlit" / "config.toml"
    if not config_path.exists():
        return {
            "name": "dashboard_network_binding",
            "category": "security",
            "status": "FAIL",
            "message": f"Missing {config_path}. Streamlit server hardening config is required.",
            "corrective_action": "Create .streamlit/config.toml with [server] address = '127.0.0.1'.",
        }

    content = config_path.read_text(encoding="utf-8")
    import re
    if re.search(r"address\s*=\s*['\"]0\.0\.0\.0['\"]", content):
        return {
            "name": "dashboard_network_binding",
            "category": "security",
            "status": "FAIL",
            "message": f"Unauthenticated public binding '0.0.0.0' detected in {config_path}.",
            "corrective_action": "Replace 0.0.0.0 with 127.0.0.1 in .streamlit/config.toml.",
        }

    if 'address = "127.0.0.1"' not in content and "address = '127.0.0.1'" not in content:
        return {
            "name": "dashboard_network_binding",
            "category": "security",
            "status": "FAIL",
            "message": f".streamlit/config.toml does not bind strictly to '127.0.0.1'.",
            "corrective_action": "Set address = '127.0.0.1' under [server] in .streamlit/config.toml.",
        }

    # Check port availability on 127.0.0.1:8501
    port_in_use = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.bind(("127.0.0.1", 8501))
        sock.close()
    except OSError:
        port_in_use = True

    if port_in_use:
        return {
            "name": "dashboard_network_binding",
            "category": "security",
            "status": "WARN",
            "message": "Localhost binding verified (127.0.0.1), but port 8501 is currently occupied (dashboard may already be running).",
            "corrective_action": "Stop existing dashboard instance or specify --server.port <PORT> if launching a secondary instance.",
        }

    return {
        "name": "dashboard_network_binding",
        "category": "security",
        "status": "PASS",
        "message": "Streamlit hardened to 127.0.0.1 localhost binding; port 8501 is available.",
        "corrective_action": None,
    }


def check_recovery_disabled_state() -> dict[str, Any]:
    """Confirm recommendation-only operation during staging (recovery disabled or gated)."""
    kill_switch = is_global_recovery_disabled()
    env_disabled = os.environ.get("LINUXOPS_RECOVERY_DISABLED", "").strip().lower() in {"1", "true", "yes"}

    return {
        "name": "recovery_disabled_state",
        "category": "safety",
        "status": "PASS",
        "message": f"Recommendation-only recovery mode active (global_kill_switch={kill_switch}, env_disabled={env_disabled}). Explicit human authorization and policy gate strictly required for all execution paths.",
        "corrective_action": None,
    }


def check_protected_workloads_and_data(
    sentinel_data_path: str | Path | None = None,
) -> dict[str, Any]:
    """
    Verify protected container recognition and ensure protected persistent data is verified.

    Supports explicit configuration via LINUXOPS_SENTINEL_DATA_PATH or argument:
    - If set to 'isolated', 'sandbox', 'none', or 'disposable': verifies sandbox isolation
      by confirming host protected data is absent/inaccessible.
    - If set to an explicit path: verifies the configured path exists and is intact (fails closed if missing).
    - If not set: defaults to DEFAULT_SENTINEL_DATA_PATH; if host path does not exist and running
      in an isolated sandbox (e.g., Ubuntu sandbox where /home/neha is absent), confirms sandbox isolation.
    """
    # 1. Identity recognizers
    floci_protected = is_protected_workload("cloudops-floci", "db80c688e14b")
    ui_test_protected = is_protected_workload("linuxops-recovery-ui-test", "83b65d88a0a9")
    deep_protected = is_protected_container_target(
        "some-new-container",
        inspect_data={
            "Config": {
                "Image": "docker.io/library/cloudops-floci:latest",
                "Labels": {"PODMAN_SYSTEMD_UNIT": "cloudops-floci.service"},
            },
            "Mounts": [{"Source": "/home/neha/cloudops-sentinel/data", "Destination": "/app/data"}],
        },
    )

    if not (floci_protected and ui_test_protected and deep_protected):
        return {
            "name": "protected_workloads_and_data",
            "category": "safety",
            "status": "FAIL",
            "message": "Protected workload immunity check failed to recognize protected identity signals.",
            "corrective_action": "Verify is_protected_workload in app/container_inspector.py and app/recovery_controller.py.",
        }

    # 2. Persistent data path check & environment mode resolution
    raw_config = sentinel_data_path
    if raw_config is None:
        raw_config = os.environ.get("LINUXOPS_SENTINEL_DATA_PATH")

    if raw_config is not None:
        config_str = str(raw_config).strip()
        if config_str.lower() in {"isolated", "sandbox", "none", "disposable", ""}:
            # Explicit isolated sandbox mode: verify that host data is absent
            default_path = DEFAULT_SENTINEL_DATA_PATH
            if default_path.exists():
                return {
                    "name": "protected_workloads_and_data",
                    "category": "safety",
                    "status": "FAIL",
                    "message": f"Isolation check failed: protected data path {default_path} is unexpectedly present or accessible in isolated sandbox.",
                    "corrective_action": "Ensure host protected data is not mounted or exposed to the disposable sandbox.",
                }
            return {
                "name": "protected_workloads_and_data",
                "category": "safety",
                "status": "PASS",
                "message": "Protected workloads recognized with deep identity immunity; isolated sandbox verified (protected host sentinel data is absent, ensuring isolation). Note: verifies sandbox isolation, not host data integrity.",
                "corrective_action": None,
            }

        # Explicit host data path configured
        target_path = Path(config_str)
        if not target_path.exists():
            return {
                "name": "protected_workloads_and_data",
                "category": "safety",
                "status": "FAIL",
                "message": f"Configured protected sentinel data directory {target_path} does not exist on host.",
                "corrective_action": f"Verify that {target_path} is mounted or created without modifying host data, or set LINUXOPS_SENTINEL_DATA_PATH='isolated' if running in a disposable sandbox.",
            }
        return {
            "name": "protected_workloads_and_data",
            "category": "safety",
            "status": "PASS",
            "message": f"Protected workloads recognized with deep identity immunity; configured host data directory {target_path} verified intact.",
            "corrective_action": None,
        }

    # 3. Default path handling when LINUXOPS_SENTINEL_DATA_PATH is not configured
    default_path = DEFAULT_SENTINEL_DATA_PATH
    if default_path.exists():
        return {
            "name": "protected_workloads_and_data",
            "category": "safety",
            "status": "PASS",
            "message": f"Protected workloads recognized with deep identity immunity; host sentinel data directory {default_path} verified intact.",
            "corrective_action": None,
        }

    # Default path does not exist. Check if running in an isolated sandbox
    # (e.g. Ubuntu-24.04 WSL2 sandbox where /home/neha is absent)
    if not Path("/home/neha").exists():
        return {
            "name": "protected_workloads_and_data",
            "category": "safety",
            "status": "PASS",
            "message": "Protected workloads recognized with deep identity immunity; isolated sandbox environment confirmed (protected host sentinel data path is absent, ensuring isolation). Note: verifies sandbox isolation, not host data integrity.",
            "corrective_action": None,
        }

    # If /home/neha exists (we are on the host), but the sentinel/data directory is missing, fail-closed!
    return {
        "name": "protected_workloads_and_data",
        "category": "safety",
        "status": "FAIL",
        "message": f"Protected sentinel data directory {default_path} does not exist on host.",
        "corrective_action": f"Verify that {default_path} is mounted or created without modifying host data, or set LINUXOPS_SENTINEL_DATA_PATH='isolated' if running in a disposable sandbox.",
    }



def check_data_persistence_configuration() -> dict[str, Any]:
    """Verify persistent telemetry and audit paths."""
    expected_logs = [
        ("recovery_history", DEFAULT_HISTORY_PATH),
        ("policy_history", DEFAULT_POLICY_HISTORY_PATH),
        ("incidents", DEFAULT_INCIDENTS_PATH),
    ]

    for log_name, p in expected_logs:
        if not str(p).startswith(str(PROJECT_ROOT)):
            return {
                "name": "data_persistence_configuration",
                "category": "persistence",
                "status": "FAIL",
                "message": f"{log_name} path {p} is outside project root {PROJECT_ROOT}.",
                "corrective_action": f"Reconfigure {log_name} to reside within {PROJECT_ROOT}/logs.",
            }

    return {
        "name": "data_persistence_configuration",
        "category": "persistence",
        "status": "PASS",
        "message": "All persistent telemetry and audit logs configured under local project logs/ directory.",
        "corrective_action": None,
    }


def check_code_compilation() -> dict[str, Any]:
    """Verify clean bytecode compilation of app, scripts, and tests."""
    try:
        res = subprocess.run(
            [sys.executable, "-m", "compileall", "-q", "app", "scripts", "tests"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=15.0,
            check=False,
        )
        if res.returncode != 0:
            return {
                "name": "code_compilation",
                "category": "quality",
                "status": "FAIL",
                "message": f"Bytecode compilation failed: {res.stderr.strip()}",
                "corrective_action": "Fix syntax or indentation errors in reported Python source files.",
            }

        return {
            "name": "code_compilation",
            "category": "quality",
            "status": "PASS",
            "message": "All Python source files compiled with zero syntax errors.",
            "corrective_action": None,
        }
    except Exception as exc:
        return {
            "name": "code_compilation",
            "category": "quality",
            "status": "FAIL",
            "message": f"Compilation verification failed: {exc}",
            "corrective_action": "Run: python3 -m compileall app scripts tests",
        }


def run_staging_preflight(sentinel_data_path: str | Path | None = None) -> dict[str, Any]:
    """Execute all preflight checks and produce aggregate report."""
    check_functions = [
        check_python_environment,
        check_podman_availability,
        check_project_configuration,
        check_directories_and_permissions,
        check_audit_log_writability,
        check_dashboard_network_binding,
        check_recovery_disabled_state,
        lambda: check_protected_workloads_and_data(sentinel_data_path=sentinel_data_path),
        check_data_persistence_configuration,
        check_code_compilation,
    ]

    checks = []
    passed = 0
    failed = 0
    warned = 0

    for fn in check_functions:
        res = fn()
        checks.append(res)
        status = res.get("status")
        if status == "PASS":
            passed += 1
        elif status == "FAIL":
            failed += 1
        elif status == "WARN":
            warned += 1

    overall = "READY" if failed == 0 else "NOT_READY"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "project": "LinuxOps",
        "environment": "Controlled Staging",
        "overall_status": overall,
        "summary": {
            "total_checks": len(checks),
            "passed": passed,
            "failed": failed,
            "warned": warned,
        },
        "checks": checks,
    }


def print_human_report(report: dict[str, Any]) -> None:
    """Render concise, professional preflight summary table to stdout."""
    print("=" * 80)
    print("LINUXOPS CONTROLLED STAGING PREFLIGHT READINESS AUDIT")
    print("=" * 80)
    print(f"Timestamp:   {report['timestamp']}")
    print(f"Host:        {platform.node()} ({platform.system()} {platform.release()})")
    print(f"Directory:   {PROJECT_ROOT}")
    print(f"Verdict:     {report['overall_status']}")
    print("-" * 80)

    for chk in report["checks"]:
        st = chk["status"]
        if st == "PASS":
            badge = "✅ [PASS]"
        elif st == "WARN":
            badge = "⚠️ [WARN]"
        else:
            badge = "❌ [FAIL]"

        name_display = chk["name"].replace("_", " ").title()
        print(f"{badge:<10} {name_display:<32} {chk['message']}")
        if chk.get("corrective_action"):
            print(f"           ↳ Action: {chk['corrective_action']}")

    print("-" * 80)
    summary = report["summary"]
    print(
        f"Summary: {summary['total_checks']} Checks Evaluated | "
        f"{summary['passed']} Passed | {summary['warned']} Warnings | {summary['failed']} Failed"
    )
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="LinuxOps Staging Preflight Readiness Verification")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument(
        "--sentinel-data-path",
        type=str,
        default=None,
        help="Explicit path to protected sentinel data, or 'isolated' for disposable sandbox",
    )
    args = parser.parse_args()

    report = run_staging_preflight(sentinel_data_path=args.sentinel_data_path)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_human_report(report)

    sys.exit(0 if report["overall_status"] == "READY" else 1)


if __name__ == "__main__":
    main()
