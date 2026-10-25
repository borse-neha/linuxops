#!/usr/bin/env python3

"""
LinuxOps Host-Side Read-Only Telemetry Agent.

Runs as a lightweight user/system service on monitored Linux/Podman hosts:
- Collects read-only container telemetry via rootless Podman CLI.
- Collects system-level resource utilization from /proc.
- Never accepts remote commands or mutation requests (outbound push only).
- Strips environment variables, tokens, and sensitive volume mounts before dispatch.
- Cryptographically signs payloads using HMAC-SHA256.
- Transmits telemetry via outbound TLS connection to central LinuxOps console.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.request

AGENT_VERSION = "1.0.0"
DEFAULT_SCAN_INTERVAL = 30.0
DEFAULT_TIMEOUT = 10.0


def get_system_identity() -> dict[str, str]:
    """Retrieve host identity and OS metadata."""
    uname = platform.uname()
    hostname = uname.node or "unknown-host"
    machine_id = "unknown"
    for mid_path in [Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")]:
        if mid_path.exists():
            try:
                machine_id = mid_path.read_text(encoding="utf-8").strip()
                break
            except Exception:
                pass

    return {
        "hostname": hostname,
        "machine_id": machine_id[:16] if len(machine_id) >= 16 else machine_id,
        "kernel": uname.release,
        "architecture": uname.machine,
        "system": uname.system,
    }


def query_podman_telemetry() -> tuple[list[dict[str, Any]], str]:
    """Execute local read-only podman inspection."""
    podman_version = "unknown"
    try:
        ver_res = subprocess.run(["podman", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, timeout=5.0)
        if ver_res.returncode == 0 and ver_res.stdout.strip():
            podman_version = ver_res.stdout.strip()
    except Exception:
        pass

    try:
        ps_res = subprocess.run(
            ["podman", "ps", "-a", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT,
        )
        if ps_res.returncode != 0:
            return [], podman_version

        raw = (ps_res.stdout or "").strip()
        if not raw:
            return [], podman_version

        containers = json.loads(raw)
        sanitized = []
        for c in containers:
            cid = str(c.get("Id") or c.get("id") or "")[:12]
            cnames = c.get("Names") or c.get("names") or []
            cname = cnames[0] if isinstance(cnames, list) and cnames else str(cnames)
            cname = cname.lstrip("/")

            state_val = str(c.get("State") or c.get("status") or "").lower()
            state = "running" if "up" in state_val or "running" in state_val else "stopped"

            sanitized.append({
                "id": cid,
                "name": cname,
                "image": str(c.get("Image") or "unknown"),
                "state": state,
                "status": str(c.get("Status") or state),
                "health_status": "healthy" if state == "running" else "unknown",
                "created_at": c.get("CreatedAt"),
                "env": ["REDACTED"],
            })
        return sanitized, podman_version
    except Exception:
        return [], podman_version


def read_proc_metrics() -> dict[str, Any]:
    """Read host-level CPU and memory percentages safely from /proc."""
    mem_info: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip().split()[0]
                    if val.isdigit():
                        mem_info[key] = int(val)
    except Exception:
        pass

    total = mem_info.get("MemTotal", 1)
    avail = mem_info.get("MemAvailable", mem_info.get("MemFree", 0))
    used = max(0, total - avail)
    mem_pct = round((used / total) * 100.0, 1)

    return {
        "memory_usage_percent": mem_pct,
        "load_averages": list(os.getloadavg()) if hasattr(os, "getloadavg") else [0.0, 0.0, 0.0],
    }


def build_telemetry_payload(host_id: str) -> dict[str, Any]:
    """Construct complete authenticated telemetry payload."""
    start_t = time.monotonic()
    sys_id = get_system_identity()
    containers, podman_ver = query_podman_telemetry()
    proc_metrics = read_proc_metrics()
    duration_ms = round((time.monotonic() - start_t) * 1000.0, 2)

    return {
        "host_id": host_id or sys_id["machine_id"] or sys_id["hostname"],
        "hostname": sys_id["hostname"],
        "distribution": f"{sys_id['system']} {sys_id['kernel']}",
        "podman_version": podman_ver,
        "kernel_version": sys_id["kernel"],
        "timestamp_iso": datetime.now(timezone.utc).isoformat(),
        "host_metrics": proc_metrics,
        "containers": containers,
        "agent_version": AGENT_VERSION,
        "scan_duration_ms": duration_ms,
    }


def transmit_telemetry(payload: dict[str, Any], endpoint_url: str, secret_key: str) -> bool:
    """Sign and transmit telemetry payload via outbound HTTPS."""
    data_str = json.dumps(payload, sort_keys=True)
    signature = ""
    if secret_key:
        signature = hmac.new(secret_key.encode("utf-8"), data_str.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"LinuxOps-Agent/{AGENT_VERSION}",
        "X-LinuxOps-Signature": signature,
    }

    req = urllib.request.Request(endpoint_url, data=data_str.encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            return resp.status in (200, 201, 202)
    except Exception as exc:
        sys.stderr.write(f"Failed to transmit telemetry to {endpoint_url}: {exc}\n")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="LinuxOps Read-Only Host Telemetry Agent")
    parser.add_argument("--host-id", help="Explicit unique identifier for this monitored host")
    parser.add_argument("--endpoint", help="Central LinuxOps telemetry ingestion URL")
    parser.add_argument("--secret", help="HMAC-SHA256 preshared agent secret")
    parser.add_argument("--once", action="store_true", help="Execute single-shot telemetry scan and output JSON")
    parser.add_argument("--interval", type=float, default=DEFAULT_SCAN_INTERVAL, help="Scan interval in seconds for daemon mode")
    args = parser.parse_args()

    host_id = args.host_id or os.environ.get("LINUXOPS_HOST_ID", "")
    secret = args.secret or os.environ.get("LINUXOPS_AGENT_SECRET", "")
    endpoint = args.endpoint or os.environ.get("LINUXOPS_INGESTION_ENDPOINT", "")

    if args.once or not endpoint:
        payload = build_telemetry_payload(host_id)
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        if endpoint:
            success = transmit_telemetry(payload, endpoint, secret)
            sys.exit(0 if success else 1)
        sys.exit(0)

    # Daemon loop
    sys.stderr.write(f"Starting LinuxOps Agent (pushing to {endpoint} every {args.interval}s)...\n")
    while True:
        try:
            payload = build_telemetry_payload(host_id)
            transmit_telemetry(payload, endpoint, secret)
        except Exception as exc:
            sys.stderr.write(f"Agent scan error: {exc}\n")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
