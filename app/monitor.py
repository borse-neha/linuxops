
#!/usr/bin/env python3

import json
import os
import platform
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_DIR / "logs" / "metrics.jsonl"

def _parse_threshold(env_name, default, min_val=0.0, max_val=100.0):
    val_str = os.getenv(env_name)
    if val_str is None:
        return default
    try:
        val = float(val_str)
        if min_val <= val <= max_val:
            return val
    except (ValueError, TypeError):
        pass
    return default


def get_thresholds():
    cpu_warn = _parse_threshold("CPU_WARNING", 70.0)
    cpu_crit = _parse_threshold("CPU_CRITICAL", 90.0)
    if cpu_warn >= cpu_crit:
        cpu_warn, cpu_crit = 70.0, 90.0

    mem_warn = _parse_threshold("MEMORY_WARNING", 80.0)
    mem_crit = _parse_threshold("MEMORY_CRITICAL", 90.0)
    if mem_warn >= mem_crit:
        mem_warn, mem_crit = 80.0, 90.0

    disk_warn = _parse_threshold("DISK_WARNING", 80.0)
    disk_crit = _parse_threshold("DISK_CRITICAL", 90.0)
    if disk_warn >= disk_crit:
        disk_warn, disk_crit = 80.0, 90.0

    return {
        "cpu": (cpu_warn, cpu_crit),
        "memory": (mem_warn, mem_crit),
        "disk": (disk_warn, disk_crit),
    }


CPU_WARNING = _parse_threshold("CPU_WARNING", 70.0)
CPU_CRITICAL = _parse_threshold("CPU_CRITICAL", 90.0)

MEMORY_WARNING = _parse_threshold("MEMORY_WARNING", 80.0)
MEMORY_CRITICAL = _parse_threshold("MEMORY_CRITICAL", 90.0)

DISK_WARNING = _parse_threshold("DISK_WARNING", 80.0)
DISK_CRITICAL = _parse_threshold("DISK_CRITICAL", 90.0)


def get_memory_usage(proc_meminfo_path="/proc/meminfo"):
    memory = {}

    try:
        with open(proc_meminfo_path, encoding="utf-8") as file:
            for line in file:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    val_parts = parts[1].strip().split()
                    if val_parts:
                        try:
                            memory[key] = int(val_parts[0])
                        except ValueError:
                            continue
    except (OSError, FileNotFoundError):
        return {
            "total_mb": 0.0,
            "used_mb": 0.0,
            "available_mb": 0.0,
            "usage_percent": 0.0,
        }

    total = memory.get("MemTotal", 0)
    # MemAvailable was added in Linux 3.14. Fall back to MemFree + Buffers + Cached if missing
    available = memory.get(
        "MemAvailable",
        memory.get("MemFree", 0) + memory.get("Buffers", 0) + memory.get("Cached", 0),
    )

    if total <= 0:
        return {
            "total_mb": 0.0,
            "used_mb": 0.0,
            "available_mb": 0.0,
            "usage_percent": 0.0,
        }

    # Guard against available > total due to kernel counter timing
    available = max(0, min(total, available))
    used = total - available
    usage_percent = round((used / total) * 100, 2)

    return {
        "total_mb": round(total / 1024, 2),
        "used_mb": round(used / 1024, 2),
        "available_mb": round(available / 1024, 2),
        "usage_percent": max(0.0, min(100.0, usage_percent)),
    }


def get_disk_usage(path="/"):
    try:
        disk = shutil.disk_usage(path)
    except (OSError, FileNotFoundError):
        return {
            "total_gb": 0.0,
            "used_gb": 0.0,
            "free_gb": 0.0,
            "usage_percent": 0.0,
        }

    if disk.total <= 0:
        return {
            "total_gb": 0.0,
            "used_gb": 0.0,
            "free_gb": 0.0,
            "usage_percent": 0.0,
        }

    usage_percent = round((disk.used / disk.total) * 100, 2)
    return {
        "total_gb": round(disk.total / 1024**3, 2),
        "used_gb": round(disk.used / 1024**3, 2),
        "free_gb": round(disk.free / 1024**3, 2),
        "usage_percent": max(0.0, min(100.0, usage_percent)),
    }


def get_cpu_usage(interval=1.0, proc_stat_path="/proc/stat"):
    def read_cpu_times():
        try:
            with open(proc_stat_path, encoding="utf-8") as file:
                for line in file:
                    if line.startswith("cpu "):
                        return list(map(int, line.split()[1:]))
        except (OSError, FileNotFoundError):
            return []
        return []

    first = read_cpu_times()
    if not first or len(first) < 4:
        return 0.0

    if interval > 0:
        time.sleep(interval)

    second = read_cpu_times()
    if not second or len(second) < 4:
        return 0.0

    idle_first = first[3] + (first[4] if len(first) > 4 else 0)
    idle_second = second[3] + (second[4] if len(second) > 4 else 0)

    total_difference = sum(second) - sum(first)
    idle_difference = idle_second - idle_first

    if total_difference <= 0:
        return 0.0

    idle_difference = max(0, min(total_difference, idle_difference))
    usage = round(100 * (1 - idle_difference / total_difference), 2)
    return max(0.0, min(100.0, usage))


def classify_health(value, warning, critical):
    if value >= critical:
        return "CRITICAL"
    if value >= warning:
        return "WARNING"
    return "NORMAL"


def collect_metrics():
    cpu = get_cpu_usage()
    memory = get_memory_usage()
    disk = get_disk_usage()

    thresholds = get_thresholds()
    cpu_warn, cpu_crit = thresholds["cpu"]
    mem_warn, mem_crit = thresholds["memory"]
    disk_warn, disk_crit = thresholds["disk"]

    checks = {
        "cpu": classify_health(cpu, cpu_warn, cpu_crit),
        "memory": classify_health(
            memory["usage_percent"],
            mem_warn,
            mem_crit,
        ),
        "disk": classify_health(
            disk["usage_percent"],
            disk_warn,
            disk_crit,
        ),
    }

    statuses = {"NORMAL": 0, "WARNING": 1, "CRITICAL": 2}
    overall = max(checks.values(), key=statuses.get)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": platform.node(),
        "operating_system": platform.system(),
        "kernel": platform.release(),
        "cpu_usage_percent": cpu,
        "memory": memory,
        "disk": disk,
        "health_checks": checks,
        "overall_status": overall,
    }


def save_metrics(metrics):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(metrics) + "\n")


if __name__ == "__main__":
    metrics = collect_metrics()
    save_metrics(metrics)

    print(json.dumps(metrics, indent=4))
    print(f"\nOverall system health: {metrics['overall_status']}")
    print(f"Metrics saved to: {LOG_FILE}")

