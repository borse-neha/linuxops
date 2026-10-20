
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

CPU_WARNING = float(os.getenv("CPU_WARNING", "70"))
CPU_CRITICAL = float(os.getenv("CPU_CRITICAL", "90"))

MEMORY_WARNING = float(os.getenv("MEMORY_WARNING", "80"))
MEMORY_CRITICAL = float(os.getenv("MEMORY_CRITICAL", "90"))

DISK_WARNING = float(os.getenv("DISK_WARNING", "80"))
DISK_CRITICAL = float(os.getenv("DISK_CRITICAL", "90"))


def get_memory_usage():
    memory = {}

    with open("/proc/meminfo", encoding="utf-8") as file:
        for line in file:
            key, value = line.split(":", 1)
            memory[key] = int(value.strip().split()[0])

    total = memory["MemTotal"]
    available = memory["MemAvailable"]
    used = total - available

    return {
        "total_mb": round(total / 1024, 2),
        "used_mb": round(used / 1024, 2),
        "available_mb": round(available / 1024, 2),
        "usage_percent": round(used / total * 100, 2),
    }


def get_disk_usage():
    disk = shutil.disk_usage("/")

    return {
        "total_gb": round(disk.total / 1024**3, 2),
        "used_gb": round(disk.used / 1024**3, 2),
        "free_gb": round(disk.free / 1024**3, 2),
        "usage_percent": round(disk.used / disk.total * 100, 2),
    }


def get_cpu_usage():
    def read_cpu_times():
        with open("/proc/stat", encoding="utf-8") as file:
            return list(map(int, file.readline().split()[1:]))

    first = read_cpu_times()
    time.sleep(1)
    second = read_cpu_times()

    idle_first = first[3] + first[4]
    idle_second = second[3] + second[4]

    total_difference = sum(second) - sum(first)
    idle_difference = idle_second - idle_first

    if total_difference <= 0:
        return 0.0

    return round(
        100 * (1 - idle_difference / total_difference), 2
    )


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

    checks = {
        "cpu": classify_health(cpu, CPU_WARNING, CPU_CRITICAL),
        "memory": classify_health(
            memory["usage_percent"],
            MEMORY_WARNING,
            MEMORY_CRITICAL,
        ),
        "disk": classify_health(
            disk["usage_percent"],
            DISK_WARNING,
            DISK_CRITICAL,
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

