
#!/usr/bin/env python3

import json
import os
import platform
import shutil
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


_CPU_LOCK = threading.Lock()
# Maps proc_stat_path -> (times: list[int], timestamp: float)
_LAST_CPU_SAMPLE: dict[str, tuple[list[int], float]] = {}


def _read_cpu_times(proc_stat_path: str = "/proc/stat") -> list[int]:
    """Read CPU times from /proc/stat. Returns empty list on missing/malformed data."""
    try:
        with open(proc_stat_path, encoding="utf-8") as file:
            for line in file:
                if line.startswith("cpu "):
                    parts = line.split()[1:]
                    return [int(p) for p in parts if p.isdigit()]
    except (OSError, FileNotFoundError, ValueError):
        return []
    return []


# Seed initial baseline sample on module import without blocking or sleeping
try:
    with _CPU_LOCK:
        _initial_stat = "/proc/stat"
        _init_times = _read_cpu_times(_initial_stat)
        if _init_times and len(_init_times) >= 4:
            _LAST_CPU_SAMPLE[_initial_stat] = (_init_times, time.monotonic())
except Exception:
    pass


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


def get_cpu_usage(interval: float | None = None, proc_stat_path: str = "/proc/stat") -> float | None:
    """
    Calculate CPU utilization percentage from /proc/stat.

    Modes:
    1. Stateful Non-Blocking Sampling (default: interval=None):
       Reads current counters from proc_stat_path and compares against the previous
       cached sample for that path.
       - Does NOT sleep.
       - Returns None if no prior sample exists (documented warm-up / unavailable state).
       - Serializes reading counters, timestamping, baseline comparison, and updating under threading.Lock without sleeping.
       - Handles zero delta, counter resets, and missing files safely.

    2. Explicit Blocking Sampling (interval is not None and interval >= 0):
       Preserves backward compatibility for callers and tests that explicitly request an interval.
       - Reads first sample.
       - Sleeps for `interval` seconds if interval > 0.
       - Reads second sample.
       - Computes delta and returns float percentage.
    """
    # Mode 2: Explicit interval requested
    if interval is not None and interval >= 0:
        first = _read_cpu_times(proc_stat_path)
        if not first or len(first) < 4:
            return 0.0

        if interval > 0:
            time.sleep(interval)

        second = _read_cpu_times(proc_stat_path)
        if not second or len(second) < 4:
            return 0.0

        idle_first = first[3] + (first[4] if len(first) > 4 else 0)
        idle_second = second[3] + (second[4] if len(second) > 4 else 0)

        total_difference = sum(second) - sum(first)
        idle_difference = idle_second - idle_first

        if total_difference <= 0:
            return 0.0

        idle_difference = max(0, min(total_difference, idle_difference))
        usage = round(100.0 * (1.0 - idle_difference / total_difference), 2)
        return max(0.0, min(100.0, usage))

    # Mode 1: Stateful non-blocking sampling (interval is None)
    with _CPU_LOCK:
        curr_times = _read_cpu_times(proc_stat_path)
        if not curr_times or len(curr_times) < 4:
            return None

        curr_time = time.monotonic()
        prev_entry = _LAST_CPU_SAMPLE.get(proc_stat_path)

        # Ensure a stale sample cannot overwrite a newer baseline
        if prev_entry is not None and curr_time < prev_entry[1]:
            return None

        _LAST_CPU_SAMPLE[proc_stat_path] = (curr_times, curr_time)

        if prev_entry is None:
            # First sample recorded; awaiting subsequent sample for delta calculation
            return None

        prev_times, _ = prev_entry

        idle_prev = prev_times[3] + (prev_times[4] if len(prev_times) > 4 else 0)
        idle_curr = curr_times[3] + (curr_times[4] if len(curr_times) > 4 else 0)

        total_diff = sum(curr_times) - sum(prev_times)
        idle_diff = idle_curr - idle_prev

        # Counter reset (system reboot, kernel overflow, or tick reset)
        # The new baseline is already saved in _LAST_CPU_SAMPLE. Return None (unavailable).
        if total_diff < 0 or idle_diff < 0:
            return None

        # Zero total delta: no ticks elapsed, unavailable
        if total_diff == 0:
            return None

        # Impossible idle delta (idle increase exceeds total elapsed ticks)
        if idle_diff > total_diff:
            return None

        usage = round(100.0 * (1.0 - idle_diff / total_diff), 2)
        return max(0.0, min(100.0, usage))



def classify_health(value, warning, critical):
    if value is None:
        return "UNKNOWN"
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

    statuses = {"UNKNOWN": -1, "NORMAL": 0, "WARNING": 1, "CRITICAL": 2}
    overall = max(checks.values(), key=lambda s: statuses.get(s, -1))
    if overall == "UNKNOWN":
        overall = "NORMAL"

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


def _parse_and_normalize_timestamp(ts) -> datetime | None:
    """Safely parse an ISO-8601 string or datetime object into a UTC timezone-aware datetime."""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    if isinstance(ts, str) and ts.strip():
        s = ts.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except (ValueError, TypeError):
            return None
    return None


def get_metric_trends(
    limit: int = 100,
    since: datetime | str | None = None,
    until: datetime | str | None = None,
    metrics_path: Path | str | None = None,
) -> list[dict]:
    """
    Extract a bounded sequence of recent metric samples for trend analysis and charting.

    Features:
    - Bounded memory read: uses collections.deque to stream lines without loading the full log into memory.
    - Explicit time-window filtering: filters by [since, until] timestamps.
    - Timezone normalization: converts timestamps to UTC timezone-aware ISO-8601 strings.
    - Chronological ordering: returns samples in ascending chronological order.
    - Value preservation: retains original metric values without fabrication or interpolation.
    - Safe error handling: skips malformed JSON, missing timestamps, and missing files without crashing.

    Note on filtering:
    The record 'limit' applies AFTER timestamp filtering: up to the most recent 'limit'
    samples that fall within the specified [since, until] window are retained and returned.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        return []

    path = Path(metrics_path) if metrics_path else LOG_FILE
    if not path.exists():
        return []

    since_dt = _parse_and_normalize_timestamp(since) if since is not None else None
    until_dt = _parse_and_normalize_timestamp(until) if until is not None else None

    # If caller provided an explicit since or until that could not be parsed, treat as invalid window
    if since is not None and since_dt is None:
        return []
    if until is not None and until_dt is None:
        return []
    if since_dt is not None and until_dt is not None and since_dt > until_dt:
        return []

    matching_samples = deque(maxlen=limit)

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line_str = line.strip()
            if not line_str:
                continue

            try:
                sample = json.loads(line_str)
            except json.JSONDecodeError:
                continue

            if not isinstance(sample, dict):
                continue

            raw_ts = sample.get("timestamp")
            sample_dt = _parse_and_normalize_timestamp(raw_ts)
            if sample_dt is None:
                continue

            # Time-window filtering
            if since_dt is not None and sample_dt < since_dt:
                continue
            if until_dt is not None and sample_dt > until_dt:
                continue

            # Normalize timestamp to UTC ISO-8601 string while preserving original metrics
            sample_copy = dict(sample)
            sample_copy["timestamp"] = sample_dt.isoformat()
            matching_samples.append((sample_dt, sample_copy))

    # Return matching samples sorted in ascending chronological order
    sorted_samples = sorted(matching_samples, key=lambda item: item[0])
    return [item[1] for item in sorted_samples]


if __name__ == "__main__":
    metrics = collect_metrics()
    save_metrics(metrics)

    print(json.dumps(metrics, indent=4))
    print(f"\nOverall system health: {metrics['overall_status']}")
    print(f"Metrics saved to: {LOG_FILE}")

