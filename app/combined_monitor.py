#!/usr/bin/env python3

import json
from datetime import datetime, timezone

from app.monitor import collect_metrics
from app.container_monitor import collect_container_status


def collect_combined_report():
    """Combine system metrics and container status."""

    system = collect_metrics()
    containers = collect_container_status()

    if containers["stopped_count"] > 0:
        container_health = "WARNING"
    else:
        container_health = "NORMAL"

    priority = {
        "NORMAL": 0,
        "WARNING": 1,
        "CRITICAL": 2,
    }

    overall_status = max(
        [system["overall_status"], container_health],
        key=priority.get,
    )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "project": "LinuxOps",
        "overall_status": overall_status,
        "system": system,
        "container_summary": {
            "total": containers["container_count"],
            "running": containers["running_count"],
            "stopped": containers["stopped_count"],
            "health": container_health,
        },
        "containers": containers["containers"],
    }


if __name__ == "__main__":
    try:
        report = collect_combined_report()
        print(json.dumps(report, indent=4))
    except Exception as error:
        print(f"Combined monitoring failed: {error}")
        raise SystemExit(1)
