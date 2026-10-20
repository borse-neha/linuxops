#!/usr/bin/env python3

import json
import subprocess
from datetime import datetime, timezone


def get_containers():
    """Retrieve all Podman containers, including stopped ones."""
    result = subprocess.run(
        ["podman", "ps", "-a", "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )

    return json.loads(result.stdout or "[]")


def collect_container_status():
    """Return a simplified status report for each container."""
    containers = get_containers()
    report = []

    for container in containers:
        name = container.get("Names", "unknown")

        if isinstance(name, list):
            name = ", ".join(name)

        state = container.get("State", "unknown").lower()

        report.append({
            "id": container.get("Id", "unknown")[:12],
            "name": name,
            "image": container.get("Image", "unknown"),
            "state": state,
            "status": container.get("Status", "unknown"),
            "health": (
                "NORMAL" if state == "running"
                else "WARNING" if state in {"exited", "stopped"}
                else "UNKNOWN"
            ),
        })

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "container_count": len(report),
        "running_count": sum(
            item["state"] == "running" for item in report
        ),
        "stopped_count": sum(
            item["state"] in {"exited", "stopped"} for item in report
        ),
        "containers": report,
    }


if __name__ == "__main__":
    try:
        result = collect_container_status()
        print(json.dumps(result, indent=4))
    except (subprocess.CalledProcessError, FileNotFoundError,
            json.JSONDecodeError) as error:
        print(f"Container monitoring failed: {error}")
        raise SystemExit(1)
