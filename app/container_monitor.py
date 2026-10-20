#!/usr/bin/env python3

import json
import subprocess
from datetime import datetime, timezone


def get_containers(timeout=15):
    """Retrieve all Podman containers, including stopped ones."""
    result = subprocess.run(
        ["podman", "ps", "-a", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )

    raw_output = (result.stdout or "").strip()
    if not raw_output:
        return []

    data = json.loads(raw_output)
    if not isinstance(data, list):
        raise ValueError(
            "Podman ps returned unexpected data structure (expected a JSON list)."
        )

    return data


def collect_container_status():
    """Return a simplified status report for each container."""
    report = []
    error_message = None
    success = True

    try:
        raw_containers = get_containers()

        for item in raw_containers:
            if not isinstance(item, dict):
                continue

            name = item.get("Names") or item.get("names") or "unknown"
            if isinstance(name, list):
                name = ", ".join(str(n).lstrip("/") for n in name if n)
            elif isinstance(name, str):
                name = name.lstrip("/")
            else:
                name = "unknown"

            raw_id = item.get("Id") or item.get("id") or "unknown"
            container_id = str(raw_id)[:12] if raw_id else "unknown"

            image = str(item.get("Image") or item.get("image") or "unknown")
            raw_state = item.get("State") or item.get("state")
            state = (
                str(raw_state).strip().lower()
                if raw_state is not None
                else "unknown"
            )
            status = str(item.get("Status") or item.get("status") or "unknown")

            health = (
                "NORMAL" if state == "running"
                else "WARNING" if state in {"exited", "stopped"}
                else "UNKNOWN"
            )

            report.append({
                "id": container_id,
                "name": name,
                "image": image,
                "state": state,
                "status": status,
                "health": health,
            })

    except FileNotFoundError:
        success = False
        error_message = "Podman executable was not found on the system."
    except subprocess.TimeoutExpired:
        success = False
        error_message = "Podman command timed out while querying containers."
    except subprocess.CalledProcessError as exc:
        success = False
        stderr_msg = (exc.stderr or "").strip()
        error_message = (
            f"Podman command failed: {stderr_msg}"
            if stderr_msg
            else f"Podman command failed with exit code {exc.returncode}."
        )
    except (json.JSONDecodeError, ValueError) as exc:
        success = False
        error_message = f"Malformed container inventory data: {exc}"
    except Exception as exc:
        success = False
        error_message = f"Unexpected container monitoring error: {exc}"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "success": success,
        "error": error_message,
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
