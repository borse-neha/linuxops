
#!/usr/bin/env python3

import subprocess


def restart_container(container_name):
    """Safely start a stopped container and verify its state."""

    if not isinstance(container_name, str) or not container_name.strip():
        return {
            "success": False,
            "message": "Container name cannot be empty.",
        }

    try:
        # Step 1: Inspect the container before changing anything.
        inspect_result = subprocess.run(
            [
                "podman",
                "inspect",
                "--format",
                "{{.State.Status}}",
                container_name,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if inspect_result.returncode != 0:
            return {
                "success": False,
                "message": (
                    inspect_result.stderr.strip()
                    or "Container not found or inspection failed."
                ),
            }

        current_state = inspect_result.stdout.strip().lower()

        if current_state == "running":
            return {
                "success": False,
                "message": (
                    f"Container '{container_name}' is already running. "
                    "No recovery action was needed."
                ),
            }

        if current_state not in {"exited", "stopped"}:
            return {
                "success": False,
                "message": (
                    f"Container state is '{current_state}'. "
                    "Automatic start was not attempted."
                ),
            }

        # Step 2: Start the stopped container.
        start_result = subprocess.run(
            ["podman", "start", container_name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if start_result.returncode != 0:
            return {
                "success": False,
                "message": (
                    start_result.stderr.strip()
                    or "Podman could not start the container."
                ),
            }

        # Step 3: Verify the container's current state.
        verify_result = subprocess.run(
            [
                "podman",
                "inspect",
                "--format",
                "{{.State.Running}}",
                container_name,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if verify_result.returncode != 0:
            return {
                "success": False,
                "message": (
                    "Start command succeeded, but the final state "
                    "could not be verified."
                ),
            }

        if verify_result.stdout.strip().lower() == "true":
            return {
                "success": True,
                "message": (
                    f"Container '{container_name}' is running. "
                    "Initial recovery verification succeeded."
                ),
            }

        return {
            "success": False,
            "message": (
                f"Container '{container_name}' exited or stopped "
                "after startup. Inspect its logs and exit code."
            ),
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "Container recovery timed out.",
        }

    except FileNotFoundError:
        return {
            "success": False,
            "message": "Podman command was not found.",
        }

