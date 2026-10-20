
import re
import subprocess

CONTAINER_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")


def validate_container_name(container_name):
    """Validate that the container name conforms to safe Podman naming rules."""
    if not isinstance(container_name, str) or not container_name.strip():
        return False, "Container name cannot be empty."

    name = container_name.strip()

    if name.startswith("-"):
        return (
            False,
            f"Invalid container name: '{container_name}'. "
            "Names starting with a dash are not permitted.",
        )

    if not CONTAINER_NAME_PATTERN.match(name):
        return (
            False,
            f"Invalid container name: '{container_name}'. "
            "Container names must start with an alphanumeric character and "
            "contain only letters, numbers, underscores, periods, and hyphens.",
        )

    return True, name


def restart_container(container_name):
    """Safely start a stopped container and verify its state."""

    is_valid, validation_msg = validate_container_name(container_name)
    if not is_valid:
        return {
            "success": False,
            "message": validation_msg,
        }

    name = validation_msg

    try:
        # Step 1: Inspect the container before changing anything.
        try:
            inspect_result = subprocess.run(
                [
                    "podman",
                    "inspect",
                    "--format",
                    "{{.State.Status}}",
                    name,
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "message": "Container inspection timed out before recovery.",
            }

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
                    f"Container '{name}' is already running. "
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
        try:
            start_result = subprocess.run(
                ["podman", "start", name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "message": "Podman start command timed out.",
            }

        if start_result.returncode != 0:
            return {
                "success": False,
                "message": (
                    start_result.stderr.strip()
                    or "Podman could not start the container."
                ),
            }

        # Step 3: Verify the container's current state.
        try:
            verify_result = subprocess.run(
                [
                    "podman",
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    name,
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "message": "Post-start verification timed out.",
            }

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
                    f"Container '{name}' is running. "
                    "Initial recovery verification succeeded."
                ),
            }

        return {
            "success": False,
            "message": (
                f"Container '{name}' exited or stopped "
                "after startup. Inspect its logs and exit code."
            ),
        }

    except FileNotFoundError:
        return {
            "success": False,
            "message": "Podman command was not found.",
        }

    except PermissionError as error:
        return {
            "success": False,
            "message": f"Permission denied during container recovery: {error}",
        }

    except OSError as error:
        return {
            "success": False,
            "message": f"Operating system error during container recovery: {error}",
        }

    except Exception as error:
        return {
            "success": False,
            "message": f"Unexpected error during container recovery: {error}",
        }

