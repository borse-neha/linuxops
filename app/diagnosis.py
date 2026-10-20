
#!/usr/bin/env python3

import json
import subprocess


def diagnose_container(container_name):
    """Collect container state, exit code, and recent logs."""

    if not isinstance(container_name, str) or not container_name.strip():
        return {
            "success": False,
            "message": "Container name cannot be empty.",
        }

    try:
        result = subprocess.run(
            [
                "podman",
                "inspect",
                "--format",
                (
                    '{"name":{{json .Name}},'
                    '"state":{{json .State.Status}},'
                    '"exit_code":{{.State.ExitCode}},'
                    '"oom_killed":{{.State.OOMKilled}}}'
                ),
                container_name,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if result.returncode != 0:
            return {
                "success": False,
                "message": (
                    result.stderr.strip()
                    or "Container inspection failed."
                ),
            }

        details = json.loads(result.stdout)
        state = details["state"].lower()
        exit_code = details["exit_code"]
        oom_killed = details.get("oom_killed", False)

        if state == "running":
            diagnosis = "Container is running; no stopped-container recovery is needed."
            recommendation = "MONITOR"

        elif state in {"created", "configured"}:
            diagnosis = f"Container has not started normally; current state is {state}."
            recommendation = "INVESTIGATE"

        elif exit_code == 0:
            diagnosis = "Container exited with code 0; it may have completed normally."
            recommendation = "NO_ACTION_UNLESS_SERVICE_EXPECTED"

        elif oom_killed:
            diagnosis = "Podman reports that the container was OOM-killed."
            recommendation = "HUMAN_REVIEW"

        elif exit_code == 137:
            diagnosis = "Container exited with code 137; it may have been killed."
            recommendation = "INVESTIGATE"

        else:
            diagnosis = f"Container exited with non-zero code {exit_code}."
            recommendation = "CHECK_LOGS"

        log_result = subprocess.run(
            [
                "podman",
                "logs",
                "--tail",
                "20",
                container_name,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        recent_logs = (
            (log_result.stdout or "") + (log_result.stderr or "")
        ).strip()

        return {
            "success": True,
            "container": details["name"],
            "state": state,
            "exit_code": exit_code,
            "oom_killed": oom_killed,
            "diagnosis": diagnosis,
            "recommendation": recommendation,
            "recent_logs": recent_logs,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "Container diagnosis timed out.",
        }

    except FileNotFoundError:
        return {
            "success": False,
            "message": "Podman command was not found.",
        }

    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        return {
            "success": False,
            "message": f"Could not interpret container inspection: {error}",
        }


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: python -m app.diagnosis CONTAINER_NAME")
        raise SystemExit(2)

    print(json.dumps(diagnose_container(sys.argv[1]), indent=4))

