
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
                    '"exit_code":{{json .State.ExitCode}},'
                    '"oom_killed":{{json .State.OOMKilled}}}'
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
        if not isinstance(details, dict):
            return {
                "success": False,
                "message": "Container inspection returned unexpected data format.",
            }

        state = str(details.get("state") or "").strip().lower() or "unknown"
        raw_exit = details.get("exit_code")
        try:
            exit_code = int(raw_exit) if raw_exit is not None else None
        except (TypeError, ValueError):
            exit_code = None

        oom_killed = bool(details.get("oom_killed", False))
        reported_name = str(details.get("name") or container_name).lstrip("/")

        if state == "running":
            diagnosis = "Container is running; no stopped-container recovery is needed."
            recommendation = "MONITOR"

        elif state in {"created", "configured"}:
            diagnosis = f"Container has not started normally; current state is {state}."
            recommendation = "INVESTIGATE"

        elif state == "paused":
            diagnosis = "Container is paused; process execution is suspended."
            recommendation = "INVESTIGATE"

        elif state == "restarting":
            diagnosis = "Container is currently in a restart loop or restarting."
            recommendation = "INVESTIGATE"

        elif state in {"exited", "stopped"}:
            if oom_killed:
                diagnosis = (
                    "Podman confirms the container was terminated by the OOM killer "
                    f"(exit code {exit_code}). The container exceeded its memory limit "
                    "or the host ran out of memory."
                )
                recommendation = "HUMAN_REVIEW"

            elif exit_code == 0:
                diagnosis = "Container exited with code 0; it may have completed normally."
                recommendation = "NO_ACTION_UNLESS_SERVICE_EXPECTED"

            elif exit_code == 137:
                diagnosis = (
                    "Container terminated by SIGKILL (exit code 137). "
                    "Podman does not report an OOM kill. Possible causes include "
                    "a stop timeout, manual kill, or cgroup termination."
                )
                recommendation = "INVESTIGATE"

            elif exit_code is not None and exit_code > 128:
                sig_num = exit_code - 128
                diagnosis = f"Container terminated by signal {sig_num} (exit code {exit_code})."
                recommendation = "CHECK_LOGS"

            elif exit_code is not None:
                diagnosis = f"Container exited with non-zero code {exit_code}."
                recommendation = "CHECK_LOGS"

            else:
                diagnosis = "Container is stopped with an unknown exit code."
                recommendation = "CHECK_LOGS"

        else:
            diagnosis = f"Container is in an unexpected state: '{state}'."
            recommendation = "INVESTIGATE"

        # Log retrieval is handled defensively so log errors do not mask container diagnosis
        recent_logs = ""
        try:
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
                timeout=10,
                check=False,
            )
            if log_result.returncode == 0:
                recent_logs = (
                    (log_result.stdout or "") + (log_result.stderr or "")
                ).strip()
            else:
                err_msg = log_result.stderr.strip() or f"exit code {log_result.returncode}"
                recent_logs = f"(Log retrieval failed: {err_msg})"
        except subprocess.TimeoutExpired:
            recent_logs = "(Log retrieval timed out)"
        except Exception as log_err:
            recent_logs = f"(Log retrieval error: {log_err})"

        return {
            "success": True,
            "container": reported_name,
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

    except (json.JSONDecodeError, KeyError, TypeError, ValueError, AttributeError) as error:
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

