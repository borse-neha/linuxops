
#!/usr/bin/env python3

import json
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_HISTORY_PATH = (
    Path(__file__).resolve().parent.parent
    / "logs"
    / "recovery_history.jsonl"
)


def record_recovery_event(container_name, result, history_path=None):
    """Append one recovery attempt to the audit log."""

    if not isinstance(container_name, str) or not container_name.strip():
        raise ValueError("Container name cannot be empty.")

    if not isinstance(result, dict):
        raise ValueError("Recovery result must be a dictionary.")

    path = Path(history_path) if history_path else DEFAULT_HISTORY_PATH

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "start_container",
        "container": container_name,
        "success": bool(result.get("success", False)),
        "message": str(result.get("message", "No message provided.")),
    }

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    return event


def load_recovery_history(limit=20, history_path=None):
    """Return the most recent valid recovery events first."""

    if limit <= 0:
        return []

    path = Path(history_path) if history_path else DEFAULT_HISTORY_PATH

    if not path.exists():
        return []

    events = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
            except json.JSONDecodeError:
                continue

    return list(reversed(events[-limit:]))


if __name__ == "__main__":
    history = load_recovery_history()
    print(json.dumps(history, indent=4))

