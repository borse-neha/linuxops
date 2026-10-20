#!/usr/bin/env python3

"""
LinuxOps Recovery & Policy History Module.

Maintains separate, isolated audit logs for:
1. Actual container recovery execution attempts (recovery_history.jsonl)
2. Standalone recovery policy evaluation decisions (policy_history.jsonl)
"""

import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_HISTORY_PATH = (
    Path(__file__).resolve().parent.parent
    / "logs"
    / "recovery_history.jsonl"
)

DEFAULT_POLICY_HISTORY_PATH = (
    Path(__file__).resolve().parent.parent
    / "logs"
    / "policy_history.jsonl"
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
        "container": container_name.strip(),
        "success": bool(result.get("success", False)),
        "message": str(result.get("message", "No message provided.")),
    }

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    return event


def load_recovery_history(limit=20, history_path=None):
    """Return the most recent valid recovery events first."""

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        return []

    path = Path(history_path) if history_path else DEFAULT_HISTORY_PATH

    if not path.exists():
        return []

    events = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                event = json.loads(line_str)
                # Keep recovery history strictly isolated from policy records
                if (
                    isinstance(event, dict)
                    and event.get("event_type") != "policy_decision"
                    and event.get("action") == "start_container"
                ):
                    events.append(event)
            except json.JSONDecodeError:
                continue

    return list(reversed(events[-limit:]))


def record_policy_decision(container_name, decision_result, history_path=None):
    """Append one policy evaluation audit decision to the policy history log."""

    if not isinstance(container_name, str) or not container_name.strip():
        raise ValueError("Container name cannot be empty.")

    if not isinstance(decision_result, dict):
        raise ValueError("Policy decision result must be a dictionary.")

    decision_raw = decision_result.get("decision") or decision_result.get("action")
    if not isinstance(decision_raw, str):
        raise ValueError("Policy decision must include a valid 'decision' string ('ALLOW' or 'DENY').")

    decision = decision_raw.strip().upper()
    if decision not in {"ALLOW", "DENY"}:
        raise ValueError(f"Invalid policy decision '{decision}'; must be 'ALLOW' or 'DENY'.")

    allowed = decision_result.get("allowed")
    if not isinstance(allowed, bool):
        raise ValueError("Policy decision must include a boolean 'allowed' flag.")

    # Ensure decision and allowed agree
    if (decision == "ALLOW" and not allowed) or (decision == "DENY" and allowed):
        raise ValueError(
            f"Inconsistent policy decision: decision is '{decision}' but allowed is {allowed}."
        )

    # Strictly require dry_run: True
    if decision_result.get("dry_run") is not True:
        raise ValueError("Policy records must have dry_run set to True.")

    checks = decision_result.get("checks", {})
    if not isinstance(checks, dict):
        raise ValueError("Policy decision 'checks' field must be a dictionary.")

    reason = str(decision_result.get("reason", "No reason provided."))

    path = Path(history_path) if history_path else DEFAULT_POLICY_HISTORY_PATH

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "policy_decision",
        "action": "evaluate_policy",
        "container": container_name.strip(),
        "decision": decision,
        "allowed": allowed,
        "reason": reason,
        "checks": checks,
        "dry_run": True,
    }

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    return event


def load_policy_history(limit=20, history_path=None):
    """Return the most recent valid policy decision records first."""

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        return []

    path = Path(history_path) if history_path else DEFAULT_POLICY_HISTORY_PATH

    if not path.exists():
        return []

    events = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                event = json.loads(line_str)
                if isinstance(event, dict) and event.get("event_type") == "policy_decision":
                    events.append(event)
            except json.JSONDecodeError:
                continue

    return list(reversed(events[-limit:]))


def format_policy_history_rows(policy_events):
    """Format policy audit events into display rows for dashboards or tables."""
    if not policy_events:
        return []
    return [
        {
            "Timestamp (UTC)": event.get("timestamp", "N/A"),
            "Container": event.get("container", "N/A"),
            "Decision": str(event.get("decision", "N/A")).upper(),
            "Reason": str(event.get("reason", "")),
            "Dry Run": "TRUE" if event.get("dry_run") else "FALSE",
        }
        for event in policy_events
        if isinstance(event, dict)
    ]


def format_recovery_history_rows(recovery_events):
    """Format recovery attempt events into display rows for dashboards or tables."""
    if not recovery_events:
        return []
    return [
        {
            "Timestamp (UTC)": event.get("timestamp", "N/A"),
            "Container": event.get("container", "N/A"),
            "Status": "SUCCESS" if event.get("success") else "FAILED",
            "Message": str(event.get("message", "")),
        }
        for event in recovery_events
        if isinstance(event, dict)
    ]


if __name__ == "__main__":
    history = load_recovery_history()
    print(json.dumps(history, indent=4))
