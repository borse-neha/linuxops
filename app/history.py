#!/usr/bin/env python3

"""
LinuxOps Recovery & Policy History Module.

Maintains separate, isolated audit logs for:
1. Actual container recovery execution attempts (recovery_history.jsonl)
2. Standalone recovery policy evaluation decisions (policy_history.jsonl)
"""

from collections import deque
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import shutil

logger = logging.getLogger(__name__)

from app.diagnostics_engine import redact_sensitive_text
from app.monitor import get_metric_trends

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

DEFAULT_INCIDENTS_PATH = (
    Path(__file__).resolve().parent.parent
    / "logs"
    / "incidents.jsonl"
)


def record_recovery_event(container_name, result, history_path=None):
    """Append one recovery attempt to the audit log with durable sync and strict permissions."""

    if not isinstance(container_name, str) or not container_name.strip():
        raise ValueError("Container name cannot be empty.")

    if not isinstance(result, dict):
        raise ValueError("Recovery result must be a dictionary.")

    path = Path(history_path) if history_path else DEFAULT_HISTORY_PATH

    action_val = str(result.get("action") or "start_container")
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action_val,
        "container": container_name.strip(),
        "success": bool(result.get("success", False)),
        "message": redact_sensitive_text(str(result.get("message", "No message provided."))),
    }
    if "verification_status" in result:
        event["verification_status"] = str(result["verification_status"])
    if "approval_token" in result and result["approval_token"]:
        event["approval_token"] = str(result["approval_token"])
    if "plan_id" in result and result["plan_id"]:
        event["plan_id"] = str(result["plan_id"])
    if "decision" in result and result["decision"]:
        event["decision"] = str(result["decision"])

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass

        with path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")
            file.flush()
            os.fsync(file.fileno())

        try:
            path.chmod(0o600)
        except OSError:
            pass
    except (PermissionError, OSError) as exc:
        logger.error(f"Failed to persist recovery audit event for '{container_name}': {exc}")
        raise

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

    reason = redact_sensitive_text(str(decision_result.get("reason", "No reason provided.")))

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

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass

        with path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")
            file.flush()
            os.fsync(file.fileno())

        try:
            path.chmod(0o600)
        except OSError:
            pass
    except (PermissionError, OSError) as exc:
        logger.error(f"Failed to persist policy audit decision for '{container_name}': {exc}")
        raise

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


def get_policy_decision_stats(limit=100, history_path=None):
    """
    Compute operational analytics on recent recovery policy evaluation decisions.

    Reads up to a bounded number of recent lines from policy_history.jsonl.
    Reports:
    - total_evaluations: count of valid policy evaluations analyzed
    - allow_count: count of ALLOW decisions
    - deny_count: count of DENY decisions
    - denial_reasons: dictionary mapping recorded denial reasons to occurrence counts
    - most_frequent_denial_reason: string of the most common denial reason (or None)
    - skipped_records: count of malformed, invalid, or non-policy records skipped
    """
    default_stats = {
        "total_evaluations": 0,
        "allow_count": 0,
        "deny_count": 0,
        "denial_reasons": {},
        "most_frequent_denial_reason": None,
        "skipped_records": 0,
    }

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        return default_stats

    path = Path(history_path) if history_path else DEFAULT_POLICY_HISTORY_PATH
    if not path.exists():
        return default_stats

    recent_lines = deque(maxlen=limit)
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line_str = line.strip()
            if line_str:
                recent_lines.append(line_str)

    total_evaluations = 0
    allow_count = 0
    deny_count = 0
    denial_reasons = {}
    skipped_records = 0

    for line_str in recent_lines:
        try:
            event = json.loads(line_str)
        except json.JSONDecodeError:
            skipped_records += 1
            continue

        if not isinstance(event, dict):
            skipped_records += 1
            continue

        # Keep strictly isolated: ignore or skip non-policy records
        if event.get("event_type") != "policy_decision":
            skipped_records += 1
            continue

        raw_decision = event.get("decision")
        if not isinstance(raw_decision, str):
            skipped_records += 1
            continue

        decision = raw_decision.strip().upper()
        if decision not in {"ALLOW", "DENY"}:
            skipped_records += 1
            continue

        allowed = event.get("allowed")
        if not isinstance(allowed, bool):
            skipped_records += 1
            continue

        if (decision == "ALLOW" and not allowed) or (decision == "DENY" and allowed):
            skipped_records += 1
            continue

        container = event.get("container")
        if not isinstance(container, str) or not container.strip():
            skipped_records += 1
            continue

        if event.get("dry_run") is not True:
            skipped_records += 1
            continue

        total_evaluations += 1
        if decision == "ALLOW":
            allow_count += 1
        else:
            deny_count += 1
            reason = str(event.get("reason", "No reason provided.")).strip()
            denial_reasons[reason] = denial_reasons.get(reason, 0) + 1

    most_frequent_denial_reason = None
    if denial_reasons:
        most_frequent_denial_reason = max(denial_reasons.items(), key=lambda x: x[1])[0]

    return {
        "total_evaluations": total_evaluations,
        "allow_count": allow_count,
        "deny_count": deny_count,
        "denial_reasons": denial_reasons,
        "most_frequent_denial_reason": most_frequent_denial_reason,
        "skipped_records": skipped_records,
    }


def get_recovery_success_rate(limit=100, history_path=None):
    """
    Compute operational statistics on recent recovery execution attempts.

    Reads up to a bounded number of recent lines from recovery_history.jsonl.
    Reports:
    - total_attempts: total valid recovery execution attempts analyzed
    - successful_recoveries: count where post-start verification verified success
    - failed_recoveries: count where recovery execution failed
    - unknown_outcomes: count where action is recovery but outcome is not verifiable as bool
    - success_rate_percent: percentage of successful recoveries over denominator
    - denominator: total_attempts (explicitly reported)
    - skipped_records: count of malformed, invalid, or policy records skipped
    - verified_success_supported: True
    """
    default_stats = {
        "total_attempts": 0,
        "successful_recoveries": 0,
        "failed_recoveries": 0,
        "unknown_outcomes": 0,
        "success_rate_percent": 0.0,
        "denominator": 0,
        "skipped_records": 0,
        "verified_success_supported": True,
    }

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        return default_stats

    path = Path(history_path) if history_path else DEFAULT_HISTORY_PATH
    if not path.exists():
        return default_stats

    recent_lines = deque(maxlen=limit)
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line_str = line.strip()
            if line_str:
                recent_lines.append(line_str)

    successful_recoveries = 0
    failed_recoveries = 0
    unknown_outcomes = 0
    skipped_records = 0

    for line_str in recent_lines:
        try:
            event = json.loads(line_str)
        except json.JSONDecodeError:
            skipped_records += 1
            continue

        if not isinstance(event, dict):
            skipped_records += 1
            continue

        # Exclude policy decisions from recovery statistics
        if event.get("event_type") == "policy_decision":
            skipped_records += 1
            continue

        if event.get("action") != "start_container":
            skipped_records += 1
            continue

        container = event.get("container")
        if not isinstance(container, str) or not container.strip():
            skipped_records += 1
            continue

        success_val = event.get("success")
        if isinstance(success_val, bool):
            if success_val is True:
                successful_recoveries += 1
            else:
                failed_recoveries += 1
        else:
            unknown_outcomes += 1

    total_attempts = successful_recoveries + failed_recoveries + unknown_outcomes
    denominator = total_attempts
    success_rate_percent = (
        round((successful_recoveries / denominator) * 100.0, 2)
        if denominator > 0
        else 0.0
    )

    return {
        "total_attempts": total_attempts,
        "successful_recoveries": successful_recoveries,
        "failed_recoveries": failed_recoveries,
        "unknown_outcomes": unknown_outcomes,
        "success_rate_percent": success_rate_percent,
        "denominator": denominator,
        "skipped_records": skipped_records,
        "verified_success_supported": True,
    }


def load_incident_history(limit: int = 50, incidents_path: Path | None = None) -> list[dict]:
    """Return the most recent incident resolution events first."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        return []

    path = Path(incidents_path) if incidents_path else DEFAULT_INCIDENTS_PATH
    if not path.exists():
        return []

    events = []
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    data = json.loads(stripped)
                    if isinstance(data, dict):
                        events.append(data)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []

    return list(reversed(events))[:limit]


def format_incident_history_rows(events: list[dict]) -> list[dict]:
    """Format incident resolution history events into presentation rows."""
    if not isinstance(events, list):
        return []

    rows = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        rows.append({
            "Timestamp (UTC)": ev.get("timestamp", "N/A"),
            "Incident ID": ev.get("incident_id", "N/A"),
            "Container": ev.get("container_name", "N/A"),
            "Rule ID": ev.get("rule_id", "N/A"),
            "Status": ev.get("resolution_status", "UNKNOWN"),
            "Message": ev.get("message", "N/A"),
        })
    return rows


def record_incident_resolution(
    incident: dict,
    resolution_status: str,
    message: str,
    incidents_path: Path | None = None,
) -> dict:
    """Record incident resolution or escalation into logs/incidents.jsonl with sync and permissions."""
    path = Path(incidents_path) if incidents_path else DEFAULT_INCIDENTS_PATH
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident_id": incident.get("incident_id") if isinstance(incident, dict) else "unknown",
            "container_name": incident.get("container_name") if isinstance(incident, dict) else "unknown",
            "rule_id": incident.get("rule_id") if isinstance(incident, dict) else "unknown",
            "resolution_status": resolution_status,
            "message": redact_sensitive_text(str(message or "")),
        }

        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
            f.flush()
            os.fsync(f.fileno())

        try:
            path.chmod(0o600)
        except OSError:
            pass

        return record
    except (PermissionError, OSError) as exc:
        logger.error(f"Failed to persist incident resolution to {path}: {exc}")
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident_id": incident.get("incident_id") if isinstance(incident, dict) else "unknown",
            "resolution_status": resolution_status,
            "error": str(exc),
        }


def inspect_audit_log_integrity(log_path: Path | str) -> dict:
    """
    Programmatically verify any JSONL audit log without mutating data.
    Counts valid JSON records, corrupted/malformed lines, empty lines, and verifies file permissions.
    """
    path = Path(log_path)
    if not path.exists():
        return {
            "path": str(path),
            "exists": False,
            "total_lines": 0,
            "valid_records": 0,
            "corrupted_records": 0,
            "empty_lines": 0,
            "size_bytes": 0,
            "permissions": None,
            "is_healthy": True,
        }

    total_lines = 0
    valid_records = 0
    corrupted_records = 0
    empty_lines = 0

    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                total_lines += 1
                stripped = line.strip()
                if not stripped:
                    empty_lines += 1
                    continue
                try:
                    data = json.loads(stripped)
                    if isinstance(data, dict):
                        valid_records += 1
                    else:
                        corrupted_records += 1
                except json.JSONDecodeError:
                    corrupted_records += 1
    except (PermissionError, OSError) as exc:
        return {
            "path": str(path),
            "exists": True,
            "error": str(exc),
            "is_healthy": False,
        }

    try:
        stat = path.stat()
        perm_str = oct(stat.st_mode & 0o777)
        size = stat.st_size
    except OSError:
        perm_str = None
        size = 0

    return {
        "path": str(path),
        "exists": True,
        "total_lines": total_lines,
        "valid_records": valid_records,
        "corrupted_records": corrupted_records,
        "empty_lines": empty_lines,
        "size_bytes": size,
        "permissions": perm_str,
        "is_healthy": (corrupted_records == 0),
    }


def rotate_audit_log(
    log_path: Path | str,
    max_bytes: int = 10_000_000,
    backup_count: int = 5,
) -> dict:
    """
    Safely rotate an audit log when size exceeds max_bytes, without deleting historical records.
    Cycles existing logs through log_path.1, log_path.2, ... up to backup_count.
    """
    path = Path(log_path)
    if not path.exists():
        return {"rotated": False, "reason": "File does not exist"}

    try:
        if path.stat().st_size < max_bytes:
            return {"rotated": False, "reason": f"File size ({path.stat().st_size} B) is below threshold ({max_bytes} B)"}

        for i in range(backup_count - 1, 0, -1):
            sfn = path.with_name(f"{path.name}.{i}")
            dfn = path.with_name(f"{path.name}.{i + 1}")
            if sfn.exists():
                sfn.replace(dfn)

        backup_target = path.with_name(f"{path.name}.1")
        path.replace(backup_target)

        # Create fresh replacement file with 0600 permissions
        path.touch(mode=0o600, exist_ok=True)
        return {"rotated": True, "archived_to": str(backup_target)}
    except (PermissionError, OSError) as exc:
        logger.error(f"Failed to rotate audit log {path}: {exc}")
        return {"rotated": False, "error": str(exc)}


def __getattr__(name):
    """Lazy re-export of Phase 12 operational analytics and intelligence utilities."""
    if name in (
        "get_unified_incident_timeline",
        "format_timeline_rows",
        "compute_operational_reliability_metrics",
        "evaluate_advanced_operational_alerts",
        "get_explainable_diagnostic_guidance",
        "get_watchdog_status",
    ):
        import app.analytics as _analytics
        return getattr(_analytics, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


if __name__ == "__main__":
    history = load_recovery_history()
    print(json.dumps(history, indent=4))
