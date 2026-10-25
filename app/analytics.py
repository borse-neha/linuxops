#!/usr/bin/env python3

"""
LinuxOps Operational Intelligence & Observability Analytics Engine (Phase 12).

Provides:
1. Unified Incident Timeline: Correlates and normalizes records across incidents,
   recovery executions, policy decisions, and host watchdog logs.
2. Reliable Reliability Metrics: Availability %, Incident Frequency, Restart Attempts,
   Successful Recoveries, and Mean Time to Recovery (MTTR), strictly separating measured
   data from estimates and missing telemetry without data fabrication.
3. Advanced Operational Alerts: Detects persistent outages, crash loops / repeated failures,
   active restart cooldowns, and failed recovery attempts with stable deduplication.
4. Explainable Diagnostics & Safe Troubleshooting: Root-cause determination with
   certainty scores and safe, read-only operational troubleshooting steps.
5. Watchdog Activity Integration: Inspects Windows / WSL host watchdog state and cooldowns.
"""

from collections import deque
from datetime import datetime, timezone, timedelta
import json
import logging
import math
import os
from pathlib import Path
import re
from typing import Any

logger = logging.getLogger(__name__)

# Sensitive text redactor
from app.diagnostics_engine import redact_sensitive_text

PROJECT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_HISTORY_PATH = PROJECT_DIR / "logs" / "recovery_history.jsonl"
DEFAULT_POLICY_PATH = PROJECT_DIR / "logs" / "policy_history.jsonl"
DEFAULT_INCIDENTS_PATH = PROJECT_DIR / "logs" / "incidents.jsonl"
DEFAULT_METRICS_PATH = PROJECT_DIR / "logs" / "metrics.jsonl"

INCIDENT_CATEGORIES = {
    "OOM_KILL": "OOM Killer / Memory Pressure",
    "CRASH_LOOP": "Repeated Restarts / Crash Loop",
    "UNHEALTHY_PROBE": "Health Check Probe Failure",
    "CONNECTION_FAILURE": "Network / Connection Refused",
    "STORAGE_EXHAUSTION": "Filesystem / Disk Space Depleted",
    "PERMISSION_DENIED": "Access / Permission Denied",
    "POLICY_DENIAL": "Policy / Guardrail Denial",
    "WATCHDOG_INTERVENTION": "Host Watchdog Intervention",
    "SERVICE_OUTAGE": "Service Stopped / Outage",
    "CONFIGURATION_ERROR": "Configuration / Missing Env",
    "GENERAL_INCIDENT": "Operational Incident",
}

SEVERITY_RANKS = {"INFO": 1, "WARNING": 2, "CRITICAL": 3}


def parse_iso_timestamp(ts_val: Any) -> datetime | None:
    """
    Safely parse an ISO 8601 timestamp string or datetime into a timezone-aware UTC datetime.
    Handles datetime objects, 'Z' suffixes, numerical timezone offsets (+05:30, -04:00), and invalid values.
    """
    if ts_val is None or isinstance(ts_val, bool):
        return None

    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None:
            ts_val = ts_val.replace(tzinfo=timezone.utc)
        return ts_val.astimezone(timezone.utc)

    if isinstance(ts_val, (int, float)):
        try:
            return datetime.fromtimestamp(ts_val, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    if not isinstance(ts_val, str):
        return None

    ts_str = str(ts_val).strip()
    if not ts_str:
        return None

    # Replace trailing 'Z' with '+00:00'
    if ts_str.endswith("Z") or ts_str.endswith("z"):
        ts_str = ts_str[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def get_watchdog_status(
    state_path: Path | str | None = None,
    log_path: Path | str | None = None,
) -> dict[str, Any]:
    """
    Inspect the host watchdog supervisor state and recent log activity.
    Cross-platform safe: Checks provided path, Windows/WSL paths, and local fallbacks.
    Returns structured status without raising exceptions.
    """
    if state_path:
        explicit_path = Path(state_path)
        if not explicit_path.exists() or not explicit_path.is_file():
            return {
                "available": False,
                "status": "UNAVAILABLE",
                "last_probe_time": None,
                "last_probe_status": "N/A",
                "consecutive_failures": 0,
                "restart_count_in_window": 0,
                "in_cooldown": False,
                "cooldown_until": None,
                "last_recovery_action": None,
                "recent_events": [],
                "state_file": str(explicit_path),
            }
        resolved_state_path = explicit_path
    else:
        candidate_state_paths = []
        env_path = os.getenv("LINUXOPS_WATCHDOG_STATE_PATH")
        if env_path:
            candidate_state_paths.append(Path(env_path))

        # WSL mount path for Windows user
        wsl_win_path = Path("/mnt/c/Users/Neha Borse/.linuxops/logs/watchdog-state.json")
        candidate_state_paths.append(wsl_win_path)

        # Windows native path
        candidate_state_paths.append(Path(r"C:\Users\Neha Borse\.linuxops\logs\watchdog-state.json"))

        # Local Linux fallback
        candidate_state_paths.append(Path.home() / ".linuxops" / "logs" / "watchdog-state.json")
        candidate_state_paths.append(PROJECT_DIR / "logs" / "watchdog-state.json")

        resolved_state_path = None
        for p in candidate_state_paths:
            try:
                if p.exists() and p.is_file():
                    resolved_state_path = p
                    break
            except (OSError, PermissionError):
                continue

    if not resolved_state_path:
        return {
            "available": False,
            "status": "UNAVAILABLE",
            "last_probe_time": None,
            "last_probe_status": "N/A",
            "consecutive_failures": 0,
            "restart_count_in_window": 0,
            "in_cooldown": False,
            "cooldown_until": None,
            "last_recovery_action": None,
            "recent_events": [],
            "state_file": None,
        }

    try:
        with resolved_state_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        logger.warning(f"Failed to parse watchdog state from {resolved_state_path}: {exc}")
        return {
            "available": False,
            "status": "DEGRADED",
            "error": str(exc),
            "state_file": str(resolved_state_path),
            "consecutive_failures": 0,
            "restart_count_in_window": 0,
            "in_cooldown": False,
            "cooldown_until": None,
            "last_recovery_action": None,
            "recent_events": [],
        }

    last_probe_time = data.get("LastProbeTime")
    last_probe_status = data.get("LastProbeStatus", "UNKNOWN")
    consecutive_failures = int(data.get("ConsecutiveFailures", 0) or 0)
    restart_count = int(data.get("RestartCountInWindow", 0) or 0)
    in_cooldown = bool(data.get("InCooldown", False))
    cooldown_until = data.get("CooldownUntil")
    last_recovery = data.get("LastRecoveryAction")

    # Determine overall status
    if in_cooldown:
        status = "COOLDOWN"
    elif consecutive_failures > 0 or last_probe_status not in ("HEALTHY", "200"):
        status = "DEGRADED"
    else:
        status = "HEALTHY"

    # Optional: tail recent log lines if log path exists
    recent_events = []
    resolved_log_path = Path(log_path) if log_path else resolved_state_path.with_name("watchdog.log")
    try:
        if resolved_log_path.exists() and resolved_log_path.is_file():
            with resolved_log_path.open("r", encoding="utf-8") as lf:
                lines = deque(lf, maxlen=10)
                for line in lines:
                    stripped = line.strip()
                    if stripped:
                        recent_events.append(redact_sensitive_text(stripped))
    except Exception:
        pass

    return {
        "available": True,
        "status": status,
        "last_probe_time": last_probe_time,
        "last_probe_status": last_probe_status,
        "consecutive_failures": consecutive_failures,
        "restart_count_in_window": restart_count,
        "in_cooldown": in_cooldown,
        "cooldown_until": cooldown_until,
        "last_recovery_action": last_recovery,
        "recent_events": recent_events,
        "state_file": str(resolved_state_path),
    }


def classify_incident_category(event: dict[str, Any]) -> str:
    """Classify an incident, alert, or log record into a standard category string."""
    if not isinstance(event, dict):
        return "GENERAL_INCIDENT"

    # Check explicit fields
    cat = event.get("incident_category") or event.get("category")
    if isinstance(cat, str) and cat.strip().upper() in INCIDENT_CATEGORIES:
        return cat.strip().upper()

    rule_id = str(event.get("rule_id") or event.get("rule") or "").lower()
    msg = str(event.get("message") or event.get("symptoms") or event.get("reason") or "").lower()
    exit_code = event.get("exit_code")
    oom_killed = event.get("oom_killed")

    if oom_killed is True or exit_code == 137 or "oom" in msg or "oom" in rule_id or "memory limit" in msg:
        return "OOM_KILL"
    if "crash" in msg or "repeated" in msg or "thrashing" in msg or "restart_count" in rule_id:
        return "CRASH_LOOP"
    if "probe" in msg or "503" in msg or "health" in rule_id or "unhealthy" in msg:
        return "UNHEALTHY_PROBE"
    if "refused" in msg or "econnrefused" in msg or "connection" in msg or "502" in msg:
        return "CONNECTION_FAILURE"
    if "space" in msg or "quota" in msg or "enospc" in msg or "storage" in rule_id:
        return "STORAGE_EXHAUSTION"
    if "permission" in msg or "denied" in msg or "eacces" in msg:
        return "PERMISSION_DENIED"
    if "policy" in rule_id or event.get("event_type") == "policy_decision" or event.get("decision") == "DENY":
        return "POLICY_DENIAL"
    if "watchdog" in rule_id or "watchdog" in msg or event.get("source") == "watchdog":
        return "WATCHDOG_INTERVENTION"
    if "stopped" in msg or "exited" in msg or "dead" in msg or "service_outage" in rule_id:
        return "SERVICE_OUTAGE"
    if "config" in msg or "env" in msg or "variable" in msg:
        return "CONFIGURATION_ERROR"

    return "GENERAL_INCIDENT"


def normalize_severity(raw_sev: Any, default: str = "INFO") -> str:
    """Normalize severity strings into standard CRITICAL, WARNING, or INFO."""
    if not raw_sev or not isinstance(raw_sev, str):
        return default
    clean = raw_sev.strip().upper()
    if "CRIT" in clean:
        return "CRITICAL"
    if "WARN" in clean:
        return "WARNING"
    if "INFO" in clean:
        return "INFO"
    return default


def get_unified_incident_timeline(
    limit: int = 100,
    history_path: Path | str | None = None,
    incidents_path: Path | str | None = None,
    policy_path: Path | str | None = None,
    watchdog_state_path: Path | str | None = None,
    watchdog_log_path: Path | str | None = None,
    include_watchdog: bool = True,
    since: datetime | str | None = None,
    until: datetime | str | None = None,
    category_filter: str | list[str] | None = None,
    component_filter: str | None = None,
    severity_filter: str | list[str] | None = None,
    outcome_filter: str | list[str] | None = None,
    synthetic_events: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Construct a unified, chronologically ordered incident timeline.

    Aggregates records across:
    - Incident resolutions (incidents.jsonl)
    - Container recovery events (recovery_history.jsonl)
    - Policy evaluation decisions (policy_history.jsonl)
    - Watchdog interventions and synthetic events

    Applies comprehensive filtering, duration calculations, and secret redaction.
    """
    raw_events = []

    # Parse time bounds
    since_dt = parse_iso_timestamp(since) if since else None
    until_dt = parse_iso_timestamp(until) if until else None
    if since_dt and until_dt and since_dt > until_dt:
        return []

    # 1. Load incidents.jsonl
    inc_file = Path(incidents_path) if incidents_path else DEFAULT_INCIDENTS_PATH
    if inc_file.exists():
        try:
            with inc_file.open("r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        record = json.loads(stripped)
                        if isinstance(record, dict):
                            record["_source_type"] = "incidents"
                            raw_events.append(record)
                    except json.JSONDecodeError:
                        continue
        except OSError as exc:
            logger.warning(f"Unable to read incidents file {inc_file}: {exc}")

    # 2. Load recovery_history.jsonl
    rec_file = Path(history_path) if history_path else DEFAULT_HISTORY_PATH
    if rec_file.exists():
        try:
            with rec_file.open("r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        record = json.loads(stripped)
                        if isinstance(record, dict) and record.get("event_type") != "policy_decision":
                            record["_source_type"] = "recovery"
                            raw_events.append(record)
                    except json.JSONDecodeError:
                        continue
        except OSError as exc:
            logger.warning(f"Unable to read recovery history file {rec_file}: {exc}")

    # 3. Load policy_history.jsonl
    pol_file = Path(policy_path) if policy_path else DEFAULT_POLICY_PATH
    if pol_file.exists():
        try:
            with pol_file.open("r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        record = json.loads(stripped)
                        if isinstance(record, dict) and record.get("event_type") == "policy_decision":
                            record["_source_type"] = "policy"
                            raw_events.append(record)
                    except json.JSONDecodeError:
                        continue
        except OSError as exc:
            logger.warning(f"Unable to read policy history file {pol_file}: {exc}")

    # 4. Integrate synthetic / mock records
    if isinstance(synthetic_events, list):
        for s in synthetic_events:
            if isinstance(s, dict):
                sc = dict(s)
                sc["_source_type"] = sc.get("_source_type", "synthetic")
                raw_events.append(sc)

    # 5. Extract host watchdog events if available and enabled
    if include_watchdog:
        watchdog = get_watchdog_status(watchdog_state_path, watchdog_log_path)
        if watchdog.get("available") and watchdog.get("last_recovery_action"):
            last_rec_ts = watchdog.get("last_recovery_action")
            raw_events.append({
                "_source_type": "watchdog",
                "timestamp": last_rec_ts,
                "component": "service:linuxops-dashboard",
                "incident_category": "WATCHDOG_INTERVENTION",
                "severity": "WARNING",
                "symptoms": f"Host watchdog initiated automated recovery (Consecutive failures: {watchdog.get('consecutive_failures', 0)})",
                "action_attempted": "watchdog_restart",
                "outcome": "VERIFIED" if watchdog.get("last_probe_status") == "HEALTHY" else "FAILED",
                "incident_id": f"watchdog-{last_rec_ts}",
            })

    # Standardize timeline records
    unified: list[dict[str, Any]] = []
    for item in raw_events:
        stype = item.get("_source_type", "unknown")
        dt = parse_iso_timestamp(item.get("timestamp"))
        if not dt:
            continue

        # Time range check
        if since_dt and dt < since_dt:
            continue
        if until_dt and dt > until_dt:
            continue

        iso_ts = dt.isoformat()
        component = (
            item.get("component")
            or item.get("container_name")
            or item.get("container")
            or item.get("target")
            or "unknown"
        )
        component = redact_sensitive_text(str(component).strip())

        # Determine category & symptoms
        symptoms = item.get("symptoms") or item.get("message") or item.get("reason") or "No symptoms recorded."
        symptoms = redact_sensitive_text(str(symptoms).strip())

        category = classify_incident_category(item)

        # Determine action and outcome
        if stype == "incidents":
            inc_id = item.get("incident_id", "N/A")
            action = item.get("action_attempted") or "incident_investigation"
            res_status = str(item.get("resolution_status") or "PENDING").upper()
            outcome = res_status
            default_sev = "CRITICAL" if res_status in ("ESCALATED", "FAILED", "FAILED_VERIFICATION") else ("INFO" if res_status in ("RESOLVED", "VERIFIED") else "WARNING")
            severity = normalize_severity(item.get("severity"), default=default_sev)
        elif stype == "recovery":
            inc_id = item.get("plan_id") or f"rec-{int(dt.timestamp())}"
            action = str(item.get("action") or "start_container")
            succ = item.get("success")
            v_status = str(item.get("verification_status") or "").upper()
            if succ is True:
                outcome = "VERIFIED" if v_status == "VERIFIED" else "RESOLVED"
                default_sev = "INFO"
            else:
                outcome = "FAILED"
                default_sev = "WARNING"
            severity = normalize_severity(item.get("severity"), default=default_sev)
        elif stype == "policy":
            inc_id = f"policy-{int(dt.timestamp())}"
            action = "evaluate_policy"
            decision = str(item.get("decision") or "UNKNOWN").upper()
            outcome = "DENIED" if decision == "DENY" else ("ALLOWED" if decision == "ALLOW" else decision)
            severity = "WARNING" if decision == "DENY" else "INFO"
        elif stype == "watchdog":
            inc_id = item.get("incident_id") or f"wd-{int(dt.timestamp())}"
            action = item.get("action_attempted") or "watchdog_restart"
            outcome = item.get("outcome") or "VERIFIED"
            severity = normalize_severity(item.get("severity"), default="WARNING")
        else:
            inc_id = item.get("incident_id") or f"event-{int(dt.timestamp())}"
            action = item.get("action_attempted") or "manual_action"
            outcome = str(item.get("outcome") or "RECORDED").upper()
            severity = normalize_severity(item.get("severity"), default="INFO")

        record_entry = {
            "timestamp": iso_ts,
            "_datetime": dt,
            "incident_id": inc_id,
            "incident_category": category,
            "category_label": INCIDENT_CATEGORIES.get(category, category),
            "component": component,
            "severity": severity,
            "symptoms": symptoms,
            "action_attempted": action,
            "outcome": outcome,
            "source": stype,
            "duration_seconds": None,
        }
        unified.append(record_entry)

    # Sort chronologically by timestamp to correlate durations
    unified.sort(key=lambda x: x["_datetime"])

    # Correlate duration between failure/incident onset and resolution/recovery
    last_unresolved: dict[str, dict] = {}
    for ev in unified:
        comp = ev["component"]
        outcome = ev["outcome"]
        if outcome in ("FAILED", "ESCALATED", "FAILED_VERIFICATION", "PENDING", "PENDING_REVIEW"):
            last_unresolved[comp] = ev
        elif outcome in ("RESOLVED", "VERIFIED") and comp in last_unresolved:
            prior = last_unresolved.pop(comp)
            dur = (ev["_datetime"] - prior["_datetime"]).total_seconds()
            if dur >= 0:
                ev["duration_seconds"] = dur

    # Filtering
    filtered = []
    cat_filter_set = None
    if category_filter and category_filter != "ALL":
        if isinstance(category_filter, str):
            cat_filter_set = {category_filter.strip().upper()}
        else:
            cat_filter_set = {c.strip().upper() for c in category_filter if isinstance(c, str)}

    sev_filter_set = None
    if severity_filter and severity_filter != "ALL":
        if isinstance(severity_filter, str):
            sev_filter_set = {severity_filter.strip().upper()}
        else:
            sev_filter_set = {s.strip().upper() for s in severity_filter if isinstance(s, str)}

    out_filter_set = None
    if outcome_filter and outcome_filter != "ALL":
        if isinstance(outcome_filter, str):
            out_filter_set = {outcome_filter.strip().upper()}
        else:
            out_filter_set = {o.strip().upper() for o in outcome_filter if isinstance(o, str)}

    for ev in unified:
        if cat_filter_set and ev["incident_category"] not in cat_filter_set:
            continue
        if sev_filter_set and ev["severity"] not in sev_filter_set:
            continue
        if out_filter_set and ev["outcome"] not in out_filter_set:
            continue
        if component_filter:
            c_filter = component_filter.strip().lower()
            if c_filter and c_filter not in ev["component"].lower():
                continue
        filtered.append(ev)

    # Reverse sort: newest records first
    filtered.sort(key=lambda x: x["_datetime"], reverse=True)

    # Clean internal temporary keys
    for ev in filtered:
        ev.pop("_datetime", None)

    limit_int = limit if (isinstance(limit, int) and not isinstance(limit, bool) and limit > 0) else 100
    return filtered[:limit_int]


def format_timeline_rows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Format unified incident timeline records into clean table rows for display."""
    if not isinstance(events, list):
        return []

    rows = []
    for ev in events:
        if not isinstance(ev, dict):
            continue

        sev = ev.get("severity", "INFO")
        if sev == "CRITICAL":
            sev_icon = "🚨 CRITICAL"
        elif sev == "WARNING":
            sev_icon = "⚠️ WARNING"
        else:
            sev_icon = "ℹ️ INFO"

        dur = ev.get("duration_seconds")
        dur_str = f"{dur:.1f}s" if (dur is not None and dur >= 0) else "N/A"

        rows.append({
            "Timestamp (UTC)": ev.get("timestamp", "N/A"),
            "Severity": sev_icon,
            "Category": ev.get("category_label") or ev.get("incident_category", "GENERAL"),
            "Component": ev.get("component", "N/A"),
            "Symptoms & Evidence": ev.get("symptoms", "N/A"),
            "Action Attempted": ev.get("action_attempted", "N/A"),
            "Final Outcome": ev.get("outcome", "UNKNOWN"),
            "Duration": dur_str,
        })
    return rows


def compute_operational_reliability_metrics(
    timeline_events: list[dict[str, Any]] | None = None,
    metrics_path: Path | str | None = None,
    watchdog_status: dict[str, Any] | None = None,
    window_hours: float = 24.0,
    now: datetime | None = None,
) -> dict[str, Any]:
    """
    Calculate reliable reliability and operational intelligence metrics.

    Guarantees:
    - Availability: Computed from recorded telemetry samples in metrics.jsonl. If no samples
      exist, explicitly marked as 'INSUFFICIENT_DATA' rather than inventing data.
    - Incident Frequency: Incidents occurring in the selected time window.
    - Restart Attempts & Recoveries: Derived from verified recovery history.
    - MTTR: Strictly calculated from measured durations where both incident onset and
      verified resolution/recovery timestamps are confirmed. If none exist, returns None.
    """
    ref_time = now or datetime.now(timezone.utc)
    win_hours = max(float(window_hours), 0.1)
    since_window = ref_time - timedelta(hours=win_hours)

    events = timeline_events
    if events is None:
        events = get_unified_incident_timeline(limit=500, since=since_window)

    # 1. Availability Calculation from Telemetry Samples
    m_path = Path(metrics_path) if metrics_path else DEFAULT_METRICS_PATH
    sample_count = 0
    healthy_samples = 0
    degraded_samples = 0

    if m_path.exists():
        try:
            with m_path.open("r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        sample = json.loads(stripped)
                        if not isinstance(sample, dict):
                            continue
                        s_dt = parse_iso_timestamp(sample.get("timestamp"))
                        if s_dt and s_dt >= since_window:
                            sample_count += 1
                            overall = str(sample.get("overall_status") or "").upper()
                            if overall in ("CRITICAL", "FAILED", "DOWN"):
                                degraded_samples += 1
                            else:
                                healthy_samples += 1
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    if sample_count > 0:
        availability_pct = round((healthy_samples / sample_count) * 100.0, 2)
        avail_status = "MEASURED"
        avail_details = f"Calculated across {sample_count} telemetry samples ({healthy_samples} nominal, {degraded_samples} degraded) in past {win_hours:.1f}h."
    else:
        availability_pct = None
        avail_status = "INSUFFICIENT_DATA"
        avail_details = f"N/A: No periodic telemetry samples recorded in metrics.jsonl for the past {win_hours:.1f}h window; historical uptime is not fabricated."

    # 2. Incident Frequency
    incident_count = 0
    for ev in events:
        # Count failures or incidents
        sev = ev.get("severity")
        out = ev.get("outcome")
        if sev in ("CRITICAL", "WARNING") or out in ("FAILED", "ESCALATED", "DENIED"):
            incident_count += 1

    incidents_per_hour = round(incident_count / win_hours, 2)
    incidents_per_day = round(incidents_per_hour * 24.0, 2)

    # 3. Restart Attempts and Success Recoveries
    restart_attempts = 0
    successful_recoveries = 0
    failed_recoveries = 0

    durations: list[float] = []

    for ev in events:
        act = str(ev.get("action_attempted") or "")
        out = str(ev.get("outcome") or "")

        if act in ("start_container", "restart_service", "watchdog_restart"):
            restart_attempts += 1
            if out in ("RESOLVED", "VERIFIED"):
                successful_recoveries += 1
            elif out == "FAILED":
                failed_recoveries += 1

        dur = ev.get("duration_seconds")
        if dur is not None and isinstance(dur, (int, float)) and dur > 0:
            durations.append(float(dur))

    success_rate = (
        round((successful_recoveries / restart_attempts) * 100.0, 2)
        if restart_attempts > 0
        else 0.0
    )

    # 4. Mean Time to Recovery (MTTR)
    if durations:
        avg_dur_sec = sum(durations) / len(durations)
        mttr_minutes = round(avg_dur_sec / 60.0, 1)
        mttr_seconds = round(avg_dur_sec, 1)
        mttr_status = "MEASURED"
        mttr_formatted = f"{mttr_minutes} min"
        mttr_details = f"Empirical MTTR calculated across {len(durations)} verified recovery cycle(s)."
    else:
        avg_dur_sec = None
        mttr_minutes = None
        mttr_seconds = None
        mttr_status = "INSUFFICIENT_DATA"
        mttr_formatted = "N/A (insufficient duration data)"
        mttr_details = "No verified incident-to-resolution duration pairs recorded in audit logs; duration data is not fabricated."

    # 5. Watchdog Supervision and Cooldown Indicators
    wd = watchdog_status or get_watchdog_status()
    in_cooldown = wd.get("in_cooldown", False)
    cooldown_until = wd.get("cooldown_until")
    consecutive_failures = wd.get("consecutive_failures", 0)
    restart_count_window = wd.get("restart_count_in_window", 0)

    return {
        "window_hours": win_hours,
        "availability": {
            "percent": availability_pct,
            "status": avail_status,
            "sample_count": sample_count,
            "healthy_samples": healthy_samples,
            "degraded_samples": degraded_samples,
            "details": avail_details,
        },
        "incident_frequency": {
            "total_incidents": incident_count,
            "incidents_per_hour": incidents_per_hour,
            "incidents_per_day": incidents_per_day,
            "status": "MEASURED" if sample_count > 0 or incident_count > 0 else "NO_INCIDENTS",
        },
        "recoveries": {
            "restart_attempts": restart_attempts,
            "successful_recoveries": successful_recoveries,
            "failed_recoveries": failed_recoveries,
            "success_rate_percent": success_rate,
        },
        "mttr": {
            "formatted": mttr_formatted,
            "minutes": mttr_minutes,
            "seconds": mttr_seconds,
            "status": mttr_status,
            "sample_size": len(durations),
            "details": mttr_details,
        },
        "watchdog": {
            "available": wd.get("available", False),
            "status": wd.get("status", "UNAVAILABLE"),
            "in_cooldown": in_cooldown,
            "cooldown_until": cooldown_until,
            "consecutive_failures": consecutive_failures,
            "restart_count_in_window": restart_count_window,
            "last_recovery_action": wd.get("last_recovery_action"),
        },
    }


def evaluate_advanced_operational_alerts(
    timeline_events: list[dict[str, Any]] | None = None,
    active_containers: list[dict[str, Any]] | None = None,
    watchdog_status: dict[str, Any] | None = None,
    outage_threshold_seconds: float = 300.0,
    crash_loop_threshold: int = 3,
    crash_loop_window_seconds: float = 900.0,
    suppression_window_seconds: float = 300.0,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """
    Evaluate advanced operational alert rules with stable deduplication:
    1. Persistent Outage: Workload or service down longer than outage_threshold_seconds.
    2. Repeated Failures / Crash Loop: Multiple restarts or failure events within rolling window.
    3. Restart Cooldown Active: Automated restarts suppressed by watchdog or policy throttling.
    4. Failed Recovery Streak: Workload underwent restart attempt but failed verification.

    Alerts are deduplicated across time and fingerprint keys to eliminate operator noise.
    """
    ref_time = now or datetime.now(timezone.utc)
    alerts_map: dict[str, dict[str, Any]] = {}

    # Check 1: Active Container Telemetry for Persistent Outages & Crash Loops
    if isinstance(active_containers, list):
        for c in active_containers:
            if not isinstance(c, dict):
                continue
            name = c.get("name", "unknown")
            state = str(c.get("state") or "unknown").lower()
            restarts = int(c.get("restart_count") or 0)
            uptime = c.get("uptime_seconds")

            # Crash loop detection by restart count
            if restarts >= crash_loop_threshold:
                dedup_key = f"crash_loop:{name}"
                alerts_map[dedup_key] = {
                    "id": dedup_key,
                    "rule": "repeated_failures_crash_loop",
                    "target": name,
                    "target_type": "container",
                    "severity": "CRITICAL",
                    "category": "CRASH_LOOP",
                    "message": f"Container '{name}' has restarted {restarts} times (threshold: {crash_loop_threshold}). Possible crash loop or memory thrashing.",
                    "observed_evidence": f"restart_count={restarts}, state={state}, exit_code={c.get('exit_code')}",
                    "timestamp": ref_time.isoformat(),
                    "occurrence_count": restarts,
                }

            # Persistent outage detection
            if state in ("exited", "stopped", "dead"):
                started_at = parse_iso_timestamp(c.get("started_at"))
                is_persistent = False
                if started_at:
                    downtime = (ref_time - started_at).total_seconds()
                    if downtime >= outage_threshold_seconds:
                        is_persistent = True
                elif uptime is None or uptime == 0:
                    is_persistent = True

                if is_persistent:
                    dedup_key = f"persistent_outage:{name}"
                    alerts_map[dedup_key] = {
                        "id": dedup_key,
                        "rule": "persistent_workload_outage",
                        "target": name,
                        "target_type": "container",
                        "severity": "CRITICAL",
                        "category": "SERVICE_OUTAGE",
                        "message": f"Container '{name}' remains in an outage state ('{state}').",
                        "observed_evidence": f"state={state}, exit_code={c.get('exit_code')}, oom_killed={c.get('oom_killed')}",
                        "timestamp": ref_time.isoformat(),
                        "occurrence_count": 1,
                    }

    # Check 2: Timeline Events for Failed Recoveries & Crash Loops
    events = timeline_events if timeline_events is not None else get_unified_incident_timeline(limit=100)
    window_start = ref_time - timedelta(seconds=crash_loop_window_seconds)

    failure_counts_by_comp: dict[str, int] = {}
    for ev in events:
        ev_dt = parse_iso_timestamp(ev.get("timestamp"))
        comp = ev.get("component", "unknown")
        outcome = ev.get("outcome")

        # Unsuccessful recovery attempt
        if ev.get("action_attempted") in ("start_container", "restart_service") and outcome == "FAILED":
            dedup_key = f"failed_recovery:{comp}"
            if dedup_key not in alerts_map:
                alerts_map[dedup_key] = {
                    "id": dedup_key,
                    "rule": "unsuccessful_recovery_attempt",
                    "target": comp,
                    "target_type": "workload",
                    "severity": "CRITICAL",
                    "category": "RECOVERY_FAILURE",
                    "message": f"Automated recovery attempt for '{comp}' failed verification or execution.",
                    "observed_evidence": ev.get("symptoms", "Recovery start failed."),
                    "timestamp": ev.get("timestamp", ref_time.isoformat()),
                    "occurrence_count": 1,
                }
            else:
                alerts_map[dedup_key]["occurrence_count"] += 1

        # Repeated failures in rolling window
        if ev_dt and ev_dt >= window_start:
            if outcome in ("FAILED", "ESCALATED", "DENIED") or ev.get("severity") == "CRITICAL":
                failure_counts_by_comp[comp] = failure_counts_by_comp.get(comp, 0) + 1

    for comp, count in failure_counts_by_comp.items():
        if count >= crash_loop_threshold:
            dedup_key = f"crash_loop:{comp}"
            if dedup_key not in alerts_map:
                alerts_map[dedup_key] = {
                    "id": dedup_key,
                    "rule": "repeated_failures_crash_loop",
                    "target": comp,
                    "target_type": "workload",
                    "severity": "CRITICAL",
                    "category": "CRASH_LOOP",
                    "message": f"Component '{comp}' recorded {count} operational failures within {crash_loop_window_seconds / 60:.1f} minutes.",
                    "observed_evidence": f"{count} distinct failure events logged.",
                    "timestamp": ref_time.isoformat(),
                    "occurrence_count": count,
                }
            else:
                alerts_map[dedup_key]["occurrence_count"] = max(alerts_map[dedup_key]["occurrence_count"], count)

    # Check 3: Watchdog Restart Cooldown
    wd = watchdog_status or get_watchdog_status()
    if wd.get("in_cooldown"):
        dedup_key = "cooldown:watchdog_supervisor"
        cooldown_until = wd.get("cooldown_until") or "next evaluation window"
        alerts_map[dedup_key] = {
            "id": dedup_key,
            "rule": "restart_cooldown_active",
            "target": "supervisor:watchdog",
            "target_type": "supervisor",
            "severity": "WARNING",
            "category": "WATCHDOG_INTERVENTION",
            "message": f"Host watchdog restart cooldown is active until {cooldown_until}. Automated service restarts are throttled to protect host stability.",
            "observed_evidence": f"InCooldown=true, ConsecutiveFailures={wd.get('consecutive_failures')}, RestartsInWindow={wd.get('restart_count_in_window')}",
            "timestamp": ref_time.isoformat(),
            "occurrence_count": 1,
        }

    # Sort alerts by severity (CRITICAL first) then timestamp
    result = list(alerts_map.values())
    result.sort(key=lambda a: (SEVERITY_RANKS.get(a.get("severity"), 0), a.get("timestamp", "")), reverse=True)
    return result


def get_explainable_diagnostic_guidance(
    incident_or_component: dict[str, Any] | str,
    active_containers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Provide explainable likely causes and safe, actionable troubleshooting guidance.
    Strictly emphasizes non-destructive operations and flags risky actions.
    """
    if isinstance(incident_or_component, str):
        comp_name = incident_or_component
        record = {}
        if isinstance(active_containers, list):
            match = next((c for c in active_containers if c.get("name") == comp_name or c.get("id") == comp_name), None)
            if match:
                record = match
    elif isinstance(incident_or_component, dict):
        record = incident_or_component
        comp_name = record.get("component") or record.get("container_name") or record.get("name") or "target"
    else:
        comp_name = "target"
        record = {}

    category = classify_incident_category(record)
    exit_code = record.get("exit_code")
    oom_killed = record.get("oom_killed")
    symptoms = str(record.get("symptoms") or record.get("message") or "")

    # 1. OOM Kill
    if category == "OOM_KILL" or exit_code == 137 or oom_killed is True:
        return {
            "component": comp_name,
            "category": "OOM_KILL",
            "likely_cause": "The Linux kernel OOM (Out-Of-Memory) killer abruptly terminated the container process after it exceeded its assigned cgroup memory limit.",
            "certainty": "HIGH (Confirmed exit code 137 and oom_killed=true flag)",
            "safe_troubleshooting_steps": [
                "1. Inspect cgroup memory limit: verify whether the configured memory_limit_bytes is undersized for current application workload.",
                "2. Check application heap: verify JVM (-Xmx), Node.js (--max-old-space-size), or Go memory allocation thresholds.",
                "3. Review historical memory trends in the Host System Resources panel to identify memory leak ramp-up patterns.",
            ],
            "safe_read_only_commands": [
                f"podman inspect {comp_name} | grep -iE 'oom|memory'",
                f"podman logs --tail 100 {comp_name}",
            ],
            "risky_actions_to_avoid": [
                "Do NOT execute automated restart in a loop without increasing memory allocation; this triggers restart thrashing.",
                "Do NOT remove memory limits entirely on shared nodes as it risks starving neighboring workloads.",
            ],
        }

    # 2. Connection Refused
    if category == "CONNECTION_FAILURE":
        return {
            "component": comp_name,
            "category": "CONNECTION_FAILURE",
            "likely_cause": "The container failed to establish a network connection with an upstream dependency (e.g. database, cache, or internal microservice) because the target host/port refused the connection or is offline.",
            "certainty": "HIGH (Socket connection refused / dial tcp error detected)",
            "safe_troubleshooting_steps": [
                "1. Verify upstream service health and target port 5432: confirm whether target database or dependency container is in 'running' state.",
                "2. Check listening ports: verify port binding using ss/netstat within the network namespace.",
                "3. Confirm network bridge connectivity: ensure both containers are attached to the same Podman bridge network.",
            ],
            "safe_read_only_commands": [
                f"podman logs --tail 50 {comp_name}",
                "podman network inspect podman",
            ],
            "risky_actions_to_avoid": [
                "Do NOT expose container ports to 0.0.0.0 or disable firewall rules.",
                "Do NOT restart dependent microservices concurrently before the core database reaches healthy state.",
            ],
        }

    # 3. Crash Loop / Repeated Failures
    if category == "CRASH_LOOP":
        return {
            "component": comp_name,
            "category": "CRASH_LOOP",
            "likely_cause": "The container process is entering a rapid crash-restart thrash cycle, failing immediately upon invocation before reaching a stable running state.",
            "certainty": "HIGH (Restart count exceeds threshold with low uptime)",
            "safe_troubleshooting_steps": [
                "1. Inspect early startup stderr logs: look for missing configuration files, unmet environment variables, or unhandled exceptions.",
                "2. Verify container entrypoint and binary permissions: confirm entrypoint executable exists and has execute bit (+x).",
                "3. Temporarily set container restart policy to 'no' to prevent CPU starvation while investigating logs.",
            ],
            "safe_read_only_commands": [
                f"podman logs --tail 100 {comp_name}",
                f"podman inspect {comp_name} --format '{{{{.State.ExitCode}}}} {{{{.State.Error}}}}'",
            ],
            "risky_actions_to_avoid": [
                "Do NOT force restart continuously without reading the exit code and root error.",
                "Do NOT delete persistent database or cache volumes in an attempt to clear state.",
            ],
        }

    # 4. Health Probe Failure
    if category == "UNHEALTHY_PROBE":
        return {
            "component": comp_name,
            "category": "UNHEALTHY_PROBE",
            "likely_cause": "The application process is running but its designated health probe returned a non-zero exit code or HTTP 5xx error, indicating internal deadlock, dependency starvation, or thread exhaustion.",
            "certainty": "HIGH (Configured health probe returned non-zero status)",
            "safe_troubleshooting_steps": [
                "1. Test probe endpoint locally: run probe command inside container or curl endpoint from loopback.",
                "2. Inspect application thread pool and queue depth for bottlenecks or deadlock.",
                "3. Check probe timeout: verify if probe timeout (e.g. 3s) is too aggressive under peak load.",
            ],
            "safe_read_only_commands": [
                f"podman inspect {comp_name} --format '{{{{json .State.Health}}}}'",
                f"podman logs --tail 50 {comp_name}",
            ],
            "risky_actions_to_avoid": [
                "Do NOT simply disable health checks to mask the failure status.",
                "Do NOT kill the process abruptly if graceful shutdown is supported.",
            ],
        }

    # 5. Default General Incident Guidance
    return {
        "component": comp_name,
        "category": category,
        "likely_cause": "Operational anomaly or unexpected container exit detected by monitoring telemetry.",
        "certainty": "MODERATE (Derived from runtime status and diagnostic telemetry)",
        "safe_troubleshooting_steps": [
            "1. Inspect recent container logs for stack traces and error messages.",
            "2. Check host resource pressure (CPU, memory, disk) in Host System Resources tab.",
            "3. Verify container exit code: 0 indicates graceful shutdown, non-zero indicates error.",
        ],
        "safe_read_only_commands": [
            f"podman inspect {comp_name}",
            f"podman logs --tail 50 {comp_name}",
        ],
        "risky_actions_to_avoid": [
            "Do NOT bypass policy checks or approval workflows.",
            "Do NOT run containers as root or with privileged flags without security authorization.",
        ],
    }


# Backwards compatibility re-exports from app.history & app.monitor
from app.history import (
    get_policy_decision_stats,
    get_recovery_success_rate,
    load_incident_history,
    load_policy_history,
    load_recovery_history,
    record_incident_resolution,
    record_policy_decision,
    record_recovery_event,
)
from app.monitor import get_metric_trends

