#!/usr/bin/env python3

"""
LinuxOps Recovery Policy Engine (Phase B — Step 1)

Deterministic policy evaluation for container recovery proposals.
Evaluates safeguards (state eligibility, retry limits, cooldown periods,
OOM detection) without executing any container operations.
"""

from datetime import datetime, timedelta, timezone

from app.recovery import validate_container_name

DEFAULT_MAX_FAILED_RETRIES = 3
DEFAULT_RETRY_WINDOW_SECONDS = 900  # 15 minutes
DEFAULT_COOLDOWN_SECONDS = 60
ELIGIBLE_RECOVERY_STATES = {"exited", "stopped"}
RECOVERY_ACTION = "start_container"


def _sanitize_int_threshold(
    val,
    default_val: int,
    min_val: int,
    strictly_greater: bool = False,
) -> int:
    """
    Validate that val is a strict integer (not bool, float, str, etc.)
    satisfying the minimum bound. If invalid, falls back to default_val.
    """
    if isinstance(val, bool) or not isinstance(val, int):
        return default_val
    if strictly_greater and val <= min_val:
        return default_val
    if not strictly_greater and val < min_val:
        return default_val
    return val


def _parse_timestamp(timestamp_val) -> datetime | None:
    """Safely parse an ISO-8601 timestamp string to a UTC datetime."""
    if not isinstance(timestamp_val, str) or not timestamp_val.strip():
        return None

    cleaned = timestamp_val.strip()
    try:
        # Standard library ISO-8601 parser (handles 'Z' and offset notations)
        dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def evaluate_recovery_policy(
    container_name: str,
    current_state: str,
    history_events: list[dict] | None = None,
    diagnosis: dict | None = None,
    max_failed_retries: int = DEFAULT_MAX_FAILED_RETRIES,
    retry_window_seconds: int = DEFAULT_RETRY_WINDOW_SECONDS,
    cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS,
    current_time: datetime | None = None,
) -> dict:
    """
    Deterministically evaluate whether a proposed container recovery is allowed.

    Returns a structured decision dictionary without executing any recovery actions.
    Invalid or negative threshold values fall back safely to documented defaults:
    - max_failed_retries >= 1 (default: DEFAULT_MAX_FAILED_RETRIES)
    - retry_window_seconds > 0 (default: DEFAULT_RETRY_WINDOW_SECONDS)
    - cooldown_seconds >= 0 (default: DEFAULT_COOLDOWN_SECONDS)
    """
    # Validate and normalize reference current time
    if current_time is None or not isinstance(current_time, datetime):
        now_utc = datetime.now(timezone.utc)
    elif current_time.tzinfo is None:
        now_utc = current_time.replace(tzinfo=timezone.utc)
    else:
        now_utc = current_time.astimezone(timezone.utc)

    # Validate and sanitize policy threshold parameters (D1)
    effective_max_retries = _sanitize_int_threshold(
        max_failed_retries, DEFAULT_MAX_FAILED_RETRIES, min_val=1, strictly_greater=False
    )
    effective_retry_window = _sanitize_int_threshold(
        retry_window_seconds, DEFAULT_RETRY_WINDOW_SECONDS, min_val=0, strictly_greater=True
    )
    effective_cooldown = _sanitize_int_threshold(
        cooldown_seconds, DEFAULT_COOLDOWN_SECONDS, min_val=0, strictly_greater=False
    )

    # 1. Validate container name syntax
    name_valid, validation_msg = validate_container_name(container_name)
    target_name = validation_msg if name_valid else str(container_name).strip()

    # 2. State eligibility evaluation
    state_clean = str(current_state or "").strip().lower()
    if state_clean in ELIGIBLE_RECOVERY_STATES:
        state_eligible = True
    else:
        state_eligible = False

    # 3. OOM Safeguard evaluation
    oom_safeguard_satisfied = True
    if isinstance(diagnosis, dict):
        if bool(diagnosis.get("oom_killed", False)):
            oom_safeguard_satisfied = False

    # 4. Filter relevant recovery history events for this container
    cooldown_satisfied = True
    within_retry_limit = True
    failed_attempts_in_window = 0
    cooldown_remaining_seconds = 0.0

    if name_valid and history_events and isinstance(history_events, list):
        window_start = now_utc - timedelta(seconds=effective_retry_window)
        most_recent_event_time = None

        for event in history_events:
            if not isinstance(event, dict):
                continue

            event_container = str(event.get("container") or "").strip()
            event_action = str(event.get("action") or "").strip()

            if event_container != target_name or event_action != RECOVERY_ACTION:
                continue

            event_dt = _parse_timestamp(event.get("timestamp"))
            if event_dt is None:
                continue

            # Ignore future-dated events for both cooldown and retry window (D2)
            if event_dt > now_utc:
                continue

            # Track most recent attempt for cooldown calculation (success or fail)
            if most_recent_event_time is None or event_dt > most_recent_event_time:
                most_recent_event_time = event_dt

            # Count failed recovery attempts in the preceding time window
            # Do NOT count successful attempts as failed retries
            is_success = bool(event.get("success", False))
            if not is_success and window_start <= event_dt <= now_utc:
                failed_attempts_in_window += 1

        # Evaluate cooldown
        if most_recent_event_time is not None:
            elapsed = (now_utc - most_recent_event_time).total_seconds()
            if elapsed < effective_cooldown:
                cooldown_satisfied = False
                remaining = max(0.0, effective_cooldown - elapsed)
                # Ensure cooldown_remaining_seconds never exceeds configured cooldown
                cooldown_remaining_seconds = round(min(float(effective_cooldown), remaining), 1)

        # Evaluate retry limit
        if failed_attempts_in_window >= effective_max_retries:
            within_retry_limit = False

    # 5. Determine overall allowed status and priority reason
    checks = {
        "name_valid": name_valid,
        "state_eligible": state_eligible,
        "oom_safeguard_satisfied": oom_safeguard_satisfied,
        "cooldown_satisfied": cooldown_satisfied,
        "within_retry_limit": within_retry_limit,
    }

    if not name_valid:
        allowed = False
        reason = validation_msg
    elif not state_eligible:
        allowed = False
        if state_clean == "running":
            reason = (
                f"Container '{target_name}' is currently running; recovery is not needed."
            )
        elif not state_clean:
            reason = (
                f"Container '{target_name}' has an empty or missing state; "
                "only stopped or exited containers can be recovered."
            )
        else:
            reason = (
                f"Container '{target_name}' is in ineligible state '{state_clean}'; "
                "only stopped or exited containers can be recovered."
            )
    elif not oom_safeguard_satisfied:
        allowed = False
        reason = (
            f"Container '{target_name}' was terminated by an Out-Of-Memory (OOM) event; "
            "human review of resource limits is required before restarting."
        )
    elif not cooldown_satisfied:
        allowed = False
        reason = (
            f"Container '{target_name}' is in cooldown. Please wait "
            f"{cooldown_remaining_seconds:.1f}s before attempting recovery again."
        )
    elif not within_retry_limit:
        allowed = False
        window_minutes = effective_retry_window // 60
        if window_minutes > 0:
            window_desc = f"{window_minutes} minutes"
        else:
            window_desc = f"{effective_retry_window} seconds"
        reason = (
            f"Container '{target_name}' reached the maximum failed retry limit "
            f"({failed_attempts_in_window}/{effective_max_retries}) within the last "
            f"{window_desc}."
        )
    else:
        allowed = True
        reason = (
            f"Container '{target_name}' is eligible for recovery (state: '{state_clean}')."
        )

    return {
        "allowed": allowed,
        "action": "ALLOW" if allowed else "DENY",
        "reason": reason,
        "checks": checks,
        "attempts_in_window": failed_attempts_in_window,
        "cooldown_remaining_seconds": max(0.0, float(cooldown_remaining_seconds)),
        "dry_run": True,
    }
