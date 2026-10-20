#!/usr/bin/env python3

"""
LinuxOps Policy Evaluation Service (Phase B — Step 3).

Integration layer that connects container monitoring, diagnosis, and recovery
history with the deterministic policy evaluator, and records policy audit decisions.
Strictly dry-run: never executes container restart or recovery operations.
"""

from app.container_monitor import collect_container_status
from app.diagnosis import diagnose_container
from app.history import load_recovery_history, record_policy_decision
from app.policy import evaluate_recovery_policy
from app.recovery import validate_container_name


def evaluate_container_recovery_policy(
    container_name: str,
    current_state: str | None = None,
    diagnosis: dict | None = None,
    history_events: list[dict] | None = None,
    record_decision: bool = True,
    recovery_history_path=None,
    policy_history_path=None,
    current_time=None,
) -> dict:
    """
    Safely evaluate whether a proposed container recovery is permitted by policy.

    1. Validates the container name syntax.
    2. Gathers container state and diagnosis if not provided, handling failures safely.
    3. Loads actual recovery history (ignoring prior policy decisions).
    4. Evaluates the policy deterministically (pure dry-run).
    5. Records the policy decision in policy_history.jsonl if requested.
    6. Returns the structured policy decision. NEVER invokes container recovery.
    """
    # 1. Validate container name
    is_valid, validation_msg = validate_container_name(container_name)
    if not is_valid:
        # Invalid container name cannot be evaluated or safely audited
        return evaluate_recovery_policy(
            container_name=container_name,
            current_state="unknown",
            current_time=current_time,
        )

    target_name = validation_msg

    # 2. Resolve diagnosis and state if not explicitly passed
    resolved_state = current_state
    resolved_diagnosis = diagnosis

    if resolved_diagnosis is None or resolved_state is None:
        try:
            diag_result = diagnose_container(target_name)
            if isinstance(diag_result, dict) and diag_result.get("success"):
                if resolved_diagnosis is None:
                    resolved_diagnosis = diag_result
                if resolved_state is None:
                    resolved_state = diag_result.get("state")
            elif resolved_diagnosis is None:
                resolved_diagnosis = diag_result
        except Exception as diag_err:
            resolved_diagnosis = {
                "success": False,
                "oom_killed": False,
                "error": f"Diagnosis failed: {diag_err}",
            }

    # If state is still undetermined, query container status inventory
    if resolved_state is None:
        try:
            status_report = collect_container_status()
            containers = status_report.get("containers", []) if isinstance(status_report, dict) else []
            for item in containers:
                if isinstance(item, dict) and item.get("name") == target_name:
                    resolved_state = item.get("state")
                    break
        except Exception:
            pass

    if resolved_state is None:
        resolved_state = "unknown"

    # 3. Load actual recovery history (strictly isolating policy audit logs)
    if history_events is None:
        try:
            history_events = load_recovery_history(
                limit=50,
                history_path=recovery_history_path,
            )
        except Exception:
            history_events = []

    # 4. Evaluate policy deterministically
    decision = evaluate_recovery_policy(
        container_name=target_name,
        current_state=resolved_state,
        history_events=history_events,
        diagnosis=resolved_diagnosis,
        current_time=current_time,
    )

    # Attach contextual metadata for UI callers
    decision["container"] = target_name
    decision["current_state"] = str(resolved_state)

    # 5. Record policy decision audit trail if requested
    if record_decision:
        try:
            record_policy_decision(
                target_name,
                decision,
                history_path=policy_history_path,
            )
        except Exception as log_err:
            decision["log_error"] = f"Failed to record policy decision: {log_err}"

    return decision


# Convenience alias
evaluate_container_policy = evaluate_container_recovery_policy
