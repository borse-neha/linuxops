#!/usr/bin/env python3

"""
LinuxOps Safe Recovery Controller & Policy Integration (Phase 2).

Integrates diagnostic incidents with the deterministic recovery policy engine:
- Recommendation-only / dry-run by default
- Explicit authorization required for any real execution
- Global recovery kill-switch (GLOBAL_RECOVERY_DISABLED)
- Per-container custom policies (custom cooldown, retry limit, or disabled)
- Non-destructive action allowlists ('start_container' only)
- Automatic incident escalation for crash loops and unresolvable failures
- Post-recovery running and health verification
- Strict immunity for protected workloads ('cloudops-floci', 'linuxops-recovery-ui-test')
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
from typing import Any, Callable

from app.history import (
    DEFAULT_HISTORY_PATH,
    DEFAULT_INCIDENTS_PATH,
    load_recovery_history,
    record_incident_resolution,
    record_recovery_event,
)
from app.policy import (
    DEFAULT_COOLDOWN_SECONDS,
    DEFAULT_MAX_FAILED_RETRIES,
    DEFAULT_RETRY_WINDOW_SECONDS,
    evaluate_recovery_policy,
)
from app.recovery import (
    restart_container,
    validate_container_name,
)

# Global recovery kill-switch (can be set via env or function)
_GLOBAL_RECOVERY_DISABLED = os.environ.get("LINUXOPS_RECOVERY_DISABLED", "").strip().lower() in {"1", "true", "yes"}


class SupportedOperation:
    """Definition and safety schema for a supported remediation operation."""

    def __init__(
        self,
        name: str,
        op_type: str,
        description: str,
        impact: str,
        risk: str,
        verification: str,
        is_state_changing: bool = True,
    ):
        self.name = name
        self.op_type = op_type
        self.description = description
        self.impact = impact
        self.risk = risk
        self.verification = verification
        self.is_state_changing = is_state_changing

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "op_type": self.op_type,
            "description": self.description,
            "impact": self.impact,
            "risk": self.risk,
            "verification": self.verification,
            "is_state_changing": self.is_state_changing,
        }


# Fixed registry of supported operations with strict validation
SUPPORTED_OPERATIONS: dict[str, SupportedOperation] = {
    "start_container": SupportedOperation(
        name="start_container",
        op_type="STATE_CHANGING",
        description="Safely start a stopped or exited Podman container without modifying configuration or volumes.",
        impact="Process initialized inside isolated container namespace; host port bindings reactivated.",
        risk="Low: Non-destructive start. If configuration or external dependency is unresolved, container may exit again.",
        verification="Query container inspect; verify State.Running is True and State.Health.Status is healthy or unmonitored.",
        is_state_changing=True,
    ),
    "inspect_container": SupportedOperation(
        name="inspect_container",
        op_type="READ_ONLY",
        description="Inspect full container runtime state, configuration, and mounts.",
        impact="Zero state change; read-only telemetry query.",
        risk="None: Safe read-only inspection.",
        verification="Returns structured inspection dictionary.",
        is_state_changing=False,
    ),
    "collect_logs": SupportedOperation(
        name="collect_logs",
        op_type="READ_ONLY",
        description="Collect bounded, secret-redacted recent container logs.",
        impact="Zero state change; read-only log query.",
        risk="None: Safe bounded retrieval.",
        verification="Returns redacted text lines.",
        is_state_changing=False,
    ),
    "verify_health": SupportedOperation(
        name="verify_health",
        op_type="READ_ONLY",
        description="Evaluate container running status and execute or inspect health check probe.",
        impact="Zero state change; health telemetry evaluation.",
        risk="None: Safe health query.",
        verification="Reports health status: healthy, unhealthy, or unmonitored.",
        is_state_changing=False,
    ),
}

# Action allowlist: destructive actions (rm, kill, prune) are permanently forbidden
ALLOWED_RECOVERY_ACTIONS = {"start_container"}

# Protected containers
PROTECTED_NAMES = {"cloudops-floci", "linuxops-recovery-ui-test"}
PROTECTED_PREFIXES = {"510d4cfc0d22", "db80c688e14b", "83b65d88a0a9"}

# In-memory per-container policy overrides
_PER_CONTAINER_POLICIES: dict[str, dict[str, Any]] = {}
# Track executed approval tokens to prevent duplicate executions
_EXECUTED_APPROVAL_TOKENS: set[str] = set()


def clear_executed_approval_tokens() -> None:
    """Clear executed approval tokens cache (used for test resets)."""
    _EXECUTED_APPROVAL_TOKENS.clear()


def compute_plan_hash(
    container_name: str,
    operation: str,
    parameters: dict[str, Any] | None = None,
    target_state: str = "exited",
) -> str:
    """Compute a deterministic hash for a proposed remediation plan."""
    param_str = json.dumps(parameters or {}, sort_keys=True)
    raw = f"{container_name}:{operation}:{param_str}:{target_state}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def create_approval_token(plan_hash: str) -> str:
    """Generate an approval token strictly bound to a plan hash."""
    return f"APPR_{plan_hash}"


def validate_approval_token(approval_token: str | None, plan_hash: str) -> bool:
    """Validate that approval token strictly matches the current plan hash."""
    if not approval_token or not plan_hash:
        return False
    expected = create_approval_token(plan_hash)
    return secrets.compare_digest(str(approval_token).strip(), expected)


def is_approval_valid(approval_token: str | None, current_plan: dict[str, Any]) -> bool:
    """Check if an approval token is valid for the current plan."""
    if not approval_token or not isinstance(current_plan, dict):
        return False
    current_hash = current_plan.get("plan_hash")
    if not current_hash:
        return False
    recomputed = compute_plan_hash(
        container_name=current_plan.get("container_name", ""),
        operation=current_plan.get("operation", ""),
        parameters=current_plan.get("parameters"),
        target_state=current_plan.get("target_state", "exited"),
    )
    if current_hash != recomputed:
        return False
    return validate_approval_token(approval_token, current_hash)


def build_remediation_plan(
    container_name: str,
    operation: str = "start_container",
    parameters: dict[str, Any] | None = None,
    current_state: str = "exited",
    incident: dict[str, Any] | None = None,
    container_id: str = "",
    history_events: list[dict] | None = None,
    current_time: datetime | None = None,
    history_path: Path | None = None,
) -> dict[str, Any]:
    """
    Construct a formal remediation plan with numbered steps, exact proposed operations,
    impact, risks, verification criteria, and a tamper-evident plan hash.
    """
    valid_name, validated_name = validate_container_name(container_name)
    target_name = validated_name if valid_name else container_name
    params = parameters or {}

    # Validate operation against registry
    op_def = SUPPORTED_OPERATIONS.get(operation)
    if not op_def:
        return {
            "plan_id": f"PLAN_INVALID_{secrets.token_hex(4)}",
            "plan_hash": "",
            "container_name": target_name,
            "operation": operation,
            "parameters": params,
            "target_state": current_state,
            "is_state_changing": True,
            "allowed": False,
            "status": "INVALID_OPERATION",
            "decision": "DENY",
            "reason": f"Operation '{operation}' is not recognized in the supported operations registry.",
            "impact": "None",
            "risk": "High: Unknown operation rejected.",
            "numbered_steps": [],
            "verification_criteria": "None",
            "checks": {"operation_registered": False},
        }

    plan_hash = compute_plan_hash(
        container_name=target_name,
        operation=operation,
        parameters=params,
        target_state=current_state,
    )
    plan_id = f"PLAN_{operation}_{plan_hash[:8]}"

    # Evaluate policy
    proposal = evaluate_incident_recovery(
        container_name=target_name,
        current_state=current_state,
        incident=incident,
        container_id=container_id,
        history_events=history_events,
        current_time=current_time,
        history_path=history_path,
    )

    numbered_steps = [
        f"1. Target Verification: Validate container '{target_name}' exists and verify operation '{operation}' in supported registry.",
        f"2. Workload Immunity: Confirm '{target_name}' is not a protected workload (e.g. cloudops-floci, linuxops-recovery-ui-test).",
        "3. Safeguard Check: Confirm global recovery kill-switch is inactive.",
        f"4. Runtime State Validation: Verify container is currently in '{current_state}' state.",
        "5. Policy Engine Check: Evaluate recovery eligibility, retry thresholds, and cooldown window.",
        "6. Operator Authorization Boundary: Require explicit operator approval with bound cryptographic plan token.",
        f"7. Execution: Execute approved '{operation}' operation with strict timeout.",
        "8. Post-Action Health Verification: Query runtime State.Running and State.Health.Status to confirm operational health.",
        "9. Audit Commitment: Record execution result and post-action verification status to durable audit history.",
    ]

    return {
        "plan_id": plan_id,
        "plan_hash": plan_hash,
        "container_name": target_name,
        "container_id": container_id,
        "operation": operation,
        "parameters": params,
        "target_state": current_state,
        "is_state_changing": op_def.is_state_changing,
        "allowed": proposal.get("allowed", False),
        "status": "PROPOSED",
        "decision": proposal.get("decision", "DENY"),
        "reason": proposal.get("reason", "No reason provided."),
        "escalated": proposal.get("escalated", False),
        "impact": op_def.impact,
        "risk": op_def.risk,
        "numbered_steps": numbered_steps,
        "verification_criteria": op_def.verification,
        "checks": proposal.get("checks", {}),
        "cooldown_remaining_seconds": proposal.get("cooldown_remaining_seconds", 0.0),
        "attempts_in_window": proposal.get("attempts_in_window", 0),
        "incident_id": proposal.get("incident_id"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def approve_remediation_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Approve a proposed remediation plan and generate its bound approval token."""
    if not isinstance(plan, dict) or not plan.get("plan_hash"):
        raise ValueError("Cannot approve an invalid or unhashed remediation plan.")

    approved_plan = dict(plan)
    token = create_approval_token(plan["plan_hash"])
    approved_plan["approval_token"] = token
    approved_plan["status"] = "APPROVED"
    approved_plan["approved_at"] = datetime.now(timezone.utc).isoformat()
    return approved_plan


def reject_remediation_plan(
    plan: dict[str, Any],
    reason: str = "Operator rejected proposed remediation action.",
    history_path: Path | None = None,
) -> dict[str, Any]:
    """Explicitly reject a proposed remediation plan and record the rejection in audit history."""
    if not isinstance(plan, dict):
        raise ValueError("Plan must be a valid dictionary.")

    rejected_plan = dict(plan)
    rejected_plan["status"] = "REJECTED"
    rejected_plan["rejected_at"] = datetime.now(timezone.utc).isoformat()
    rejected_plan["rejection_reason"] = reason

    target_name = plan.get("container_name", "unknown")
    event_payload = {
        "success": False,
        "action": plan.get("operation", "start_container"),
        "verification_status": "REJECTED_BY_OPERATOR",
        "message": f"Remediation rejected by operator: {reason}",
        "plan_id": plan.get("plan_id"),
        "decision": "REJECTED",
    }
    try:
        record_recovery_event(target_name, event_payload, history_path=history_path)
    except Exception:
        pass

    return rejected_plan


def is_global_recovery_disabled() -> bool:
    """Return whether the global recovery kill-switch is active."""
    return _GLOBAL_RECOVERY_DISABLED


def set_global_recovery_disabled(disabled: bool) -> None:
    """Enable or disable the global recovery kill-switch."""
    global _GLOBAL_RECOVERY_DISABLED
    _GLOBAL_RECOVERY_DISABLED = bool(disabled)


def is_protected_container_target(
    name: str,
    container_id: str = "",
    inspect_data: dict[str, Any] | None = None,
    runner: Callable | None = None,
) -> bool:
    """Check if target matches a protected workload that must never be targeted."""
    clean_name = str(name or "").strip().lstrip("/")
    clean_id = str(container_id or "").strip()

    if clean_name in PROTECTED_NAMES:
        return True

    for pfx in PROTECTED_PREFIXES:
        if clean_id and (clean_id.startswith(pfx) or (len(clean_id) >= 12 and pfx.startswith(clean_id[:12]))):
            return True
        if clean_name and (clean_name.startswith(pfx) or (len(clean_name) >= 12 and pfx.startswith(clean_name[:12]))):
            return True

    # Check inspect data if provided directly
    if isinstance(inspect_data, dict):
        img = str(
            inspect_data.get("Config", {}).get("Image")
            or inspect_data.get("ImageName")
            or inspect_data.get("Image")
            or ""
        ).lower()
        if "floci" in img:
            return True
        labels = inspect_data.get("Config", {}).get("Labels") or inspect_data.get("Labels") or {}
        if isinstance(labels, dict) and labels.get("PODMAN_SYSTEMD_UNIT") == "cloudops-floci.service":
            return True
        mounts = inspect_data.get("Mounts") or []
        for m in mounts:
            if isinstance(m, dict) and "/home/neha/cloudops-sentinel/data" in str(m.get("Source") or ""):
                return True
            elif isinstance(m, str) and "/home/neha/cloudops-sentinel/data" in m:
                return True

    # Check live container inspect via runner if runner is provided
    if runner is not None and (clean_name or clean_id):
        target_query = clean_name or clean_id
        try:
            res = runner(
                ["podman", "inspect", target_query],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            if res.returncode == 0 and res.stdout:
                raw_list = json.loads(res.stdout)
                if isinstance(raw_list, list) and raw_list and isinstance(raw_list[0], dict):
                    insp_rec = raw_list[0]
                    if is_protected_container_target(name, container_id, inspect_data=insp_rec):
                        return True
            elif "floci" in target_query.lower() or "recovery-ui" in target_query.lower():
                return True
        except Exception:
            if "floci" in target_query.lower() or "recovery-ui" in target_query.lower():
                return True

    return False


def set_container_recovery_policy(
    container_name: str,
    enabled: bool = True,
    max_retries: int | None = None,
    cooldown_seconds: int | None = None,
) -> None:
    """Configure per-container recovery policy overrides."""
    valid, target_name = validate_container_name(container_name)
    if not valid:
        return
    _PER_CONTAINER_POLICIES[target_name] = {
        "enabled": enabled,
        "max_retries": max_retries,
        "cooldown_seconds": cooldown_seconds,
    }


def get_container_recovery_policy(container_name: str) -> dict[str, Any]:
    """Retrieve effective policy overrides for a container."""
    return _PER_CONTAINER_POLICIES.get(container_name, {})


def clear_container_recovery_policies() -> None:
    """Clear all per-container policy overrides (useful for test resets)."""
    _PER_CONTAINER_POLICIES.clear()


def evaluate_incident_recovery(
    container_name: str,
    current_state: str,
    incident: dict[str, Any] | None = None,
    container_id: str = "",
    history_events: list[dict] | None = None,
    current_time: datetime | None = None,
    history_path: Path | None = None,
) -> dict[str, Any]:
    """
    Evaluate whether a recovery action is permitted for a container and its incident.
    Returns structured preview proposal (strictly dry-run, never mutates system).
    """
    valid_name, validated_name = validate_container_name(container_name)
    if not valid_name:
        return {
            "allowed": False,
            "decision": "DENY",
            "action": "start_container",
            "container": container_name,
            "reason": validated_name,
            "dry_run": True,
            "escalated": False,
            "checks": {"name_valid": False},
        }

    target_name = validated_name

    # 1. Check Global Kill-Switch
    if is_global_recovery_disabled():
        return {
            "allowed": False,
            "decision": "DENY",
            "action": "start_container",
            "container": target_name,
            "reason": "Global recovery kill-switch is active. All container recoveries are disabled.",
            "dry_run": True,
            "escalated": False,
            "checks": {"global_kill_switch_clear": False},
        }

    # 2. Check Protected Workload Immunity
    if is_protected_container_target(target_name, container_id):
        return {
            "allowed": False,
            "decision": "DENY",
            "action": "start_container",
            "container": target_name,
            "reason": f"Protected workload immunity: recovery operations on '{target_name}' are permanently forbidden.",
            "dry_run": True,
            "escalated": True,
            "checks": {"protected_workload_clear": False},
        }

    # 3. Check Per-Container Policy Override
    c_policy = get_container_recovery_policy(target_name)
    if c_policy.get("enabled") is False:
        return {
            "allowed": False,
            "decision": "DENY",
            "action": "start_container",
            "container": target_name,
            "reason": f"Recovery is explicitly disabled by per-container policy for '{target_name}'.",
            "dry_run": True,
            "escalated": False,
            "checks": {"container_policy_enabled": False},
        }

    # 4. Check Incident-Specific Unresolvable Blockers
    incident_list = [incident] if isinstance(incident, dict) else (incident if isinstance(incident, list) else [])
    rule_ids = {i.get("rule_id") for i in incident_list if isinstance(i, dict)}

    if "OOM_KILLED" in rule_ids:
        return {
            "allowed": False,
            "decision": "DENY",
            "action": "start_container",
            "container": target_name,
            "reason": f"Container '{target_name}' was terminated by an OOM event; human review of resource limits is required before restart.",
            "dry_run": True,
            "escalated": True,
            "checks": {"oom_safeguard_satisfied": False},
        }

    if "CRASH_LOOP_DETECTED" in rule_ids:
        return {
            "allowed": False,
            "decision": "DENY",
            "action": "start_container",
            "container": target_name,
            "reason": f"Container '{target_name}' is in an active crash loop (escalated); automated restart is prohibited to protect host.",
            "dry_run": True,
            "escalated": True,
            "checks": {"crash_loop_safeguard_satisfied": False},
        }

    if "MISSING_BIND_MOUNT_SOURCE" in rule_ids:
        return {
            "allowed": False,
            "decision": "DENY",
            "action": "start_container",
            "container": target_name,
            "reason": f"Cannot recover '{target_name}': bind mount source directory does not exist on host.",
            "dry_run": True,
            "escalated": True,
            "checks": {"mount_source_valid": False},
        }

    if "PORT_CONFLICT_DETECTED" in rule_ids:
        return {
            "allowed": False,
            "decision": "DENY",
            "action": "start_container",
            "container": target_name,
            "reason": f"Cannot recover '{target_name}': host port conflict must be resolved first.",
            "dry_run": True,
            "escalated": True,
            "checks": {"port_conflict_clear": False},
        }

    # 5. Load Recovery History if not provided
    if history_events is None:
        try:
            history_events = load_recovery_history(limit=50, history_path=history_path)
        except Exception:
            history_events = []

    # 6. Evaluate Cooldown and Retry Limits using Core Policy Engine
    max_retries = c_policy.get("max_retries") or DEFAULT_MAX_FAILED_RETRIES
    cooldown = c_policy.get("cooldown_seconds") or DEFAULT_COOLDOWN_SECONDS

    diag_payload = {"oom_killed": False}
    if "OOM_KILLED" in rule_ids:
        diag_payload["oom_killed"] = True

    core_decision = evaluate_recovery_policy(
        container_name=target_name,
        current_state=current_state,
        history_events=history_events,
        diagnosis=diag_payload,
        max_failed_retries=max_retries,
        cooldown_seconds=cooldown,
        current_time=current_time,
    )

    is_allowed = core_decision.get("allowed", False)
    escalated = False
    if not is_allowed and core_decision.get("attempts_in_window", 0) >= max_retries:
        escalated = True

    first_inc = incident_list[0] if incident_list else {}
    first_inc_id = first_inc.get("incident_id") if isinstance(first_inc, dict) else None

    return {
        "allowed": is_allowed,
        "decision": "ALLOW" if is_allowed else "DENY",
        "action": "start_container",
        "container": target_name,
        "reason": core_decision.get("reason", "No reason provided."),
        "dry_run": True,
        "escalated": escalated,
        "checks": core_decision.get("checks", {}),
        "cooldown_remaining_seconds": core_decision.get("cooldown_remaining_seconds", 0.0),
        "attempts_in_window": core_decision.get("attempts_in_window", 0),
        "incident_id": first_inc_id,
    }


def verify_post_recovery_health(
    container_name: str,
    runner: Callable = subprocess.run,
    timeout: float = 10.0,
) -> tuple[bool, str]:
    """
    Verify container runtime state and healthcheck status immediately following restart.
    Returns (verified_healthy, message).
    """
    try:
        res = runner(
            [
                "podman", "inspect",
                "--format",
                '{"running":{{json .State.Running}},"status":{{json .State.Status}},"health":{{json .State.Health.Status}}}',
                container_name,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if res.returncode != 0:
            return False, f"Post-recovery inspect failed (exit code {res.returncode}): {res.stderr.strip()}"

        raw = (res.stdout or "").strip()
        data = json.loads(raw)
        is_running = bool(data.get("running", False))
        health_status = str(data.get("health") or "").strip().lower()

        if not is_running:
            return False, f"Container '{container_name}' is not running after start attempt."

        if health_status == "unhealthy":
            return False, f"Container '{container_name}' started but healthcheck reported UNHEALTHY."

        if health_status == "starting":
            return True, f"Container '{container_name}' is running, but healthcheck probe is still STARTING (inconclusive)."

        return True, f"Container '{container_name}' is running and verified healthy (healthcheck: {health_status or 'none'})."
    except subprocess.TimeoutExpired:
        return False, "Post-recovery inspection timed out."
    except Exception as exc:
        return False, f"Post-recovery verification error: {exc}"



def execute_authorized_recovery(
    container_name: str,
    action: str = "start_container",
    incident: dict[str, Any] | None = None,
    authorized: bool = False,
    approval_token: str | None = None,
    plan: dict[str, Any] | None = None,
    precondition_current_state: str | None = None,
    history_path: Path | None = None,
    incidents_path: Path | None = None,
    runner: Callable = subprocess.run,
    restart_fn: Callable = restart_container,
) -> dict[str, Any]:
    """
    Execute an approved recovery action with strict human-in-the-loop authorization gate.
    Never executes without explicit authorized=True flag or valid approval token.
    Never performs destructive actions.
    Performs post-recovery health verification and honest reporting.
    """
    valid_name, target_name = validate_container_name(container_name)
    if not valid_name:
        return {
            "success": False,
            "container": container_name,
            "action": action,
            "message": f"Recovery rejected: {target_name}",
            "verification_status": "REJECTED",
        }

    # 1. Authorization Gate
    if not authorized and not approval_token:
        return {
            "success": False,
            "container": target_name,
            "action": action,
            "message": f"Recovery rejected: explicit human authorization required for '{target_name}' (dry-run mode).",
            "verification_status": "AUTHORIZATION_REQUIRED",
        }

    # 1b. Plan & Approval Token Validation (Invalidate if plan or target changed)
    plan_id = None
    if plan is not None:
        if not isinstance(plan, dict):
            return {
                "success": False,
                "container": target_name,
                "action": action,
                "message": "Recovery rejected: provided remediation plan is invalid.",
                "verification_status": "INVALID_PLAN",
            }
        plan_id = plan.get("plan_id")

        # Invalidate if plan was explicitly rejected
        if plan.get("status") == "REJECTED":
            return {
                "success": False,
                "container": target_name,
                "action": action,
                "message": f"Recovery rejected: plan '{plan_id or target_name}' was explicitly rejected by operator.",
                "verification_status": "APPROVAL_REJECTED",
            }

        # Invalidate if plan target or operation does not match
        if plan.get("container_name") != target_name or plan.get("operation") != action:
            return {
                "success": False,
                "container": target_name,
                "action": action,
                "message": f"Recovery rejected: plan mismatch. Approved plan target '{plan.get('container_name')}' or op '{plan.get('operation')}' does not match execution request.",
                "verification_status": "APPROVAL_INVALIDATED",
            }

        # Recompute hash to detect any parameter or plan content tampering
        recomputed_hash = compute_plan_hash(
            container_name=plan.get("container_name", ""),
            operation=plan.get("operation", ""),
            parameters=plan.get("parameters"),
            target_state=plan.get("target_state", "exited"),
        )
        if plan.get("plan_hash") != recomputed_hash:
            return {
                "success": False,
                "container": target_name,
                "action": action,
                "message": "Recovery rejected: plan parameters or contents changed (approval invalidated).",
                "verification_status": "APPROVAL_INVALIDATED",
            }

        # If approval_token provided with plan, ensure it matches
        effective_token = approval_token or plan.get("approval_token")
        if effective_token:
            if effective_token in _EXECUTED_APPROVAL_TOKENS:
                return {
                    "success": False,
                    "container": target_name,
                    "action": action,
                    "message": "Recovery rejected: duplicate execution detected (approval token already consumed).",
                    "verification_status": "DUPLICATE_REQUEST_BLOCKED",
                }
            if not validate_approval_token(effective_token, recomputed_hash):
                return {
                    "success": False,
                    "container": target_name,
                    "action": action,
                    "message": "Recovery rejected: approval token does not match the proposed plan (plan parameters changed or token tampered).",
                    "verification_status": "APPROVAL_INVALIDATED",
                }
            approval_token = effective_token
    elif approval_token:
        if approval_token in _EXECUTED_APPROVAL_TOKENS:
            return {
                "success": False,
                "container": target_name,
                "action": action,
                "message": "Recovery rejected: duplicate execution detected (approval token already consumed).",
                "verification_status": "DUPLICATE_REQUEST_BLOCKED",
            }
        # Standalone approval token without plan: validate against standard target hash
        expected_hash = compute_plan_hash(target_name, action, target_state="exited")
        if not validate_approval_token(approval_token, expected_hash):
            return {
                "success": False,
                "container": target_name,
                "action": action,
                "message": "Recovery rejected: invalid approval token for target container and operation.",
                "verification_status": "APPROVAL_INVALIDATED",
            }

    # 2. Action Allowlist and Registry Validation
    if action not in ALLOWED_RECOVERY_ACTIONS or action not in SUPPORTED_OPERATIONS:
        return {
            "success": False,
            "container": target_name,
            "action": action,
            "message": f"Recovery rejected: action '{action}' is not in the approved safe recovery allowlist.",
            "verification_status": "FORBIDDEN_ACTION",
        }

    # 3. Global Recovery Kill-Switch
    if is_global_recovery_disabled():
        return {
            "success": False,
            "container": target_name,
            "action": action,
            "message": "Recovery rejected: global recovery kill-switch is active.",
            "verification_status": "GLOBAL_KILL_SWITCH",
        }

    # 4. Protected Workload Immunity
    if is_protected_container_target(target_name, runner=runner):
        return {
            "success": False,
            "container": target_name,
            "action": action,
            "message": f"Recovery rejected: protected workload '{target_name}' must never be modified.",
            "verification_status": "PROTECTED_WORKLOAD",
        }

    # 5. Precondition Revalidation: ensure container is not already running
    if precondition_current_state == "running":
        return {
            "success": False,
            "container": target_name,
            "action": action,
            "message": f"Precondition failed: container '{target_name}' is already running; state-changing start aborted.",
            "verification_status": "PRECONDITION_FAILED",
        }

    # 6. Backend Policy Gate: Re-evaluate recovery proposal to ensure policy approval cannot be bypassed
    policy_proposal = evaluate_incident_recovery(
        container_name=target_name,
        current_state="exited",
        incident=incident,
        history_path=history_path,
    )
    if not policy_proposal.get("allowed", False):
        return {
            "success": False,
            "container": target_name,
            "action": action,
            "message": f"Recovery policy rejected execution: {policy_proposal.get('reason', 'Policy denied')}",
            "verification_status": "POLICY_DENIED",
            "policy_proposal": policy_proposal,
        }

    # 7. Execute Non-Destructive Container Start
    try:
        if restart_fn is restart_container:
            restart_result = restart_container(target_name, runner=runner)
        else:
            restart_result = restart_fn(target_name)
    except subprocess.TimeoutExpired:
        restart_result = {
            "success": False,
            "message": "Podman execution timed out during recovery operation.",
        }
    except Exception as exc:
        restart_result = {
            "success": False,
            "message": f"Execution exception during recovery operation: {exc}",
        }
    restart_success = bool(restart_result.get("success", False))

    # Mark approval token as consumed so it cannot be re-executed
    if approval_token:
        _EXECUTED_APPROVAL_TOKENS.add(approval_token)

    verification_status = "FAILED"
    verify_msg = ""
    if restart_success:
        # 8. Post-Recovery Verification
        verified_healthy, verify_msg = verify_post_recovery_health(target_name, runner=runner)
        if not verified_healthy:
            verification_status = "FAILED_VERIFICATION"
        elif "starting" in verify_msg.lower() or "inconclusive" in verify_msg.lower():
            verification_status = "INCONCLUSIVE_VERIFICATION"
        else:
            verification_status = "VERIFIED"
    else:
        verify_msg = restart_result.get("message", "Start command failed.")

    # 9. Record to recovery history audit log
    event_payload = {
        "success": restart_success and (verification_status in {"VERIFIED", "INCONCLUSIVE_VERIFICATION"}),
        "message": f"{restart_result.get('message', '')} Verification: {verify_msg}".strip(),
        "verification_status": verification_status,
        "action": action,
        "approval_token": approval_token,
        "plan_id": plan_id,
        "decision": "APPROVED",
    }
    try:
        record_recovery_event(target_name, event_payload, history_path=history_path)
    except Exception:
        pass

    # 10. Record to incident resolution log if incident was provided
    if incident:
        res_status = "RESOLVED" if verification_status == "VERIFIED" else ("INCONCLUSIVE" if verification_status == "INCONCLUSIVE_VERIFICATION" else "FAILED_VERIFICATION")
        record_incident_resolution(incident, res_status, verify_msg, incidents_path=incidents_path)

    return {
        "success": restart_success and (verification_status in {"VERIFIED", "INCONCLUSIVE_VERIFICATION"}),
        "container": target_name,
        "action": action,
        "restart_result": restart_result,
        "verification_status": verification_status,
        "message": verify_msg or restart_result.get("message", ""),
        "approval_token": approval_token,
        "plan_id": plan_id,
    }
