#!/usr/bin/env python3

"""
LinuxOps Root-Cause Diagnostics & Incident Analysis Engine (Phase 2).

Provides rule-based expert diagnostics for:
- Exited/unexpectedly stopped containers
- Repeated restarts & crash loops
- Failed health checks
- CPU & memory pressure / OOM events
- Resource limit misconfigurations
- Missing or inaccessible bind mounts
- Image availability & pull issues
- Port conflicts
- Application readiness failures
- Runtime inspection failures & stale telemetry

Features strict evidence-based certainty scoring, secret redaction, and bounded log tailing.
"""

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import secrets
import subprocess
from typing import Any, Callable

# Sensitive tokens and credential redaction patterns
REDACTION_PATTERNS = [
    # Authorization & Bearer tokens
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{8,}", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(Basic\s+)[A-Za-z0-9+/=]{8,}", re.IGNORECASE), r"\1[REDACTED_BASIC]"),
    (re.compile(r"(Authorization:\s*)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED_AUTH]"),
    # AWS Access Key IDs & Secrets
    (re.compile(r"(AKIA[0-9A-Z]{16})"), r"[REDACTED_AWS_KEY]"),
    (re.compile(r"(aws_secret_access_key\s*=\s*)[^\s\r\n]+", re.IGNORECASE), r"\1[REDACTED_AWS_SECRET]"),
    # Key-value secret assignments in logs or env (e.g. PASSWORD=..., secret=..., token=...)
    (re.compile(r"((?:password|passwd|secret|token|api_?key|private_?key|auth_?token|credential|jwt)[a-z0-9_]*\s*[:=]\s*)[^\s,;&\r\n]+", re.IGNORECASE), r"\1[REDACTED_SECRET]"),
    # Private key blocks
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), r"[REDACTED_PRIVATE_KEY]"),
    # Generic hex/base64 tokens >= 32 chars
    (re.compile(r"(?<=\btoken=)[a-zA-Z0-9_\-]{20,}", re.IGNORECASE), r"[REDACTED_TOKEN]"),
    # Database and service connection string passwords (e.g. postgres://user:password@host)
    (re.compile(r"(://[^:\s/@]+:)[^@\s/]+(@)", re.IGNORECASE), r"\1[REDACTED_SECRET]\2"),
]


def redact_sensitive_text(text: str) -> str:
    """Redact passwords, credentials, API keys, and sensitive tokens from text."""
    if not text or not isinstance(text, str):
        return ""
    redacted = text
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


# Deterministic failure category patterns for logs and runtime errors
CONNECTION_REFUSED_RE = re.compile(
    r"(?:connection refused|econnrefused|failed to connect to|could not connect to|connection reset by peer|dial tcp .* connection refused|connect: connection refused|upstream .* offline|502 bad gateway|http 502|upstream .* unreachable)",
    re.IGNORECASE,
)
DNS_NETWORK_FAILURE_RE = re.compile(
    r"(?:name or service not known|could not resolve host|getaddrinfo\s+(?:eai_again|enotfound)|temporary failure in name resolution|no route to host|network is unreachable)",
    re.IGNORECASE,
)
PERMISSION_DENIED_RE = re.compile(
    r"(?:permission denied|\beacces\b|operation not permitted|\berrno 13\b)",
    re.IGNORECASE,
)
MISSING_CONFIG_ENV_RE = re.compile(
    r"(?:missing required environment variable|keyerror:\s*['\"][A-Za-z0-9_]+['\"]|environment variable .* is not set|configuration error|config file not found|failed to load config|no such file or directory:.*(?:\.conf|\.yaml|\.yml|\.env|\.json))",
    re.IGNORECASE,
)
STORAGE_FILESYSTEM_RE = re.compile(
    r"(?:no space left on device|read-only file system|disk quota exceeded|\benospc\b|input/output error|\bi/o error\b)",
    re.IGNORECASE,
)
IMAGE_PULL_RE = re.compile(
    r"(?:manifest unknown|failed to pull image|image not found|repository does not exist|unable to retrieve auth token|short-name \".*\" did not resolve to an alias)",
    re.IGNORECASE,
)


def extract_matching_lines(text: str, pattern: re.Pattern, max_lines: int = 3) -> list[str]:
    """Extract and redact matching lines from text."""
    if not text or not isinstance(text, str):
        return []
    matches = []
    for line in text.splitlines():
        clean = line.strip()
        if clean and pattern.search(clean):
            redacted = redact_sensitive_text(clean)
            if redacted not in matches:
                matches.append(redacted)
            if len(matches) >= max_lines:
                break
    return matches


def tail_container_logs(
    container_name: str,
    max_lines: int = 20,
    max_chars: int = 2000,
    runner: Callable = subprocess.run,
) -> tuple[str, bool]:
    """
    Retrieve bounded, secret-redacted recent container logs.
    Returns (redacted_logs, success).
    """
    if not container_name or not isinstance(container_name, str):
        return "", False

    cmd = ["podman", "logs", "--tail", str(max_lines), container_name]
    try:
        res = runner(cmd, capture_output=True, text=True, timeout=5.0, check=False)
        raw = ((res.stdout or "") + (res.stderr or "")).strip()
        if not raw:
            return "(No log records returned)", True
        # Bound character length
        if len(raw) > max_chars:
            raw = raw[-max_chars:]
            raw = f"...(truncated to {max_chars} chars)...\n" + raw
        return redact_sensitive_text(raw), res.returncode == 0
    except subprocess.TimeoutExpired:
        return "(Log retrieval timed out)", False
    except Exception as exc:
        return f"(Log retrieval failed: {exc})", False


def default_host_path_exists(source_path: str) -> bool:
    """Check whether a host path exists (read-only filesystem check)."""
    if not source_path:
        return False
    try:
        p = Path(source_path)
        return p.exists()
    except (OSError, ValueError):
        return False


def build_incident(
    container_name: str,
    container_id: str,
    rule_id: str,
    category: str,
    severity: str,
    probable_cause: str,
    confidence: float,
    evidence: list[str],
    recommended_action: str,
    verification_status: str = "UNVERIFIED",
    incident_id: str | None = None,
    severity_reason: str | None = None,
    symptoms: list[str] | None = None,
    candidate_causes: list[dict[str, Any]] | None = None,
    confidence_explanation: str | None = None,
    alternative_explanations: list[str] | None = None,
    suggested_investigation_steps: list[str] | None = None,
    investigation_commands: list[str] | None = None,
    action_reason: str | None = None,
    risks_and_prerequisites: str | None = None,
    expected_outcome: str | None = None,
    post_action_verification: str | None = None,
    escalation_guidance: str | None = None,
    first_seen: str | None = None,
    last_seen: str | None = None,
    correlated_containers: list[str] | None = None,
) -> dict[str, Any]:
    """Construct a standardized, immutable incident record with automatic secret redaction and stable ID."""
    if not incident_id:
        raw_key = f"{container_name}:{rule_id}"
        stable_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:8]
        inc_id = f"INC_{rule_id}_{stable_hash}"
    else:
        inc_id = incident_id

    now_iso = datetime.now(timezone.utc).isoformat()
    norm_confidence = round(max(0.0, min(1.0, float(confidence))), 2)

    # Defaults for operator guidance fields
    if not severity_reason:
        if severity == "CRITICAL":
            severity_reason = "Critical service failure, data loss risk, or workload termination."
        elif severity == "WARNING":
            severity_reason = "Degraded performance, potential instability, or misconfiguration."
        else:
            severity_reason = "Informational state transition or clean termination."

    if symptoms is None:
        symptoms = [f"Observed condition matching {rule_id}"]

    if not confidence_explanation:
        if norm_confidence >= 0.90:
            confidence_explanation = "High certainty derived from direct runtime telemetry and deterministic rule matching."
        elif norm_confidence >= 0.70:
            confidence_explanation = "Moderate certainty inferred from container state signals; requires log confirmation."
        else:
            confidence_explanation = "Low certainty hypothesis; missing definitive diagnostic telemetry."

    if candidate_causes is None:
        candidate_causes = [
            {
                "cause": redact_sensitive_text(probable_cause),
                "type": "CONFIRMED" if norm_confidence >= 0.90 else "INFERRED",
                "confidence": norm_confidence,
                "explanation": redact_sensitive_text(confidence_explanation),
            }
        ]
    else:
        sanitized_candidates = []
        for c in candidate_causes:
            if isinstance(c, dict):
                sanitized_candidates.append({
                    "cause": redact_sensitive_text(str(c.get("cause", ""))),
                    "type": str(c.get("type", "INFERRED")),
                    "confidence": round(max(0.0, min(1.0, float(c.get("confidence", norm_confidence)))), 2),
                    "explanation": redact_sensitive_text(str(c.get("explanation", ""))),
                })
        candidate_causes = sanitized_candidates

    if alternative_explanations is None:
        alternative_explanations = ["Transient host resource contention or upstream network timeout"]

    if suggested_investigation_steps is None:
        suggested_investigation_steps = [
            f"Review recent container logs for {container_name}.",
            "Inspect container configuration and resource limits.",
            "Verify dependencies and host system resource availability.",
        ]

    if investigation_commands is None:
        investigation_commands = [
            f"podman logs --tail 50 {container_name}",
            f"podman inspect {container_name}",
        ]

    if not action_reason:
        action_reason = f"Mitigate {probable_cause} and restore service stability."

    if not risks_and_prerequisites:
        risks_and_prerequisites = "Review service SLA and downstream dependencies before modifying container configuration."

    if not expected_outcome:
        expected_outcome = "Workload restored to healthy operational state."

    if not post_action_verification:
        post_action_verification = f"Verify container is running and healthy: podman ps --filter name={container_name}"

    if not escalation_guidance:
        escalation_guidance = "If issue persists after executing steps, escalate to service owner and platform engineer."

    return {
        "incident_id": inc_id,
        "container_name": container_name,
        "container_id": container_id,
        "rule_id": rule_id,
        "category": category,
        "severity": severity,  # CRITICAL, WARNING, INFO
        "severity_reason": redact_sensitive_text(severity_reason),
        "timestamp": now_iso,
        "first_seen": first_seen or now_iso,
        "last_seen": last_seen or now_iso,
        "symptoms": [redact_sensitive_text(str(s)) for s in symptoms],
        "probable_cause": redact_sensitive_text(probable_cause),
        "candidate_causes": candidate_causes,
        "confidence": norm_confidence,
        "confidence_explanation": redact_sensitive_text(confidence_explanation),
        "alternative_explanations": [redact_sensitive_text(str(a)) for a in alternative_explanations],
        "evidence": [redact_sensitive_text(str(e)) for e in (evidence or [])],
        "suggested_investigation_steps": [redact_sensitive_text(str(step)) for step in suggested_investigation_steps],
        "investigation_commands": [redact_sensitive_text(str(cmd)) for cmd in investigation_commands],
        "recommended_action": redact_sensitive_text(recommended_action),
        "action_reason": redact_sensitive_text(action_reason),
        "risks_and_prerequisites": redact_sensitive_text(risks_and_prerequisites),
        "expected_outcome": redact_sensitive_text(expected_outcome),
        "post_action_verification": redact_sensitive_text(post_action_verification),
        "escalation_guidance": redact_sensitive_text(escalation_guidance),
        "verification_status": verification_status,
        "correlated_containers": [str(c) for c in (correlated_containers or [])],
    }


def diagnose_container_record(
    container: dict[str, Any],
    all_containers: list[dict[str, Any]] | None = None,
    host_source_checker: Callable[[str], bool] = default_host_path_exists,
    log_retriever: Callable[[str], tuple[str, bool]] | None = None,
) -> list[dict[str, Any]]:
    """
    Evaluate deterministic diagnostic rules against an inspected ContainerRecord.
    Never claims a root cause without evidence; reports uncertainty and guidance explicitly.
    """
    incidents: list[dict[str, Any]] = []

    name = container.get("name", "unknown")
    cid = container.get("id", "unknown")
    state = str(container.get("state") or "").strip().lower()
    exit_code = container.get("exit_code")
    oom_killed = bool(container.get("oom_killed", False))
    restart_count = int(container.get("restart_count") or 0)
    health_status = str(container.get("health_status") or "").strip().lower()
    limits = container.get("resource_limits") or {}
    metrics = container.get("metrics") or {}
    mounts = container.get("mounts") or []
    inspection_status = container.get("inspection_status", "inspected")
    error = container.get("error")

    # Rule 10: Runtime inspection failure or stale telemetry
    if inspection_status == "failed" or error:
        incidents.append(build_incident(
            container_name=name,
            container_id=cid,
            rule_id="RUNTIME_INSPECTION_FAILURE",
            category="observability",
            severity="WARNING",
            severity_reason="Inspection failure prevents real-time health and telemetry tracking.",
            symptoms=["Container inspection query returned an error or failed to complete"],
            probable_cause=f"Podman runtime inspection failed or container disappeared: {error}",
            confidence=0.95,
            confidence_explanation="Direct subprocess inspect call returned an error response.",
            evidence=[f"inspection_status='failed'", f"error='{error}'"],
            suggested_investigation_steps=[
                f"Verify container presence: podman ps -a --filter id={cid}",
                "Check user systemd Podman service logs for socket errors",
            ],
            investigation_commands=[
                f"podman inspect {cid}",
                "systemctl --user status podman.socket",
            ],
            recommended_action="Verify container presence in Podman engine and check daemon logs.",
            action_reason="Restore telemetry pipeline to maintain observability.",
            risks_and_prerequisites="Read-only operation; zero impact on running workloads.",
            expected_outcome="Subprocess inspection succeeds with valid JSON record.",
            post_action_verification="Rerun LinuxOps scan and verify zero failed inspections.",
            escalation_guidance="If daemon socket is unreachable, check user linger settings and journalctl --user.",
            verification_status="VERIFIED",
        ))

    if metrics.get("telemetry_state") == "stale":
        incidents.append(build_incident(
            container_name=name,
            container_id=cid,
            rule_id="STALE_TELEMETRY",
            category="observability",
            severity="WARNING",
            severity_reason="Resource metrics are older than freshness window; metrics may not reflect live state.",
            symptoms=["Metrics timestamp exceeds freshness interval"],
            probable_cause="Container resource metrics are older than freshness window.",
            confidence=0.90,
            confidence_explanation="Telemetry age calculation exceeded configured freshness threshold.",
            evidence=["metrics.telemetry_state='stale'"],
            suggested_investigation_steps=[
                "Verify if podman stats monitor loop is running without delay",
                "Check host CPU load to ensure stats queries are not being starved",
            ],
            investigation_commands=[
                "podman stats --no-stream",
                "uptime",
            ],
            recommended_action="Ensure podman stats monitor service is running and responsive.",
            action_reason="Keep monitoring metrics fresh and actionable.",
            risks_and_prerequisites="None; stats queries are read-only.",
            expected_outcome="Fresh resource metrics populated on next polling cycle.",
            post_action_verification="Check that data_freshness_seconds is under configured threshold.",
            escalation_guidance="Increase stats timeout if host is experiencing high I/O wait.",
            verification_status="VERIFIED",
        ))

    # Rule 4: OOM Killer or Memory Pressure
    if oom_killed:
        incidents.append(build_incident(
            container_name=name,
            container_id=cid,
            rule_id="OOM_KILLED",
            category="resource",
            severity="CRITICAL",
            severity_reason="Workload was forcibly killed by the Linux kernel cgroup OOM killer.",
            symptoms=[
                "Process killed abruptly by SIGKILL (exit code 137)",
                "Kernel cgroup memory controller flagged OOMKilled=True",
            ],
            probable_cause="Container exceeded cgroup memory boundary and was terminated by kernel Out-Of-Memory killer.",
            confidence=1.0,
            confidence_explanation="Deterministic certainty: State.OOMKilled flag set directly by the Linux kernel.",
            evidence=[f"State.OOMKilled=True", f"exit_code={exit_code}"],
            suggested_investigation_steps=[
                "Inspect memory consumption trends leading up to termination.",
                "Review application logs for memory leak indicators or large payload allocations.",
                "Verify host memory capacity and current container limit.",
            ],
            investigation_commands=[
                f"podman inspect -f '{{{{.State.OOMKilled}}}}' {name}",
                f"podman logs --tail 100 {name}",
                f"podman inspect -f '{{{{.HostConfig.Memory}}}}' {name}",
            ],
            recommended_action="Increase container memory limit (--memory) or optimize application memory footprint.",
            action_reason="Prevent kernel from terminating workload under standard traffic volume.",
            risks_and_prerequisites="Ensure host has sufficient unallocated RAM before increasing limits.",
            expected_outcome="Container executes without exceeding memory boundary.",
            post_action_verification=f"Monitor podman stats {name} over 15 minutes to confirm memory stays below 80% limit.",
            escalation_guidance="If memory continuously increases regardless of limit size, escalate to development team for memory leak profiling.",
            verification_status="VERIFIED",
        ))
    elif state == "running":
        mem_pct = metrics.get("memory_percent", {}).get("value")
        if mem_pct is not None and mem_pct >= 95.0:
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="MEMORY_PRESSURE_CRITICAL",
                category="resource",
                severity="CRITICAL",
                severity_reason=f"Memory utilization is critically saturated at {mem_pct:.1f}%, imminent risk of OOM kill.",
                symptoms=[f"Memory usage at {mem_pct:.1f}% of allocated cgroup limit"],
                probable_cause=f"Container memory consumption is critically saturated at {mem_pct:.1f}% of limit.",
                confidence=0.90,
                confidence_explanation="Real-time telemetry reports usage above 95% threshold.",
                evidence=[f"memory_percent={mem_pct:.1f}% (>=95.0%)"],
                suggested_investigation_steps=[
                    "Check for sudden spike in concurrent requests or uncollected memory cache.",
                    "Review application heap allocation metrics.",
                ],
                investigation_commands=[
                    f"podman stats --no-stream {name}",
                    f"podman top {name}",
                ],
                recommended_action="Investigate memory leak or increase memory limit before container is OOM-killed.",
                action_reason="Avert imminent kernel OOM termination.",
                risks_and_prerequisites="Increasing memory limits requires operator review of available host memory.",
                expected_outcome="Memory headroom restored to >= 20%.",
                post_action_verification=f"Confirm memory_percent drops below 85% via podman stats {name}.",
                escalation_guidance="If usage remains >95%, prepare to restart container during a scheduled maintenance window.",
                verification_status="VERIFIED",
            ))

    # Rule 1: Exited or unexpectedly stopped container
    if state in {"exited", "stopped"}:
        if oom_killed:
            pass  # Already covered under OOM_KILLED
        elif exit_code == 0:
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="CONTAINER_STOPPED_NORMAL",
                category="lifecycle",
                severity="INFO",
                severity_reason="Container exited with status 0 indicating completed task or graceful shutdown.",
                symptoms=["State is stopped/exited with exit code 0"],
                probable_cause="Container exited with status 0; completed execution or shut down gracefully.",
                confidence=0.85,
                confidence_explanation="Exit code 0 confirms standard process termination.",
                evidence=["State.Status in ('exited', 'stopped')", "exit_code=0"],
                suggested_investigation_steps=[
                    "Confirm whether container was expected to terminate (e.g. batch job or migration).",
                ],
                investigation_commands=[
                    f"podman inspect -f '{{{{.State.FinishedAt}}}}' {name}",
                ],
                recommended_action="No recovery action required unless container is an ongoing service.",
                action_reason="Container completed work successfully.",
                risks_and_prerequisites="None.",
                expected_outcome="Container remains stopped until next scheduled run.",
                post_action_verification="Verify job completed output in logs if required.",
                escalation_guidance="If container was meant to be a persistent daemon, check its entrypoint configuration.",
                verification_status="VERIFIED",
            ))
        elif exit_code == 137:
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="SIGKILL_STOPPED",
                category="lifecycle",
                severity="WARNING",
                severity_reason="Workload was killed abruptly by SIGKILL (signal 9) without OOM indicator.",
                symptoms=["Terminated with exit code 137, OOMKilled=False"],
                probable_cause="Container terminated abruptly by SIGKILL (exit code 137). Possible manual stop or timeout.",
                confidence=0.75,
                confidence_explanation="Exit code 137 indicates SIGKILL; lack of OOM flag suggests external stop command or stop timeout.",
                evidence=["exit_code=137", "oom_killed=False"],
                suggested_investigation_steps=[
                    "Check audit log or operator command history for manual `podman stop` or `kill`.",
                    "Check system shutdown or container stop timeout logs.",
                ],
                investigation_commands=[
                    f"podman inspect -f '{{{{.State.FinishedAt}}}}' {name}",
                    "journalctl --user -n 50",
                ],
                recommended_action="Check host logs and timeout configuration before attempting recovery.",
                action_reason="Determine if stop was intentional before restarting.",
                risks_and_prerequisites="Restarting a manually stopped container may conflict with maintenance activities.",
                expected_outcome="Clarification on termination origin.",
                post_action_verification="Ensure container starts cleanly when operator initiates restart.",
                escalation_guidance="Check with operator team to verify if container was deliberately decommissioned.",
                verification_status="UNVERIFIED",
            ))
        elif exit_code in {125, 126, 127}:
            sub_cause = (
                "Podman engine failed to invoke container" if exit_code == 125
                else "Command cannot be invoked (permission denied or not executable)" if exit_code == 126
                else "Command not found inside container image"
            )
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="CONTAINER_STARTUP_EXEC_ERROR",
                category="lifecycle",
                severity="CRITICAL",
                severity_reason=f"Container failed at startup with engine/exec code {exit_code}: {sub_cause}.",
                symptoms=[f"Immediate termination on start with exit code {exit_code}"],
                probable_cause=f"Startup execution error: {sub_cause}.",
                confidence=0.90,
                confidence_explanation=f"Exit code {exit_code} is standard POSIX/OCI code for startup execution failure.",
                evidence=[f"exit_code={exit_code}"],
                suggested_investigation_steps=[
                    "Inspect container Entrypoint and Cmd definitions.",
                    "Verify file permissions inside image.",
                ],
                investigation_commands=[
                    f"podman inspect -f '{{{{.Config.Entrypoint}}}} {{{{.Config.Cmd}}}}' {name}",
                    f"podman logs {name}",
                ],
                recommended_action="Correct image entrypoint path, executable permissions, or container command.",
                action_reason="Container cannot execute entrypoint command.",
                risks_and_prerequisites="Re-building or re-pulling image may be required.",
                expected_outcome="Container entrypoint executes cleanly.",
                post_action_verification=f"Run podman run --rm -it <image> to verify binary exists and is executable.",
                escalation_guidance="Escalate to image maintainer.",
                verification_status="VERIFIED",
            ))
        elif exit_code is not None and exit_code > 128:
            sig = exit_code - 128
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="SIGNAL_TERMINATED",
                category="lifecycle",
                severity="WARNING",
                severity_reason=f"Container process terminated by Linux signal {sig} (exit code {exit_code}).",
                symptoms=[f"Exited with signal {sig}"],
                probable_cause=f"Container terminated by Linux signal {sig} (exit code {exit_code}).",
                confidence=0.80,
                confidence_explanation=f"Exit code {exit_code} maps mathematically to signal {sig} (128 + {sig}).",
                evidence=[f"exit_code={exit_code} (signal {sig})"],
                suggested_investigation_steps=[
                    f"Inspect logs for panic, abort, or signal handler output for signal {sig}.",
                ],
                investigation_commands=[
                    f"podman logs --tail 50 {name}",
                ],
                recommended_action="Inspect application logs around termination timestamp.",
                action_reason="Identify what triggered process signal termination.",
                risks_and_prerequisites="Review logs before restarting to avoid repeating crash.",
                expected_outcome="Identification of crash trigger.",
                post_action_verification="Verify clean startup without signal termination.",
                escalation_guidance="Escalate to application developers if signal is SIGSEGV (11) or SIGABRT (6).",
                verification_status="VERIFIED",
            ))
        elif exit_code is not None:
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="CONTAINER_NONZERO_EXIT",
                category="lifecycle",
                severity="WARNING",
                severity_reason=f"Application exited with non-zero error code {exit_code}.",
                symptoms=[f"Application process exited with error status {exit_code}"],
                probable_cause=f"Container application exited with non-zero error code {exit_code}.",
                confidence=0.85,
                confidence_explanation="Container runtime reported definitive non-zero exit code.",
                evidence=[f"exit_code={exit_code}"],
                suggested_investigation_steps=[
                    "Review application stderr output for stack trace or unhandled exception.",
                ],
                investigation_commands=[
                    f"podman logs --tail 50 {name}",
                ],
                recommended_action="Review container stderr/stdout logs to determine application failure cause.",
                action_reason="Address application-level error causing exit.",
                risks_and_prerequisites="Do not blindly restart without addressing application error.",
                expected_outcome="Application initializes and maintains running state.",
                post_action_verification=f"Check podman ps --filter name={name} after resolving error.",
                escalation_guidance="Escalate to application maintainer with relevant log stack traces.",
                verification_status="VERIFIED",
            ))
        else:
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="CONTAINER_STOPPED_UNKNOWN_EXIT",
                category="lifecycle",
                severity="WARNING",
                severity_reason="Container is stopped but exit code could not be determined.",
                symptoms=["Container state is exited/stopped with null exit code"],
                probable_cause="Container is stopped with indeterminate exit code.",
                confidence=0.50,
                confidence_explanation="Indeterminate state; exit metadata missing from Podman inspect response.",
                evidence=["state in ('exited', 'stopped')", "exit_code=None"],
                suggested_investigation_steps=[
                    "Inspect Podman daemon state and host journal.",
                ],
                investigation_commands=[
                    f"podman inspect {name}",
                ],
                recommended_action="Inspect container logs and system journal.",
                action_reason="Retrieve missing exit diagnostics.",
                risks_and_prerequisites="Low risk read-only inspection.",
                expected_outcome="Obtain exit code and termination reason.",
                post_action_verification="Check container record has updated exit_code on subsequent scan.",
                escalation_guidance="Escalate if daemon inspect repeatedly omits container state metadata.",
                verification_status="UNVERIFIED",
            ))

    # Rule 2: Repeated restarts & crash loops
    if restart_count >= 3:
        incidents.append(build_incident(
            container_name=name,
            container_id=cid,
            rule_id="CRASH_LOOP_DETECTED",
            category="lifecycle",
            severity="CRITICAL",
            severity_reason=f"Container has repeatedly failed and restarted {restart_count} times, indicating a crash loop.",
            symptoms=[
                f"Restart count {restart_count} exceeded threshold (>=3)",
                "Continuous crash-restart cycle consuming host resources",
            ],
            probable_cause=f"Container has repeatedly failed and restarted {restart_count} times, indicating a crash loop.",
            confidence=0.95,
            confidence_explanation=f"Restart count {restart_count} confirms ongoing failure cycle.",
            evidence=[f"restart_count={restart_count} (>=3)", f"restart_policy={container.get('restart_policy')}"],
            candidate_causes=[
                {
                    "cause": "Startup crash due to missing dependency or invalid configuration",
                    "type": "INFERRED",
                    "confidence": 0.90,
                    "explanation": f"High restart count ({restart_count}) with short execution lifecycle.",
                }
            ],
            alternative_explanations=[
                "External dependency unreachable on startup",
                "Database migration failure",
            ],
            suggested_investigation_steps=[
                "Halt restart loop to prevent resource exhaustion.",
                "Inspect latest logs for initialization errors.",
                "Verify required network and storage dependencies.",
            ],
            investigation_commands=[
                f"podman logs --tail 50 {name}",
                f"podman inspect -f '{{{{.HostConfig.RestartPolicy.Name}}}}' {name}",
            ],
            recommended_action="Halt automatic restarts; investigate application startup exceptions.",
            action_reason="Stop resource thrashing and isolate root cause.",
            risks_and_prerequisites="Pausing or stopping restarts will take container offline until fixed.",
            expected_outcome="Root cause diagnosed and container starts stably without restarting.",
            post_action_verification=f"Monitor container for 5 minutes; verify restart_count does not increment.",
            escalation_guidance="Escalate to development team with startup log traces.",
            verification_status="VERIFIED",
        ))

    # Rule 3: Failed health checks
    if health_status == "unhealthy":
        incidents.append(build_incident(
            container_name=name,
            container_id=cid,
            rule_id="HEALTHCHECK_FAILING",
            category="health",
            severity="CRITICAL",
            severity_reason="Podman healthcheck probe failed repeatedly; container is non-functional.",
            symptoms=["Container Health.Status is 'unhealthy'"],
            probable_cause="Podman container healthcheck probe failed repeatedly.",
            confidence=0.95,
            confidence_explanation="Direct status from Podman engine healthcheck evaluator.",
            evidence=["health_status='unhealthy'"],
            suggested_investigation_steps=[
                "Inspect healthcheck probe command and last output log.",
                "Test health endpoint from inside the container.",
            ],
            investigation_commands=[
                f"podman inspect -f '{{{{json .State.Health}}}}' {name}",
                f"podman logs --tail 50 {name}",
            ],
            recommended_action="Inspect healthcheck endpoint or probe command output in container metadata.",
            action_reason="Determine why health probe is returning non-zero exit code.",
            risks_and_prerequisites="Verify whether probe failure is due to internal deadlock or external dependency.",
            expected_outcome="Healthcheck probe passes and status transitions to 'healthy'.",
            post_action_verification=f"Run podman healthcheck run {name} to verify resolution.",
            escalation_guidance="Escalate to application owner if internal health endpoint returns HTTP 500.",
            verification_status="VERIFIED",
        ))

    # Rule 5: Resource Limit Misconfiguration
    mem_bytes = limits.get("memory_bytes") or 0
    swap_bytes = limits.get("memory_swap_bytes") or 0
    if 0 < swap_bytes < mem_bytes:
        incidents.append(build_incident(
            container_name=name,
            container_id=cid,
            rule_id="INVALID_SWAP_LIMIT",
            category="configuration",
            severity="WARNING",
            severity_reason="Swap limit configured smaller than memory limit; violates Linux cgroup specification.",
            symptoms=[f"Swap limit ({swap_bytes} B) < Memory limit ({mem_bytes} B)"],
            probable_cause=f"Memory swap limit ({swap_bytes} B) is configured smaller than memory limit ({mem_bytes} B).",
            confidence=0.90,
            confidence_explanation="Deterministic configuration check: cgroup memory-swap cannot be less than memory.",
            evidence=[f"memory_bytes={mem_bytes}", f"memory_swap_bytes={swap_bytes}"],
            suggested_investigation_steps=[
                "Check container creation parameters or compose file for --memory-swap.",
            ],
            investigation_commands=[
                f"podman inspect -f '{{{{.HostConfig.MemorySwap}}}}' {name}",
            ],
            recommended_action="Set memory-swap to be equal to or greater than memory limit.",
            action_reason="Comply with Linux cgroup memory controller constraints.",
            risks_and_prerequisites="Requires updating container configuration on next recreation.",
            expected_outcome="Valid memory-swap boundary applied.",
            post_action_verification=f"Verify HostConfig.MemorySwap >= HostConfig.Memory in podman inspect {name}.",
            escalation_guidance="Review deployment templates or compose files.",
            verification_status="VERIFIED",
        ))

    # Rule 6: Missing or inaccessible bind mounts
    for m in mounts:
        if isinstance(m, dict) and m.get("type") == "bind":
            src = m.get("source", "")
            if src and not host_source_checker(src):
                incidents.append(build_incident(
                    container_name=name,
                    container_id=cid,
                    rule_id="MISSING_BIND_MOUNT_SOURCE",
                    category="storage",
                    severity="CRITICAL",
                    severity_reason="Host directory for bind mount does not exist; container storage inaccessible.",
                    symptoms=[f"Host path '{src}' does not exist on host filesystem"],
                    probable_cause=f"Bind mount source directory does not exist on host: '{src}'.",
                    confidence=0.95,
                    confidence_explanation="Host filesystem check returned False for bind mount source path.",
                    evidence=[f"mount.source='{src}' not found on host filesystem", f"destination='{m.get('destination')}'"],
                    suggested_investigation_steps=[
                        f"Check if parent directory exists: ls -ld $(dirname '{src}')",
                        "Verify whether external volume or network share needs to be mounted first.",
                    ],
                    investigation_commands=[
                        f"ls -la '{src}'",
                        "df -h",
                    ],
                    recommended_action=f"Create host directory '{src}' with appropriate permissions or update container volume config.",
                    action_reason="Enable container to mount required host storage.",
                    risks_and_prerequisites="Ensure directory permissions (UID/GID) match container process user.",
                    expected_outcome="Container mounts directory cleanly without storage errors.",
                    post_action_verification=f"Verify directory exists with correct permissions: ls -ld '{src}'.",
                    escalation_guidance="Escalate to host systems administrator if path belongs to unmounted network share.",
                    verification_status="VERIFIED",
                ))

    # Rule 8: Port Conflicts
    if all_containers and isinstance(all_containers, list) and state == "running":
        my_ports = container.get("ports", {})
        for cport, host_bindings in my_ports.items():
            for b in host_bindings:
                conflict_found = False
                for other in all_containers:
                    if not isinstance(other, dict) or other.get("id") == cid or other.get("state") != "running":
                        continue
                    other_ports = other.get("ports", {})
                    for ocport, obindings in other_ports.items():
                        if b in obindings:
                            other_name = other.get("name", "unknown")
                            incidents.append(build_incident(
                                container_name=name,
                                container_id=cid,
                                rule_id="PORT_CONFLICT_DETECTED",
                                category="network",
                                severity="CRITICAL",
                                severity_reason=f"Host port binding '{b}' is concurrently claimed by container '{other_name}'.",
                                symptoms=[f"Two active containers claiming identical host socket {b}"],
                                probable_cause=f"Host port binding '{b}' is concurrently bound by container '{other_name}'.",
                                confidence=0.90,
                                confidence_explanation="Inventory inspection revealed duplicate host port bindings across active containers.",
                                evidence=[f"conflicting_host_binding='{b}'", f"conflicting_container='{other_name}'"],
                                suggested_investigation_steps=[
                                    f"Identify intended port mappings for both {name} and {other_name}.",
                                    "Check if one container is an obsolete instance from previous deployment.",
                                ],
                                investigation_commands=[
                                    f"podman port {name}",
                                    f"podman port {other_name}",
                                ],
                                recommended_action="Reassign conflicting container port to an unused host port.",
                                action_reason="Eliminate socket conflict so network traffic reaches intended service.",
                                risks_and_prerequisites="Rebinding port requires updating reverse proxy or client connection strings.",
                                expected_outcome="Both services run without port collision.",
                                post_action_verification=f"Verify with 'podman port {name}' that no duplicate port bindings exist.",
                                escalation_guidance="Coordinate with application owners to assign unique non-conflicting host ports.",
                                verification_status="VERIFIED",
                                correlated_containers=[other_name],
                            ))
                            conflict_found = True
                            break
                    if conflict_found:
                        break

    # Rule 9: Application readiness failure
    if state == "running" and health_status == "starting":
        created_str = container.get("created_at") or container.get("started_at")
        if created_str:
            try:
                dt = datetime.fromisoformat(str(created_str).replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - dt).total_seconds()
                if age > 300.0:  # In starting state for > 5 minutes
                    incidents.append(build_incident(
                        container_name=name,
                        container_id=cid,
                        rule_id="APPLICATION_READINESS_TIMEOUT",
                        category="health",
                        severity="WARNING",
                        severity_reason=f"Container has remained in 'starting' readiness state for {int(age)} seconds (> 300s).",
                        symptoms=[f"Starting readiness state duration {int(age)}s exceeds 300s SLA"],
                        probable_cause=f"Container has remained in 'starting' readiness state for {int(age)} seconds.",
                        confidence=0.75,
                        confidence_explanation="Duration in 'starting' state significantly exceeds normal initialization window.",
                        evidence=[f"health_status='starting'", f"elapsed_seconds={int(age)} (>300s)"],
                        suggested_investigation_steps=[
                            "Check if startup probe command is hanging or timing out.",
                            "Inspect initialization logs to see if app is waiting on external database.",
                        ],
                        investigation_commands=[
                            f"podman logs --tail 50 {name}",
                            f"podman inspect -f '{{{{json .State.Health}}}}' {name}",
                        ],
                        recommended_action="Inspect startup initialization hooks and health probe timeouts.",
                        action_reason="Resolve startup stall before health probe fails permanently.",
                        risks_and_prerequisites="Probe timeout adjustment should not mask genuine startup hangs.",
                        expected_outcome="Application completes initialization and reports healthy.",
                        post_action_verification=f"Verify health status transitions to 'healthy' in podman ps.",
                        escalation_guidance="Escalate if database connection or initialization hook is deadlocked.",
                        verification_status="UNVERIFIED",
                    ))
            except Exception:
                pass

    # Rule 11: Common runtime & log failure categories
    # Collect logs and error outputs for evidence-based failure category detection
    logs_content = ""
    if container.get("recent_logs"):
        logs_content = str(container.get("recent_logs"))
    elif container.get("logs"):
        logs_content = str(container.get("logs"))
    elif log_retriever and callable(log_retriever) and name and name != "unknown":
        try:
            fetched_logs, _ = log_retriever(name)
            logs_content = str(fetched_logs or "")
        except Exception:
            logs_content = ""

    health_hist = container.get("health_check_history") or []
    health_output = ""
    if health_hist and isinstance(health_hist, list) and isinstance(health_hist[-1], dict):
        health_output = str(health_hist[-1].get("output") or "")

    combined_diagnostic_text = f"{error or ''}\n{logs_content}\n{health_output}".strip()

    if combined_diagnostic_text:
        # 11A: Connection refused & dependency outages
        conn_matches = extract_matching_lines(combined_diagnostic_text, CONNECTION_REFUSED_RE)
        if conn_matches:
            correlated_upstreams: list[str] = []
            if all_containers and isinstance(all_containers, list):
                for other in all_containers:
                    if not isinstance(other, dict):
                        continue
                    other_name = str(other.get("name") or "")
                    if not other_name or other_name == name:
                        continue
                    other_base = other_name.removeprefix("demo-")
                    if (other_base and other_base in combined_diagnostic_text) or (other_name in combined_diagnostic_text):
                        if other_name not in correlated_upstreams:
                            correlated_upstreams.append(other_name)

            sev = "CRITICAL" if (state in {"exited", "stopped", "restarting"} or health_status == "unhealthy" or restart_count > 0) else "WARNING"
            cause_desc = (
                f"Upstream dependency ({', '.join(correlated_upstreams)}) is offline or rejecting connections."
                if correlated_upstreams
                else "Upstream dependency is offline, unreachable, or rejecting TCP connection."
            )
            investigation_steps = [
                f"1. Check if upstream dependency ({', '.join(correlated_upstreams)}) is running: podman ps" if correlated_upstreams else "1. Identify the target host and port reported in the log error message.",
                "2. Verify container network connectivity and DNS reachability from container namespace.",
                "3. Ensure upstream service is ready to accept connections before restarting dependent containers.",
            ]
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="DEPENDENCY_CONNECTION_REFUSED",
                category="network",
                severity=sev,
                severity_reason="Workload cannot establish network connection to required upstream service.",
                symptoms=["Network socket connection actively rejected by target host/port", "Application failed to connect to dependency"],
                probable_cause=cause_desc,
                confidence=0.90,
                confidence_explanation="Deterministic log evidence: process encountered connection refused or upstream offline on socket connect.",
                evidence=conn_matches + ([f"exit_code={exit_code}"] if exit_code is not None else []),
                candidate_causes=[
                    {
                        "cause": f"Upstream service ({', '.join(correlated_upstreams) if correlated_upstreams else 'database, cache, or API'}) is stopped or not listening on configured port",
                        "type": "CONFIRMED",
                        "confidence": 0.90,
                        "explanation": f"Log error: '{conn_matches[0]}'",
                    },
                    {
                        "cause": "Network routing, container firewall, or bridge network misconfiguration",
                        "type": "INFERRED",
                        "confidence": 0.60,
                        "explanation": "Target port may be closed or host firewall is blocking traffic.",
                    },
                ],
                alternative_explanations=[
                    "Upstream service is restarting and temporarily unresponsive",
                    "Misconfigured hostname or port in application environment",
                ],
                suggested_investigation_steps=investigation_steps,
                investigation_commands=[
                    f"podman logs --tail 50 {name}",
                    "podman network ls",
                ],
                recommended_action=f"Restore upstream dependency ({', '.join(correlated_upstreams) if correlated_upstreams else 'upstream service'}) before restarting container.",
                action_reason="Resolve upstream dependency outage before restarting to avoid repeated crashes.",
                risks_and_prerequisites="Ensure upstream service is ready to accept traffic before starting dependent containers.",
                expected_outcome="Container establishes successful connection to upstream service without errors.",
                post_action_verification=f"Check logs with 'podman logs --tail 20 {name}' to confirm successful network handshake.",
                escalation_guidance="Escalate to platform network administrator if port is listening but packets are dropped.",
                verification_status="VERIFIED",
                correlated_containers=correlated_upstreams,
            ))

        # 11B: DNS and networking failures
        dns_matches = extract_matching_lines(combined_diagnostic_text, DNS_NETWORK_FAILURE_RE)
        if dns_matches:
            sev = "CRITICAL" if (state in {"exited", "stopped", "restarting"} or health_status == "unhealthy" or restart_count > 0) else "WARNING"
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="DNS_RESOLUTION_FAILURE",
                category="network",
                severity=sev,
                severity_reason="Container DNS resolution failed or destination network is unreachable.",
                symptoms=["Domain name lookup failure", "Temporary failure in name resolution"],
                probable_cause="DNS resolution failure or host networking configuration issue.",
                confidence=0.90,
                confidence_explanation="Deterministic log evidence: standard DNS error string returned by resolver.",
                evidence=dns_matches + ([f"exit_code={exit_code}"] if exit_code is not None else []),
                candidate_causes=[
                    {
                        "cause": "DNS resolver unreachable or target hostname does not exist in DNS zone",
                        "type": "CONFIRMED",
                        "confidence": 0.90,
                        "explanation": f"Log error: '{dns_matches[0]}'",
                    },
                    {
                        "cause": "Container resolv.conf missing valid nameservers",
                        "type": "INFERRED",
                        "confidence": 0.70,
                        "explanation": "Podman network DNS plugin may be unconfigured.",
                    },
                ],
                suggested_investigation_steps=[
                    "1. Verify the hostname in container configuration or environment variables.",
                    "2. Test DNS resolution from host and container network.",
                    "3. Check /etc/resolv.conf inside the container.",
                ],
                investigation_commands=[
                    f"podman logs --tail 50 {name}",
                    "cat /etc/resolv.conf",
                ],
                recommended_action="Correct hostname configuration or restore container DNS nameserver reachability.",
                action_reason="Workload cannot resolve upstream endpoints without functioning DNS.",
                risks_and_prerequisites="Verify whether hostname typo or network DNS server outage.",
                expected_outcome="Container successfully resolves domain names and establishes network connections.",
                post_action_verification=f"Verify podman logs --tail 20 {name} does not report resolution errors.",
                escalation_guidance="Escalate to infrastructure network team if upstream DNS server is unresponsive.",
                verification_status="VERIFIED",
            ))

        # 11C: Permission denied
        perm_matches = extract_matching_lines(combined_diagnostic_text, PERMISSION_DENIED_RE)
        if perm_matches or (exit_code == 126 and not any(i.get("rule_id") == "PERMISSION_DENIED" for i in incidents)):
            ev = perm_matches if perm_matches else [f"exit_code=126 (Permission denied or not executable)"]
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="PERMISSION_DENIED",
                category="security",
                severity="CRITICAL",
                severity_reason="Container execution halted due to file permission, UID/GID, or security policy restriction.",
                symptoms=["Permission denied error during file access or binary execution"],
                probable_cause="Filesystem permissions, UID/GID mismatch, or security context prevents required operation.",
                confidence=0.90,
                confidence_explanation="Deterministic runtime error: Permission denied / EACCES error code.",
                evidence=ev + ([f"exit_code={exit_code}"] if exit_code is not None else []),
                candidate_causes=[
                    {
                        "cause": "Process user UID/GID lacks read/write permissions on mounted directory or file",
                        "type": "CONFIRMED" if perm_matches else "INFERRED",
                        "confidence": 0.90,
                        "explanation": f"Evidence: '{ev[0]}'",
                    },
                    {
                        "cause": "SELinux context missing ':z' or ':Z' volume flag on host bind mount",
                        "type": "INFERRED",
                        "confidence": 0.75,
                        "explanation": "Podman containers running with SELinux enforce strict MLS labels.",
                    },
                ],
                suggested_investigation_steps=[
                    f"1. Check container user ID: podman inspect -f '{{{{.Config.User}}}}' {name}",
                    "2. Inspect host permissions and ownership on mounted directories: ls -ld <path>",
                    "3. Check for SELinux denials in audit log: ausearch -m avc -ts recent",
                ],
                investigation_commands=[
                    f"podman inspect -f '{{{{.Config.User}}}}' {name}",
                    f"podman logs --tail 50 {name}",
                ],
                recommended_action="Adjust host file permissions or append ':z' SELinux flag to bind mount configuration.",
                action_reason="Enable container process user to read and write required files.",
                risks_and_prerequisites="Ensure host file permissions adhere to principle of least privilege.",
                expected_outcome="Container initializes and accesses files without permission errors.",
                post_action_verification=f"Confirm container starts cleanly without exit code 126 or EACCES logs.",
                escalation_guidance="Escalate to security or systems engineer if SELinux policy requires custom module.",
                verification_status="VERIFIED",
            ))

        # 11D: Missing configuration or environment variables
        cfg_matches = extract_matching_lines(combined_diagnostic_text, MISSING_CONFIG_ENV_RE)
        if cfg_matches:
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="MISSING_CONFIGURATION_OR_ENV",
                category="configuration",
                severity="CRITICAL",
                severity_reason="Application startup halted because mandatory configuration parameter or environment variable is missing.",
                symptoms=["Missing environment variable or configuration file unreadable"],
                probable_cause="Required environment variable or configuration file was not supplied at container launch.",
                confidence=0.90,
                confidence_explanation="Deterministic log error: unhandled KeyError or missing configuration parameter.",
                evidence=cfg_matches + ([f"exit_code={exit_code}"] if exit_code is not None else []),
                candidate_causes=[
                    {
                        "cause": "Required environment variable missing from container definition",
                        "type": "CONFIRMED",
                        "confidence": 0.90,
                        "explanation": f"Log error: '{cfg_matches[0]}'",
                    },
                    {
                        "cause": "Configuration file mount missing or invalid path in entrypoint command",
                        "type": "INFERRED",
                        "confidence": 0.70,
                        "explanation": "Application entrypoint could not find specified config file.",
                    },
                ],
                suggested_investigation_steps=[
                    "1. Identify the missing configuration key or environment variable from the error trace.",
                    f"2. Inspect current container environment variables: podman inspect {name}",
                    "3. Update deployment parameters or compose file to supply required values.",
                ],
                investigation_commands=[
                    f"podman inspect -f '{{{{json .Config.Env}}}}' {name}",
                    f"podman logs --tail 50 {name}",
                ],
                recommended_action="Supply required configuration or environment variable before starting container.",
                action_reason="Workload cannot initialize without mandatory settings.",
                risks_and_prerequisites="Ensure secrets are provided securely without logging them in plain text.",
                expected_outcome="Container initializes successfully with valid configuration.",
                post_action_verification=f"Verify application initializes past configuration loading phase in podman logs {name}.",
                escalation_guidance="Consult application documentation or maintainer for mandatory configuration schema.",
                verification_status="VERIFIED",
            ))

        # 11E: Storage and filesystem errors
        storage_matches = extract_matching_lines(combined_diagnostic_text, STORAGE_FILESYSTEM_RE)
        if storage_matches:
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="STORAGE_FILESYSTEM_ERROR",
                category="storage",
                severity="CRITICAL",
                severity_reason="Filesystem write failed due to exhausted disk space, quota limit, or read-only mount.",
                symptoms=["No space left on device or read-only filesystem error"],
                probable_cause="Host storage volume is full, quota exceeded, or mounted read-only.",
                confidence=0.95,
                confidence_explanation="Deterministic I/O error: ENOSPC or EROFS reported during write operation.",
                evidence=storage_matches + ([f"exit_code={exit_code}"] if exit_code is not None else []),
                candidate_causes=[
                    {
                        "cause": "Disk partition hosting container rootfs or volume is 100% full",
                        "type": "CONFIRMED",
                        "confidence": 0.95,
                        "explanation": f"Log error: '{storage_matches[0]}'",
                    },
                    {
                        "cause": "Volume mounted with read-only ':ro' flag when write access is required",
                        "type": "INFERRED",
                        "confidence": 0.75,
                        "explanation": "Container wrote to a path configured with read-only mount.",
                    },
                ],
                suggested_investigation_steps=[
                    "1. Check host disk space: df -h",
                    f"2. Check container mount configuration: podman inspect -f '{{{{json .Mounts}}}}' {name}",
                    "3. Inspect volume paths for unexpected log or cache accumulation.",
                ],
                investigation_commands=[
                    "df -h",
                    f"podman inspect -f '{{{{json .Mounts}}}}' {name}",
                ],
                recommended_action="Free disk space on host filesystem or reconfigure volume mount with read-write permissions.",
                action_reason="Restore writable storage capacity to permit database and log writes.",
                risks_and_prerequisites="Verify data retention policies before pruning old logs or data.",
                expected_outcome="Storage operations complete without ENOSPC errors.",
                post_action_verification="Verify df -h shows >= 15% available space and container writes succeed.",
                escalation_guidance="Escalate to storage administrator if underlying physical volume is degraded.",
                verification_status="VERIFIED",
            ))

        # 11F: Image pull and startup failures
        pull_matches = extract_matching_lines(combined_diagnostic_text, IMAGE_PULL_RE)
        if pull_matches or (exit_code == 125 and "pull" in combined_diagnostic_text.lower()):
            ev = pull_matches if pull_matches else [f"exit_code=125 with image pull failure: '{error}'"]
            incidents.append(build_incident(
                container_name=name,
                container_id=cid,
                rule_id="IMAGE_PULL_FAILURE",
                category="lifecycle",
                severity="CRITICAL",
                severity_reason="Podman engine failed to pull or resolve specified container image.",
                symptoms=["Container failed to start because image could not be fetched or verified"],
                probable_cause="Container image tag does not exist, registry is unreachable, or authentication failed.",
                confidence=0.95,
                confidence_explanation="Deterministic runtime error: engine returned manifest unknown or pull failure.",
                evidence=ev,
                candidate_causes=[
                    {
                        "cause": "Specified image tag or repository does not exist in registry",
                        "type": "CONFIRMED" if pull_matches else "INFERRED",
                        "confidence": 0.90,
                        "explanation": f"Evidence: '{ev[0]}'",
                    },
                    {
                        "cause": "Registry authentication token missing or expired",
                        "type": "INFERRED",
                        "confidence": 0.75,
                        "explanation": "Private registry access requires active credentials in auth.json.",
                    },
                ],
                suggested_investigation_steps=[
                    "1. Verify exact image name and tag in registry or registry web portal.",
                    "2. Test manual pull: podman pull <image>",
                    "3. Verify registry credentials: podman login <registry>",
                ],
                investigation_commands=[
                    f"podman inspect -f '{{{{.Config.Image}}}}' {name}",
                    "podman image ls",
                ],
                recommended_action="Verify image reference, login to registry if private, or build image locally.",
                action_reason="Container cannot be initialized without a valid image rootfs.",
                risks_and_prerequisites="Ensure target registry is reachable over HTTPS.",
                expected_outcome="Image pull succeeds and container creation/start proceeds.",
                post_action_verification="Run podman pull <image> to confirm image is present in local storage.",
                escalation_guidance="Escalate to release engineer if image was not published to registry.",
                verification_status="VERIFIED",
            ))

    return incidents


def diagnose_all_containers(
    containers: list[dict[str, Any]],
    host_source_checker: Callable[[str], bool] = default_host_path_exists,
    log_retriever: Callable[[str], tuple[str, bool]] | None = None,
) -> dict[str, Any]:
    """Diagnose all containers in a scan and produce an aggregated incident report."""
    all_incidents: list[dict[str, Any]] = []
    incidents_by_container: dict[str, list[dict[str, Any]]] = {}

    critical_count = 0
    warning_count = 0
    info_count = 0

    for c in containers:
        if not isinstance(c, dict):
            continue
        c_incs = diagnose_container_record(
            container=c,
            all_containers=containers,
            host_source_checker=host_source_checker,
            log_retriever=log_retriever,
        )
        if c_incs:
            cname = c.get("name", "unknown")
            incidents_by_container[cname] = c_incs
            all_incidents.extend(c_incs)
            for inc in c_incs:
                sev = inc.get("severity")
                if sev == "CRITICAL":
                    critical_count += 1
                elif sev == "WARNING":
                    warning_count += 1
                elif sev == "INFO":
                    info_count += 1

    # Bidirectional cross-correlation: link downstream affected services back to upstream outages
    for inc in all_incidents:
        c_src = inc.get("container_name")
        corrs = inc.get("correlated_containers", [])
        for upstream_name in corrs:
            upstream_incs = incidents_by_container.get(upstream_name, [])
            for u_inc in upstream_incs:
                u_corrs = u_inc.setdefault("correlated_containers", [])
                if c_src and c_src not in u_corrs:
                    u_corrs.append(c_src)
                symptom_text = f"Cascading impact: Downstream service '{c_src}' is failing while this dependency is unavailable."
                if not any("Cascading impact" in s and c_src in s for s in u_inc.get("symptoms", [])):
                    u_inc.setdefault("symptoms", []).append(symptom_text)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_incidents": len(all_incidents),
        "critical_count": critical_count,
        "warning_count": warning_count,
        "info_count": info_count,
        "affected_containers_count": len(incidents_by_container),
        "incidents_by_container": incidents_by_container,
        "incidents": all_incidents,
    }
