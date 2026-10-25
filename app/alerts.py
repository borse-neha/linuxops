#!/usr/bin/env python3

"""
LinuxOps Alert Classification and Deduplication Engine (Phase C — Step 2).

Evaluates system metrics and container health states from monitoring reports,
classifying active threshold breaches and failures as WARNING or CRITICAL alerts.
Provides stable identities and deduplication without persistent side effects.
"""

from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import time
from typing import Any, Callable
import urllib.error
import urllib.request

from app.diagnostics_engine import redact_sensitive_text
from app.monitor import get_thresholds

DEFAULT_ALERT_DELIVERY_LOG_PATH = (
    Path(__file__).resolve().parent.parent
    / "logs"
    / "alert_delivery.jsonl"
)

SEVERITY_LEVELS = {"WARNING": 1, "CRITICAL": 2}


def _coerce_float(val) -> float | None:
    """Safely coerce a metric value to float, rejecting booleans, infinities, and invalid values."""
    if isinstance(val, bool) or val is None:
        return None
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f) or f < 0.0:
            return None
        return f
    except (ValueError, TypeError):
        return None


def _extract_threshold(thresholds: dict | None, key: str, default: tuple[float, float]) -> tuple[float, float]:
    """Safely extract warning and critical thresholds from a dictionary."""
    if not isinstance(thresholds, dict):
        return default
    pair = thresholds.get(key)
    if not isinstance(pair, (tuple, list)) or len(pair) < 2:
        return default
    warn = _coerce_float(pair[0])
    crit = _coerce_float(pair[1])
    if warn is None or crit is None or warn >= crit:
        return default
    return (warn, crit)


def classify_system_alerts(system_data: dict | None, thresholds: dict | None = None) -> list[dict]:
    """Classify system resource threshold breaches (CPU, Memory, Disk)."""
    alerts = []
    now_utc = datetime.now(timezone.utc).isoformat()

    if thresholds is None:
        try:
            thresholds = get_thresholds()
        except Exception:
            thresholds = {
                "cpu": (70.0, 90.0),
                "memory": (80.0, 90.0),
                "disk": (80.0, 90.0),
            }

    if not isinstance(system_data, dict) or not system_data:
        alerts.append({
            "id": "system:telemetry_unavailable",
            "rule": "system_telemetry_missing",
            "target": "system",
            "target_type": "system",
            "severity": "CRITICAL",
            "message": "Host system metrics telemetry is missing or unavailable.",
            "current_value": None,
            "threshold": None,
            "timestamp": now_utc,
        })
        return alerts

    # 1. CPU
    cpu_warn, cpu_crit = _extract_threshold(thresholds, "cpu", (70.0, 90.0))
    cpu_val = _coerce_float(system_data.get("cpu_usage_percent"))
    if cpu_val is None:
        alerts.append({
            "id": "system:cpu",
            "rule": "system_cpu_unavailable",
            "target": "cpu",
            "target_type": "system",
            "severity": "WARNING",
            "message": "CPU usage metric is unavailable or malformed.",
            "current_value": None,
            "threshold": None,
            "timestamp": now_utc,
        })
    elif cpu_val >= cpu_crit:
        alerts.append({
            "id": "system:cpu",
            "rule": "system_cpu_high",
            "target": "cpu",
            "target_type": "system",
            "severity": "CRITICAL",
            "message": f"CPU usage is {cpu_val:.2f}% (critical threshold: {cpu_crit:.2f}%)",
            "current_value": cpu_val,
            "threshold": cpu_crit,
            "timestamp": now_utc,
        })
    elif cpu_val >= cpu_warn:
        alerts.append({
            "id": "system:cpu",
            "rule": "system_cpu_high",
            "target": "cpu",
            "target_type": "system",
            "severity": "WARNING",
            "message": f"CPU usage is {cpu_val:.2f}% (warning threshold: {cpu_warn:.2f}%)",
            "current_value": cpu_val,
            "threshold": cpu_warn,
            "timestamp": now_utc,
        })

    # 2. Memory
    mem_warn, mem_crit = _extract_threshold(thresholds, "memory", (80.0, 90.0))
    memory_dict = system_data.get("memory")
    mem_val = None
    if isinstance(memory_dict, dict):
        mem_val = _coerce_float(memory_dict.get("usage_percent"))

    if mem_val is None:
        alerts.append({
            "id": "system:memory",
            "rule": "system_memory_unavailable",
            "target": "memory",
            "target_type": "system",
            "severity": "WARNING",
            "message": "Memory usage metric is unavailable or malformed.",
            "current_value": None,
            "threshold": None,
            "timestamp": now_utc,
        })
    elif mem_val >= mem_crit:
        alerts.append({
            "id": "system:memory",
            "rule": "system_memory_high",
            "target": "memory",
            "target_type": "system",
            "severity": "CRITICAL",
            "message": f"Memory usage is {mem_val:.2f}% (critical threshold: {mem_crit:.2f}%)",
            "current_value": mem_val,
            "threshold": mem_crit,
            "timestamp": now_utc,
        })
    elif mem_val >= mem_warn:
        alerts.append({
            "id": "system:memory",
            "rule": "system_memory_high",
            "target": "memory",
            "target_type": "system",
            "severity": "WARNING",
            "message": f"Memory usage is {mem_val:.2f}% (warning threshold: {mem_warn:.2f}%)",
            "current_value": mem_val,
            "threshold": mem_warn,
            "timestamp": now_utc,
        })

    # 3. Disk
    disk_warn, disk_crit = _extract_threshold(thresholds, "disk", (80.0, 90.0))
    disk_dict = system_data.get("disk")
    disk_val = None
    if isinstance(disk_dict, dict):
        disk_val = _coerce_float(disk_dict.get("usage_percent"))

    if disk_val is None:
        alerts.append({
            "id": "system:disk",
            "rule": "system_disk_unavailable",
            "target": "disk",
            "target_type": "system",
            "severity": "WARNING",
            "message": "Disk usage metric is unavailable or malformed.",
            "current_value": None,
            "threshold": None,
            "timestamp": now_utc,
        })
    elif disk_val >= disk_crit:
        alerts.append({
            "id": "system:disk",
            "rule": "system_disk_high",
            "target": "disk",
            "target_type": "system",
            "severity": "CRITICAL",
            "message": f"Disk usage is {disk_val:.2f}% (critical threshold: {disk_crit:.2f}%)",
            "current_value": disk_val,
            "threshold": disk_crit,
            "timestamp": now_utc,
        })
    elif disk_val >= disk_warn:
        alerts.append({
            "id": "system:disk",
            "rule": "system_disk_high",
            "target": "disk",
            "target_type": "system",
            "severity": "WARNING",
            "message": f"Disk usage is {disk_val:.2f}% (warning threshold: {disk_warn:.2f}%)",
            "current_value": disk_val,
            "threshold": disk_warn,
            "timestamp": now_utc,
        })

    return alerts


def classify_container_alerts(container_summary: dict | None, containers: list[dict] | None) -> list[dict]:
    """Classify container subsystem inventory errors and individual container health problems."""
    alerts = []
    now_utc = datetime.now(timezone.utc).isoformat()

    # 1. Check top-level container inventory failure
    if isinstance(container_summary, dict):
        inv_error = container_summary.get("error")
        inv_health = container_summary.get("health")
        if inv_error or inv_health == "CRITICAL":
            alerts.append({
                "id": "container_inventory:podman",
                "rule": "container_inventory_failure",
                "target": "podman",
                "target_type": "container_subsystem",
                "severity": "CRITICAL",
                "message": f"Container inventory query failed: {inv_error or 'Podman subsystem error'}",
                "current_value": inv_health,
                "threshold": None,
                "timestamp": now_utc,
            })
            # When inventory fails, containers list may be empty or invalid
            return alerts
    elif container_summary is None and containers is None:
        alerts.append({
            "id": "container_inventory:podman",
            "rule": "container_inventory_missing",
            "target": "podman",
            "target_type": "container_subsystem",
            "severity": "WARNING",
            "message": "Container inventory data is missing.",
            "current_value": None,
            "threshold": None,
            "timestamp": now_utc,
        })
        return alerts

    # 2. Check individual container records
    if containers is None and isinstance(container_summary, dict):
        alerts.append({
            "id": "container_inventory:missing_containers",
            "rule": "container_records_missing",
            "target": "containers",
            "target_type": "container_subsystem",
            "severity": "WARNING",
            "message": "Container records list is missing.",
            "current_value": None,
            "threshold": None,
            "timestamp": now_utc,
        })
        return alerts

    if not isinstance(containers, list):
        alerts.append({
            "id": "container_inventory:malformed_data",
            "rule": "container_inventory_malformed",
            "target": "containers",
            "target_type": "container_subsystem",
            "severity": "WARNING",
            "message": "Container records structure is malformed (expected list).",
            "current_value": None,
            "threshold": None,
            "timestamp": now_utc,
        })
        return alerts

    for item in containers:
        if not isinstance(item, dict):
            alerts.append({
                "id": "container:malformed_record",
                "rule": "container_record_malformed",
                "target": "unknown",
                "target_type": "container",
                "severity": "WARNING",
                "message": "Container inventory contains a malformed non-dictionary record.",
                "current_value": None,
                "threshold": None,
                "timestamp": now_utc,
            })
            continue

        name_val = item.get("name")
        id_val = item.get("id")
        if name_val and str(name_val).strip() and str(name_val).strip().lower() != "unknown":
            target_name = str(name_val).strip()
        elif id_val and str(id_val).strip() and str(id_val).strip().lower() != "unknown":
            target_name = str(id_val).strip()
        else:
            target_name = "unknown"

        raw_state = item.get("state")
        state_clean = str(raw_state or "").strip().lower()

        alert_id = f"container:{target_name}"

        # Classify based on container state
        if state_clean == "running":
            # Healthy container: no alert
            continue
        elif state_clean in {"exited", "stopped"}:
            alerts.append({
                "id": alert_id,
                "rule": "container_stopped",
                "target": target_name,
                "target_type": "container",
                "severity": "WARNING",
                "message": f"Container '{target_name}' is stopped (state: '{state_clean}').",
                "current_value": state_clean,
                "threshold": None,
                "timestamp": now_utc,
            })
        elif state_clean == "dead":
            alerts.append({
                "id": alert_id,
                "rule": "container_dead",
                "target": target_name,
                "target_type": "container",
                "severity": "CRITICAL",
                "message": f"Container '{target_name}' is in DEAD state.",
                "current_value": state_clean,
                "threshold": None,
                "timestamp": now_utc,
            })
        elif state_clean in {"paused", "restarting", "created"}:
            alerts.append({
                "id": alert_id,
                "rule": "container_abnormal_state",
                "target": target_name,
                "target_type": "container",
                "severity": "WARNING",
                "message": f"Container '{target_name}' is in abnormal state '{state_clean}'.",
                "current_value": state_clean,
                "threshold": None,
                "timestamp": now_utc,
            })
        else:
            # Unknown or missing state is NOT presented as healthy
            alerts.append({
                "id": alert_id,
                "rule": "container_state_unknown",
                "target": target_name,
                "target_type": "container",
                "severity": "WARNING",
                "message": f"Container '{target_name}' has unknown or missing state ('{state_clean}').",
                "current_value": state_clean or "unknown",
                "threshold": None,
                "timestamp": now_utc,
            })

    return alerts


def deduplicate_alerts(alerts: list[dict]) -> list[dict]:
    """
    Deduplicate a list of alerts by stable 'id'.
    If duplicate IDs occur, retain the alert with the highest severity.
    """
    if not isinstance(alerts, list):
        return []

    deduped = {}
    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        alert_id = alert.get("id")
        if not isinstance(alert_id, str) or not alert_id:
            continue

        if alert_id not in deduped:
            deduped[alert_id] = alert
        else:
            # Upgrade severity if the new alert is CRITICAL and existing is WARNING
            existing_sev = SEVERITY_LEVELS.get(deduped[alert_id].get("severity"), 0)
            new_sev = SEVERITY_LEVELS.get(alert.get("severity"), 0)
            if new_sev > existing_sev:
                deduped[alert_id] = alert

    return list(deduped.values())


def classify_alerts(report: dict | None, thresholds: dict | None = None) -> list[dict]:
    """
    Pure Python alert-classification layer for LinuxOps monitoring snapshots.

    Ingests a combined report (or dictionary with 'system', 'container_summary',
    and 'containers'), evaluates all alert rules, and returns a deduplicated
    list of currently active alerts.

    Resolved conditions naturally disappear on subsequent evaluations because
    this function reflects only currently active conditions in the provided report.
    """
    if not isinstance(report, dict) or not report:
        now_utc = datetime.now(timezone.utc).isoformat()
        return [{
            "id": "system:monitoring_unavailable",
            "rule": "monitoring_report_missing",
            "target": "system",
            "target_type": "system",
            "severity": "CRITICAL",
            "message": "Combined monitoring report data is missing or invalid.",
            "current_value": None,
            "threshold": None,
            "timestamp": now_utc,
        }]

    system_alerts = classify_system_alerts(report.get("system"), thresholds=thresholds)
    container_alerts = classify_container_alerts(
        report.get("container_summary"),
        report.get("containers"),
    )

    all_raw_alerts = system_alerts + container_alerts
    return deduplicate_alerts(all_raw_alerts)


def summarize_alerts(alerts: list[dict]) -> dict:
    """Return an aggregate count summary of active alerts by severity."""
    if not isinstance(alerts, list):
        return {"total": 0, "critical": 0, "warning": 0, "has_critical": False, "has_warning": False}

    critical_count = sum(1 for a in alerts if isinstance(a, dict) and a.get("severity") == "CRITICAL")
    warning_count = sum(1 for a in alerts if isinstance(a, dict) and a.get("severity") == "WARNING")

    return {
        "total": len(alerts),
        "critical": critical_count,
        "warning": warning_count,
        "has_critical": critical_count > 0,
        "has_warning": warning_count > 0,
    }


def format_alert_rows(alerts: list[dict]) -> list[dict]:
    """Format active alert dictionaries into clean rows suitable for dashboard table display."""
    if not isinstance(alerts, list):
        return []

    rows = []
    for a in alerts:
        if not isinstance(a, dict):
            continue

        sev = a.get("severity", "UNKNOWN")
        icon = "🚨 CRITICAL" if sev == "CRITICAL" else "⚠️ WARNING"
        target_str = f"{a.get('target_type', 'unknown')}: {a.get('target', 'unknown')}"

        rows.append({
            "Severity": icon,
            "Target": target_str,
            "Rule": a.get("rule", "unknown"),
            "Message": a.get("message", "No message provided."),
            "Timestamp (UTC)": a.get("timestamp", "N/A"),
        })

    return rows


class MockAlertTransport:
    """Mock notification transport for operational testing and dry-runs."""

    def __init__(self, should_fail: bool = False, failure_message: str = "Simulated delivery failure"):
        self.should_fail = should_fail
        self.failure_message = failure_message
        self.dispatched_alerts: list[dict] = []

    def send(self, alert_payload: dict) -> dict:
        """Simulate delivering an alert payload."""
        if self.should_fail:
            raise ConnectionError(self.failure_message)
        self.dispatched_alerts.append(alert_payload)
        return {"status": "DELIVERED", "timestamp": datetime.now(timezone.utc).isoformat()}


def dispatch_alert_notifications(
    alerts: list[dict],
    transport: Any | None = None,
    redact_secrets: bool = True,
) -> dict:
    """
    Dispatch classified alerts to an external notification transport.

    - Alerts are deduplicated prior to dispatch.
    - If redact_secrets is True, all alert messages and targets are scrubbed of credentials/tokens.
    - If transport is None, returns status 'NO_TRANSPORT_CONFIGURED' without failing.
    - Transport failures (exceptions, connection drops) are isolated per alert without aborting remaining alerts.
    """
    if not isinstance(alerts, list) or not alerts:
        return {
            "status": "EMPTY",
            "total_alerts": 0,
            "dispatched": 0,
            "failed": 0,
            "results": [],
        }

class WebhookConfig:
    """Configuration for HTTPS Webhook Alert Delivery."""

    def __init__(
        self,
        enabled: bool = False,
        webhook_url: str = "",
        timeout_seconds: float = 5.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        rate_limit_per_minute: int = 30,
        cooldown_seconds_per_alert: float = 300.0,
        auth_token: str | None = None,
        custom_headers: dict[str, str] | None = None,
        allow_insecure_http: bool = False,
        audit_log_path: Path | str | None = None,
    ):
        self.enabled = bool(enabled)
        self.webhook_url = str(webhook_url or "").strip()
        self.timeout_seconds = max(0.5, float(timeout_seconds))
        self.max_retries = max(0, int(max_retries))
        self.backoff_factor = max(0.0, float(backoff_factor))
        self.rate_limit_per_minute = max(1, int(rate_limit_per_minute))
        self.cooldown_seconds_per_alert = max(0.0, float(cooldown_seconds_per_alert))
        self.auth_token = auth_token
        self.custom_headers = dict(custom_headers or {})
        self.allow_insecure_http = bool(allow_insecure_http)
        self.audit_log_path = Path(audit_log_path) if audit_log_path else DEFAULT_ALERT_DELIVERY_LOG_PATH

    @classmethod
    def from_env(cls) -> "WebhookConfig":
        """Load configuration from environment variables with safe defaults (disabled by default)."""
        enabled = os.getenv("LINUXOPS_ALERT_WEBHOOK_ENABLED", "").strip().lower() in ("1", "true", "yes")
        url = os.getenv("LINUXOPS_ALERT_WEBHOOK_URL", "").strip()
        try:
            timeout = float(os.getenv("LINUXOPS_ALERT_WEBHOOK_TIMEOUT", "5.0"))
        except (ValueError, TypeError):
            timeout = 5.0
        try:
            max_retries = int(os.getenv("LINUXOPS_ALERT_WEBHOOK_MAX_RETRIES", "3"))
        except (ValueError, TypeError):
            max_retries = 3
        token = os.getenv("LINUXOPS_ALERT_WEBHOOK_TOKEN") or None
        allow_http = os.getenv("LINUXOPS_ALERT_ALLOW_HTTP", "").strip().lower() in ("1", "true", "yes")
        return cls(
            enabled=enabled,
            webhook_url=url,
            timeout_seconds=timeout,
            max_retries=max_retries,
            auth_token=token,
            allow_insecure_http=allow_http,
        )


def _default_http_post(
    url: str,
    data: bytes,
    headers: dict[str, str],
    timeout: float,
) -> tuple[int, str]:
    """Default HTTP POST executor using standard library urllib."""
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body


class WebhookAlertTransport:
    """
    Hardened HTTPS Webhook Transport for LinuxOps Alert Dispatching.

    Adheres to all operational safety and reliability standards:
    - Explicit opt-in via config or LINUXOPS_ALERT_WEBHOOK_ENABLED.
    - HTTPS enforcement (rejects plaintext http:// unless allow_insecure_http=True).
    - Connection and read timeouts.
    - Bounded exponential retries for transient 5xx server errors and network drops.
    - Immediate failure on 4xx client errors (no infinite retries on invalid tokens/URLs).
    - Rate-limiting (token bucket, default 30 calls/minute).
    - Alert deduplication and notification storm suppression (cooldown window per alert ID).
    - Automatic redaction of sensitive incident text and secrets.
    - Durable audit trail in logs/alert_delivery.jsonl.
    """

    def __init__(
        self,
        config: WebhookConfig | None = None,
        http_post_fn: Callable[[str, bytes, dict[str, str], float], tuple[int, str]] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ):
        self.config = config or WebhookConfig.from_env()
        self.http_post_fn = http_post_fn or _default_http_post
        self.sleeper = sleeper or time.sleep
        self._dispatched_cooldowns: dict[str, tuple[datetime, str]] = {}
        self._dispatch_timestamps: list[float] = []

    def validate_configuration(self) -> tuple[bool, str]:
        """Validate webhook transport configuration."""
        if not self.config.enabled:
            return False, "Webhook transport is disabled (opt-in required)."
        if not self.config.webhook_url:
            return False, "Webhook URL is not configured."
        url_lower = self.config.webhook_url.lower()
        if not self.config.allow_insecure_http and not url_lower.startswith("https://"):
            return False, "Insecure HTTP scheme rejected; webhook URL must use HTTPS."
        if not (url_lower.startswith("https://") or url_lower.startswith("http://")):
            return False, "Malformed webhook URL scheme; must start with https:// or http://."
        return True, "Configuration valid."

    def reset_state(self) -> None:
        """Clear storm cooldowns and rate limit history (useful for test resets)."""
        self._dispatched_cooldowns.clear()
        self._dispatch_timestamps.clear()

    def record_delivery_audit(self, entry: dict[str, Any]) -> None:
        """Durable append to alert_delivery.jsonl audit log."""
        log_path = self.config.audit_log_path
        if not log_path:
            return
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                log_path.parent.chmod(0o700)
            except OSError:
                pass

            with log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())

            try:
                log_path.chmod(0o600)
            except OSError:
                pass
        except Exception:
            pass

    def send(self, alert_payload: dict[str, Any]) -> dict[str, Any]:
        """
        Deliver an alert payload to the configured webhook endpoint.
        Returns structured delivery report; never raises unhandled exceptions.
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        if not isinstance(alert_payload, dict):
            return {
                "status": "INVALID_PAYLOAD",
                "delivered": False,
                "message": "Alert payload must be a dictionary.",
                "timestamp": now_iso,
            }

        # Check opt-in & configuration
        if not self.config.enabled:
            return {
                "status": "DISABLED",
                "delivered": False,
                "message": "Webhook alert transport is disabled.",
                "timestamp": now_iso,
            }

        is_valid, validation_msg = self.validate_configuration()
        if not is_valid:
            audit_entry = {
                "timestamp": now_iso,
                "alert_id": alert_payload.get("id"),
                "status": "CONFIGURATION_ERROR",
                "message": validation_msg,
            }
            self.record_delivery_audit(audit_entry)
            return {
                "status": "CONFIGURATION_ERROR",
                "delivered": False,
                "message": validation_msg,
                "timestamp": now_iso,
            }

        alert_id = str(alert_payload.get("id") or "unknown_alert")
        severity = str(alert_payload.get("severity") or "WARNING")

        # Notification Storm Cooldown Check
        if alert_id in self._dispatched_cooldowns:
            last_ts, last_sev = self._dispatched_cooldowns[alert_id]
            cooldown_active = (now - last_ts).total_seconds() < self.config.cooldown_seconds_per_alert
            # Allow escalation from WARNING to CRITICAL
            severity_escalated = (
                SEVERITY_LEVELS.get(severity, 0) > SEVERITY_LEVELS.get(last_sev, 0)
            )
            if cooldown_active and not severity_escalated:
                audit_entry = {
                    "timestamp": now_iso,
                    "alert_id": alert_id,
                    "status": "SUPPRESSED_STORM_COOLDOWN",
                    "severity": severity,
                    "cooldown_remaining_seconds": round(
                        self.config.cooldown_seconds_per_alert - (now - last_ts).total_seconds(), 1
                    ),
                }
                self.record_delivery_audit(audit_entry)
                return {
                    "status": "SUPPRESSED_STORM_COOLDOWN",
                    "delivered": False,
                    "alert_id": alert_id,
                    "message": f"Alert '{alert_id}' suppressed under notification storm cooldown ({self.config.cooldown_seconds_per_alert}s window).",
                    "timestamp": now_iso,
                }

        # Rate Limiting Check (sliding 60s window)
        now_mono = time.monotonic()
        cutoff = now_mono - 60.0
        self._dispatch_timestamps = [ts for ts in self._dispatch_timestamps if ts > cutoff]
        if len(self._dispatch_timestamps) >= self.config.rate_limit_per_minute:
            audit_entry = {
                "timestamp": now_iso,
                "alert_id": alert_id,
                "status": "RATE_LIMITED",
                "limit": self.config.rate_limit_per_minute,
            }
            self.record_delivery_audit(audit_entry)
            return {
                "status": "RATE_LIMITED",
                "delivered": False,
                "alert_id": alert_id,
                "message": f"Alert dispatch rate limit exceeded ({self.config.rate_limit_per_minute} dispatches/minute).",
                "timestamp": now_iso,
            }

        # Redact secrets from payload before transmitting
        scrubbed_payload = {}
        for k, v in alert_payload.items():
            if isinstance(v, str):
                scrubbed_payload[k] = redact_sensitive_text(v)
            else:
                scrubbed_payload[k] = v

        envelope = {
            "source": "linuxops",
            "event_type": "operational_alert",
            "timestamp": now_iso,
            "alert": scrubbed_payload,
        }
        json_bytes = json.dumps(envelope).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "LinuxOps-AlertTransport/1.0",
        }
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        headers.update(self.config.custom_headers)

        # Retry loop
        last_error = ""
        last_status_code = None
        max_attempts = self.config.max_retries + 1

        for attempt in range(max_attempts):
            self._dispatch_timestamps.append(time.monotonic())
            t_start = time.perf_counter()
            try:
                status_code, body = self.http_post_fn(
                    self.config.webhook_url,
                    json_bytes,
                    headers,
                    self.config.timeout_seconds,
                )
                elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)
                last_status_code = status_code

                if 200 <= status_code < 300:
                    # Successfully delivered
                    self._dispatched_cooldowns[alert_id] = (now, severity)
                    audit_entry = {
                        "timestamp": now_iso,
                        "alert_id": alert_id,
                        "status": "DELIVERED",
                        "severity": severity,
                        "http_status": status_code,
                        "attempts": attempt + 1,
                        "elapsed_ms": elapsed_ms,
                    }
                    self.record_delivery_audit(audit_entry)
                    return {
                        "status": "DELIVERED",
                        "delivered": True,
                        "alert_id": alert_id,
                        "http_status": status_code,
                        "attempts": attempt + 1,
                        "elapsed_ms": elapsed_ms,
                        "timestamp": now_iso,
                    }

                elif status_code == 429:
                    last_error = f"HTTP 429 Rate Limited from endpoint: {body[:200]}"
                    if attempt < self.config.max_retries:
                        backoff = self.config.backoff_factor * (2 ** attempt)
                        self.sleeper(backoff)
                        continue

                elif 400 <= status_code < 500:
                    # Non-retryable client error (400, 401, 403, 404, etc.)
                    last_error = f"HTTP {status_code} Client Error from endpoint: {body[:200]}"
                    audit_entry = {
                        "timestamp": now_iso,
                        "alert_id": alert_id,
                        "status": "FAILED_CLIENT_ERROR",
                        "severity": severity,
                        "http_status": status_code,
                        "attempts": attempt + 1,
                        "error": last_error,
                    }
                    self.record_delivery_audit(audit_entry)
                    return {
                        "status": "FAILED_CLIENT_ERROR",
                        "delivered": False,
                        "alert_id": alert_id,
                        "http_status": status_code,
                        "attempts": attempt + 1,
                        "error": last_error,
                        "timestamp": now_iso,
                    }

                else:
                    # 5xx Server Error: retryable
                    last_error = f"HTTP {status_code} Server Error from endpoint: {body[:200]}"
                    if attempt < self.config.max_retries:
                        backoff = self.config.backoff_factor * (2 ** attempt)
                        self.sleeper(backoff)
                        continue

            except Exception as exc:
                elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)
                last_error = str(exc)
                if attempt < self.config.max_retries:
                    backoff = self.config.backoff_factor * (2 ** attempt)
                    self.sleeper(backoff)
                    continue

        # Retry exhausted
        audit_entry = {
            "timestamp": now_iso,
            "alert_id": alert_id,
            "status": "FAILED_RETRY_EXHAUSTED",
            "severity": severity,
            "http_status": last_status_code,
            "attempts": max_attempts,
            "error": redact_sensitive_text(last_error),
        }
        self.record_delivery_audit(audit_entry)
        return {
            "status": "FAILED_RETRY_EXHAUSTED",
            "delivered": False,
            "alert_id": alert_id,
            "http_status": last_status_code,
            "attempts": max_attempts,
            "error": redact_sensitive_text(last_error),
            "timestamp": now_iso,
        }


def get_alert_transport_from_env() -> WebhookAlertTransport | None:
    """Return an active WebhookAlertTransport if configured and enabled, otherwise None."""
    config = WebhookConfig.from_env()
    if config.enabled and config.webhook_url:
        return WebhookAlertTransport(config=config)
    return None


def dispatch_alert_notifications(
    alerts: list[dict],
    transport: Any | None = None,
    redact_secrets: bool = True,
) -> dict:
    """
    Dispatch classified alerts to an external notification transport.

    - Alerts are deduplicated prior to dispatch.
    - If redact_secrets is True, all alert messages and targets are scrubbed of credentials/tokens.
    - If transport is None, checks environment configuration via get_alert_transport_from_env().
      If still None, returns status 'NO_TRANSPORT_CONFIGURED' without failing.
    - Transport failures (exceptions, connection drops) are isolated per alert without aborting remaining alerts.
    """
    if not isinstance(alerts, list) or not alerts:
        return {
            "status": "EMPTY",
            "total_alerts": 0,
            "dispatched": 0,
            "failed": 0,
            "results": [],
        }

    deduped = deduplicate_alerts(alerts)
    active_transport = transport if transport is not None else get_alert_transport_from_env()

    if active_transport is None:
        return {
            "status": "NO_TRANSPORT_CONFIGURED",
            "total_alerts": len(deduped),
            "dispatched": 0,
            "failed": 0,
            "message": "External notification delivery transport is not configured; alerts remain local/dashboard-only.",
            "results": [],
        }

    results = []
    dispatched_count = 0
    failed_count = 0

    for alert in deduped:
        payload = dict(alert)
        if redact_secrets:
            if "message" in payload and isinstance(payload["message"], str):
                payload["message"] = redact_sensitive_text(payload["message"])
            if "target" in payload and isinstance(payload["target"], str):
                payload["target"] = redact_sensitive_text(payload["target"])

        try:
            if hasattr(active_transport, "send"):
                send_fn = active_transport.send
            elif callable(active_transport):
                send_fn = active_transport
            else:
                raise TypeError(f"Invalid transport object: {type(active_transport)}")

            outcome = send_fn(payload)
            is_delivered = True
            if isinstance(outcome, dict) and outcome.get("delivered") is False:
                is_delivered = False

            if is_delivered:
                dispatched_count += 1
                results.append({
                    "alert_id": payload.get("id"),
                    "status": "DELIVERED",
                    "details": outcome if isinstance(outcome, dict) else str(outcome),
                })
            else:
                sub_status = outcome.get("status", "FAILED") if isinstance(outcome, dict) else "FAILED"
                if sub_status in ("SUPPRESSED_STORM_COOLDOWN", "DISABLED", "RATE_LIMITED"):
                    results.append({
                        "alert_id": payload.get("id"),
                        "status": sub_status,
                        "details": outcome,
                    })
                else:
                    failed_count += 1
                    results.append({
                        "alert_id": payload.get("id"),
                        "status": "FAILED",
                        "details": outcome,
                    })
        except Exception as exc:
            failed_count += 1
            results.append({
                "alert_id": payload.get("id"),
                "status": "FAILED",
                "error": str(exc),
            })

    overall_status = "SUCCESS" if failed_count == 0 else ("PARTIAL" if dispatched_count > 0 else "FAILED")
    return {
        "status": overall_status,
        "total_alerts": len(deduped),
        "dispatched": dispatched_count,
        "failed": failed_count,
        "results": results,
    }

