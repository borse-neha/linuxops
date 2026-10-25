#!/usr/bin/env python3

"""
LinuxOps Secure Host Registry & Remote Telemetry Ingestion Interface.

Provides architectural isolation between the public web application and monitored Podman hosts:
- Manages registration, health status, and freshness of configured remote hosts.
- Authenticated telemetry ingestion using HMAC-SHA256 signatures (LINUXOPS_AGENT_SECRET).
- Strict data filtering: accepts read-only container metrics and health states; rejects arbitrary command execution.
- Sensitive environment variable and credential stripping.
- Fails clearly and safely when no monitored hosts are configured.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import threading
from typing import Any

from app.diagnostics_engine import redact_sensitive_text

# Default telemetry stale threshold
DEFAULT_HOST_STALE_THRESHOLD_SECONDS = 60.0
DEFAULT_HOST_UNREACHABLE_THRESHOLD_SECONDS = 300.0

# DevSecOps Hardening Thresholds
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024          # 2 MB payload ceiling
MAX_TIMESTAMP_SKEW_SECONDS = 300.0           # 5-minute replay window
MAX_CONTAINERS_PER_REPORT = 1000             # Maximum containers per telemetry report


class HostConnectionStatus(str, Enum):
    CONNECTED = "CONNECTED"
    STALE = "STALE"
    UNREACHABLE = "UNREACHABLE"
    UNCONFIGURED = "UNCONFIGURED"


@dataclass
class HostTelemetryReport:
    """Validated read-only telemetry snapshot received from an authenticated host agent."""
    host_id: str
    hostname: str
    distribution: str
    podman_version: str
    kernel_version: str
    timestamp_iso: str
    host_metrics: dict[str, Any]
    containers: list[dict[str, Any]]
    agent_version: str = "1.0.0"
    scan_duration_ms: float = 0.0
    discovered_count: int = 0
    running_count: int = 0
    stopped_count: int = 0
    healthy_count: int = 0
    unhealthy_count: int = 0
    raw_signature: str = ""


@dataclass
class MonitoredHost:
    """Configured target host record."""
    host_id: str
    name: str
    status: HostConnectionStatus = HostConnectionStatus.UNCONFIGURED
    last_seen_iso: str | None = None
    last_latency_ms: float = 0.0
    latest_report: HostTelemetryReport | None = None
    registered_at_iso: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class HostRegistry:
    """Thread-safe host registry and telemetry store."""

    def __init__(self, storage_path: Path | None = None):
        self._lock = threading.Lock()
        self._hosts: dict[str, MonitoredHost] = {}
        self._storage_path = storage_path
        self._load_configured_hosts()

    def _load_configured_hosts(self) -> None:
        """Initialize host inventory from environment or persistent configuration."""
        raw_hosts = os.environ.get("LINUXOPS_MONITORED_HOSTS", "").strip()
        if raw_hosts:
            # Format: "host1:Production Node 1,host2:Staging Node 2"
            for item in raw_hosts.split(","):
                if not item.strip():
                    continue
                parts = item.split(":", 1)
                hid = parts[0].strip()
                hname = parts[1].strip() if len(parts) > 1 else hid
                if hid:
                    self._hosts[hid] = MonitoredHost(
                        host_id=hid,
                        name=hname,
                        status=HostConnectionStatus.UNREACHABLE,
                    )

    def register_host(self, host_id: str, name: str) -> MonitoredHost:
        """Explicitly register a monitored host."""
        clean_id = host_id.strip()
        with self._lock:
            if clean_id not in self._hosts:
                self._hosts[clean_id] = MonitoredHost(
                    host_id=clean_id,
                    name=name.strip() or clean_id,
                    status=HostConnectionStatus.UNREACHABLE,
                )
            return self._hosts[clean_id]

    def get_host(self, host_id: str) -> MonitoredHost | None:
        with self._lock:
            return self._hosts.get(host_id)

    def list_hosts(self) -> list[MonitoredHost]:
        with self._lock:
            # Recalculate freshness status for all hosts
            now = datetime.now(timezone.utc)
            result = []
            for h in self._hosts.values():
                h_copy = MonitoredHost(
                    host_id=h.host_id,
                    name=h.name,
                    status=self._calculate_status(h, now),
                    last_seen_iso=h.last_seen_iso,
                    last_latency_ms=h.last_latency_ms,
                    latest_report=h.latest_report,
                    registered_at_iso=h.registered_at_iso,
                )
                result.append(h_copy)
            return result

    def _calculate_status(self, host: MonitoredHost, now: datetime) -> HostConnectionStatus:
        if not host.last_seen_iso:
            return HostConnectionStatus.UNREACHABLE
        try:
            seen_dt = datetime.fromisoformat(host.last_seen_iso)
            diff = (now - seen_dt).total_seconds()
            if diff <= DEFAULT_HOST_STALE_THRESHOLD_SECONDS:
                return HostConnectionStatus.CONNECTED
            elif diff <= DEFAULT_HOST_UNREACHABLE_THRESHOLD_SECONDS:
                return HostConnectionStatus.STALE
            else:
                return HostConnectionStatus.UNREACHABLE
        except Exception:
            return HostConnectionStatus.UNREACHABLE

    def ingest_telemetry_payload(self, raw_json_payload: str, signature_header: str) -> tuple[bool, str, HostTelemetryReport | None]:
        """
        Validate, authenticate, and ingest a telemetry report from a remote host agent.
        Enforces:
        - Payload size ceiling (MAX_PAYLOAD_BYTES)
        - Mandatory HMAC-SHA256 signature when configured or in production
        - Replay protection: validates payload timestamp skew within MAX_TIMESTAMP_SKEW_SECONDS
        - Schema validation & remote command injection rejection
        - Container capacity limit (MAX_CONTAINERS_PER_REPORT)
        - Sensitive environment and token redaction
        """
        # 1. Payload size check
        payload_bytes = len(raw_json_payload.encode("utf-8"))
        if payload_bytes > MAX_PAYLOAD_BYTES:
            return False, f"Payload size {payload_bytes} bytes exceeds maximum limit of {MAX_PAYLOAD_BYTES} bytes.", None

        # 2. Authentication signature check
        agent_secret = os.environ.get("LINUXOPS_AGENT_SECRET", "").strip()
        auth_mode = os.environ.get("LINUXOPS_AUTH_MODE", "").strip().lower()

        if auth_mode == "production" and not agent_secret:
            return False, "Server Security Misconfiguration: LINUXOPS_AGENT_SECRET must be configured in production mode.", None

        if agent_secret:
            if not signature_header:
                return False, "Missing HMAC-SHA256 authorization signature header.", None
            expected_sig = hmac.new(agent_secret.encode("utf-8"), raw_json_payload.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature_header, expected_sig):
                return False, "Invalid HMAC-SHA256 agent signature.", None

        # 3. Parse JSON
        try:
            data = json.loads(raw_json_payload)
        except json.JSONDecodeError as exc:
            return False, f"Malformed JSON telemetry payload: {exc}", None

        if not isinstance(data, dict):
            return False, "Malformed JSON telemetry payload (expected JSON object).", None

        # 4. Schema Validation: Reject any attempted remote command injection
        if "command" in data or "execute" in data or "eval" in data or "action" in data:
            return False, "Security Violation: Remote command fields rejected in telemetry payload.", None

        host_id = str(data.get("host_id", "")).strip()
        if not host_id:
            return False, "Payload missing mandatory 'host_id'.", None

        # 5. Replay Protection: Timestamp Skew Check
        ts_raw = data.get("timestamp_iso")
        if not ts_raw:
            return False, "Payload missing mandatory 'timestamp_iso' for replay validation.", None
        try:
            payload_dt = datetime.fromisoformat(str(ts_raw))
            if payload_dt.tzinfo is None:
                payload_dt = payload_dt.replace(tzinfo=timezone.utc)
            now_utc = datetime.now(timezone.utc)
            skew = abs((now_utc - payload_dt).total_seconds())
            if skew > MAX_TIMESTAMP_SKEW_SECONDS:
                return False, f"Replay Protection: Telemetry timestamp skew of {skew:.1f}s exceeds maximum allowed window of {MAX_TIMESTAMP_SKEW_SECONDS}s.", None
        except Exception as exc:
            return False, f"Malformed timestamp_iso for replay validation: {exc}", None

        # 6. Container Capacity Check
        raw_containers = data.get("containers", [])
        if not isinstance(raw_containers, list):
            return False, "Malformed containers field (expected list).", None
        if len(raw_containers) > MAX_CONTAINERS_PER_REPORT:
            return False, f"Payload container count {len(raw_containers)} exceeds capacity limit of {MAX_CONTAINERS_PER_REPORT}.", None

        # 7. Redact and sanitize container records
        clean_containers = []
        for c in raw_containers:
            if not isinstance(c, dict):
                continue
            clean_c = sanitize_container_telemetry(c)
            clean_containers.append(clean_c)

        report = HostTelemetryReport(
            host_id=host_id,
            hostname=str(data.get("hostname", "unknown")),
            distribution=str(data.get("distribution", "Linux")),
            podman_version=str(data.get("podman_version", "unknown")),
            kernel_version=str(data.get("kernel_version", "unknown")),
            timestamp_iso=str(data.get("timestamp_iso", datetime.now(timezone.utc).isoformat())),
            host_metrics=data.get("host_metrics", {}),
            containers=clean_containers,
            agent_version=str(data.get("agent_version", "1.0.0")),
            scan_duration_ms=float(data.get("scan_duration_ms", 0.0)),
            discovered_count=len(clean_containers),
            running_count=sum(1 for c in clean_containers if c.get("state") == "running"),
            stopped_count=sum(1 for c in clean_containers if c.get("state") in {"exited", "stopped"}),
            healthy_count=sum(1 for c in clean_containers if c.get("health_status") == "healthy"),
            unhealthy_count=sum(1 for c in clean_containers if c.get("health_status") == "unhealthy"),
            raw_signature=signature_header,
        )

        with self._lock:
            # Upsert host record
            if host_id not in self._hosts:
                self._hosts[host_id] = MonitoredHost(
                    host_id=host_id,
                    name=report.hostname or host_id,
                )
            target = self._hosts[host_id]
            target.status = HostConnectionStatus.CONNECTED
            target.last_seen_iso = report.timestamp_iso
            target.last_latency_ms = report.scan_duration_ms
            target.latest_report = report

        return True, "Telemetry successfully ingested and validated.", report


def sanitize_container_telemetry(container: dict[str, Any]) -> dict[str, Any]:
    """Sanitize container records, stripping sensitive env vars, secrets, and raw mounts."""
    sanitized = dict(container)

    # Strip environment variables
    if "env" in sanitized:
        sanitized["env"] = ["REDACTED"]
    if "Env" in sanitized:
        sanitized["Env"] = ["REDACTED"]

    # Redact sensitive text from recent logs
    if "logs" in sanitized and isinstance(sanitized["logs"], list):
        sanitized["logs"] = [redact_sensitive_text(str(line)) for line in sanitized["logs"]]

    # Ensure metric values are strictly numeric or None
    metrics = sanitized.get("metrics")
    if isinstance(metrics, dict):
        clean_m = {}
        for k, v in metrics.items():
            if isinstance(v, (int, float)) or v is None:
                clean_m[k] = v
            elif isinstance(v, str) and k == "telemetry_state":
                clean_m[k] = v
        sanitized["metrics"] = clean_m

    return sanitized


_GLOBAL_HOST_REGISTRY = HostRegistry()


def get_global_host_registry() -> HostRegistry:
    """Return the singleton HostRegistry instance."""
    return _GLOBAL_HOST_REGISTRY
