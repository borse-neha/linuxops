#!/usr/bin/env python3

"""
LinuxOps Interactive Demo Mode & Synthetic Scenario Engine.

Provides realistic synthetic container records, telemetry metrics, and multi-incident
scenarios designed for live demonstrations to faculty, interviewers, and engineers.

Guarantees:
- Clear labelling: All synthetic containers carry explicit 'demo-' prefixes and demo labels.
- Application logic reuse: Synthetic records feed directly through the production
  diagnostics engine (diagnose_all_containers), inventory filters, and remediation planning.
- Simulation safety: Recovery execution on demo data is strictly simulated and never
  dispatches real Podman commands.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import secrets
from typing import Any


def _make_stats_entry(
    cpu_percent: float | None = 2.5,
    mem_percent: float | None = 25.0,
    mem_used_bytes: int | None = 134217728,  # 128 MB
    mem_limit_bytes: int | None = 536870912,  # 512 MB
    is_running: bool = True,
    is_stale: bool = False,
) -> dict[str, Any]:
    """Build a typed metrics dictionary matching container_inspector.parse_stats_entry."""
    now_iso = datetime.now(timezone.utc).isoformat()
    telemetry_state = "stale" if is_stale else ("ok" if is_running else "unavailable")

    cpu_status = "stale" if is_stale else ("ok" if (is_running and cpu_percent is not None) else "unavailable")
    mem_status = "stale" if is_stale else ("ok" if (is_running and mem_percent is not None) else "unavailable")

    return {
        "cpu_percent": {
            "value": cpu_percent if is_running else None,
            "unit": "%",
            "status": cpu_status,
            "observed_at": now_iso,
        },
        "cpu_percent_status": cpu_status,
        "memory_percent": {
            "value": mem_percent if is_running else None,
            "unit": "%",
            "status": mem_status,
            "observed_at": now_iso,
        },
        "mem_percent_status": mem_status,
        "memory_usage_bytes": {
            "value": mem_used_bytes if is_running else None,
            "unit": "bytes",
            "status": mem_status,
            "observed_at": now_iso,
        },
        "memory_limit_bytes": {
            "value": mem_limit_bytes if is_running else None,
            "unit": "bytes",
            "status": "ok" if mem_limit_bytes else "unavailable",
            "observed_at": now_iso,
        },
        "telemetry_state": telemetry_state,
    }


def _make_demo_container(
    name: str,
    image: str,
    state: str = "running",
    health_status: str = "healthy",
    exit_code: int | None = 0,
    oom_killed: bool = False,
    restart_count: int = 0,
    restart_policy: str = "on-failure",
    uptime_seconds: float = 7200.0,
    cpu_percent: float = 3.5,
    mem_percent: float = 30.0,
    mem_limit_mb: int = 512,
    ports: dict[str, list[str]] | None = None,
    mounts: list[dict[str, Any]] | None = None,
    health_history: list[dict[str, Any]] | None = None,
    recent_logs: str = "",
    error: str | None = None,
    short_id_suffix: str = "",
) -> dict[str, Any]:
    """Construct a full ContainerRecord conforming to container_inspector schema."""
    clean_suffix = short_id_suffix or hashlib.md5(name.encode("utf-8")).hexdigest()[:8]
    full_id = f"demo-cont-{clean_suffix}000000000000000000000000000000000000"[:64]
    short_id = f"demo-{clean_suffix[:6]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    is_running = state == "running"
    mem_limit_bytes = mem_limit_mb * 1024 * 1024 if mem_limit_mb else 0
    mem_used_bytes = int(mem_limit_bytes * (mem_percent / 100.0)) if (is_running and mem_limit_bytes) else 0

    metrics = _make_stats_entry(
        cpu_percent=cpu_percent,
        mem_percent=mem_percent,
        mem_used_bytes=mem_used_bytes,
        mem_limit_bytes=mem_limit_bytes,
        is_running=is_running,
    )

    return {
        "host_id": "demo-host-ubuntu24",
        "hostname": "NehaBorse (WSL2 Demo)",
        "id": full_id,
        "short_id": short_id,
        "name": f"demo-{name}",
        "image": image,
        "image_id": f"sha256:demo{clean_suffix}img",
        "state": state,
        "health_status": health_status,
        "health": health_status,
        "health_check_history": health_history or [],
        "exit_code": exit_code,
        "oom_killed": oom_killed,
        "restart_count": restart_count,
        "restart_policy": restart_policy,
        "created_at": "2026-10-24T08:00:00Z",
        "started_at": "2026-10-24T08:01:00Z" if is_running else None,
        "finished_at": "2026-10-24T10:15:00Z" if not is_running else None,
        "uptime_seconds": round(uptime_seconds, 1) if is_running else 0.0,
        "telemetry_age_seconds": 1.2,
        "last_inspected_at": now_iso,
        "ports": ports or {},
        "mounts": mounts or [],
        "labels": {
            "linuxops.demo": "true",
            "environment": "demonstration-synthetic",
            "service_mesh": "demo-internal",
        },
        "resource_limits": {
            "memory_bytes": mem_limit_bytes,
            "memory_swap_bytes": mem_limit_bytes * 2 if mem_limit_bytes else 0,
            "cpu_quota": 100000,
            "cpu_period": 100000,
            "nano_cpus": 1000000000,
            "pids_limit": 256,
        },
        "metrics": metrics,
        "inspection_status": "inspected",
        "is_protected": False,
        "error": error,
        "recent_logs": recent_logs,
        "logs": recent_logs,
        "is_demo": True,
    }


def _build_nominal_scenario() -> dict[str, Any]:
    """Scenario 1: Nominal Fleet (All 8 microservices running and healthy)."""
    containers = [
        _make_demo_container(
            name="frontend-web",
            image="quay.io/linuxops/frontend:v2.4",
            state="running",
            health_status="healthy",
            cpu_percent=4.2,
            mem_percent=28.5,
            mem_limit_mb=512,
            ports={"80/tcp": ["0.0.0.0:8080"]},
            recent_logs=(
                "2026-10-24T16:20:01Z [INFO] React Web Frontend listening on 0.0.0.0:80\n"
                "2026-10-24T16:20:15Z [INFO] GET /api/v1/inventory HTTP/1.1 200 OK (latency: 3.8ms)\n"
                "2026-10-24T16:20:45Z [INFO] GET /api/v1/health HTTP/1.1 200 OK (latency: 1.1ms)\n"
                "2026-10-24T16:21:00Z [INFO] Static assets cached; zero client handshake errors."
            ),
            health_history=[
                {"end_time": "2026-10-24T16:20:00Z", "exit_code": 0, "output": "HTTP 200 OK"},
                {"end_time": "2026-10-24T16:20:30Z", "exit_code": 0, "output": "HTTP 200 OK"},
            ],
            short_id_suffix="fe01",
        ),
        _make_demo_container(
            name="api-gateway",
            image="quay.io/linuxops/api-gateway:v1.9",
            state="running",
            health_status="healthy",
            cpu_percent=6.8,
            mem_percent=32.0,
            mem_limit_mb=512,
            ports={"443/tcp": ["0.0.0.0:8443"]},
            recent_logs=(
                "2026-10-24T16:20:00Z [INFO] API Gateway reverse proxy initialized.\n"
                "2026-10-24T16:20:12Z [INFO] Route /api/v1/* forwarded to internal microservice mesh.\n"
                "2026-10-24T16:20:44Z [INFO] Rate limiter: 1,420 req/s within healthy quota."
            ),
            health_history=[
                {"end_time": "2026-10-24T16:20:10Z", "exit_code": 0, "output": "Proxy endpoint alive"},
            ],
            short_id_suffix="gw01",
        ),
        _make_demo_container(
            name="auth-service",
            image="quay.io/linuxops/auth-service:v3.1",
            state="running",
            health_status="healthy",
            cpu_percent=2.1,
            mem_percent=22.4,
            mem_limit_mb=256,
            recent_logs=(
                "2026-10-24T16:20:00Z [INFO] JWT authentication provider loaded public key set.\n"
                "2026-10-24T16:20:22Z [INFO] Validated token for operator user: session active."
            ),
            short_id_suffix="au01",
        ),
        _make_demo_container(
            name="catalog-db",
            image="docker.io/library/postgres:16-alpine",
            state="running",
            health_status="healthy",
            cpu_percent=8.5,
            mem_percent=54.2,
            mem_limit_mb=1024,
            ports={"5432/tcp": ["127.0.0.1:5432"]},
            mounts=[
                {"type": "volume", "source": "postgres_data", "destination": "/var/lib/postgresql/data", "rw": True}
            ],
            recent_logs=(
                "2026-10-24T16:15:00Z [INFO] PostgreSQL Database server ready to accept connections.\n"
                "2026-10-24T16:15:01Z [INFO] Autovacuum worker launcher started.\n"
                "2026-10-24T16:20:00Z [INFO] Connection pool: 14 active, 36 idle."
            ),
            health_history=[
                {"end_time": "2026-10-24T16:20:15Z", "exit_code": 0, "output": "pg_isready: accepting connections"},
            ],
            short_id_suffix="db01",
        ),
        _make_demo_container(
            name="order-processor",
            image="quay.io/linuxops/order-processor:v2.0",
            state="running",
            health_status="healthy",
            cpu_percent=5.1,
            mem_percent=38.6,
            mem_limit_mb=512,
            recent_logs=(
                "2026-10-24T16:20:00Z [INFO] Order ingestion worker started.\n"
                "2026-10-24T16:20:30Z [INFO] Batch job committed: 48 orders processed without error."
            ),
            short_id_suffix="op01",
        ),
        _make_demo_container(
            name="redis-cache",
            image="docker.io/library/redis:7.2-alpine",
            state="running",
            health_status="running_unmonitored",
            cpu_percent=1.4,
            mem_percent=14.0,
            mem_limit_mb=256,
            ports={"6379/tcp": ["127.0.0.1:6379"]},
            recent_logs=(
                "2026-10-24T16:10:00Z [INFO] Running in standalone mode.\n"
                "2026-10-24T16:10:01Z [INFO] Ready to accept connections tcp.\n"
                "2026-10-24T16:20:00Z [INFO] Hit ratio: 94.2% (12,400 hits / 760 misses)."
            ),
            short_id_suffix="rd01",
        ),
        _make_demo_container(
            name="notification-worker",
            image="quay.io/linuxops/notifications:v1.2",
            state="running",
            health_status="healthy",
            cpu_percent=1.8,
            mem_percent=18.0,
            mem_limit_mb=256,
            recent_logs=(
                "2026-10-24T16:20:00Z [INFO] Email and webhook dispatch worker connected to message queue.\n"
                "2026-10-24T16:20:25Z [INFO] Dispatched 12 notification alerts successfully."
            ),
            short_id_suffix="nt01",
        ),
        _make_demo_container(
            name="metrics-agent",
            image="quay.io/linuxops/telemetry-agent:v1.0",
            state="running",
            health_status="healthy",
            cpu_percent=1.1,
            mem_percent=12.5,
            mem_limit_mb=128,
            recent_logs=(
                "2026-10-24T16:20:00Z [INFO] cgroup telemetry collector initialized.\n"
                "2026-10-24T16:20:30Z [INFO] Emitted 8 container metric samples to monitoring ring buffer."
            ),
            short_id_suffix="ma01",
        ),
    ]

    return {
        "key": "nominal",
        "title": "🟢 1. Nominal Fleet (All Systems Healthy — 8 Microservices)",
        "badge": "NOMINAL (HEALTHY)",
        "summary": "Full microservice fleet running with zero active incidents. CPU, memory, and healthcheck probes are operating within baseline limits.",
        "demonstration_focus": [
            "Observe 8 running containers with structured telemetry and verified health.",
            "Zero incidents in the Incident Operations Center.",
            "Clean search, filter, and responsive paging controls.",
            "Historical resource utilization graph showing steady-state baseline.",
        ],
        "system": {
            "cpu_usage_percent": 18.5,
            "memory": {"usage_percent": 41.2, "used_mb": 3296, "total_mb": 8000},
            "disk": {"usage_percent": 34.0, "used_gb": 34.0, "total_gb": 100.0},
            "health_checks": {"cpu": "NORMAL", "memory": "NORMAL", "disk": "NORMAL"},
        },
        "metrics_samples": [
            {"timestamp": f"16:{m:02d}:00", "cpu_usage_percent": 18.0 + (m % 3), "memory": {"usage_percent": 41.0 + (m % 2)}, "disk": {"usage_percent": 34.0}}
            for m in range(10, 26)
        ],
        "containers": containers,
    }


def _build_db_connection_refused_scenario() -> dict[str, Any]:
    """Scenario 2: Database Outage & Cascading Connection Refused Failures."""
    containers = [
        # Stopped Database
        _make_demo_container(
            name="catalog-db",
            image="docker.io/library/postgres:16-alpine",
            state="exited",
            health_status="stopped",
            exit_code=143,
            uptime_seconds=0.0,
            cpu_percent=0.0,
            mem_percent=0.0,
            recent_logs=(
                "2026-10-24T16:15:00Z [WARN] Received SIGTERM signal (143). Shutting down server.\n"
                "2026-10-24T16:15:02Z [INFO] Active connections terminated. Closing database buffer pools.\n"
                "2026-10-24T16:15:04Z [INFO] PostgreSQL database server stopped. Exit code 143."
            ),
            short_id_suffix="db02",
        ),
        # Order Processor crashed due to missing DB connection
        _make_demo_container(
            name="order-processor",
            image="quay.io/linuxops/order-processor:v2.0",
            state="exited",
            health_status="stopped",
            exit_code=1,
            restart_count=1,
            uptime_seconds=0.0,
            cpu_percent=0.0,
            mem_percent=0.0,
            recent_logs=(
                "2026-10-24T16:15:10Z [INFO] Connecting to postgres database catalog-db:5432...\n"
                "2026-10-24T16:15:11Z [ERROR] dial tcp catalog-db:5432: connect: connection refused\n"
                "2026-10-24T16:15:12Z [FATAL] Database connection failed. Aborting application startup. Exit code 1."
            ),
            short_id_suffix="op02",
        ),
        # Auth Service crashed due to missing DB connection
        _make_demo_container(
            name="auth-service",
            image="quay.io/linuxops/auth-service:v3.1",
            state="exited",
            health_status="stopped",
            exit_code=1,
            restart_count=1,
            uptime_seconds=0.0,
            cpu_percent=0.0,
            mem_percent=0.0,
            recent_logs=(
                "2026-10-24T16:15:10Z [INFO] Initializing user authentication repository...\n"
                "2026-10-24T16:15:12Z [ERROR] Connection refused to postgres://catalog-db:5432/auth\n"
                "2026-10-24T16:15:13Z [ERROR] Failed to connect to database pool: connection refused"
            ),
            short_id_suffix="au02",
        ),
        # Degraded API Gateway
        _make_demo_container(
            name="api-gateway",
            image="quay.io/linuxops/api-gateway:v1.9",
            state="running",
            health_status="healthy",
            cpu_percent=3.2,
            mem_percent=26.0,
            recent_logs=(
                "2026-10-24T16:15:15Z [WARN] Upstream auth-service:8080 offline; returning HTTP 502 Bad Gateway\n"
                "2026-10-24T16:15:30Z [WARN] Upstream order-processor:8082 unreachable"
            ),
            short_id_suffix="gw02",
        ),
        _make_demo_container(name="frontend-web", image="quay.io/linuxops/frontend:v2.4", state="running", health_status="healthy", cpu_percent=2.5, mem_percent=24.0, short_id_suffix="fe02"),
        _make_demo_container(name="redis-cache", image="docker.io/library/redis:7.2-alpine", state="running", health_status="running_unmonitored", cpu_percent=1.1, mem_percent=12.0, short_id_suffix="rd02"),
        _make_demo_container(name="notification-worker", image="quay.io/linuxops/notifications:v1.2", state="running", health_status="healthy", cpu_percent=1.2, mem_percent=15.0, short_id_suffix="nt02"),
        _make_demo_container(name="metrics-agent", image="quay.io/linuxops/telemetry-agent:v1.0", state="running", health_status="healthy", cpu_percent=1.0, mem_percent=11.0, short_id_suffix="ma02"),
    ]

    return {
        "key": "db_connection_refused",
        "title": "🚨 2. Database Outage & Cascading Failures (Connection Refused)",
        "badge": "CRITICAL INCIDENT",
        "summary": "Upstream database 'catalog-db' was stopped. Dependent services 'order-processor' and 'auth-service' failed on startup with TCP connection refused errors.",
        "demonstration_focus": [
            "Demonstrates rule DEPENDENCY_CONNECTION_REFUSED triggered by the diagnostics engine.",
            "Evidence extraction: matches 'connection refused' and 'dial tcp ... connect: connection refused' directly from container logs.",
            "The 7 Operator Questions clearly identify the primary root cause ('catalog-db' offline) vs symptomatic crashes.",
            "Remediation guidance recommends starting the upstream dependency before restarting dependent containers.",
        ],
        "system": {
            "cpu_usage_percent": 11.2,
            "memory": {"usage_percent": 36.5, "used_mb": 2920, "total_mb": 8000},
            "disk": {"usage_percent": 34.0, "used_gb": 34.0, "total_gb": 100.0},
            "health_checks": {"cpu": "NORMAL", "memory": "NORMAL", "disk": "NORMAL"},
        },
        "metrics_samples": [
            {"timestamp": f"16:{m:02d}:00", "cpu_usage_percent": 19.0 if m < 15 else 11.0, "memory": {"usage_percent": 41.0 if m < 15 else 36.5}, "disk": {"usage_percent": 34.0}}
            for m in range(10, 26)
        ],
        "containers": containers,
    }


def _build_crash_loop_oom_scenario() -> dict[str, Any]:
    """Scenario 3: Memory Exhaustion, OOM Killer & Crash Loop."""
    containers = [
        # Crash-looping OOM killed analytics engine
        _make_demo_container(
            name="analytics-engine",
            image="quay.io/linuxops/analytics:v4.0",
            state="restarting",
            health_status="unhealthy",
            exit_code=137,
            oom_killed=True,
            restart_count=6,
            restart_policy="always",
            uptime_seconds=12.0,
            cpu_percent=88.4,
            mem_percent=99.2,
            mem_limit_mb=256,
            recent_logs=(
                "2026-10-24T16:18:00Z [INFO] Processing large time-series batch allocation...\n"
                "2026-10-24T16:18:08Z [WARN] Memory utilization reached 245 MB / 256 MB cgroup limit\n"
                "2026-10-24T16:18:10Z [FATAL] Fatal error: JavaScript heap out of memory / cgroup memory limit exceeded\n"
                "2026-10-24T16:18:11Z [ERROR] Kernel OOM Killer invoked: Process killed by SIGKILL (exit code 137, OOMKilled=True)"
            ),
            short_id_suffix="an03",
        ),
        # Memory pressure warning on report generator
        _make_demo_container(
            name="report-generator",
            image="quay.io/linuxops/reports:v1.5",
            state="running",
            health_status="healthy",
            cpu_percent=42.0,
            mem_percent=96.5,
            mem_limit_mb=512,
            recent_logs=(
                "2026-10-24T16:18:00Z [INFO] Generating monthly PDF aggregation report...\n"
                "2026-10-24T16:18:30Z [WARN] High memory watermark: 494 MB / 512 MB (96.5%). Approaching cgroup ceiling."
            ),
            short_id_suffix="rp03",
        ),
        _make_demo_container(name="frontend-web", image="quay.io/linuxops/frontend:v2.4", state="running", health_status="healthy", cpu_percent=3.5, mem_percent=26.0, short_id_suffix="fe03"),
        _make_demo_container(name="api-gateway", image="quay.io/linuxops/api-gateway:v1.9", state="running", health_status="healthy", cpu_percent=4.1, mem_percent=28.0, short_id_suffix="gw03"),
        _make_demo_container(name="auth-service", image="quay.io/linuxops/auth-service:v3.1", state="running", health_status="healthy", cpu_percent=2.0, mem_percent=20.0, short_id_suffix="au03"),
        _make_demo_container(name="catalog-db", image="docker.io/library/postgres:16-alpine", state="running", health_status="healthy", cpu_percent=9.0, mem_percent=55.0, short_id_suffix="db03"),
        _make_demo_container(name="order-processor", image="quay.io/linuxops/order-processor:v2.0", state="running", health_status="healthy", cpu_percent=4.5, mem_percent=35.0, short_id_suffix="op03"),
        _make_demo_container(name="redis-cache", image="docker.io/library/redis:7.2-alpine", state="running", health_status="running_unmonitored", cpu_percent=1.5, mem_percent=15.0, short_id_suffix="rd03"),
    ]

    return {
        "key": "crash_loop_oom",
        "title": "🚨 3. Memory Leak & Crash Loop (Kernel OOM Killer & Restart Thrashing)",
        "badge": "CRITICAL INCIDENT",
        "summary": "Container 'analytics-engine' exceeded its 256MB cgroup memory limit and was terminated by the Linux kernel OOM killer (exit code 137). Restart count has reached 6 (crash loop).",
        "demonstration_focus": [
            "Demonstrates rules OOM_KILLED, CRASH_LOOP_DETECTED, and MEMORY_PRESSURE_CRITICAL.",
            "Direct kernel evidence: State.OOMKilled=True and exit_code=137.",
            "Policy engine safety safeguard: Automated restart is DENIED and ESCALATED to protect host stability.",
            "Operator guidance recommends profiling heap allocation or increasing memory ceiling before attempting restart.",
            "Historical trends graph clearly shows memory climbing from 45% to 88% over time.",
        ],
        "system": {
            "cpu_usage_percent": 68.4,
            "memory": {"usage_percent": 84.2, "used_mb": 6736, "total_mb": 8000},
            "disk": {"usage_percent": 35.0, "used_gb": 35.0, "total_gb": 100.0},
            "health_checks": {"cpu": "WARNING", "memory": "CRITICAL", "disk": "NORMAL"},
        },
        "metrics_samples": [
            {
                "timestamp": f"16:{m:02d}:00",
                "cpu_usage_percent": round(22.0 + ((m - 10) * 3.0), 1),
                "memory": {"usage_percent": round(44.0 + ((m - 10) * 2.6), 1)},
                "disk": {"usage_percent": 35.0},
            }
            for m in range(10, 26)
        ],
        "containers": containers,
    }


def _build_failing_health_check_scenario() -> dict[str, Any]:
    """Scenario 4: Failing Health Check Probe & Degraded Microservice."""
    containers = [
        # Payment service running but unhealthy
        _make_demo_container(
            name="payment-service",
            image="quay.io/linuxops/payments:v1.8",
            state="running",
            health_status="unhealthy",
            exit_code=0,
            restart_count=0,
            cpu_percent=14.2,
            mem_percent=45.0,
            mem_limit_mb=512,
            health_history=[
                {"end_time": "2026-10-24T16:21:00Z", "exit_code": 1, "output": "HTTP 503 Service Unavailable: upstream payment gateway timeout after 5000ms"},
                {"end_time": "2026-10-24T16:21:30Z", "exit_code": 1, "output": "HTTP 503 Service Unavailable: upstream payment gateway timeout after 5000ms"},
                {"end_time": "2026-10-24T16:22:00Z", "exit_code": 1, "output": "HTTP 503 Service Unavailable: internal deadlock in transaction worker"},
            ],
            recent_logs=(
                "2026-10-24T16:20:00Z [INFO] Payment processing daemon listening on port 8084\n"
                "2026-10-24T16:21:00Z [ERROR] Health probe GET /healthz failed: status 503\n"
                "2026-10-24T16:21:30Z [ERROR] Probe timeout: database lock wait timeout exceeded"
            ),
            short_id_suffix="py04",
        ),
        _make_demo_container(name="frontend-web", image="quay.io/linuxops/frontend:v2.4", state="running", health_status="healthy", cpu_percent=3.8, mem_percent=27.0, short_id_suffix="fe04"),
        _make_demo_container(name="api-gateway", image="quay.io/linuxops/api-gateway:v1.9", state="running", health_status="healthy", cpu_percent=5.2, mem_percent=30.0, short_id_suffix="gw04"),
        _make_demo_container(name="auth-service", image="quay.io/linuxops/auth-service:v3.1", state="running", health_status="healthy", cpu_percent=2.2, mem_percent=21.0, short_id_suffix="au04"),
        _make_demo_container(name="catalog-db", image="docker.io/library/postgres:16-alpine", state="running", health_status="healthy", cpu_percent=7.8, mem_percent=52.0, short_id_suffix="db04"),
        _make_demo_container(name="order-processor", image="quay.io/linuxops/order-processor:v2.0", state="running", health_status="healthy", cpu_percent=4.8, mem_percent=36.0, short_id_suffix="op04"),
        _make_demo_container(name="redis-cache", image="docker.io/library/redis:7.2-alpine", state="running", health_status="running_unmonitored", cpu_percent=1.2, mem_percent=13.0, short_id_suffix="rd04"),
        _make_demo_container(name="notification-worker", image="quay.io/linuxops/notifications:v1.2", state="running", health_status="healthy", cpu_percent=1.4, mem_percent=16.0, short_id_suffix="nt04"),
    ]

    return {
        "key": "failing_health_check",
        "title": "⚠️ 4. Unhealthy Probe & Internal Deadlock (HTTP 503 Failing Probe)",
        "badge": "UNHEALTHY PROBE",
        "summary": "Container 'payment-service' is running (process alive), but its Podman healthcheck probe failed 3 consecutive times with HTTP 503 Service Unavailable.",
        "demonstration_focus": [
            "Demonstrates rule HEALTHCHECK_FAILING triggered by the diagnostics engine.",
            "Highlights crucial operational distinction: running does NOT equal healthy!",
            "Inventory table clearly displays '🔴 Unhealthy' rather than green running.",
            "Health probe history tab in deep inspection reveals the exact probe error message.",
        ],
        "system": {
            "cpu_usage_percent": 24.5,
            "memory": {"usage_percent": 45.0, "used_mb": 3600, "total_mb": 8000},
            "disk": {"usage_percent": 34.0, "used_gb": 34.0, "total_gb": 100.0},
            "health_checks": {"cpu": "NORMAL", "memory": "NORMAL", "disk": "NORMAL"},
        },
        "metrics_samples": [
            {"timestamp": f"16:{m:02d}:00", "cpu_usage_percent": 22.0 + (m % 4), "memory": {"usage_percent": 44.0 + (m % 3)}, "disk": {"usage_percent": 34.0}}
            for m in range(10, 26)
        ],
        "containers": containers,
    }


def _build_stopped_container_scenario() -> dict[str, Any]:
    """Scenario 5: Gracefully Stopped Batch Container (Normal Exit Code 0)."""
    containers = [
        # Batch worker stopped normally
        _make_demo_container(
            name="batch-sync-worker",
            image="quay.io/linuxops/batch-sync:v1.1",
            state="stopped",
            health_status="stopped",
            exit_code=0,
            restart_count=0,
            uptime_seconds=0.0,
            cpu_percent=0.0,
            mem_percent=0.0,
            recent_logs=(
                "2026-10-24T16:00:00Z [INFO] Batch catalog synchronization job started.\n"
                "2026-10-24T16:02:14Z [INFO] Successfully synced 14,820 SKU records.\n"
                "2026-10-24T16:02:15Z [INFO] Process completed gracefully. Exiting with status 0."
            ),
            short_id_suffix="bt05",
        ),
        _make_demo_container(name="frontend-web", image="quay.io/linuxops/frontend:v2.4", state="running", health_status="healthy", cpu_percent=4.0, mem_percent=28.0, short_id_suffix="fe05"),
        _make_demo_container(name="api-gateway", image="quay.io/linuxops/api-gateway:v1.9", state="running", health_status="healthy", cpu_percent=5.0, mem_percent=30.0, short_id_suffix="gw05"),
        _make_demo_container(name="auth-service", image="quay.io/linuxops/auth-service:v3.1", state="running", health_status="healthy", cpu_percent=2.0, mem_percent=21.0, short_id_suffix="au05"),
        _make_demo_container(name="catalog-db", image="docker.io/library/postgres:16-alpine", state="running", health_status="healthy", cpu_percent=7.5, mem_percent=51.0, short_id_suffix="db05"),
        _make_demo_container(name="order-processor", image="quay.io/linuxops/order-processor:v2.0", state="running", health_status="healthy", cpu_percent=4.5, mem_percent=35.0, short_id_suffix="op05"),
        _make_demo_container(name="redis-cache", image="docker.io/library/redis:7.2-alpine", state="running", health_status="running_unmonitored", cpu_percent=1.1, mem_percent=12.0, short_id_suffix="rd05"),
        _make_demo_container(name="notification-worker", image="quay.io/linuxops/notifications:v1.2", state="running", health_status="healthy", cpu_percent=1.3, mem_percent=15.0, short_id_suffix="nt05"),
    ]

    return {
        "key": "stopped_container",
        "title": "ℹ️ 5. Gracefully Stopped Batch Container (Maintenance / Exit 0)",
        "badge": "MAINTENANCE / NORMAL",
        "summary": "Container 'batch-sync-worker' completed its batch task and terminated gracefully with exit code 0. Diagnostic engine classifies it as INFO (no action needed).",
        "demonstration_focus": [
            "Demonstrates rule CONTAINER_STOPPED_NORMAL (INFO severity).",
            "Clear diagnostic distinction between unexpected crashes (non-zero exits) and graceful task completions (exit code 0).",
            "Controlled remediation proposal confirms action is safe if the operator wishes to trigger an on-demand restart.",
        ],
        "system": {
            "cpu_usage_percent": 17.5,
            "memory": {"usage_percent": 40.0, "used_mb": 3200, "total_mb": 8000},
            "disk": {"usage_percent": 34.0, "used_gb": 34.0, "total_gb": 100.0},
            "health_checks": {"cpu": "NORMAL", "memory": "NORMAL", "disk": "NORMAL"},
        },
        "metrics_samples": [
            {"timestamp": f"16:{m:02d}:00", "cpu_usage_percent": 17.0 + (m % 3), "memory": {"usage_percent": 40.0 + (m % 2)}, "disk": {"usage_percent": 34.0}}
            for m in range(10, 26)
        ],
        "containers": containers,
    }


def _build_scale_105_scenario() -> dict[str, Any]:
    """Scenario 6: 100+ Scale Fleet Benchmark (105 microservices)."""
    containers = []
    # 95 running microservices
    for i in range(1, 96):
        c_state = "running"
        c_health = "healthy" if (i % 3 != 0) else "running_unmonitored"
        containers.append(_make_demo_container(
            name=f"svc-node-{i:03d}",
            image=f"quay.io/linuxops/microservice:v{1 + (i % 5)}.0",
            state=c_state,
            health_status=c_health,
            cpu_percent=round(1.0 + ((i * 7) % 25) * 0.4, 1),
            mem_percent=round(15.0 + ((i * 11) % 45), 1),
            mem_limit_mb=256,
            recent_logs=f"[INFO] Service worker svc-node-{i:03d} listening and processing requests cleanly.",
            short_id_suffix=f"sc{i:03d}",
        ))

    # 5 stopped containers
    for i in range(96, 101):
        containers.append(_make_demo_container(
            name=f"svc-node-{i:03d}",
            image="quay.io/linuxops/batch-job:v1.0",
            state="stopped",
            health_status="stopped",
            exit_code=0,
            uptime_seconds=0.0,
            cpu_percent=0.0,
            mem_percent=0.0,
            recent_logs=f"[INFO] Batch job svc-node-{i:03d} finished successfully with exit code 0.",
            short_id_suffix=f"sc{i:03d}",
        ))

    # 3 unhealthy containers
    for i in range(101, 104):
        containers.append(_make_demo_container(
            name=f"svc-node-{i:03d}",
            image="quay.io/linuxops/api-worker:v2.1",
            state="running",
            health_status="unhealthy",
            exit_code=0,
            cpu_percent=18.0,
            mem_percent=60.0,
            health_history=[{"end_time": "2026-10-24T16:20:00Z", "exit_code": 1, "output": "HTTP 503 Gateway Timeout"}],
            recent_logs=f"[ERROR] Service svc-node-{i:03d} health probe failed: endpoint timed out.",
            short_id_suffix=f"sc{i:03d}",
        ))

    # 2 crash looping containers
    for i in range(104, 106):
        containers.append(_make_demo_container(
            name=f"svc-node-{i:03d}",
            image="quay.io/linuxops/worker-crash:v1.0",
            state="restarting",
            health_status="unhealthy",
            exit_code=137,
            oom_killed=True,
            restart_count=5,
            uptime_seconds=5.0,
            cpu_percent=75.0,
            mem_percent=98.0,
            recent_logs=f"[FATAL] Service svc-node-{i:03d} OOM killed by kernel cgroup memory controller.",
            short_id_suffix=f"sc{i:03d}",
        ))

    return {
        "key": "scale_105_benchmark",
        "title": "⚡ 6. 100+ Scale Fleet Benchmark (105 Microservices & Pagination)",
        "badge": "100+ SCALE BENCHMARK",
        "summary": "High-scale demonstration consisting of 105 container records. Demonstrates sub-second pagination, text search filtering, severity breakdown, and p50/p95 latency telemetry.",
        "demonstration_focus": [
            "Demonstrates sub-second pagination (Page 1 of 5 at 25 containers per page).",
            "Instant text search across 100+ containers (e.g. search 'node-042').",
            "High-scale latency percentiles: p50 latency = 2.1 ms, p95 latency = 5.8 ms.",
            "Metadata cache hit ratio: 98.4% with bounded concurrency.",
        ],
        "latency_stats": {
            "p50_ms": 2.1,
            "p90_ms": 4.6,
            "p95_ms": 5.8,
            "p99_ms": 9.2,
            "max_ms": 14.5,
            "min_ms": 0.8,
            "sample_count": 105,
        },
        "cache_stats": {
            "hits": 103,
            "misses": 2,
            "hit_ratio_percent": 98.1,
            "size": 105,
            "max_size": 2000,
        },
        "system": {
            "cpu_usage_percent": 34.2,
            "memory": {"usage_percent": 62.0, "used_mb": 4960, "total_mb": 8000},
            "disk": {"usage_percent": 38.0, "used_gb": 38.0, "total_gb": 100.0},
            "health_checks": {"cpu": "NORMAL", "memory": "NORMAL", "disk": "NORMAL"},
        },
        "metrics_samples": [
            {"timestamp": f"16:{m:02d}:00", "cpu_usage_percent": 32.0 + (m % 5), "memory": {"usage_percent": 61.0 + (m % 3)}, "disk": {"usage_percent": 38.0}}
            for m in range(10, 26)
        ],
        "containers": containers,
    }


# Scenario Registry
SCENARIO_BUILDERS = {
    "nominal": _build_nominal_scenario,
    "db_connection_refused": _build_db_connection_refused_scenario,
    "crash_loop_oom": _build_crash_loop_oom_scenario,
    "failing_health_check": _build_failing_health_check_scenario,
    "stopped_container": _build_stopped_container_scenario,
    "scale_105_benchmark": _build_scale_105_scenario,
}


def get_demo_scenario_keys() -> list[str]:
    """Return all available demo scenario identifiers."""
    return list(SCENARIO_BUILDERS.keys())


def get_demo_scenario(scenario_key: str = "nominal") -> dict[str, Any]:
    """Retrieve full scenario data dictionary by key (defaults to nominal)."""
    builder = SCENARIO_BUILDERS.get(scenario_key) or _build_nominal_scenario
    data = builder()

    # Precalculate summary counters
    conts = data.get("containers", [])
    healthy_cnt = sum(1 for c in conts if c.get("health_status") == "healthy")
    unhealthy_cnt = sum(1 for c in conts if c.get("health_status") == "unhealthy")
    stopped_cnt = sum(1 for c in conts if c.get("state") in {"exited", "stopped"})
    running_cnt = sum(1 for c in conts if c.get("state") == "running")

    data["summary_counts"] = {
        "discovered_count": len(conts),
        "inspected_count": len(conts),
        "healthy_count": healthy_cnt,
        "unhealthy_count": unhealthy_cnt,
        "stopped_count": stopped_cnt,
        "running_count": running_cnt,
        "failed_count": 0,
        "stale_count": 0,
        "scan_duration_seconds": 0.04,
    }

    return data


def is_demo_target(container_name_or_id: str) -> bool:
    """Check if a container target belongs to synthetic demo data."""
    clean = str(container_name_or_id or "").strip()
    return clean.startswith("demo-") or "demo" in clean.lower()


def simulate_demo_approval(plan: dict[str, Any]) -> dict[str, Any]:
    """
    Simulate approval token generation for a demo scenario.
    Binds cryptographically to plan hash, labeled SIMULATED.
    """
    plan_hash = str(plan.get("plan_hash") or "demo_hash")
    token_suffix = secrets.token_hex(6).upper()
    simulated_token = f"SIMULATED-APPROVAL-TOKEN-{token_suffix}"

    return {
        "status": "APPROVED",
        "approval_token": simulated_token,
        "approved_plan_hash": plan_hash,
        "container_name": plan.get("container_name"),
        "operation": plan.get("operation"),
        "simulated": True,
    }


def simulate_demo_execution(plan: dict[str, Any], approval_token: str) -> dict[str, Any]:
    """
    Simulate safe remediation execution on a demo container.
    Strictly verifies token without calling any real Podman commands.
    """
    target_name = plan.get("container_name", "unknown")
    operation = plan.get("operation", "start_container")

    if not approval_token or not approval_token.startswith("SIMULATED-APPROVAL-TOKEN-"):
        return {
            "success": False,
            "container": target_name,
            "action": operation,
            "verification_status": "APPROVAL_INVALIDATED",
            "message": "Simulated recovery rejected: missing or invalid simulated approval token.",
            "simulated": True,
        }

    return {
        "success": True,
        "container": target_name,
        "action": operation,
        "verification_status": "VERIFIED",
        "message": (
            f"[SIMULATED OUTCOME] Container '{target_name}' simulated healthy. "
            "Post-action verification probe simulated HTTP 200 OK. "
            "Zero real containers or host state were altered."
        ),
        "simulated": True,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "token_used": approval_token,
    }


def get_demo_timeline_events(scenario_key: str = "nominal") -> list[dict[str, Any]]:
    """
    Generate realistic synthetic timeline events for the specified demo scenario.
    Provides multi-category incidents, recovery attempts, policy decisions, and outcomes.
    """
    now = datetime.now(timezone.utc)
    t0 = (now - timedelta(minutes=2)).isoformat()
    t1 = (now - timedelta(minutes=7)).isoformat()
    t2 = (now - timedelta(minutes=14)).isoformat()
    t3 = (now - timedelta(minutes=25)).isoformat()
    t4 = (now - timedelta(minutes=40)).isoformat()

    if scenario_key == "db_connection_refused":
        return [
            {
                "timestamp": t0,
                "incident_id": "demo-inc-db01",
                "incident_category": "CONNECTION_FAILURE",
                "category_label": "Network / Connection Refused",
                "component": "demo-catalog-db",
                "severity": "CRITICAL",
                "symptoms": "PostgreSQL database offline on port 5432; socket connection refused.",
                "action_attempted": "start_container",
                "outcome": "FAILED",
                "source": "synthetic",
                "duration_seconds": None,
            },
            {
                "timestamp": t1,
                "incident_id": "demo-inc-ord02",
                "incident_category": "CONNECTION_FAILURE",
                "category_label": "Network / Connection Refused",
                "component": "demo-order-processor",
                "severity": "CRITICAL",
                "symptoms": "Cascading dependency failure: failed to connect to catalog-db:5432.",
                "action_attempted": "remediation_investigation",
                "outcome": "PENDING_REVIEW",
                "source": "synthetic",
                "duration_seconds": None,
            },
            {
                "timestamp": t3,
                "incident_id": "demo-pol-01",
                "incident_category": "POLICY_DENIAL",
                "category_label": "Policy / Guardrail Denial",
                "component": "demo-order-processor",
                "severity": "WARNING",
                "symptoms": "Recovery denied: upstream dependency catalog-db is unhealthy.",
                "action_attempted": "evaluate_policy",
                "outcome": "DENIED",
                "source": "synthetic",
                "duration_seconds": None,
            },
        ]

    if scenario_key == "crash_loop_oom":
        return [
            {
                "timestamp": t0,
                "incident_id": "demo-inc-oom01",
                "incident_category": "CRASH_LOOP",
                "category_label": "Repeated Restarts / Crash Loop",
                "component": "demo-order-processor",
                "severity": "CRITICAL",
                "symptoms": "Process restarted 4 times in 5 minutes; rapid crash loop detected.",
                "action_attempted": "start_container",
                "outcome": "FAILED",
                "source": "synthetic",
                "duration_seconds": None,
            },
            {
                "timestamp": t1,
                "incident_id": "demo-inc-oom02",
                "incident_category": "OOM_KILL",
                "category_label": "OOM Killer / Memory Pressure",
                "component": "demo-order-processor",
                "severity": "CRITICAL",
                "symptoms": "Kernel OOM killer terminated process with exit code 137 (cgroup limit exceeded).",
                "action_attempted": "start_container",
                "outcome": "FAILED",
                "source": "synthetic",
                "duration_seconds": None,
            },
            {
                "timestamp": t2,
                "incident_id": "demo-pol-oom03",
                "incident_category": "POLICY_DENIAL",
                "category_label": "Policy / Guardrail Denial",
                "component": "demo-order-processor",
                "severity": "WARNING",
                "symptoms": "Automated recovery denied: OOM crash loop protection safeguard active.",
                "action_attempted": "evaluate_policy",
                "outcome": "DENIED",
                "source": "synthetic",
                "duration_seconds": None,
            },
            {
                "timestamp": t4,
                "incident_id": "demo-rec-init",
                "incident_category": "SERVICE_OUTAGE",
                "category_label": "Service Stopped / Outage",
                "component": "demo-order-processor",
                "severity": "INFO",
                "symptoms": "Baseline deployment started successfully.",
                "action_attempted": "start_container",
                "outcome": "VERIFIED",
                "source": "synthetic",
                "duration_seconds": 18.0,
            },
        ]

    if scenario_key == "failing_health_check":
        return [
            {
                "timestamp": t0,
                "incident_id": "demo-inc-probe01",
                "incident_category": "UNHEALTHY_PROBE",
                "category_label": "Health Check Probe Failure",
                "component": "demo-auth-service",
                "severity": "WARNING",
                "symptoms": "Health probe returned HTTP 503 Service Unavailable (consecutive failures: 3).",
                "action_attempted": "remediation_investigation",
                "outcome": "PENDING_REVIEW",
                "source": "synthetic",
                "duration_seconds": None,
            },
            {
                "timestamp": t3,
                "incident_id": "demo-rec-auth01",
                "incident_category": "SERVICE_OUTAGE",
                "category_label": "Service Stopped / Outage",
                "component": "demo-auth-service",
                "severity": "INFO",
                "symptoms": "Scheduled auth token cache rotation completed.",
                "action_attempted": "start_container",
                "outcome": "VERIFIED",
                "source": "synthetic",
                "duration_seconds": 32.5,
            },
        ]

    if scenario_key == "stopped_container":
        return [
            {
                "timestamp": t1,
                "incident_id": "demo-inc-stop01",
                "incident_category": "SERVICE_OUTAGE",
                "category_label": "Service Stopped / Outage",
                "component": "demo-batch-reporter",
                "severity": "INFO",
                "symptoms": "Batch report execution finished gracefully with exit code 0.",
                "action_attempted": "remediation_investigation",
                "outcome": "RESOLVED",
                "source": "synthetic",
                "duration_seconds": 210.0,
            },
        ]

    if scenario_key == "scale_105_benchmark":
        return [
            {
                "timestamp": t0,
                "incident_id": "demo-scale-01",
                "incident_category": "CRASH_LOOP",
                "category_label": "Repeated Restarts / Crash Loop",
                "component": "demo-worker-012",
                "severity": "CRITICAL",
                "symptoms": "Worker task queue crashed with unhandled NullPointer exception.",
                "action_attempted": "start_container",
                "outcome": "FAILED",
                "source": "synthetic",
                "duration_seconds": None,
            },
            {
                "timestamp": t1,
                "incident_id": "demo-scale-02",
                "incident_category": "OOM_KILL",
                "category_label": "OOM Killer / Memory Pressure",
                "component": "demo-worker-045",
                "severity": "CRITICAL",
                "symptoms": "Batch computation worker exceeded 256MB limit (exit 137).",
                "action_attempted": "start_container",
                "outcome": "RESOLVED",
                "source": "synthetic",
                "duration_seconds": 65.0,
            },
            {
                "timestamp": t2,
                "incident_id": "demo-scale-03",
                "incident_category": "UNHEALTHY_PROBE",
                "category_label": "Health Check Probe Failure",
                "component": "demo-worker-088",
                "severity": "WARNING",
                "symptoms": "Worker health probe timeout after 5000ms.",
                "action_attempted": "remediation_investigation",
                "outcome": "PENDING_REVIEW",
                "source": "synthetic",
                "duration_seconds": None,
            },
            {
                "timestamp": t3,
                "incident_id": "demo-scale-04",
                "incident_category": "POLICY_DENIAL",
                "category_label": "Policy / Guardrail Denial",
                "component": "demo-worker-099",
                "severity": "WARNING",
                "symptoms": "Restart throttled: host scale protection barrier active.",
                "action_attempted": "evaluate_policy",
                "outcome": "DENIED",
                "source": "synthetic",
                "duration_seconds": None,
            },
            {
                "timestamp": t4,
                "incident_id": "demo-scale-05",
                "incident_category": "WATCHDOG_INTERVENTION",
                "category_label": "Host Watchdog Intervention",
                "component": "service:linuxops-dashboard",
                "severity": "INFO",
                "symptoms": "Host watchdog verified dashboard listener status.",
                "action_attempted": "watchdog_restart",
                "outcome": "VERIFIED",
                "source": "synthetic",
                "duration_seconds": 24.0,
            },
        ]

    # Nominal scenario (clean default)
    return [
        {
            "timestamp": t1,
            "incident_id": "demo-nom-01",
            "incident_category": "SERVICE_OUTAGE",
            "category_label": "Service Stopped / Outage",
            "component": "demo-catalog-db",
            "severity": "INFO",
            "symptoms": "Routine container maintenance completed successfully.",
            "action_attempted": "start_container",
            "outcome": "VERIFIED",
            "source": "synthetic",
            "duration_seconds": 42.0,
        },
        {
            "timestamp": t3,
            "incident_id": "demo-nom-02",
            "incident_category": "WATCHDOG_INTERVENTION",
            "category_label": "Host Watchdog Intervention",
            "component": "service:linuxops-dashboard",
            "severity": "INFO",
            "symptoms": "Watchdog supervisor verified dashboard HTTP 200 OK health check.",
            "action_attempted": "watchdog_restart",
            "outcome": "VERIFIED",
            "source": "synthetic",
            "duration_seconds": 15.0,
        },
    ]


def get_demo_watchdog_state(scenario_key: str = "nominal") -> dict[str, Any]:
    """Return synthetic watchdog supervisor state for demonstration scenarios."""
    now = datetime.now(timezone.utc)
    if scenario_key == "crash_loop_oom":
        return {
            "available": True,
            "status": "COOLDOWN",
            "last_probe_time": now.isoformat(),
            "last_probe_status": "DEGRADED",
            "consecutive_failures": 3,
            "restart_count_in_window": 3,
            "in_cooldown": True,
            "cooldown_until": (now + timedelta(minutes=5)).isoformat(),
            "last_recovery_action": (now - timedelta(minutes=1)).isoformat(),
            "recent_events": [
                f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] [WARN] Probe failed (consecutive failures: 3).",
                f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] [ALERT] 3 restart attempts reached in rolling window. Entering 5-minute cooldown.",
            ],
            "state_file": "simulated://watchdog-state.json",
        }

    return {
        "available": True,
        "status": "HEALTHY",
        "last_probe_time": now.isoformat(),
        "last_probe_status": "HEALTHY",
        "consecutive_failures": 0,
        "restart_count_in_window": 0,
        "in_cooldown": False,
        "cooldown_until": None,
        "last_recovery_action": (now - timedelta(hours=1)).isoformat(),
        "recent_events": [
            f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] [SUCCESS] LinuxOps dashboard healthy at http://127.0.0.1:8501/_stcore/health (HTTP 200 OK).",
        ],
        "state_file": "simulated://watchdog-state.json",
    }

