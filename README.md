# LinuxOps — Container Monitoring & Safe Recovery Platform
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-WSL2%20%7C%20Linux-green.svg)](https://ubuntu.com/)
[![Containers](https://img.shields.io/badge/Engine-Rootless%20Podman-orange.svg)](https://podman.io/)
[![Tests](https://img.shields.io/badge/Unit%20Tests-570%20Passing-brightgreen.svg)]()

**LinuxOps** is an enterprise-grade, defensive operations platform built for Linux environments. It monitors host system health, tracks and diagnoses rootless Podman containers, enforces deterministic dry-run recovery policies, and enables human-in-the-loop verified container recovery.

---

## Architecture Overview

LinuxOps separates **telemetry**, **diagnosis**, **deterministic policy evaluation**, and **recovery execution** into modular, decoupled layers to prevent destructive actions or cascading restart loops.

```
                              ┌────────────────────────┐
                              │  Streamlit Operations  │
                              │         Center         │
                              │    (app/dashboard.py)  │
                              └───────────┬────────────┘
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  ▼                       ▼                       ▼
      ┌───────────────────────┐┌──────────────────────┐┌──────────────────────┐
      │  Combined Monitoring  ││   Container Diagnosis││Policy Service & Layer│
      │  & System Telemetry   ││  (app/diagnosis.py)  ││(app/policy_service.py│
      │(app/combined_monitor) ││ - Podman inspect     │└──────────┬───────────┘
      │ - /proc/stat CPU      ││ - Exit codes (137)   │           │
      │ - /proc/meminfo RAM   ││ - OOM detection      │           │
      │ - Statvfs Disk        ││ - Recent logs tail   │           │
      └───────────────────────┘└──────────────────────┘           │
                                                                  ▼
                                                      ┌──────────────────────┐
                                                      │Deterministic Policy  │
                                                      │   Engine (Dry-Run)   │
                                                      │  (app/policy.py)     │
                                                      └───────────┬──────────┘
                                                                  │
                                      ┌───────────────────────────┴───────────────────────────┐
                                      ▼                                                       ▼
                          ┌───────────────────────┐                               ┌───────────────────────┐
                          │ Isolated Policy Audit │                               │ Verified Manual       │
                          │   (policy_history)    │                               │     Recovery          │
                          │  - Dry-run records    │                               │  (app/recovery.py)    │
                          │  - ALLOW/DENY history │                               │ - Rootless podman     │
                          │  - Never triggers lock│                               │ - Health verification │
                          └───────────────────────┘                               │ - Human confirmation  │
                                                                                  │ - recovery_history    │
                                                                                  └───────────────────────┘
```

---

## Key Reliability & DevOps Principles

### 1. Separation of Policy Decision vs. Recovery Execution
- **Policy Evaluation (`app/policy.py`)**: Pure mathematical and deterministic evaluation. Takes container state, diagnosis, and history as inputs and outputs structured decisions (`ALLOW` or `DENY`). It contains **zero execution paths** to Podman or subprocesses and returns `dry_run: true` unconditionally.
- **Recovery Execution (`app/recovery.py`)**: Dedicated execution path requiring explicit human confirmation. Podman start commands are followed by post-start status verification before reporting success.
- **No Cascading Auto-Restarts**: An `ALLOW` decision **never** automatically restarts a container. The platform remains strictly human-in-the-loop to prevent flapping services.

### 2. Five Core Safeguards
| Safeguard | Requirement | Failure Reason |
|---|---|---|
| **Container Name Syntax** | Alphanumeric, underscores, hyphens, periods; no leading dashes or shell metacharacters | Rejects injection attempts and CLI flag confusion |
| **State Eligibility** | State must strictly be `exited` or `stopped` | Denies `running` (recovery unneeded) and `paused`/`created`/`dead`/`unknown` |
| **OOM-Kill Protection** | Container exit must not be caused by kernel Out-Of-Memory (`oom_killed == False`) | Requires human memory limit review before starting to prevent crashloops |
| **Cooldown Period** | Minimum 60-second cooldown since the most recent recovery attempt | Prevents high-frequency restart attempts |
| **Sliding Retry Window** | Maximum 3 failed recovery attempts in the preceding 15-minute window | Protects host resources from persistent service crashes |

### 3. Dual-Stream Audit History Isolation
Audit trails are partitioned into two dedicated files in `logs/`:
1. `logs/recovery_history.jsonl`: Stores actual execution attempts (`action: "start_container"`, `success: bool`, `message: str`).
2. `logs/policy_history.jsonl`: Stores dry-run policy evaluation previews (`event_type: "policy_decision"`, `action: "evaluate_policy"`, `decision: "ALLOW"|"DENY"`, `checks: dict`, `dry_run: true`).

**Isolation Guarantee**: Evaluating a container's recovery policy 100 times writes 100 policy audit records, but **never** increments the failed retry counter or activates the cooldown period. Actual recoveries and policy audits cannot contaminate each other.

---

## Operating Modes

LinuxOps supports two dedicated, mutually isolated operating modes:

### 1. 🧪 Simulation Lab (Synthetic Scenarios)
- **Zero Real Mutations**: Runs entirely against in-memory synthetic state (`app/demo_data.py`). Never invokes real Podman commands.
- **Six Demonstration Scenarios**:
  1. *Nominal Fleet*: 8 healthy microservices operating at peak SLA.
  2. *Database Outage & Cascading Failures*: Upstream PostgreSQL connection failure with automatic cross-service correlation to order and auth services.
  3. *Memory Leak & Crash Loop*: Kernel OOM-killed detection with automated policy denial of blind restart attempts.
  4. *Unhealthy Probe & Deadlock*: HTTP 503 probe failure with escalation guidance.
  5. *Normal Stopped Container*: Maintenance / exit 0 container with informational guidance.
  6. *100+ Scale Fleet Benchmark*: 105 microservices demonstrating pagination, sub-second search, and latency percentiles.

### 2. 🟢 Live Host Monitoring (Configured Remote Hosts)
- **Zero Public Sockets**: Monitored hosts run `scripts/linuxops_agent.py` and push telemetry outbound over TLS with HMAC-SHA256 signatures. Podman API sockets are never exposed to the internet.
- **Strictly Read-Only**: Live remediation is disabled by default to prevent accidental disruptions to production workloads.
- **Host Status Lifecycle**: Tracks host connection state (`CONNECTED`, `STALE`, `UNREACHABLE`, `UNCONFIGURED`) with 60-second staleness thresholds.

---

## Authentication & Role-Based Access Control (RBAC)

- **Native OpenID Connect (OIDC)**: Corporate SSO integration using Streamlit's official `st.login()` and `st.logout()` primitives.
- **Fail-Closed Security**: In `production` mode, unauthenticated access is strictly blocked before any private metrics, containers, or telemetry render.
- **Role Hierarchy**:
  - **Administrator (`ADMIN`)**: Can approve remediation plans, simulate execution, toggle the global recovery freeze switch, and configure monitored hosts.
  - **Viewer (`VIEWER`)**: Read-only observability across telemetry, incident logs, and container trends. Cannot approve or execute actions.
- **Session Isolation**: Approval tokens, plan hashes, and audit entries are cryptographically scoped to the authenticated operator.

---

## Verified Operating Environment

- **OS / Distribution**: Ubuntu 24.04 LTS on WSL2 & Linux (x86_64)
- **Runtime**: Python 3.12+ (standard library for agent & core services)
- **Container Engine**: Rootless Podman 4.9+ / 5.x
- **Dashboard Framework**: Streamlit 1.62+
- **Production Deployment Guide**: See [docs/deployment_guide.md](docs/deployment_guide.md) for Nginx reverse proxy, TLS, and OIDC setup.

---

## Setup & Running Guide

### 1. Clone & Enter Repository
```bash
cd /home/neha_borse/linuxops
```

### 2. Run Test Suites
LinuxOps includes automated unit and integration tests covering all system, diagnosis, recovery, policy, auth, host registry, and dashboard features:

```bash
# Run the complete test suite (570 tests)
make test
# or directly: .venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

### 3. Launch the Operations Center Dashboard (Local Dev)
```bash
./scripts/run_dashboard.sh
```
Open `http://127.0.0.1:8501` or `http://localhost:8501` in your browser.

### 4. Stop the Dashboard
```bash
./scripts/stop_dashboard.sh
```

---

## Autonomous Startup & Reliability Architecture (WSL2 / Windows)

LinuxOps runs autonomously across Windows reboots and user logons without requiring manual terminal launches:

- **Silent Windows Startup**:
  - `Start-LinuxOps.vbs` located in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` invokes `startup.ps1` via `wscript.exe` with zero visible console windows or command prompts.
  - Automatically boots `Ubuntu-24.04`, initiates the persistent keepalive process (preventing WSL2 idle VM termination), waits for the systemd user manager to become active, and launches `linuxops-dashboard.service` and `linuxops-bridge.service`.
  - Performs bounded readiness health probes against `http://127.0.0.1:8501/_stcore/health` and verifies Windows loopback accessibility on `http://localhost:8501`.
- **Self-Healing Watchdog Supervisor**:
  - The `LinuxOps-Watchdog` Windows Scheduled Task invokes `run-watchdog.vbs` -> `watchdog.ps1` completely hidden with zero console flashes.
  - Probes `http://127.0.0.1:8501/_stcore/health`. If healthy, operations are left completely untouched (idempotent).
  - If unhealthy, initiates bounded recovery (max 3 restarts in a 5-minute rolling window, followed by a 5-minute cooldown) to recover failed services and prevent restart loops.
- **Diagnostic Tooling**:
  - Run `%USERPROFILE%\.linuxops\check-status.bat` at any time to inspect web endpoints, systemd unit status, WSL IP listeners, recovery safeguards, and recent watchdog logs.
- **Cold-Reboot Hardware Verification**:
  - Manually verified by operator on physical Windows host — upon cold reboot and user logon, the background supervisor silently boots the WSL2 services, the dashboard automatically becomes accessible at \http://localhost:8501\, no PowerShell or CMD windows flash, and loopback connectivity remains stable. (Documented as a physical manual verification, not an automated test).
