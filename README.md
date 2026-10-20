# LinuxOps — Container Monitoring & Safe Recovery Platform

[![Python](https://img.shields.io/badge/Python-3.14-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Fedora%20WSL2%20%7C%20Linux-green.svg)](https://getfedora.org/)
[![Containers](https://img.shields.io/badge/Engine-Rootless%20Podman-orange.svg)](https://podman.io/)
[![Tests](https://img.shields.io/badge/Unit%20Tests-117%20Passing-brightgreen.svg)]()

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

## Verified Operating Environment

- **OS / Distribution**: Fedora Linux 44 on WSL2 (x86_64)
- **Runtime**: Python 3.14 (pure standard library for core services)
- **Container Engine**: Rootless Podman 5.8.4
- **Dashboard Framework**: Streamlit 1.x
- **WSL2 Considerations**:
  - Leverages cgroups v2 resource accounting without requiring root or daemon processes.
  - Sub-second poll-based file watching enabled for Streamlit compatibility.

---

## Setup & Running Guide

### 1. Clone & Enter Repository
```bash
cd ~/projects/linuxops
```

### 2. Run Test Suites
LinuxOps includes 117 automated unit tests covering all system, diagnosis, recovery, policy, and integration features.

```bash
# Run the complete test suite
python3 -m unittest discover -s tests -v

# Run targeted subsystem test suites
python3 -m unittest tests.test_policy -v          # Deterministic policy rules (26 tests)
python3 -m unittest tests.test_history -v         # Dual-stream audit logs (18 tests)
python3 -m unittest tests.test_policy_service -v # Policy integration & safety (11 tests)
python3 -m unittest tests.test_dashboard -v      # Dashboard formatting helpers (6 tests)
python3 -m unittest tests.test_monitor -v        # System metrics & /proc parsing (17 tests)
python3 -m unittest tests.test_diagnosis -v      # Container diagnosis & OOM (15 tests)
python3 -m unittest tests.test_recovery -v       # Safe container execution (14 tests)
python3 -m unittest tests.test_container_monitor -v # Podman container inventory (10 tests)
```

### 3. Launch the Operations Center Dashboard
```bash
streamlit run app/dashboard.py
```
Open `http://localhost:8501` in your browser.

---

## Troubleshooting Guide

| Issue | Root Cause | Solution |
|---|---|---|
| `Podman executable was not found` | Podman is not installed or not in `$PATH` | Install with `sudo dnf install -y podman` |
| Container shows state `unknown` | Podman socket or subuid allocation issue | Run `podman info` and verify user namespace configuration in `/etc/subuid` |
| Cooldown active in policy preview | Container had a recovery attempt within last 60 seconds | Wait for the remaining cooldown time displayed on the dashboard |
| OOM Protection lock | Container was killed by Linux OOM killer (exit code 137) | Increase container memory limits (`podman update --memory ...`) before restarting |

---

## Portfolio & Resume Highlights

### Bullet Points for DevOps / SRE Resumes
- **Architected Container Reliability Engine**: Designed a deterministic recovery policy engine for rootless Podman on Fedora Linux, safeguarding production containers with OOM detection, sliding retry windows (3 failures / 15 min), and mandatory 60s cooldowns.
- **Engineered Pure Dry-Run Safety Layer**: Built decoupled service integration layers isolating advisory dry-run evaluations from actual execution paths, preventing destructive cascading restart storms across 117 comprehensive unit tests.
- **Implemented Dual-Stream Audit Logging**: Authored isolated JSONL audit logging pipelines distinguishing policy preview telemetry from actual container restart events, eliminating state contamination and ensuring 100% test idempotency.
- **Interactive Operations Center**: Developed an operations dashboard with Streamlit and Pandas, providing real-time `/proc/stat` and `/proc/meminfo` metrics, container diagnosis tails, and human-in-the-loop manual recovery controls.
