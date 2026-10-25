# LinuxOps Production Operations Guide & Controlled Staging Hardening

## 1. System Overview

LinuxOps is an observability, diagnostics, and policy-governed safe-recovery platform for single-host Linux environments running rootless Podman containers.

The platform provides:
- Single-host container inventory discovery, deep inspection, and resource telemetry.
- 10-rule root-cause diagnostics engine with bounded, secret-redacted evidence.
- Deterministic recovery policy evaluation with recommendation-only dry-runs by default.
- Strict backend-enforced human-in-the-loop authorization gates (`start_container` only).
- Post-recovery health verification distinguishing running container state from application readiness.
- Streamlit interactive operations dashboard strictly bound to `127.0.0.1:8501`.
- Durable JSON Lines audit logging (`logs/recovery_history.jsonl`, `logs/incidents.jsonl`, `logs/policy_history.jsonl`).

```
+-----------------------------------------------------------------------------------------+
|                                    LinuxOps Platform                                    |
|                                                                                         |
|  +------------------------+    +--------------------------+    +---------------------+  |
|  |   Container Discovery  | -> |  Evidence-Based Engine   | -> |    Safe Recovery    |  |
|  |    & Deep Inspection   |    |    & Secret Redactor     |    |      Controller     |  |
|  | (Rootless Podman CLI)  |    |  (10 Diagnostic Rules)   |    | (Human Gate/Immune) |  |
|  +------------------------+    +--------------------------+    +---------------------+  |
|             |                                |                            |             |
|             v                                v                            v             |
|  +-----------------------------------------------------------------------------------+  |
|  |                     Streamlit Operations Center Dashboard                         |  |
|  |   - Bound strictly to 127.0.0.1:8501 (never exposed directly on 0.0.0.0)          |  |
|  |   - Filterable & Searchable Container Inventory with Clean Pagination             |  |
|  |   - Structured Incident Review, Probable Causes, and Evidence Telemetry           |  |
|  |   - Advisory Recovery Proposals with Operator Authorization Gate                  |  |
|  +-----------------------------------------------------------------------------------+  |
|                                             |                                           |
|                                             v                                           |
|  +-----------------------------------------------------------------------------------+  |
|  |                           Audit Logs (JSON Lines)                                 |  |
|  |   logs/metrics.jsonl  |  logs/recovery_history.jsonl  |  logs/incidents.jsonl     |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Local Installation & Configuration

### 2.1 System Requirements & Prerequisites
- **Operating System:** Linux (Fedora 38+, RHEL 9+, Ubuntu 22.04+). Tested on Fedora 44 (WSL2 kernel 6.18+).
- **Python:** Python 3.10 or newer (tested on Python 3.14.7).
- **Container Runtime:** Rootless Podman 4.x / 5.x (tested on Podman 5.8.4).
- **Core Dependencies:** `pandas`, `streamlit`.

### 2.2 Permissions & Directory Hardening
LinuxOps stores audit records and telemetry under `logs/`. The directory and files must be restricted to the operating user:
```bash
# Ensure secure directory permissions (owner-only access)
chmod 0700 logs/
chmod 0600 logs/*.jsonl 2>/dev/null || true
```

### 2.3 Environment Configuration
Monitoring and safety thresholds are configured via environment variables:
| Variable | Default | Description |
| :--- | :---: | :--- |
| `CPU_WARNING` | `70.0` | CPU utilization warning threshold (percent). |
| `CPU_CRITICAL` | `90.0` | CPU utilization critical alert threshold (percent). |
| `MEMORY_WARNING` | `80.0` | Memory usage warning threshold (percent). |
| `MEMORY_CRITICAL` | `90.0` | Memory usage critical alert threshold (percent). |
| `DISK_WARNING` | `80.0` | Disk usage warning threshold (percent). |
| `DISK_CRITICAL` | `90.0` | Disk usage critical alert threshold (percent). |
| `LINUXOPS_RECOVERY_DISABLED` | `0` | Global recovery kill-switch (`1` or `true` halts all recovery). |

---

## 3. Staging Preflight Readiness Verification

Before starting or staging LinuxOps, execute the read-only preflight check. It verifies all 10 staging criteria without altering container or filesystem state:

```bash
# Human-readable summary
python3 scripts/staging_preflight.py

# Machine-readable automation output
python3 scripts/staging_preflight.py --json
```

### Evaluated Criteria
1. **Python Environment:** Validates Python >= 3.10 and required packages (`pandas`, `streamlit`).
2. **Podman Availability:** Tests `podman --version` and rootless CLI execution.
3. **Project Configuration:** Verifies threshold sanity ($0 \le \text{warn} < \text{crit} \le 100$) and action allowlist integrity.
4. **Directory Structure:** Confirms existence of `app/`, `docs/`, `scripts/`, `tests/`, `logs/`, `.streamlit/`.
5. **Audit Log Access:** Tests read/write permissions on `logs/` without altering logs.
6. **Dashboard Network Binding:** Confirms `.streamlit/config.toml` binds strictly to `127.0.0.1` and checks port 8501.
7. **Recovery Disabled Safety:** Confirms recommendation-only default and kill-switch availability.
8. **Protected Workload Immunity:** Verifies deep identity immunity for `cloudops-floci`, `linuxops-recovery-ui-test`, and `/home/neha/cloudops-sentinel/data`.
9. **Data Persistence Paths:** Confirms all audit paths reside strictly under the local project directory.
10. **Code Compilation:** Verifies zero syntax errors via `compileall`.

---

## 4. Dashboard Access & Security Architecture

### 4.1 Localhost-Only Binding (Default)
The dashboard configuration in `.streamlit/config.toml` enforces localhost binding:
```toml
[server]
address = "127.0.0.1"
port = 8501
headless = true
enableCORS = false
enableXsrfProtection = true
```

Launch the dashboard:
```bash
streamlit run app/dashboard.py
```
Access locally at `http://127.0.0.1:8501`.

### 4.2 Security Notice: UI Checkbox vs. Backend Policy Gate
> [!WARNING]
> **The dashboard authorization checkbox is an operator confirmation gate, NOT an authentication boundary.**
> Checking the authorization box does not grant arbitrary execution rights. Every recovery execution request is independently evaluated by the backend [app/recovery_controller.py](file:///home/neha/projects/linuxops/app/recovery_controller.py) against:
> - Global kill-switch status.
> - Non-destructive action allowlist (`start_container` only).
> - Workload immunity (name, ID prefix, systemd label, image, mount path).
> - Backend policy eligibility (crash-loop protection, missing mount checks, port collisions, cooldown windows, retry limits).

### 4.3 Recommended Pattern for Remote Staging Access
Streamlit does not provide built-in multi-user authentication, sessions, or role-based access control (RBAC). **Never expose `0.0.0.0:8501` to an untrusted or public network.**

For remote staging environments, place LinuxOps behind an authenticating reverse proxy with TLS:
```
[Client Browser] 
      │ HTTPS (Port 443) + OAuth2 / mTLS / Basic Auth
      ▼
[Reverse Proxy: Caddy / Nginx / Envoy]
      │ HTTP over Loopback (127.0.0.1:8501)
      ▼
[LinuxOps Streamlit Dashboard (127.0.0.1:8501)]
```

Example Caddyfile snippet:
```caddy
ops.internal.example.com {
    tls internal
    basicauth / {
        operator $2a$14$...
    }
    reverse_proxy 127.0.0.1:8501
}
```

---

## 5. Recovery Policy & Authorization Rules

### 5.1 Default Recommendation-Only Mode
Automated container recovery is disabled by default. The system operates in **advisory recommendation mode**, proposing recovery actions without modifying workloads.

### 5.2 Mandatory Execution Guardrails
When an operator explicitly triggers recovery, the backend enforces:
1. **Name Validation:** Rejects shell metacharacters, leading dashes, or malformed identifiers.
2. **Global Kill-Switch:** If active, immediately aborts with `GLOBAL_KILL_SWITCH`.
3. **Action Allowlist:** Only `start_container` is permitted. Destructive commands (`rm`, `kill`, `stop`, `prune`, volume removal) are rejected with `FORBIDDEN_ACTION`.
4. **Workload Immunity:** Protected workloads (`cloudops-floci`, `linuxops-recovery-ui-test`, `/home/neha/cloudops-sentinel/data`) cannot be targeted under any circumstances.
5. **Backend Policy Gate:** Re-evaluates container state and incident root causes. Recovery is strictly rejected with `POLICY_DENIED` if:
   - Container is in an active crash loop (`restart_count >= 3`).
   - Host bind mount source directory does not exist on disk.
   - Host port conflict is active.
   - Container is within its cooldown window (default: 60s).
   - Maximum failed retry limit is exceeded (default: 3 attempts).
   - Container has custom policy override `enabled=False`.
6. **Post-Recovery Health Verification:** A returncode of 0 from `podman start` is **not** treated as recovery success. The controller inspects `State.Running == True` and confirms `State.Health.Status != "unhealthy"`.

---

## 6. Audit Log Integrity, Retention, & Rotation

### 6.1 Audit Log Structure
- `logs/recovery_history.jsonl`: Records every container restart attempt, timestamp, operator action, verification outcome (`VERIFIED` vs `FAILED_VERIFICATION`), and error messages.
- `logs/policy_history.jsonl`: Records all dry-run policy evaluation decisions (`ALLOW` vs `DENY`), checks evaluated, and cooldown metrics.
- `logs/incidents.jsonl`: Records incident resolution events (`RESOLVED`, `ESCALATED`, `FAILED_VERIFICATION`) with stable incident IDs.
- `logs/metrics.jsonl`: Time-series host metric samples (CPU, memory, disk utilization).

### 6.2 Partial Write & Corruption Handling
Log loaders in [app/history.py](file:///home/neha/projects/linuxops/app/history.py) catch `json.JSONDecodeError` on malformed or partially written lines, preserving all adjacent valid records without data loss.

### 6.3 Log Verification & Rotation
Use the built-in integrity and rotation primitives:
```python
from app.history import inspect_audit_log_integrity, rotate_audit_log

# Inspect log health (reports valid lines, corrupt lines, permissions)
status = inspect_audit_log_integrity("logs/recovery_history.jsonl")

# Rotate log when exceeding 10MB (preserves logs/recovery_history.jsonl.1, .2, etc.)
rotate_audit_log("logs/recovery_history.jsonl", max_bytes=10_000_000, backup_count=5)
```

### 6.4 Backup & Restore Considerations
To back up historical audit data safely without locking running services:
```bash
# Atomic snapshot copy of audit logs
cp -p logs/recovery_history.jsonl logs/recovery_history.jsonl.bak
cp -p logs/incidents.jsonl logs/incidents.jsonl.bak
cp -p logs/policy_history.jsonl logs/policy_history.jsonl.bak
```

---

## 7. Performance & Latency Baselines

LinuxOps clearly distinguishes between synthetic throughput and live host execution:

### 7.1 Synthetic In-Memory Benchmarks (Mocked Podman Runner)
Measures pure Python parsing, batch pipeline scheduling, and diagnostic rule evaluation:
- **100 Records:** 0.008s pipeline (13,179 c/s) | 0.003s diagnostics (38,781 c/s) | Peak RSS: 25.12 MB | Accuracy: 100.0%
- **250 Records:** 0.020s pipeline (12,493 c/s) | 0.008s diagnostics (32,055 c/s) | Peak RSS: 26.87 MB | Accuracy: 100.0%
- **500 Records:** 0.035s pipeline (14,455 c/s) | 0.011s diagnostics (46,845 c/s) | Peak RSS: 29.87 MB | Accuracy: 100.0%
- **1,000 Records:** 0.068s pipeline (14,687 c/s) | 0.023s diagnostics (43,940 c/s) | Peak RSS: 35.99 MB | Accuracy: 100.0%

### 7.2 Real Host Podman Operations (Read-Only)
Measured against live Fedora rootless Podman daemon:
- **Host Containers:** 2
- **Scan Duration:** ~1.10s – 1.92s
- **Throughput:** 1.04 – 1.81 containers/sec
- **Latency:** ~550ms – 960ms per container
- **Failures:** 0

*Takeaway:* Subprocess execution, IPC, and daemon lock acquisition in rootless container environments introduce ~550–960ms overhead per container query. Synthetic throughput figures must never be advertised as live Podman throughput.

---

## 8. Startup, Shutdown, Rollback & Troubleshooting Procedures

### 8.1 Startup & Validation Procedure
1. Run preflight readiness audit:
   ```bash
   python3 scripts/staging_preflight.py
   ```
2. Verify exit status is `READY` (10/10 checks passing).
3. Start the dashboard bound to localhost:
   ```bash
   streamlit run app/dashboard.py --server.address 127.0.0.1 --server.port 8501 --server.headless true
   ```

### 8.2 Graceful Shutdown Procedure
To stop LinuxOps cleanly without leaving background threads or subprocesses running:
```bash
# Gracefully stop local Streamlit instance
pkill -SIGTERM -f "streamlit run app/dashboard.py"

# Verify port 8501 is released
ss -tlpn | grep 8501
```

### 8.3 Backup & Restore Procedure for Incident History
#### Backup:
```bash
# Create timestamped atomic backup of history and telemetry
BACKUP_DIR="logs/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -p logs/*.jsonl "$BACKUP_DIR/"
chmod 0700 "$BACKUP_DIR"
chmod 0600 "$BACKUP_DIR"/*
```

#### Restore:
```bash
# 1. Stop any running dashboard/monitor processes
pkill -f "streamlit run app/dashboard.py" || true

# 2. Restore JSONL files from backup snapshot
cp -p "$BACKUP_DIR"/*.jsonl logs/

# 3. Verify restored log integrity
python3 -c "from app.history import inspect_audit_log_integrity; [print(f, inspect_audit_log_integrity(f)) for f in ['logs/recovery_history.jsonl', 'logs/incidents.jsonl', 'logs/policy_history.jsonl']]"
```

### 8.4 Non-Destructive Emergency Rollback
If a staging deployment experiences unexpected behavior:
1. **Engage Global Recovery Kill-Switch Immediately:**
   ```bash
   export LINUXOPS_RECOVERY_DISABLED=1
   ```
   Or via Python API:
   ```python
   from app.recovery_controller import set_global_recovery_disabled
   set_global_recovery_disabled(True)
   ```
2. **Stop Dashboard Process:**
   ```bash
   pkill -f "streamlit run app/dashboard.py"
   ```
3. **Verify Protected Workloads Remain Untouched:**
   ```bash
   python3 scripts/validate_live_readonly.py
   ```
   Confirm `cloudops-floci` is running and `/home/neha/cloudops-sentinel/data` is unmodified.

### 8.5 Incident Escalation & Log Review Workflow
When an incident is flagged in `logs/incidents.jsonl` or on the dashboard:
1. **Identify Incident Category:**
   - `CRASH_LOOP_DETECTED` / `OOM_KILLED`: Automatically escalated by policy; automated restart is locked out.
   - `BIND_MOUNT_MISSING` / `PORT_CONFLICT_DETECTED`: Requires host-level configuration correction before container restart.
   - `APPLICATION_READINESS_TIMEOUT`: Requires inspection of service startup logs.
2. **Review Recent Logs & Telemetry:**
   ```bash
   # Inspect recent incident audit trail
   tail -n 20 logs/incidents.jsonl | jq .

   # Check recovery history for repeated attempts
   tail -n 20 logs/recovery_history.jsonl | jq .
   ```
3. **Escalation Path:**
   - If an unresolvable root-cause occurs, LinuxOps marks `escalated=True` in the proposal.
   - Operators must resolve host preconditions (e.g. create missing mount directory or free conflicting host port) before triggering recovery.
   - In pilot operations, all escalated incidents require operator sign-off in the incident log.

### 8.6 Troubleshooting Common Issues
- **Dashboard Displays Stale Telemetry:** Ensure `podman stats` is responsive on the host. If host cgroup delegation is inactive, CPU/memory percentages transition to `unavailable` rather than crashing.
- **Preflight Fails on Port 8501:** Check if another Streamlit or web process is listening on `127.0.0.1:8501` using `ss -tlpn | grep 8501`.
- **Preflight Reports Corrupt Records:** Run `python3 -c "from app.history import inspect_audit_log_integrity; print(inspect_audit_log_integrity('logs/incidents.jsonl'))"` to identify corrupt lines.

---

## 9. Architectural Boundaries, Security Posture & Explicit Non-Claims

> [!IMPORTANT]
> **Streamlit Native Authentication Notice:**
> Streamlit does **NOT** provide native authentication, session management, or role-based access control (RBAC). The dashboard is configured to bind strictly to `127.0.0.1:8501`. It **MUST REMAIN LOCALHOST-ONLY** and must never be bound to `0.0.0.0` or exposed directly to untrusted networks. Any remote access requires an authenticated, TLS-terminating reverse proxy (e.g., Caddy or Nginx with OAuth2/mTLS/Basic Auth).

Explicit non-claims for LinuxOps Phase 6:
- **Single-Host Architecture Only:** LinuxOps monitors and manages Podman workloads on the **local host only**. It does not support multi-host clustering, Swarm, or Kubernetes pods.
- **No High Availability (HA):** LinuxOps operates as a standalone monitoring process. Failover, leader election, and distributed consensus are not implemented.
- **No Automatic Autonomous Recovery:** All recovery actions require explicit operator confirmation (`authorized=True`). Recommendation-only is the default operating posture.
- **No External Multi-Tenant Isolation:** LinuxOps runs within the operator's rootless user namespace and shares the privileges of that user account.

---

## 10. Alert Delivery Architecture & Notification Readiness

The alert infrastructure in `app/alerts.py` is architected as follows:

| Capability | Status | Implementation Details |
| :--- | :---: | :--- |
| **In-Memory Alert Classification** | **IMPLEMENTED** | Threshold-based system alerts (`CPU_HIGH`, `MEMORY_HIGH`, `DISK_HIGH`) and container state alerts (`CONTAINER_STOPPED`, `OOM_KILLED`, `HIGH_RESTART_COUNT`). |
| **Alert Deduplication** | **IMPLEMENTED** | Keyed by `(target, rule, severity)` to prevent alert spam across polling cycles. |
| **Secret & Credential Scrubbing** | **IMPLEMENTED** | `redact_sensitive_text()` automatically scrubs Bearer tokens, passwords, AWS keys, and credentials before alerts are formatted or dispatched. |
| **Mock Notification Transport** | **IMPLEMENTED** | `MockAlertTransport` simulates delivery, failure handling, and payload inspection without external dependencies. |
| **Pluggable Dispatch Pipeline** | **IMPLEMENTED** | `dispatch_alert_notifications()` supports pluggable transport objects/callables with per-alert exception isolation and `PARTIAL` / `SUCCESS` / `FAILED` accounting. |
| **External Alert Delivery (Email, Webhook, Slack, PagerDuty)** | **ABSENT (BY DESIGN)** | External notification transports are **NOT configured** in the base platform. When unconfigured, `dispatch_alert_notifications` safely returns `status="NO_TRANSPORT_CONFIGURED"` without raising exceptions or blocking monitoring cycles. |

---

## 11. Limited Pilot Measurable Go/No-Go Decision Criteria

For a controlled pilot deployment on a dedicated single host, all criteria in the table below must be satisfied:

| Category | Measurable Criterion | Threshold Required | Verification Command | Pilot Status |
| :--- | :--- | :---: | :--- | :---: |
| **Preflight Readiness** | Staging preflight check exit code | 10 / 10 PASS (100%) | `python3 scripts/staging_preflight.py` | ✅ MET |
| **Unit Test Suite** | Full test suite execution | 354+ passed, 0 failures, 0 errors | `python3 -m unittest discover tests` | ✅ MET |
| **Code Integrity** | Python bytecode compilation | Zero compilation errors | `python3 -m compileall -q app scripts tests` | ✅ MET |
| **Git Cleanliness** | Whitespace and syntax diff check | Zero whitespace / patch errors | `git diff --check` | ✅ MET |
| **Operational Stability** | Repeated monitoring cycles | 5+ cycles, 0 unhandled exceptions | `python3 scripts/validate_pilot_cycles.py` | ✅ MET |
| **Incident Stability** | Incident ID determinism across cycles | 100% stable IDs, 0 alert churn | `python3 scripts/validate_pilot_cycles.py` | ✅ MET |
| **Memory Boundedness** | Net memory growth across repeated cycles | $< 10.0\text{ MB}$ RSS delta | `python3 scripts/validate_pilot_cycles.py` | ✅ MET (+1.76 MB) |
| **Recovery Kill-Switch** | Global recovery kill-switch enforcement | 100% blocked with `GLOBAL_KILL_SWITCH` | Unit & cycle test suite | ✅ MET |
| **Workload Immunity** | Protected container immunity (`floci`, etc.) | 100% blocked with `PROTECTED_WORKLOAD` | `python3 scripts/validate_live_readonly.py` | ✅ MET |
| **Network Security** | Streamlit binding address | Strictly `127.0.0.1:8501` | `.streamlit/config.toml` & preflight | ✅ MET |
| **Diagnostic Accuracy** | Benchmark diagnostic accuracy | 100.0% across 100, 250, 500, 1000 containers | `python3 scripts/benchmark_observability.py` | ✅ MET |
| **External Alert Delivery** | Mock transport / Safe absent fallback | Safe `NO_TRANSPORT_CONFIGURED` default | `tests/test_pilot_validation.py` | ✅ MET |

---

## 12. Checklist for Future Authenticated Remote Deployment

Before any remote access to LinuxOps is provisioned beyond localhost:

- [ ] **Network Layer:** Port 8501 is strictly blocked from external/public network interfaces via `firewalld` or `nftables`.
- [ ] **Binding Guard:** `.streamlit/config.toml` confirms `address = "127.0.0.1"`. Preflight passes with zero warnings.
- [ ] **TLS Termination:** An external reverse proxy (e.g., Caddy, Nginx, or Envoy) is deployed with valid TLS certificates.
- [ ] **User Authentication:** Operator authentication (mTLS, OAuth2/OIDC, or HTTP Basic Auth) is enforced at the reverse proxy prior to proxying requests to loopback.
- [ ] **Audit Logging:** Proxy access logs are enabled to trace remote operator identities, timestamps, and client IP addresses.
- [ ] **Emergency Kill-Switch:** `export LINUXOPS_RECOVERY_DISABLED=1` is confirmed operational and testable without modifying running workloads.
- [ ] **Protected Workloads Verified:** `python3 scripts/validate_live_readonly.py` passes with deep identity immunity intact.

---

## 13. Production-Scale Container Observability & Operator Guidance (Phase 8)

### 13.1 100–500+ Container Inspection Strategy
Under rootless Podman, sequential invocation of `podman inspect <cid>` across 100–500 containers incurs ~500–850 ms per command due to process initialization and daemon socket lock contention (e.g. 100 containers = 80+ seconds).

LinuxOps Phase 8 implements a high-throughput, bounded inspection architecture:
1. **Batched Chunk Inspection (`podman inspect id1 id2 ... idN`):**
   - Containers are inspected in configurable chunks (`batch_size=25` to `50`).
   - Single command inspects an entire chunk in ~1.2s, reducing 100-container inspection to < 2.5s.
   - Individual inspect fallback is automatically triggered if an invalid or disappearing ID causes a chunk to fail, isolating the specific container without losing data for the remaining chunk.
2. **Bounded Concurrency:**
   - Inspection chunks and background tasks execute within a bounded `ThreadPoolExecutor(max_workers=8)`.
   - Prevents host resource exhaustion and daemon lock thrashing.
3. **Empty-Running Stats Bypass:**
   - When no containers are in `running` state (e.g. all workloads stopped), the expensive `podman stats --no-stream` subprocess call is completely bypassed, saving ~1.5s per cycle.
4. **Bounded Metadata Caching (`ContainerMetadataCache`):**
   - Thread-safe LRU cache with configurable capacity (`max_entries=2000`, default).
   - Tracks cache hits, misses, evictions, and hit ratio.
   - Supports per-container invalidation (`invalidate(cid)`) and global clearing (`clear()`).
5. **Latency Percentile Profiling:**
   - Every scan calculates `min_ms`, `max_ms`, `mean_ms`, `p50_ms`, `p90_ms`, and `p95_ms` across inspect chunk execution durations.
   - Ensures visibility into tail latencies without intrusive instrumentation overhead.

### 13.2 Answering the 7 Core Operator Questions
LinuxOps structures its telemetry and deterministic diagnostics to directly answer the 7 essential questions required by production operators during an incident:

| Operator Question | LinuxOps Field / Mechanism | Operational Purpose |
| :--- | :--- | :--- |
| **1. What is running, stopped, unhealthy, or failing?** | `state`, `health_status`, `symptoms`, `severity_reason` | Immediate operational status distinguishing unmonitored running from healthy containers. |
| **2. What changed, and when did the problem start?** | `first_seen`, `last_seen`, `telemetry_age_seconds`, `uptime_seconds` | Pinpoints precise incident onset and recurrence timeline. |
| **3. What is the likely root cause & evidence?** | `candidate_causes` (`[CONFIRMED]` vs `[INFERRED]`), `evidence`, `confidence`, `confidence_explanation` | Ranked causes with certainty level and deterministic telemetry proof. |
| **4. Which containers or services are affected?** | `container_name`, `container_id`, `correlated_containers` | Identifies primary target and correlated cascade or port conflict partners. |
| **5. How severe and urgent is the incident?** | `severity` (`CRITICAL`, `WARNING`, `INFO`), `severity_reason` | Explains why severity was assigned (e.g. data loss risk vs degraded performance). |
| **6. What should the operator do next?** | `recommended_action`, `action_reason`, `risks_and_prerequisites`, `suggested_investigation_steps`, `investigation_commands` | Step-by-step guidance and copyable illustrative CLI commands (read-only). |
| **7. How can the operator verify resolution?** | `expected_outcome`, `post_action_verification`, `escalation_guidance` | Verification checklist to confirm resolution before closing ticket. |

### 13.3 Operator Guidance & Shift Handover Notes
- **Non-Authorizing Acknowledgement:** The Incident Operations Center in the dashboard includes an operator shift note input and acknowledgement checkbox.
- **Strict Security Boundary:** Acknowledging an incident in the UI is strictly for shift handover and operational tracking; it **DOES NOT grant backend recovery authorization**.
- **Secret Scrubbing:** All operator guidance fields, candidate causes, evidence lines, and CLI commands are scrubbed via `redact_sensitive_text()` before rendering or persistence.

### 13.4 Procedure for Controlled 100-Container Validation in a Disposable Sandbox
When testing against 100 real Podman containers is authorized, operators must use a disposable sandbox environment. **Never substitute protected host workloads (`cloudops-floci`, etc.) as test targets.**

#### Pre-requisites:
- Disposable Linux host or dedicated ephemeral VM (e.g. cloud VM or separate WSL2 distro).
- Rootless Podman installed.
- Zero production or protected workloads present on the disposable host.

#### Step 1: Create Ephemeral Test Workloads
```bash
# Generate 100 lightweight disposable containers in the sandbox
for i in $(seq 1 100); do
  podman run -d --name "sandbox-worker-$i" --label "environment=disposable-sandbox" alpine sleep 3600
done
```

#### Step 2: Inject Controlled Fault Scenarios
```bash
# Inject sample faults across specific sandbox workers:
# 1. Stopped container:
podman stop sandbox-worker-10

# 2. OOM-kill test:
podman run -d --name sandbox-oom-test -m 10m --label "environment=disposable-sandbox" alpine sh -c 'tail /dev/zero'

# 3. Crash-loop test:
podman run -d --name sandbox-crash-test --restart=always --label "environment=disposable-sandbox" alpine sh -c 'exit 1'
```

#### Step 3: Execute LinuxOps Observability Scan
```bash
# Run real inspection scan and measure duration and latency percentiles
python3 -c "from app.container_inspector import scan_containers; import json; print(json.dumps(scan_containers(), indent=2))"
```

#### Step 4: Verify Acceptance Targets
- Total 100-container scan completed within 10 seconds.
- Inspection success rate $\ge 99\%$.
- Tail latency p95 within expected polling interval.
- Zero crashes, zero unhandled exceptions.

#### Step 5: Teardown & Clean Up Sandbox
```bash
# Remove all disposable sandbox workers
podman rm -f $(podman ps -a -q --filter "label=environment=disposable-sandbox")
```


