# LinuxOps Release Guide & Deployment Manual

## 1. Project Overview & Supported Scope

**LinuxOps** is an observability, diagnostics, and policy-governed safe-recovery platform for single-host Linux environments running rootless Podman containers.

### Supported Scope
- **Host Architecture:** Single-host Linux running rootless Podman 4.x / 5.x.
- **Runtime:** Native Python execution within an isolated virtual environment (`.venv`).
- **Telemetry:** In-memory metric aggregation, container state discovery, and deep inspection.
- **Diagnostics:** 10-rule root-cause analysis engine with secret scrubbing and bounded logs.
- **Recovery:** Advisory / recommendation-only by default. Human authorization and backend policy gates strictly enforced for any restart execution.
- **Dashboard:** Interactive Streamlit operations center strictly bound to `127.0.0.1:8501`.
- **Audit Logging:** Durable append-only JSON Lines records stored locally in `logs/`.

---

## 2. Prerequisites & Supported Environment

| Component | Requirement | Verified Baseline |
| :--- | :--- | :--- |
| **Operating System** | Linux (Fedora 38+, RHEL 9+, Ubuntu 22.04+) | Fedora Linux 44 (WSL2 kernel 6.18+) |
| **Python** | Python >= 3.10 | Python 3.14.7 |
| **Container Runtime** | Rootless Podman CLI >= 4.0 | Podman 5.8.4 |
| **Core Python Packages** | `pandas>=2.0.0,<4.0.0`, `streamlit>=1.30.0,<2.0.0` | `pandas==3.0.5`, `streamlit==1.62.0` |
| **Network Security** | Loopback binding only (`127.0.0.1`) | Bound to `127.0.0.1:8501` |

> [!NOTE]
> **Python Version Support Note:**
> LinuxOps codebase utilizes modern type union syntax (`X | Y`, PEP 604) and generic alias types (`list[dict]`, PEP 585) requiring Python >= 3.10. Compatibility is actively tested and verified on Python 3.14.7 on Fedora Linux 44.

---

## 3. Isolated Environment Setup & Installation

LinuxOps uses standard Python packaging (`pyproject.toml`, `requirements.txt`) and can be bootstrapped in an isolated virtual environment using the provided automated script or standard commands.

### Automated Setup (Recommended)
```bash
# Bootstrap isolated virtual environment, install dependencies, and run preflight checks
./scripts/setup_env.sh

# Or for development and test dependencies (includes pytest):
./scripts/setup_env.sh --dev
```

### Manual Setup Step-by-Step
```bash
# 1. Create an isolated virtual environment
python3 -m venv .venv

# 2. Activate virtual environment
source .venv/bin/activate

# 3. Upgrade bootstrap tooling
pip install --upgrade pip setuptools wheel

# 4. Install declared runtime dependencies
pip install -r requirements.txt

# (Optional) For exact pinned staging reproducibility:
pip install -r requirements-lock.txt

# 5. Verify staging readiness
python3 scripts/staging_preflight.py
```

---

## 4. Configuration & Secrets Handling

### 4.1 Configuration Template (`.env.example`)
To customize monitoring thresholds or safety toggles, copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

| Parameter | Default | Purpose |
| :--- | :---: | :--- |
| `CPU_WARNING` | `70.0` | Host CPU warning threshold (percent). |
| `CPU_CRITICAL` | `90.0` | Host CPU critical alert threshold (percent). |
| `MEMORY_WARNING` | `80.0` | Host memory warning threshold (percent). |
| `MEMORY_CRITICAL` | `90.0` | Host memory critical alert threshold (percent). |
| `DISK_WARNING` | `80.0` | Host root disk warning threshold (percent). |
| `DISK_CRITICAL` | `90.0` | Host root disk critical alert threshold (percent). |
| `LINUXOPS_RECOVERY_DISABLED` | `0` | Global recovery kill-switch (`1` or `true` halts all recovery). |

### 4.2 Secrets & Credential Policy
- **Zero Committed Secrets:** The `.env` file is strictly listed in `.gitignore` and must never be committed.
- **In-Memory Credential Scrubbing:** All container logs, environment variables, inspect data, and alert messages are automatically scrubbed by `redact_sensitive_text()` before presentation or persistence.
- **Safe Example Template:** `.env.example` contains numeric thresholds and safety flags only; zero tokens, passwords, or keys exist in configuration files.

---

## 5. Operations: Launch, Preflight & Shutdown

### 5.1 Dashboard Launch
```bash
# Launch dashboard hardened to localhost (127.0.0.1:8501)
./scripts/run_dashboard.sh
```
Access the Operations Center locally at:
👉 **`http://127.0.0.1:8501`**

### 5.2 Graceful Shutdown
To cleanly stop the dashboard without leaving orphan background threads:
```bash
./scripts/stop_dashboard.sh
```
The shutdown script sends SIGTERM, waits for clean release, and verifies port 8501 is freed.

---

## 6. Automated Validation Suite

LinuxOps provides a comprehensive multi-tier verification battery:

```bash
# Execute the full automated verification suite
./scripts/run_checks.sh
```

### Individual Verification Commands
| Verification Area | Command | Purpose |
| :--- | :--- | :--- |
| **Staging Preflight** | `python3 scripts/staging_preflight.py` | 10-point readiness check (permissions, paths, binding, Podman). |
| **Unit Test Suite** | `python3 -m unittest discover tests -p 'test_*.py' -v` | Full test suite (362 tests covering all modules). |
| **Pilot Cycle Stability** | `python3 scripts/validate_pilot_cycles.py` | 5 repeated cycles, incident determinism, memory growth audit. |
| **Controlled Benchmark** | `python3 scripts/benchmark_observability.py --measure-real` | 100/250/500/1000 synthetic records + real host Podman baseline. |
| **Live Read-Only Audit** | `python3 scripts/validate_live_readonly.py` | Verifies live host containers and protected workload immunity. |
| **Bytecode Compilation** | `python3 -m compileall -q app scripts tests` | Zero syntax or bytecode compilation errors. |
| **Diff Cleanliness** | `git diff --check` | Zero patch, whitespace, or conflict markers. |

---

## 7. Security Boundaries & Architectural Guardrails

> [!IMPORTANT]
> **Streamlit Native Authentication Notice:**
> Streamlit does **NOT** provide built-in authentication, user sessions, or role-based access control (RBAC). The dashboard is configured in `.streamlit/config.toml` to bind strictly to `127.0.0.1:8501`. It **MUST NEVER BE EXPOSED ON 0.0.0.0** or connected directly to an untrusted network. Remote access requires an authenticated reverse proxy (e.g., Caddy or Nginx with TLS and OAuth2/mTLS/Basic Auth).

### Strict Architectural Boundaries:
1. **Single-Host Boundary:** Monitored workloads must reside on the local Linux host running rootless Podman. Multi-host clustering, Kubernetes pods, and distributed consensus are not supported.
2. **Recommendation-Only Recovery:** Autonomous automatic recovery is disabled. Operator authorization (`authorized=True`) and backend policy re-evaluation are strictly required.
3. **Protected Workload Immunity:** Workloads `cloudops-floci`, `linuxops-recovery-ui-test`, and persistent directory `/home/neha/cloudops-sentinel/data` are immune from modification.
4. **Action Allowlist:** Only `start_container` is permitted. Destructive operations (`rm`, `kill`, `stop`, `prune`, volume removal) are permanently forbidden.
5. **Alert Delivery Scope:** External notification delivery (email, webhook, Slack, PagerDuty) is absent by default. In a base deployment, alerts remain in-memory and visible in the dashboard table. A mock transport (`MockAlertTransport`) is provided for dry-run simulation.
6. **Synthetic vs. Real Latency Separation:** Synthetic benchmark results (~7,000 c/s in-memory) measure pure Python parsing and must not be advertised as real host Podman throughput (~1.2 c/s, ~828 ms/container latency).

---

## 8. Backup, Rollback & Troubleshooting

### 8.1 Audit Log Backup
```bash
# Create timestamped atomic backup of audit history
BACKUP_DIR="logs/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "${BACKUP_DIR}"
cp -p logs/*.jsonl "${BACKUP_DIR}/"
chmod 0700 "${BACKUP_DIR}"
chmod 0600 "${BACKUP_DIR}"/*
```

### 8.2 Emergency Non-Destructive Rollback
If unexpected behavior occurs in staging:
1. **Engage Kill-Switch:** `export LINUXOPS_RECOVERY_DISABLED=1`
2. **Stop Dashboard:** `./scripts/stop_dashboard.sh`
3. **Verify Protected Workloads:** `python3 scripts/validate_live_readonly.py` (confirm `cloudops-floci` is running and `/home/neha/cloudops-sentinel/data` is intact).

### 8.3 Troubleshooting
- **Dashboard reports stale telemetry:** Check host rootless Podman daemon responsiveness. Missing cgroups cause CPU/memory to report `unavailable` gracefully without crashing.
- **Port 8501 collision:** Run `ss -tlpn | grep 8501` to identify competing processes before starting.
- **Audit log partial writes:** `app/history.py` catches JSON decode errors on corrupted lines and preserves valid adjacent records. Inspect health via `inspect_audit_log_integrity()`.

---

## 9. Release Candidate Verification Checklist (Phase 8 Production Scale)

| Gate | Verification Check | Required Result | Status |
| :---: | :--- | :--- | :---: |
| 1 | Python runtime environment | Python >= 3.10 in isolated `.venv` | ✅ PASS |
| 2 | Dependency declaration | `requirements.txt` & `pyproject.toml` consistent | ✅ PASS |
| 3 | Staging preflight audit | 10 / 10 checks passed | ✅ PASS |
| 4 | Automated test suite | 378 tests passed, 0 failures, 0 errors | ✅ PASS |
| 5 | Operational cycle stability | 5 cycles, bounded memory (+2.13 MB), stable incident IDs | ✅ PASS |
| 6 | Synthetic benchmarks | 100, 250, 500, 1000, 2000 records evaluated (100% accuracy, p50: 0.6ms, p95: 5.8ms) | ✅ PASS |
| 7 | Live read-only inspection | 2 real containers discovered; protected state intact | ✅ PASS |
| 8 | Dashboard network binding | Hardened strictly to `127.0.0.1:8501` | ✅ PASS |
| 9 | Recovery safeguards | Recommendation-only, kill-switch enforced, action allowlist | ✅ PASS |
| 10 | Protected workloads intact | `cloudops-floci` running, `recovery-ui-test` exited, data intact | ✅ PASS |
| 11 | Secrets safety & redaction | Zero secrets in repo; `.env` gitignored; redaction verified | ✅ PASS |
| 12 | Repository cleanliness | `compileall` clean, `git diff --check` clean | ✅ PASS |
| 13 | Operator Guidance | 7-question incident schema populated with confirmed/inferred causes | ✅ PASS |
| 14 | Real 100-container scale | Requires separately approved disposable sandbox environment | ⚠️ PENDING SANDBOX |
