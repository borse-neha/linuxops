# LinuxOps Operational Runbooks & Safe Incident Response Procedures

**Target Platform:** LinuxOps Operations Center  
**Runtime:** Ubuntu-24.04 WSL2 & Windows 11 Host Integration  
**Policy Invariant:** `LINUXOPS_RECOVERY_DISABLED=1` strictly enforced  
**Protected Targets:** `cloudops-floci`, `FedoraLinux-44`, `/home/neha/cloudops-sentinel/data` (Permanently Immune)  
**Publication Date:** `2026-10-25`  

---

## 1. Overview & Operational Principles

These standard operating procedures (SOPs) provide deterministic, safe incident response procedures for on-call SREs and platform operators running LinuxOps.

### Operational Golden Rules:
1. **Diagnostics Before Mutation:** Always execute read-only diagnostic commands before taking actions that restart services or modify workloads.
2. **Preserve Isolation:** Never access the live Podman socket on Fedora or attempt to recover `cloudops-floci`.
3. **Recovery Kill-Switch Invariant:** Keep `LINUXOPS_RECOVERY_DISABLED=1` active unless human-authorized, single-workload recovery has been explicitly cleared through change management.
4. **Non-Destructive Workload Actions:** Only `start_container` is permitted in the recovery allowlist; destructive operations (`rm`, `kill`, `stop`, volume deletion) are permanently forbidden.
5. **Durable Auditing:** Every remediation proposal, authorization, execution attempt, and alert dispatch must be recorded in durable JSONL logs (`0600` permissions with `os.fsync`).

---

## 2. Quick Incident Matrix

| Code | Incident Classification | Severity | Primary Symptom | Safe Runbook |
| :--- | :--- | :---: | :--- | :--- |
| **RB-01** | Dashboard Health-Check Failure | `CRITICAL` | `http://localhost:8501/_stcore/health` unreachable | Section 3 |
| **RB-02** | WSL Bridge or Dynamic IP Failure | `HIGH` | Windows browser unreachable while WSL localhost works | Section 4 |
| **RB-03** | Watchdog Restart Exhaustion / Cooldown | `CRITICAL` | Supervisor state `COOLDOWN`, alert throttled | Section 5 |
| **RB-04** | Repeated Application Failures / Crash Loop | `CRITICAL` | `CRASH_LOOP_DETECTED`, exit code 1 or 137 | Section 6 |
| **RB-05** | Missing or Malformed Telemetry | `WARNING` | CPU/Mem metrics `unavailable`, charts blank | Section 7 |
| **RB-06** | Alert Transport & Webhook Delivery Failure | `WARNING` | Webhook HTTP 4xx/5xx, `FAILED_RETRY_EXHAUSTED` | Section 8 |
| **RB-07** | Audit Log Integrity Warnings | `WARNING` | JSONL decode error, unclosed file or permission drift | Section 9 |

---

## 3. Runbook 01: Dashboard Health-Check Failure

### Symptoms:
- Windows browser displays "This site can't be reached" or HTTP 500/503 on `http://localhost:8501`.
- Local probe `curl -sI http://127.0.0.1:8501/_stcore/health` times out or returns non-200.

### Step 1: Read-Only Diagnostics
```bash
# 1. Check user-level systemd service status
systemctl --user status linuxops-dashboard.service --no-pager

# 2. Check if Python/Streamlit process is listening on 127.0.0.1:8501
ss -tlpn | grep 8501

# 3. Check recent systemd unit logs for crashes or Python tracebacks
journalctl --user -u linuxops-dashboard.service -n 50 --no-pager

# 4. Verify environment variable kill-switch is still present
systemctl --user show linuxops-dashboard.service -p Environment
# Expected output contains: Environment=LINUXOPS_RECOVERY_DISABLED=1
```

### Step 2: Remediating Actions (Service Restart)
```bash
# 1. Restart the user-level dashboard service cleanly
systemctl --user restart linuxops-dashboard.service

# 2. Verify service reached active (running) state
systemctl --user is-active linuxops-dashboard.service

# 3. Verify health probe returns HTTP 200 OK
curl -sI http://127.0.0.1:8501/_stcore/health
```

### Step 3: Rollback & Escalation
- If the service fails with `Address already in use`, inspect rogue processes:
  ```bash
  ss -tlpn | grep 8501
  # If a rogue orphaned streamlit process exists:
  pkill -f "streamlit run app/dashboard.py"
  systemctl --user start linuxops-dashboard.service
  ```
- If Python raises an unhandled import error or dependency corruption, run:
  ```bash
  /home/neha_borse/linuxops/.venv/bin/python3 scripts/staging_preflight.py
  ```
- Escalate to platform lead if systemd user slice is unresponsive.

---

## 4. Runbook 02: WSL Bridge or IP-Change Failure

### Symptoms:
- Dashboard works inside WSL2 (`curl -sI http://127.0.0.1:8501/_stcore/health` returns `HTTP 200 OK`), but Windows browser cannot reach `http://localhost:8501`.
- Usually occurs after Windows laptop sleep/resume, network adapter reset, or VPN connection.

### Step 1: Read-Only Diagnostics
```bash
# 1. Identify current WSL2 eth0 IP address
ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'

# 2. Check bridge service status in WSL2
systemctl --user status linuxops-bridge.service --no-pager

# 3. Check bridge service listener in WSL2
ss -tlpn | grep 8501
# Expected: 127.0.0.1:8501 (Streamlit) AND <wsl_ip>:8501 (Bridge)
```

On Windows (PowerShell):
```powershell
# Check Windows port proxy and listeners
Get-NetTCPConnection -LocalPort 8501 -ErrorAction SilentlyContinue
netsh interface portproxy show all
```

### Step 2: Remediating Actions (Bridge Re-Sync)
```bash
# In WSL2: Restart user bridge service to bind to new dynamic WSL IP
systemctl --user restart linuxops-bridge.service
systemctl --user is-active linuxops-bridge.service
```

On Windows (PowerShell):
```powershell
# Re-run Windows portproxy setup if dynamic WSL IP changed
$wslIp = (wsl.exe -d Ubuntu-24.04 bash -lc "ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'").Trim()
netsh interface portproxy delete v4tov4 listenport=8501 listenaddress=127.0.0.1
netsh interface portproxy add v4tov4 listenport=8501 listenaddress=127.0.0.1 connectport=8501 connectaddress=$wslIp
```

### Step 3: Verification
Open `http://localhost:8501` in Windows Chrome/Edge. Verify security gate renders.

---

## 5. Runbook 03: Watchdog Restart Exhaustion or Active Cooldown

### Symptoms:
- Dashboard banner reports `Host watchdog restart cooldown is active`.
- Alert `WATCHDOG_RESTART_COOLDOWN` is active (`SEVERITY: CRITICAL`).
- Supervisor log indicates `ConsecutiveFailures >= 3` in 5-minute rolling window.

### Step 1: Read-Only Diagnostics
```bash
# Inspect watchdog supervisor state file
cat /mnt/c/Users/Neha\ Borse/.linuxops/logs/watchdog-state.json | jq .

# Tail supervisor action audit log
tail -n 50 /mnt/c/Users/Neha\ Borse/.linuxops/logs/watchdog.log
```

### Step 2: Remediating Actions
> [!CAUTION]
> **DO NOT bypass the cooldown or force immediate restarts.**
> The cooldown exists to protect the Windows host from CPU starvation and restart loops.

1. **Resolve Root Cause First:** Check `Runbook 01` to determine why the dashboard failed.
2. **Allow Window to Expire:** The cooldown timer defaults to 5 minutes. Let the supervisor timer naturally clear.
3. **Manual State Reset (Only after fixing root cause):**
   ```bash
   # Reset ConsecutiveFailures and InCooldown if dashboard is verified healthy
   python3 -c "
   import json, datetime, pathlib
   p = pathlib.Path('/mnt/c/Users/Neha Borse/.linuxops/logs/watchdog-state.json')
   if p.exists():
       d = json.loads(p.read_text())
       d['InCooldown'] = False
       d['ConsecutiveFailures'] = 0
       d['LastProbeStatus'] = 'HEALTHY'
       p.write_text(json.dumps(d, indent=2))
       print('Watchdog cooldown reset successfully.')
   "
   ```

---

## 6. Runbook 04: Repeated Application Failures (Crash Loops & OOM)

### Symptoms:
- Incident category `CRASH_LOOP_DETECTED` or `OOM_KILLED` in Section `00`.
- Container restart count >= 3 or exit code 137.

### Step 1: Read-Only Diagnostics
```bash
# 1. Review incident record and root-cause evidence
tail -n 20 logs/incidents.jsonl | jq 'select(.rule_id=="CRASH_LOOP_DETECTED" or .rule_id=="OOM_KILLED")'

# 2. Inspect container exit metadata
podman inspect -f 'Name: {{.Name}} | Status: {{.State.Status}} | ExitCode: {{.State.ExitCode}} | OOMKilled: {{.State.OOMKilled}} | Restarts: {{.RestartCount}}' <container_name>

# 3. Tail recent container error logs
podman logs --tail 50 <container_name>
```

### Step 2: Remediating Actions
- **If OOM Killed (Exit 137):**
  - Automated restart is permanently locked out by `evaluate_incident_recovery`.
  - Operator must inspect host RAM availability (`free -m`) and increase `--memory` limit in container definition before restarting.
- **If Crash Loop (Exit 1):**
  - Check missing environment variables (`MISSING_CONFIGURATION_OR_ENV`) or missing mount directories (`PERMISSION_DENIED`).
  - Correct configuration in container launcher before clearing container for start.
- **Immunity Safety Check:**
  - Verify container is NOT `cloudops-floci` or sentinel data:
    ```bash
    python3 -c "from app.recovery_controller import is_protected_container_target; print(is_protected_container_target('<container_name>'))"
    ```

---

## 7. Runbook 05: Missing or Malformed Telemetry

### Symptoms:
- Metrics display `unavailable` or `stale`.
- Dashboard telemetry graphs show flatlines or gaps.

### Step 1: Read-Only Diagnostics
```bash
# 1. Test direct Podman stats responsiveness
podman stats --no-stream --format json

# 2. Verify rootless cgroup delegation
systemctl --user show -p Delegate

# 3. Check metrics log permissions and size
ls -lh logs/metrics.jsonl
```

### Step 2: Remediating Actions
- If `podman stats` hangs, the user Podman socket may be stuck:
  ```bash
  systemctl --user restart podman.socket
  ```
- If container is stopped, `unavailable` telemetry is expected and normal (not an error).

---

## 8. Runbook 06: Alert Transport & Webhook Delivery Failure

### Symptoms:
- External notifications are not delivered.
- `logs/alert_delivery.jsonl` contains `FAILED_RETRY_EXHAUSTED` or `FAILED_CLIENT_ERROR`.

### Step 1: Read-Only Diagnostics
```bash
# 1. Inspect recent delivery audit records
tail -n 20 logs/alert_delivery.jsonl | jq .

# 2. Check current webhook configuration
env | grep LINUXOPS_ALERT_

# 3. Verify target endpoint reachability (headers only, zero payload)
curl -sI -o /dev/null -w "HTTP Status: %{http_code}\n" "$LINUXOPS_ALERT_WEBHOOK_URL"
```

### Step 2: Remediating Actions
- **If HTTP 401/403 (Authentication Error):**
  - Check bearer token or secret header in `LINUXOPS_ALERT_WEBHOOK_TOKEN`.
- **If HTTP 429 (Rate Limited):**
  - The transport automatically enforces backoff. Adjust `LINUXOPS_ALERT_WEBHOOK_MAX_RETRIES` if necessary.
- **If Insecure HTTP Rejected:**
  - Ensure endpoint uses `https://`. Only set `LINUXOPS_ALERT_ALLOW_HTTP=1` in isolated local test sandboxes.
- **Temporary Silence:**
  - If external endpoint is experiencing extended maintenance, disable delivery without stopping LinuxOps:
    ```bash
    export LINUXOPS_ALERT_WEBHOOK_ENABLED=0
    ```
    Alerts will continue to appear on the operator dashboard without generating failed delivery logs.

---

## 9. Runbook 07: Audit Log Integrity Warnings & Corrupt Records

### Symptoms:
- Preflight or log loader reports corrupt JSON records or file permission drift.

### Step 1: Read-Only Diagnostics
```bash
# 1. Audit log integrity check
python3 -c "
from app.history import inspect_audit_log_integrity
for log in ['logs/recovery_history.jsonl', 'logs/incidents.jsonl', 'logs/policy_history.jsonl', 'logs/alert_delivery.jsonl']:
    print(log, inspect_audit_log_integrity(log))
"

# 2. Check file permissions
ls -ld logs/
ls -la logs/*.jsonl
```

### Step 2: Remediating Actions
```bash
# 1. Restore secure file permissions (0700 dir, 0600 files)
chmod 0700 logs/
chmod 0600 logs/*.jsonl

# 2. Rotate oversized logs (>10 MB)
python3 -c "
from app.history import rotate_audit_log
rotate_audit_log('logs/recovery_history.jsonl', max_bytes=10_000_000, backup_count=5)
rotate_audit_log('logs/incidents.jsonl', max_bytes=10_000_000, backup_count=5)
"

# 3. Create atomic backup snapshot
mkdir -p logs/backups/$(date +%Y%m%d)
cp -p logs/*.jsonl logs/backups/$(date +%Y%m%d)/
```

---

## 10. Rollback & Emergency Decommissioning

In the event of an operational anomaly during a release candidate deployment:

1. **Immediate Global Kill-Switch Activation:**
   ```bash
   export LINUXOPS_RECOVERY_DISABLED=1
   ```
2. **Stop User-Level Dashboard & Bridge Services:**
   ```bash
   systemctl --user stop linuxops-dashboard.service linuxops-bridge.service
   ```
3. **Verify Protected Workload State:**
   ```bash
   podman ps --filter name=cloudops-floci
   # Confirm cloudops-floci is intact, untouched, and running
   ```
4. **Restore Previous Git Working State (If Authorized):**
   Do not discard uncommitted user changes without explicit change ticket authorization.
