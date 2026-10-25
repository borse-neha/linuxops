# LinuxOps Phase 16: Controlled Deployment, Backup & Disaster Recovery Report

**Target Platform:** LinuxOps Operations Center & Container Observability Platform  
**Target Environment:** Ubuntu-24.04 WSL2 Runtime & Windows 11 Host Integration  
**Protected Distribution:** `FedoraLinux-44` (Untouched, Unaccessed, and Intact)  
**Protected Workloads:** `cloudops-floci`, `linuxops-recovery-ui-test`, `/home/neha/cloudops-sentinel/data` (Permanently Immune & Intact)  
**Execution Date:** `2026-10-25`  
**Phase Focus:** Idempotent Versioned Backups, Secret-Free Archival, SHA-256 Manifest Integrity, Isolated Sandbox Restoration, Path-Traversal Defense, and Rollback Procedures  
**Release Verdict:** **PASS WITH LIMITATIONS** (Physical host lifecycle tests preserved as limitation)

---

## 1. Executive Summary

Phase 16 establishes a production-grade, deterministic backup, release, and disaster recovery subsystem for the LinuxOps platform. 

The implementation introduces:
1. An idempotent backup engine ([`app/backup.py`](file:///home/neha_borse/linuxops/app/backup.py)) and CLI tools ([`scripts/backup_manager.py`](file:///home/neha_borse/linuxops/scripts/backup_manager.py), [`scripts/restore_manager.py`](file:///home/neha_borse/linuxops/scripts/restore_manager.py)).
2. An automated secret scanner that prevents credentials, API keys, private keys, and `.env` files from ever entering backup archives.
3. Strict inclusion/exclusion policies that strip transient caches (`__pycache__`, `.pytest_cache`), virtual environments (`.venv`), git history (`.git`), socket files, and ephemeral logs.
4. Tamper-evident packaging combining gzip tarballs with embedded JSON manifests, internal `SHA256SUMS`, and external companion `.tar.gz.sha256` checksum files.
5. Isolated restore validation with multi-layer security barriers: destination empty checks, live repository root rejection, protected system path rejection, path-traversal detection, decompression-bomb protection, and atomic cleanup upon integrity mismatch.
6. A verified live backup was created, validated, and successfully restored into an isolated sandbox location (`/tmp/isolated_restore_test_run1`) with zero file diffs and zero live system disruption.
7. Full regression test suite passing: **565 automated tests** (15 new dedicated backup & DR tests).

---

## 2. Inclusions & Exclusions Catalog

To ensure backups are lightweight, deterministic, and free of secrets or system-specific binaries, the backup engine enforces strict boundary filters:

### Included Components (Essential for Full System Reconstruction)
| Category | File Paths / Patterns | Description |
| :--- | :--- | :--- |
| **Core Application** | `app/**/*.py` | All application logic (`dashboard.py`, `monitor.py`, `recovery.py`, `alerts.py`, `analytics.py`, `diagnostics_engine.py`, `backup.py`, etc.). |
| **Operational Scripts** | `scripts/**/*.py`, `scripts/**/*.sh` | Launchers (`run_dashboard.sh`, `run_production.sh`), preflight tools (`staging_preflight.py`), backup/restore managers, and isolated resilience harnesses. |
| **Build & Packaging** | `pyproject.toml`, `requirements.txt`, `requirements-lock.txt`, `requirements-dev.txt`, `Dockerfile`, `Containerfile`, `Procfile`, `render.yaml`, `Makefile` | Complete pinned dependency specifications and container build manifests. |
| **Configuration Templates** | `.env.example`, `.env.production.example`, `.streamlit/config.toml` | Hardened localhost settings and sanitized environment templates without real secrets. |
| **Documentation & Runbooks** | `docs/**/*.md` | All architectural guides, runbooks (RB-01 to RB-07), and Phase 10–16 reports. |
| **Automated Tests** | `tests/**/*.py` | Full test battery across 35 test suites. |

### Excluded Components (Deterministic Rejection)
| Category | Excluded Patterns / Directories | Rationale |
| :--- | :--- | :--- |
| **Secrets & Keys** | `.env`, `.env.local`, `.env.production`, `*.pem`, `*.key`, `*.pfx`, `*.p12`, `id_rsa`, `id_ed25519`, `credentials.json` | Absolute prevention of credential leakage into archives. |
| **Bytecode & Caches** | `__pycache__`, `*.pyc`, `*.pyo`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache` | Non-reproducible compiled artifacts. |
| **Virtual Environments** | `.venv`, `venv`, `env` | Large environment trees; fully reconstructible via `requirements-lock.txt`. |
| **SCM Internals** | `.git/`, `.github/`, `.gitattributes` | SCM bloat avoided; keeps archives standalone and transportable. |
| **Transient Runtime Files** | `*.sock`, `*.log` (e.g. `dashboard.log`), `*.tmp`, `*.bak`, `*~` | Sockets, active logs, and editor backups. |
| **Existing Backups** | `logs/backups/`, `linuxops_backup_*.tar.gz*` | Avoids recursive backup nesting. |
| **External Mounts** | `/FedoraLinux-44`, `/home/neha/cloudops-sentinel/data`, `/run/podman/podman.sock` | Permanently protected host systems and workloads. |

---

## 3. Backup Architecture & Security Controls

```
                        LINUXOPS REPOSITORY (/home/neha_borse/linuxops)
                                      │
                                      ▼
                        [1. Secret Scanner & Exclusion Audit]
                        ├── Rejects .env, private keys, tokens
                        └── Skips .venv, .git, caches, logs
                                      │
                                      ▼
                        [2. File Hashing & Manifest Generation]
                        ├── Compute SHA-256 for all 105 files
                        └── Assemble structured manifest.json
                                      │
                                      ▼
                        [3. Atomic Archive Assembly (Temp File)]
                        ├── Write .tar.gz with mode 0600
                        ├── Embed manifest.json & SHA256SUMS
                        └── Compute archive-level SHA-256
                                      │
                                      ▼
                        [4. Verification & Atomic Finalization]
                        ├── Write companion .tar.gz.sha256
                        ├── Atomic rename to final archive
                        └── Immediate verify_backup() check
```

### Manifest Schema (`manifest.json`)
The embedded manifest provides a tamper-evident audit record:
```json
{
  "manifest_version": "1.0.0",
  "backup_id": "linuxops_backup_20261025_104219_0885fe",
  "created_at_utc": "2026-10-25T10:42:19.656000+00:00",
  "linuxops_version": "1.0.0",
  "source_root": "/home/neha_borse/linuxops",
  "file_count": 105,
  "total_bytes": 1785392,
  "files": {
    "app/dashboard.py": {
      "sha256": "4b9e28a25c15...",
      "size_bytes": 101080,
      "mode": "0644"
    }
  },
  "secret_scan": {
    "status": "PASSED",
    "scanned_files": 105,
    "violations": []
  },
  "recovery_prerequisites": {
    "python_version": ">=3.10",
    "dependencies_file": "requirements-lock.txt",
    "environment_template": ".env.production.example",
    "recovery_kill_switch_required": "LINUXOPS_RECOVERY_DISABLED=1"
  }
}
```

---

## 4. Isolated Restore Validation Evidence

### Live Verification Executed
A full live backup and isolated restoration was executed on the host runtime:

1. **Backup Creation:**
   ```bash
   python3 scripts/backup_manager.py create --output-dir logs/backups
   ```
   *Result:*
   - **Backup ID:** `linuxops_backup_20261025_104219_0885fe`
   - **Archive:** `logs/backups/linuxops_backup_20261025_104219_0885fe.tar.gz`
   - **Compressed Size:** 382,241 bytes
   - **Uncompressed Size:** 1,785,392 bytes
   - **Files Packaged:** 105
   - **Archive SHA-256:** `04fa802ee8ce1f992e0f9491de4e5ef2da8f75ba013c311d3a26722284614c17`
   - **Companion Checksum:** `logs/backups/linuxops_backup_20261025_104219_0885fe.tar.gz.sha256`
   - **Secret Scan:** PASSED (0 violations detected)
   - **Integrity:** VERIFIED (105/105 files verified against SHA-256 manifest)

2. **Isolated Restoration Test:**
   ```bash
   python3 scripts/restore_manager.py \
     --archive logs/backups/linuxops_backup_20261025_104219_0885fe.tar.gz \
     --target /tmp/isolated_restore_test_run1
   ```
   *Result:*
   - **Restored Location:** `/tmp/isolated_restore_test_run1`
   - **Files Restored:** 105 files
   - **Duration:** 0.076s
   - **Integrity:** All 105 restored files matched their manifest SHA-256 checksums exactly.
   - **Differential Audit:** `diff -u app/dashboard.py /tmp/isolated_restore_test_run1/app/dashboard.py` ➔ **ZERO DIFFS**.

3. **Live System Protection Tests:**
   - Attempting restore into live project root:
     ```bash
     python3 scripts/restore_manager.py --archive ... --target /home/neha_borse/linuxops
     ```
     *Output:* `[SAFETY VIOLATION] Destination rejected: SAFETY BLOCK: Destination '/home/neha_borse/linuxops' is the live project root!`
   - Attempting restore into protected external system:
     ```bash
     python3 scripts/restore_manager.py --archive ... --target /FedoraLinux-44
     ```
     *Output:* `[SAFETY VIOLATION] Destination rejected: SAFETY BLOCK: Destination '/FedoraLinux-44' is a protected system directory!`
   - Attempting restore into non-empty target directory:
     *Output:* `[SAFETY VIOLATION] Destination rejected: SAFETY BLOCK: Destination '...' is NOT empty!`

---

## 5. Automated Regression Test Battery

All 35 test suites were executed in the project virtual environment:

```text
============================= test session starts ==============================
rootdir: /home/neha_borse/linuxops
configfile: pyproject.toml
collected 565 items

565 passed, 9 subtests passed in 27.60s
============================== 565 passed in 27.60s ==============================
```

### Dedicated Disaster Recovery Test Battery ([`tests/test_backup_disaster_recovery.py`](file:///home/neha_borse/linuxops/tests/test_backup_disaster_recovery.py)):
- `test_secret_filename_detection`: PASS
- `test_content_secret_detection`: PASS
- `test_excluded_directories`: PASS
- `test_excluded_transient_files`: PASS
- `test_included_application_files`: PASS
- `test_synthetic_backup_creation_and_manifest`: PASS
- `test_corrupted_checksum_detection`: PASS
- `test_successful_isolated_restore`: PASS
- `test_reject_live_project_root`: PASS
- `test_reject_protected_system_paths`: PASS
- `test_reject_non_empty_target`: PASS
- `test_path_traversal_rejection`: PASS
- `test_atomic_rollback_on_checksum_failure`: PASS
- `test_retention_validation`: PASS
- `test_dry_run_retention_and_pruning`: PASS

---

## 6. Operational Disaster Recovery Runbooks

### Runbook DR-01: Scheduled & Pre-Deployment Backup Creation
Before performing deployments or system modifications, create a timestamped backup snapshot:
```bash
cd /home/neha_borse/linuxops
source .venv/bin/activate

# Create backup in default logs/backups/ store
python3 scripts/backup_manager.py create

# Or export to an external Windows backup store
python3 scripts/backup_manager.py create --output-dir "/mnt/c/Users/Neha Borse/linuxops_backups"
```

### Runbook DR-02: Backup Integrity Verification
Verify that an archive is readable and that all file checksums match:
```bash
python3 scripts/backup_manager.py verify \
  --archive logs/backups/linuxops_backup_<TIMESTAMP>_<HASH>.tar.gz
```

### Runbook DR-03: Isolated Disaster Recovery & Environment Reconstruction
To reconstruct LinuxOps in a clean sandbox or new host:

1. **Restore into Empty Directory:**
   ```bash
   RESTORE_DIR="/home/neha_borse/linuxops_restore_sandbox"
   mkdir -p "${RESTORE_DIR}"
   python3 scripts/restore_manager.py \
     --archive logs/backups/linuxops_backup_<ID>.tar.gz \
     --target "${RESTORE_DIR}"
   ```

2. **Reconstruct Python Virtual Environment:**
   ```bash
   cd "${RESTORE_DIR}"
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --no-cache-dir -r requirements-lock.txt
   ```

3. **Rehydrate Environment Secrets from Template:**
   ```bash
   cp .env.production.example .env
   chmod 0600 .env
   # Edit .env to supply secure credentials and ensure:
   # LINUXOPS_RECOVERY_DISABLED=1
   ```

4. **Execute Preflight Staging Audit:**
   ```bash
   python3 scripts/staging_preflight.py
   ```

5. **Verify Security Invariant:**
   Ensure `LINUXOPS_RECOVERY_DISABLED=1` is active before starting any background daemons.

### Runbook DR-04: Emergency Deployment Rollback
If a newly deployed version exhibits regressions:
1. Stop current dashboard:
   ```bash
   systemctl --user stop linuxops-dashboard.service
   ```
2. Restore verified previous backup into a fresh target path:
   ```bash
   mkdir -p /home/neha_borse/linuxops_rollback
   python3 scripts/restore_manager.py \
     --archive logs/backups/linuxops_backup_<PREVIOUS_ID>.tar.gz \
     --target /home/neha_borse/linuxops_rollback
   ```
3. Update systemd service unit working directory or copy validated files into place following change authorization.
4. Restart service and verify health endpoint:
   ```bash
   systemctl --user start linuxops-dashboard.service
   curl -sI http://127.0.0.1:8501/_stcore/health
   ```

### Runbook DR-05: Backup Retention Policy
Prune old backups without risking accidental deletion:
```bash
# 1. Simulate pruning (dry-run mode)
python3 scripts/backup_manager.py prune --max-backups 5

# 2. Execute pruning after reviewing candidate list
python3 scripts/backup_manager.py prune --max-backups 5 --confirm
```

---

## 7. Operational Boundaries & Recovery Limitations

1. **Windows Host Integration Boundary:**
   `Start-LinuxOps.bat` (in `%APPDATA%\...\Startup`), `watchdog.ps1`, and Windows Scheduled Task `\LinuxOps-Watchdog` run in the Windows host context. These files are documented in templates and operational runbooks, but automated WSL restore scripts do not overwrite Windows host configuration without explicit operator authorization.
2. **Container Recovery Kill Switch:**
   `LINUXOPS_RECOVERY_DISABLED=1` remains mandatory. No backup or restore procedure modifies this setting or accesses the Podman socket.
3. **Physical Host Power Cycle Limitation:**
   As certified in Phase 15, physical Windows restart and sleep/resume testing cannot be automated from within WSL2 and require operator action per the checklist in [`docs/PHASE15_OPERATIONAL_ACCEPTANCE_REPORT.md`](file:///home/neha_borse/linuxops/docs/PHASE15_OPERATIONAL_ACCEPTANCE_REPORT.md).

---

## 8. Final Phase 16 Release Decision

### **PASS WITH LIMITATIONS**

**Certification Summary:**
- **Backup Idempotence & Security:** Certified. Zero secrets packed, SHA-256 manifests intact, companion checksums generated.
- **Isolated Restoration:** Certified. Successfully restored into temporary sandbox with zero file differences and atomic rollback protection.
- **Safety Boundaries:** Certified. Destination checks block live project root and protected systems (`FedoraLinux-44`, `/home/neha/cloudops-sentinel/data`).
- **Regression Suite:** Certified. 565/565 tests passing.
- **Limitation Basis:** The formal release verdict remains preserved as **PASS WITH LIMITATIONS** pending physical hardware power-cycle verification by the operator.
