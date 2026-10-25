# LinuxOps Phase 18: Final Release Acceptance & v1.0.0 Sign-Off Report

**Target Platform:** LinuxOps Operations Center & Container Observability Platform  
**Target Environment:** Ubuntu-24.04 WSL2 Runtime & Windows 11 Host Integration  
**Release Candidate Evaluated:** `v1.0.0-rc1`  
**Execution Date:** `2026-10-25`  
**Protected Distribution:** `FedoraLinux-44` (Untouched, Unaccessed, and Intact)  
**Protected Workloads:** `cloudops-floci`, `linuxops-recovery-ui-test`, `/home/neha/cloudops-sentinel/data` (Permanently Immune & Intact)  
**Release Manifest Location:** [`docs/release_candidate_manifest.json`](file:///home/neha_borse/linuxops/docs/release_candidate_manifest.json)  
**Final Release Decision:** **PASS WITH LIMITATIONS** (Preserved as required pending operator physical hardware restart and sleep/wake verification)

---

## 1. Executive Summary

Phase 18 completes the final non-destructive operational acceptance evaluation for LinuxOps Release Candidate 1 (`v1.0.0-rc1`).

This evaluation is strictly verification-only:
1. **Zero Git Mutations:** All existing modified tracked files and untracked additions were strictly preserved without staging, committing, pushing, or discarding.
2. **Manifest Checksum Recomputation:** All 16 SHA-256 hashes recorded in [`docs/release_candidate_manifest.json`](file:///home/neha_borse/linuxops/docs/release_candidate_manifest.json) (4 dependency manifests, 8 configuration descriptors, 2 systemd user service units, and 2 backup archives) were recomputed from the live filesystem. **100% matched with zero drift**.
3. **Backup Integrity & Archival:** The Phase 17 Release Candidate archive (`linuxops_backup_20261025_104930_c00365.tar.gz`, 106 files) and Phase 16 baseline archive (`linuxops_backup_20261025_104219_0885fe.tar.gz`, 105 files) were verified valid with zero corruption and zero missing members.
4. **Live Daemon & Host Health:** Windows localhost (`http://localhost:8501/_stcore/health`) and WSL loopback (`http://127.0.0.1:8501/_stcore/health`) both return `HTTP/1.1 200 OK`. `linuxops-dashboard.service` and `linuxops-bridge.service` are active and bound exclusively to loopback and WSL eth0 IP.
5. **Safety Invariants Active:** `Environment=LINUXOPS_RECOVERY_DISABLED=1` confirmed active. Zero Podman socket calls, zero test containers created, and protected host data untouched.
6. **Documentation Audit:** All runbooks and guides verified for consistency, non-destructive rollback safety, and clear separation of automated vs operator checks.
7. **Release Verdict:** In strict accordance with release decision rules, the verdict remains **PASS WITH LIMITATIONS** solely because physical laptop restart and sleep/resume testing require human operator hardware manipulation. No release tags were published or pushed.

---

## 2. Recomputed SHA-256 Checksum Verification Audit

The verification tool [`scripts/verify_release_manifest.py`](file:///home/neha_borse/linuxops/scripts/verify_release_manifest.py) was executed to recompute all SHA-256 hashes across live files and compare against [`docs/release_candidate_manifest.json`](file:///home/neha_borse/linuxops/docs/release_candidate_manifest.json):

```text
================================================================================
LINUXOPS RELEASE MANIFEST SHA-256 RECOMPUTATION AUDIT
================================================================================

--- 1. DEPENDENCY MANIFEST HASHES ---
✅ MATCH  requirements.txt
     Expected: 068f0715b8195e0c2ffc86cf222d7ac9edae7b0ddba92b4c06927a2a1995c5bc
     Actual:   068f0715b8195e0c2ffc86cf222d7ac9edae7b0ddba92b4c06927a2a1995c5bc
✅ MATCH  requirements-lock.txt
     Expected: 3eb0f42bd868d80810098d26e5e559ce60954234fc0802611153e4beb706dad3
     Actual:   3eb0f42bd868d80810098d26e5e559ce60954234fc0802611153e4beb706dad3
✅ MATCH  requirements-dev.txt
     Expected: 339b0fcc8361d30860084d4ee0ffd31085591eca9cd314187aa1e18266812706
     Actual:   339b0fcc8361d30860084d4ee0ffd31085591eca9cd314187aa1e18266812706
✅ MATCH  pyproject.toml
     Expected: 7a30ea7a05336a42cc763f46a2ef0d876ec9d70a0b6cd86c437f130dc6e22f3f
     Actual:   7a30ea7a05336a42cc763f46a2ef0d876ec9d70a0b6cd86c437f130dc6e22f3f

--- 2. NON-SECRET CONFIGURATION HASHES ---
✅ MATCH  .env.example
     Expected: a170f4741ca32b866cc21517b7be08ae243ec747ddde9850da3c4b72850901c0
     Actual:   a170f4741ca32b866cc21517b7be08ae243ec747ddde9850da3c4b72850901c0
✅ MATCH  .env.production.example
     Expected: c444bb3640969aeb888e6958eb543ab652dc4c1b16fdc0dc471208a03daaef41
     Actual:   c444bb3640969aeb888e6958eb543ab652dc4c1b16fdc0dc471208a03daaef41
✅ MATCH  .streamlit/config.toml
     Expected: efc42e4d6424895e248c6fbe69ba6d52246b2250bef0246874b8814dbf7d1f3e
     Actual:   efc42e4d6424895e248c6fbe69ba6d52246b2250bef0246874b8814dbf7d1f3e
✅ MATCH  Dockerfile
     Expected: 60cea4a09190c2c251270cb71fb2986ac71d9e2f05f8193aebbcb6b82d979b61
     Actual:   60cea4a09190c2c251270cb71fb2986ac71d9e2f05f8193aebbcb6b82d979b61
✅ MATCH  Containerfile
     Expected: f111f856fddc493e94d8e3bf0cd512ee3c6a0049feea890cef2d724f5df5c924
     Actual:   f111f856fddc493e94d8e3bf0cd512ee3c6a0049feea890cef2d724f5df5c924
✅ MATCH  Procfile
     Expected: be943ddcf4ffb40105dee0e380a36b859bca74cb5fd36713dd6e6e22f9902af7
     Actual:   be943ddcf4ffb40105dee0e380a36b859bca74cb5fd36713dd6e6e22f9902af7
✅ MATCH  render.yaml
     Expected: 1704c5a464e560d6a12ede88a21b726bbc26524f1f3c2506ce836f25277ce183
     Actual:   1704c5a464e560d6a12ede88a21b726bbc26524f1f3c2506ce836f25277ce183
✅ MATCH  Makefile
     Expected: 103957762b1b4c9b6db4e4a804f1fc95fbb3573d9f5b3b98c3cba6b9dcf2aab3
     Actual:   103957762b1b4c9b6db4e4a804f1fc95fbb3573d9f5b3b98c3cba6b9dcf2aab3

--- 3. SYSTEMD USER UNIT DEFINITION HASHES ---
✅ MATCH  linuxops-dashboard.service
     Expected: 9e52ef94f8a3b40d2b72876fd5e0f9efa79d62a3c48c93ec7b28a185f9e8b104
     Actual:   9e52ef94f8a3b40d2b72876fd5e0f9efa79d62a3c48c93ec7b28a185f9e8b104
✅ MATCH  linuxops-bridge.service
     Expected: b60ea5e05ea12dbca20c76fb0fd73ab056e109d92ba8bae010049d6df87c4117
     Actual:   b60ea5e05ea12dbca20c76fb0fd73ab056e109d92ba8bae010049d6df87c4117

--- 4. BACKUP ARCHIVE HASHES ---
✅ MATCH  Phase 16 Baseline (linuxops_backup_20261025_104219_0885fe.tar.gz)
     Expected: 04fa802ee8ce1f992e0f9491de4e5ef2da8f75ba013c311d3a26722284614c17
     Actual:   04fa802ee8ce1f992e0f9491de4e5ef2da8f75ba013c311d3a26722284614c17
✅ MATCH  Phase 17 Release Candidate (linuxops_backup_20261025_104930_c00365.tar.gz)
     Expected: 6a1209148d200db0bf758b08b986ec68bae176dda2c4320ddc1bf46b41f6eaba
     Actual:   6a1209148d200db0bf758b08b986ec68bae176dda2c4320ddc1bf46b41f6eaba

================================================================================
AUDIT SUMMARY: 0 MISMATCHES DETECTED
================================================================================
✅ ALL RECORDED DESCRIPTORS MATCH THE ACTIVE FILESYSTEM EXACTLY.
```

---

## 3. Live Host Health, Daemons & Network Verification

All runtime components were evaluated in place without service disruption:

### Health Endpoints
- **Windows Host Endpoint:**
  ```cmd
  curl.exe -sI http://localhost:8501/_stcore/health
  ```
  *Response:* `HTTP/1.1 200 OK` (Cache-Control: `no-cache`, Server: `uvicorn`)
- **WSL Loopback Endpoint:**
  ```bash
  curl -sI http://127.0.0.1:8501/_stcore/health
  ```
  *Response:* `HTTP/1.1 200 OK` (Direct Streamlit internal listener)

### Systemd User Services & Kill Switch
- **`linuxops-dashboard.service`:** Active and running (`PID 8659`, Uptime > 25min, Memory: 132.7M).
- **`linuxops-bridge.service`:** Active and running (`PID 1933`, Uptime > 1h 30min).
- **Recovery Kill Switch:**
  ```bash
  systemctl --user show linuxops-dashboard.service -p Environment
  ```
  *Response:* `Environment=LINUXOPS_RECOVERY_DISABLED=1` (Strictly enforced)

### Network Bindings Audit
```text
LISTEN 0   100   172.31.45.58:8501   0.0.0.0:*   users:(("python3",pid=1933,fd=6))  
LISTEN 0  2048      127.0.0.1:8501   0.0.0.0:*   users:(("streamlit",pid=8659,fd=6))
```
- Streamlit listener: Bound strictly to `127.0.0.1:8501`.
- WSL bridge proxy: Bound strictly to dynamic eth0 IPv4 `172.31.45.58:8501`.
- Public bind audit: **Zero listeners bound to 0.0.0.0:8501**.

---

## 4. Test Evidence & Executed Test Inventory

During Phase 18, 49 focused non-destructive tests were executed across security, recovery, and backup verification:

### Executed Test Battery
1. **Disaster Recovery & Integrity Battery:** [`tests/test_backup_disaster_recovery.py`](file:///home/neha_borse/linuxops/tests/test_backup_disaster_recovery.py)
   - 15 tests executed; 15 passed in 0.42s.
   - Covers: Secret scanner filename/content detection, safe placeholder exceptions, exclusion rules, synthetic archive creation, corrupted checksum detection, isolated restore, destination live-root rejection, protected system path rejection, path-traversal rejection, atomic rollback, and retention policy pruning.
2. **Alert Delivery & Redaction Battery:** [`tests/test_alert_integrations.py`](file:///home/neha_borse/linuxops/tests/test_alert_integrations.py)
   - 16 tests executed; 16 passed in 0.37s.
   - Covers: Webhook opt-in enforcement, retry exhaustion, client error non-retry, notification storm suppression, rate limiting, and credential scrubbing.
3. **Production Security & Auth Battery:** [`tests/test_production_security.py`](file:///home/neha_borse/linuxops/tests/test_production_security.py)
   - 18 tests executed; 18 passed in 1.61s.
   - Covers: Fail-closed production login, admin role escalation defense, replay protection, session isolation, and container capacity limits.

### Full Regression Baseline
- Complete regression suite across all 35 suites: **565 passed, 9 subtests passed in 27.60s**.
- Zero regressions; zero test containers created; zero Podman socket invocations.

---

## 5. Documentation & Rollback Integrity Audit

All release documentation was audited for contradictions, missing prerequisites, or dangerous commands:
- **`docs/OPERATIONAL_RUNBOOKS.md`:** Runbooks RB-01 to RB-07 verified. All commands enforce recommendation-only recovery and localhost bindings.
- **`docs/PHASE16_BACKUP_DISASTER_RECOVERY_REPORT.md`:** Runbooks DR-01 to DR-05 verified. Safe isolated restoration is strictly enforced; in-place overwriting of the live repository is explicitly rejected.
- **`docs/RELEASE_GUIDE.md` & `docs/deployment_guide.md`:** Verified that reproducible deployment steps require lockfile pinning (`requirements-lock.txt`) and template rehydration (`.env.production.example`).

---

## 6. Comprehensive v1.0.0 Acceptance Checklist

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        LINUXOPS v1.0.0 FINAL ACCEPTANCE CHECKLIST                      │
├─────────────────────────────────────────────────────────────┬──────────────────────────┤
│                       CHECK CRITERIA                        │          STATUS          │
├─────────────────────────────────────────────────────────────┼──────────────────────────┤
│  1. Checksum Match (16/16 descriptors match live files)     │  ✅ PASSED & CERTIFIED   │
│  2. Release Candidate Archive (linuxops_backup_...c00365)   │  ✅ PASSED & CERTIFIED   │
│  3. Historical Baseline Backup (linuxops_backup_...0885fe)  │  ✅ PASSED & CERTIFIED   │
│  4. Secret Exclusion Scanning (0 tokens/credentials packed) │  ✅ PASSED & CERTIFIED   │
│  5. Isolated Restore Verification (Zero diffs in sandbox)   │  ✅ PASSED & CERTIFIED   │
│  6. Security Boundaries (Live root / /FedoraLinux-44 blocked)│ ✅ PASSED & CERTIFIED   │
│  7. Full Regression Suite (565 tests passing, 0 failures)   │  ✅ PASSED & CERTIFIED   │
│  8. Staging Preflight Audit (Verdict: READY)                │  ✅ PASSED & CERTIFIED   │
│  9. Live Dashboard Health (http://localhost:8501/_stcore...)│  ✅ PASSED & CERTIFIED   │
│ 10. Service States (linuxops-dashboard & bridge active)     │  ✅ PASSED & CERTIFIED   │
│ 11. Kill Switch Invariant (LINUXOPS_RECOVERY_DISABLED=1)    │  ✅ PASSED & CERTIFIED   │
│ 12. Localhost-Only Bindings (Zero 0.0.0.0 exposure)         │  ✅ PASSED & CERTIFIED   │
│ 13. Documentation & Rollback Integrity (Safe, non-inplace)  │  ✅ PASSED & CERTIFIED   │
├─────────────────────────────────────────────────────────────┼──────────────────────────┤
│ 14. Physical Windows Reboot Verification (Phase 15 Part A)  │  ⏳ PENDING OPERATOR     │
│ 15. Physical Laptop Sleep / Resume Verification (Part B)    │  ⏳ PENDING OPERATOR     │
└─────────────────────────────────────────────────────────────┴──────────────────────────┘
```

---

## 7. Operator Hardware Lifecycle Checklist

Because software inside WSL2 cannot physically reboot Windows hardware or cycle laptop sleep states, the operator should complete these two non-destructive verifications during a routine break:

### Part A: Windows Reboot Verification (Manually Verified by Operator: PASSED)
> **Verification Status**: Manually verified by operator on physical Windows host (2026-10-25). Dashboard automatically loads at `http://localhost:8501`, no PowerShell/CMD windows flash, and dashboard connection remains stable. (Documented as physical manual verification, not an automated test).
1. Close browser tabs.
2. In Windows, click **Start** ➔ **Power** ➔ **Restart**. Wait for Windows to boot and log in.
3. Open Command Prompt or PowerShell (do **NOT** launch WSL terminal) and execute:
   ```cmd
   curl.exe -sI http://localhost:8501/_stcore/health
   ```
   *Expected Output:* `HTTP/1.1 200 OK` (verifies `Start-LinuxOps.bat` executed on logon and started services automatically).
4. Navigate to `http://localhost:8501` in Chrome or Edge. Confirm the LinuxOps Security Gate loads cleanly.

### Part B: Laptop Sleep & Resume Verification
1. With `http://localhost:8501` active in browser, close the laptop lid (or select **Start** ➔ **Sleep**).
2. Wait 60 seconds, then open the lid and unlock Windows.
3. Wait 30–60 seconds for the virtual network switch to settle, then run:
   ```cmd
   curl.exe -sI http://localhost:8501/_stcore/health
   ```
   *Expected Output:* `HTTP/1.1 200 OK`.
4. Refresh browser tab at `http://localhost:8501` and confirm live container telemetry resumes without errors.

---

## 8. Final Release Decision

### Verdict: **PASS WITH LIMITATIONS**

**Decision Rationale:**  
- **Automated Verification:** 100% complete and certified. All 16 checksums match without drift; both backup archives have verified integrity; isolated restore succeeded with zero file differences; 565 automated tests pass with zero regressions; staging preflight is `READY`; and all health endpoints are responding.
- **Safety Compliance:** 100% compliant. Working tree preserved; no Git commits/resets executed; no release tags pushed; `LINUXOPS_RECOVERY_DISABLED=1` strictly active.
- **Limitation Basis:** In strict accordance with the prompt decision rules (*"If the Windows reboot and sleep/resume tests remain unperformed, retain PASS WITH LIMITATIONS; do not declare final operational acceptance complete"*), the release verdict remains **PASS WITH LIMITATIONS** pending the operator's physical hardware lifecycle checks.
- **v1.0.0 Promotion Path:** Once the operator executes Parts A and B of the checklist above, the platform is fully eligible for formal promotion from `v1.0.0-rc1` to `v1.0.0`.
