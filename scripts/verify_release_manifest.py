#!/usr/bin/env python3

"""
LinuxOps Release Manifest Checksum Recomputation & Verification Tool (Phase 18).

Recomputes SHA-256 checksums from live files and compares against the recorded
hashes in docs/release_candidate_manifest.json to guarantee zero tampering or drift.
"""

import hashlib
import json
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def sha256_file(path: Path) -> str:
    if not path.is_file():
        return "MISSING"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main():
    manifest_path = PROJECT_ROOT / "docs" / "release_candidate_manifest.json"
    if not manifest_path.is_file():
        print(f"ERROR: Manifest not found at {manifest_path}")
        return 1

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    mismatches = []
    print("=" * 80)
    print("LINUXOPS RELEASE MANIFEST SHA-256 RECOMPUTATION AUDIT")
    print("=" * 80)

    # 1. Dependency Manifests
    print("\n--- 1. DEPENDENCY MANIFEST HASHES ---")
    for fname, expected in manifest.get("dependency_manifest_hashes", {}).items():
        actual = sha256_file(PROJECT_ROOT / fname)
        match = (actual.lower() == expected.lower())
        status = "✅ MATCH" if match else "❌ MISMATCH"
        print(f"{status}  {fname}")
        print(f"     Expected: {expected}")
        print(f"     Actual:   {actual}")
        if not match:
            mismatches.append(("dependency", fname, expected, actual))

    # 2. Configuration Files
    print("\n--- 2. NON-SECRET CONFIGURATION HASHES ---")
    for fname, expected in manifest.get("configuration_hashes", {}).items():
        actual = sha256_file(PROJECT_ROOT / fname)
        match = (actual.lower() == expected.lower())
        status = "✅ MATCH" if match else "❌ MISMATCH"
        print(f"{status}  {fname}")
        print(f"     Expected: {expected}")
        print(f"     Actual:   {actual}")
        if not match:
            mismatches.append(("config", fname, expected, actual))

    # 3. Systemd Units
    print("\n--- 3. SYSTEMD USER UNIT DEFINITION HASHES ---")
    user_systemd = Path.home() / ".config" / "systemd" / "user"
    for fname, expected in manifest.get("systemd_unit_hashes", {}).items():
        actual = sha256_file(user_systemd / fname)
        match = (actual.lower() == expected.lower())
        status = "✅ MATCH" if match else "❌ MISMATCH"
        print(f"{status}  {fname}")
        print(f"     Expected: {expected}")
        print(f"     Actual:   {actual}")
        if not match:
            mismatches.append(("systemd", fname, expected, actual))

    # 4. Backup Archives
    print("\n--- 4. BACKUP ARCHIVE HASHES ---")
    backups = manifest.get("backup_verification", {})

    p16_meta = backups.get("phase16_baseline_backup", {})
    p16_path = Path(p16_meta.get("archive_path", ""))
    p16_exp = p16_meta.get("sha256", "")
    p16_act = sha256_file(p16_path)
    p16_match = (p16_act.lower() == p16_exp.lower())
    print(f"{'✅ MATCH' if p16_match else '❌ MISMATCH'}  Phase 16 Baseline ({p16_path.name})")
    print(f"     Expected: {p16_exp}")
    print(f"     Actual:   {p16_act}")
    if not p16_match:
        mismatches.append(("backup_p16", str(p16_path), p16_exp, p16_act))

    p17_meta = backups.get("phase17_release_candidate_backup", {})
    p17_path = Path(p17_meta.get("archive_path", ""))
    p17_exp = p17_meta.get("sha256", "")
    p17_act = sha256_file(p17_path)
    p17_match = (p17_act.lower() == p17_exp.lower())
    print(f"{'✅ MATCH' if p17_match else '❌ MISMATCH'}  Phase 17 Release Candidate ({p17_path.name})")
    print(f"     Expected: {p17_exp}")
    print(f"     Actual:   {p17_act}")
    if not p17_match:
        mismatches.append(("backup_p17", str(p17_path), p17_exp, p17_act))

    print("\n" + "=" * 80)
    print(f"AUDIT SUMMARY: {len(mismatches)} MISMATCHES DETECTED")
    print("=" * 80)

    if mismatches:
        for cat, name, exp, act in mismatches:
            print(f"❌ {cat.upper()}: {name}")
            print(f"   Expected: {exp}")
            print(f"   Actual:   {act}")
        return 1

    print("✅ ALL RECORDED DESCRIPTORS MATCH THE ACTIVE FILESYSTEM EXACTLY.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
