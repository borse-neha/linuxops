#!/usr/bin/env python3

"""
LinuxOps Dedicated Disaster Recovery & Isolated Restore Validator (Phase 16).

Provides an operator tool for validating and executing disaster recovery into
strictly isolated sandbox environments without risking live services.

Key Safety Guarantees:
- Rejects any restore into the live project root or any protected system path.
- Enforces that the target restore directory must be completely empty.
- Performs full pre-extraction integrity verification against embedded SHA-256 manifests.
- Scans all archive paths for directory-traversal attempts ('..', absolute paths, dangerous symlinks).
- Decompression bomb safeguards (max bytes and max file count limits).
- Atomic rollback: clears any partial extraction if an integrity failure occurs.

Usage:
  python3 scripts/restore_manager.py --archive /path/to/backup.tar.gz --target /path/to/empty_sandbox
  python3 scripts/restore_manager.py --archive /path/to/backup.tar.gz --verify-only
"""

import argparse
import json
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.backup import (
    BackupManager,
    DestinationSecurityError,
    IntegrityVerificationError,
    PathTraversalError,
    RestoreError,
    RestoreManager,
)


def print_json(data: dict) -> None:
    print(json.dumps(data, indent=2, default=str))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="LinuxOps Disaster Recovery & Isolated Restore Validator (Phase 16)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--archive", required=True, help="Path to .tar.gz backup archive")
    parser.add_argument("--target", help="Isolated target directory (MUST be empty; cannot be live project)")
    parser.add_argument("--verify-only", action="store_true", help="Perform integrity check without extracting")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument("--max-bytes-mb", type=int, default=500, help="Maximum allowed extraction size in MB (default: 500)")
    parser.add_argument("--max-files", type=int, default=10000, help="Maximum allowed extraction file count (default: 10000)")

    args = parser.parse_args()
    archive_path = Path(args.archive).resolve()

    if not archive_path.is_file():
        sys.stderr.write(f"[ERROR] Backup archive does not exist: {archive_path}\n")
        return 1

    bm = BackupManager(source_dir=PROJECT_ROOT)

    # 1. Verification phase
    verify_res = bm.verify_backup(archive_path)
    if not verify_res.valid:
        if args.json:
            print_json({"verification": verify_res.to_dict(), "restored": False})
        else:
            sys.stderr.write(f"[INTEGRITY ERROR] Archive verification failed:\n")
            for err in verify_res.errors:
                sys.stderr.write(f"  - {err}\n")
        return 1

    if args.verify_only:
        if args.json:
            print_json({"verification": verify_res.to_dict(), "status": "VERIFIED_OK"})
        else:
            print("================================================================================")
            print("LINUXOPS BACKUP ARCHIVE VERIFICATION (PREFLIGHT OK)")
            print("================================================================================")
            print(f"Archive:       {verify_res.archive_path}")
            print(f"Backup ID:     {verify_res.backup_id}")
            print(f"Total Files:   {verify_res.total_files} (all checksums verified)")
            print(f"Total Size:    {verify_res.total_bytes:,} bytes")
            print("Integrity:     ✅ PASSED")
            print("================================================================================")
        return 0

    if not args.target:
        sys.stderr.write("[ERROR] --target directory is required unless --verify-only is specified.\n")
        return 1

    target_dir = Path(args.target).resolve()
    rm = RestoreManager(project_root=PROJECT_ROOT)

    try:
        max_bytes = args.max_bytes_mb * 1024 * 1024
        result = rm.restore_backup(
            archive_path=archive_path,
            target_dir=target_dir,
            verify_first=False,  # Already verified above
            max_bytes=max_bytes,
            max_files=args.max_files,
        )

        if args.json:
            print_json(result.to_dict())
        else:
            print("================================================================================")
            print("LINUXOPS ISOLATED DISASTER RECOVERY RESTORATION COMPLETE")
            print("================================================================================")
            print(f"Backup ID:         {result.backup_id}")
            print(f"Source Archive:    {result.archive_path}")
            print(f"Restored Location: {result.target_dir}")
            print(f"Files Restored:    {result.restored_files}")
            print(f"Total Size:        {result.total_bytes:,} bytes")
            print(f"Duration:          {result.duration_seconds}s")
            print("Safety Status:     ISOLATION VERIFIED (Target was empty, live system unaffected)")
            print("Checksum Status:   ALL RESTORED FILES VERIFIED AGAINST SHA-256 MANIFEST")
            print("================================================================================")
        return 0

    except DestinationSecurityError as e:
        sys.stderr.write(f"[SAFETY VIOLATION] Destination rejected: {e}\n")
        return 2
    except PathTraversalError as e:
        sys.stderr.write(f"[SECURITY VIOLATION] Unsafe paths in archive: {e}\n")
        return 2
    except IntegrityVerificationError as e:
        sys.stderr.write(f"[INTEGRITY ERROR] Checksum mismatch during restoration: {e}\n")
        return 1
    except RestoreError as e:
        sys.stderr.write(f"[RESTORE ERROR] {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
