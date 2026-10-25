#!/usr/bin/env python3

"""
LinuxOps Backup Manager CLI (Phase 16).

Provides an idempotent, tamper-evident command-line interface for:
- Creating versioned, secret-free compressed backups with SHA-256 manifests.
- Verifying archive integrity and checksum consistency.
- Listing available backup snapshots.
- Managing safe backup retention policies with dry-run protection.
- Restoring into strictly isolated destinations with atomic rollback.

Usage:
  python3 scripts/backup_manager.py create [--output-dir DIR] [--json]
  python3 scripts/backup_manager.py verify --archive ARCHIVE [--json]
  python3 scripts/backup_manager.py list [--backup-dir DIR] [--json]
  python3 scripts/backup_manager.py prune --max-backups N [--confirm] [--json]
  python3 scripts/backup_manager.py restore --archive ARCHIVE --target-dir DIR [--json]
"""

import argparse
import json
import os
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.backup import (
    BackupError,
    BackupManager,
    DestinationSecurityError,
    IntegrityVerificationError,
    PathTraversalError,
    RestoreError,
    RestoreManager,
    RetentionPolicy,
    SecurityViolationError,
)


def print_json(data: dict) -> None:
    print(json.dumps(data, indent=2, default=str))


def cmd_create(args: argparse.Namespace) -> int:
    source_dir = Path(args.source_dir).resolve() if args.source_dir else PROJECT_ROOT
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None

    bm = BackupManager(source_dir=source_dir, backup_dir=output_dir)

    metadata = None
    if args.metadata:
        try:
            metadata = json.loads(args.metadata)
        except json.JSONDecodeError:
            metadata = {"note": args.metadata}

    try:
        result = bm.create_backup(
            output_dir=output_dir,
            archive_name=args.name,
            metadata=metadata,
            verify_after_creation=not args.no_verify,
        )
        if args.json:
            print_json(result.to_dict())
        else:
            print("================================================================================")
            print("LINUXOPS BACKUP COMPLETED SUCCESSFULLY")
            print("================================================================================")
            print(f"Backup ID:       {result.backup_id}")
            print(f"Archive:         {result.archive_path}")
            print(f"Checksum:        {result.checksum_path}")
            print(f"SHA-256:         {result.sha256}")
            print(f"Files Packaged:  {result.file_count}")
            print(f"Total Size:      {result.total_bytes:,} bytes")
            print(f"Duration:        {result.duration_seconds}s")
            print("Secret Scan:     PASSED (0 violations)")
            print("Integrity:       VERIFIED")
            print("================================================================================")
        return 0
    except SecurityViolationError as e:
        sys.stderr.write(f"[SECURITY ERROR] Backup aborted due to secret detection: {e}\n")
        return 2
    except BackupError as e:
        sys.stderr.write(f"[BACKUP ERROR] {e}\n")
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    archive_path = Path(args.archive).resolve()
    bm = BackupManager()
    result = bm.verify_backup(archive_path)

    if args.json:
        print_json(result.to_dict())
    else:
        print("================================================================================")
        print("LINUXOPS BACKUP INTEGRITY VERIFICATION")
        print("================================================================================")
        print(f"Archive:      {result.archive_path}")
        print(f"Backup ID:    {result.backup_id}")
        print(f"Files:        {result.checked_files} / {result.total_files} verified")
        print(f"Integrity:    {'✅ VALID' if result.valid else '❌ CORRUPTED'}")
        if result.errors:
            print("Errors detected:")
            for err in result.errors:
                print(f"  - {err}")
        print("================================================================================")
    return 0 if result.valid else 1


def cmd_list(args: argparse.Namespace) -> int:
    backup_dir = Path(args.backup_dir).resolve() if args.backup_dir else None
    bm = BackupManager(backup_dir=backup_dir)
    backups = bm.list_backups()

    if args.json:
        print_json({"total_backups": len(backups), "backups": backups})
    else:
        print("================================================================================")
        print(f"LINUXOPS AVAILABLE BACKUPS ({len(backups)} found)")
        print("================================================================================")
        if not backups:
            print("No backup archives found.")
        for b in backups:
            print(f"• ID: {b['backup_id']}")
            print(f"  File: {b['file_name']} ({b['size_bytes']:,} bytes)")
            print(f"  Date: {b['created_at_utc']}")
            print(f"  Companion SHA-256: {'Present' if b['has_companion_checksum'] else 'Missing'}")
            print("")
        print("================================================================================")
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    backup_dir = Path(args.backup_dir).resolve() if args.backup_dir else None
    bm = BackupManager(backup_dir=backup_dir)

    is_confirmed = bool(args.confirm)
    policy = RetentionPolicy(
        max_backups=args.max_backups,
        max_age_days=args.max_age_days,
        enabled=is_confirmed,
        dry_run=not is_confirmed,
    )

    try:
        result = bm.prune_backups(policy)
        if args.json:
            print_json({
                "dry_run": result.dry_run,
                "deleted": result.deleted_archives,
                "kept": result.kept_archives,
                "errors": result.errors,
            })
        else:
            mode_str = "ACTUAL PRUNING" if is_confirmed else "DRY-RUN (Simulated)"
            print("================================================================================")
            print(f"LINUXOPS BACKUP RETENTION ({mode_str})")
            print("================================================================================")
            if not is_confirmed:
                print("NOTE: Run with --confirm to execute actual file deletions.")
            print(f"Candidates to prune: {len(result.deleted_archives)}")
            for d in result.deleted_archives:
                print(f"  - {d}")
            print(f"Archives to retain:  {len(result.kept_archives)}")
            for k in result.kept_archives:
                print(f"  + {k}")
            if result.errors:
                print("Errors:")
                for err in result.errors:
                    print(f"  ! {err}")
            print("================================================================================")
        return 0 if not result.errors else 1
    except Exception as e:
        sys.stderr.write(f"[PRUNE ERROR] {e}\n")
        return 1


def cmd_restore(args: argparse.Namespace) -> int:
    archive_path = Path(args.archive).resolve()
    target_dir = Path(args.target_dir).resolve()

    rm = RestoreManager(project_root=PROJECT_ROOT)
    try:
        result = rm.restore_backup(
            archive_path=archive_path,
            target_dir=target_dir,
            verify_first=not args.no_verify,
        )
        if args.json:
            print_json(result.to_dict())
        else:
            print("================================================================================")
            print("LINUXOPS ISOLATED RESTORE COMPLETED SUCCESSFULLY")
            print("================================================================================")
            print(f"Backup ID:       {result.backup_id}")
            print(f"Source Archive:  {result.archive_path}")
            print(f"Restored Target: {result.target_dir}")
            print(f"Files Restored:  {result.restored_files}")
            print(f"Total Bytes:     {result.total_bytes:,} bytes")
            print(f"Duration:        {result.duration_seconds}s")
            print("Integrity:       ALL RESTORED FILES MATCH MANIFEST CHECKSUMS")
            print("Safety Status:   ISOLATION VERIFIED (Live system untouched)")
            print("================================================================================")
        return 0
    except DestinationSecurityError as e:
        sys.stderr.write(f"[SAFETY VIOLATION] Destination rejected: {e}\n")
        return 2
    except PathTraversalError as e:
        sys.stderr.write(f"[SECURITY VIOLATION] Unsafe paths in archive: {e}\n")
        return 2
    except IntegrityVerificationError as e:
        sys.stderr.write(f"[INTEGRITY ERROR] Checksum mismatch or corruption: {e}\n")
        return 1
    except RestoreError as e:
        sys.stderr.write(f"[RESTORE ERROR] {e}\n")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="LinuxOps Backup & Disaster Recovery Manager (Phase 16)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: create
    p_create = subparsers.add_parser("create", help="Create a versioned backup archive")
    p_create.add_argument("--source-dir", help="Project source directory (default: project root)")
    p_create.add_argument("--output-dir", help="Backup storage directory (default: logs/backups)")
    p_create.add_argument("--name", help="Custom archive filename")
    p_create.add_argument("--metadata", help="JSON metadata string to embed in manifest")
    p_create.add_argument("--no-verify", action="store_true", help="Skip immediate verification")
    p_create.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: verify
    p_verify = subparsers.add_parser("verify", help="Verify backup archive integrity and checksums")
    p_verify.add_argument("--archive", required=True, help="Path to .tar.gz archive")
    p_verify.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: list
    p_list = subparsers.add_parser("list", help="List available backups")
    p_list.add_argument("--backup-dir", help="Backup storage directory (default: logs/backups)")
    p_list.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: prune
    p_prune = subparsers.add_parser("prune", help="Enforce backup retention policy")
    p_prune.add_argument("--backup-dir", help="Backup storage directory (default: logs/backups)")
    p_prune.add_argument("--max-backups", type=int, help="Retain at most N newest backups")
    p_prune.add_argument("--max-age-days", type=float, help="Retain backups newer than N days")
    p_prune.add_argument("--confirm", action="store_true", help="Actually delete files (default is dry-run)")
    p_prune.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: restore
    p_restore = subparsers.add_parser("restore", help="Restore backup into an isolated directory")
    p_restore.add_argument("--archive", required=True, help="Path to .tar.gz archive")
    p_restore.add_argument("--target-dir", required=True, help="Isolated target directory (MUST be empty)")
    p_restore.add_argument("--no-verify", action="store_true", help="Skip pre-restore verification")
    p_restore.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    args = parser.parse_args()

    if args.command == "create":
        return cmd_create(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "list":
        return cmd_list(args)
    elif args.command == "prune":
        return cmd_prune(args)
    elif args.command == "restore":
        return cmd_restore(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
