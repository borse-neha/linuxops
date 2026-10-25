"""
LinuxOps Backup & Disaster Recovery Engine (Phase 16).

Provides deterministic, tamper-evident, versioned backups, integrity verification,
retention management, secret exclusion scanning, and safe isolated restoration.

Guarantees:
- Never includes credentials, tokens, private keys, or .env files.
- Rejects caches, virtual environments, transient sockets, and unnecessary logs.
- Calculates per-file and archive-level SHA-256 checksums embedded in a structured manifest.
- Creates backups atomically using temporary archives with restricted 0o600 permissions.
- Strictly validates isolated restore targets: rejects non-empty targets, live project root,
  and protected system directories.
- Full path-traversal protection and decompression-bomb safeguards during restore.
- Fail-safe rollback: cleans up any partial extractions if verification fails.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Core project root resolution
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Standard protected system locations that MUST NEVER be overwritten or used as restore targets
PROTECTED_SYSTEM_PATHS: Set[Path] = {
    Path("/"),
    Path("/etc"),
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/var"),
    Path("/home"),
    Path("/home/neha_borse"),
    Path("/home/neha_borse/linuxops"),
    Path("/FedoraLinux-44"),
    Path("/home/neha/cloudops-sentinel"),
    Path("/home/neha/cloudops-sentinel/data"),
}

# Exclusion rules for reproducible and secret-free backups
DEFAULT_EXCLUDED_DIR_NAMES: Set[str] = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    ".git",
    "node_modules",
    "backups",
}

DEFAULT_EXCLUDED_FILE_PATTERNS: List[re.Pattern] = [
    re.compile(r"^.*\.py[cod]$"),
    re.compile(r"^.*\.sock$"),
    re.compile(r"^.*\.log$"),
    re.compile(r"^.*\.tmp$"),
    re.compile(r"^.*\.bak$"),
    re.compile(r"^.*~$"),
    re.compile(r"^\.DS_Store$"),
    re.compile(r"^Thumbs\.db$"),
    re.compile(r"^.*backup.*\.tar\.gz.*$"),
]

# Strict secret filename patterns (never backed up)
SECRET_FILENAME_PATTERNS: List[re.Pattern] = [
    re.compile(r"^\.env(?!\.example|\.production\.example).*$", re.IGNORECASE),
    re.compile(r"^.*\.(pem|key|pkcs12|pfx|p12|kdbx)$", re.IGNORECASE),
    re.compile(r"^(id_rsa|id_dsa|id_ecdsa|id_ed25519).*$", re.IGNORECASE),
    re.compile(r"^credentials(\.json|\.ini)?$", re.IGNORECASE),
]

# Regex patterns for detecting potential unredacted secrets in text files
CONTENT_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----")),
    ("AWS_SECRET_KEY", re.compile(r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}")),
    ("GENERIC_SECRET_TOKEN", re.compile(r"(?i)(?:api_?key|secret_?key|auth_?token|access_?token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{24,}['\"]")),
]

# Allowable template placeholders that shouldn't trigger false positives
SAFE_PLACEHOLDER_SUBSTRINGS: List[str] = [
    "changeme",
    "example",
    "placeholder",
    "your_",
    "test_",
    "dummy",
    "mock",
    "sample",
    "redacted",
    "<",
]


class BackupError(Exception):
    """Base exception for all backup and restore operations."""
    pass


class RestoreError(BackupError):
    """Exception raised during restore operations."""
    pass


class SecurityViolationError(BackupError):
    """Exception raised when secret scanner or permission audit fails."""
    pass


class PathTraversalError(RestoreError):
    """Exception raised when archive contains unsafe paths."""
    pass


class DestinationSecurityError(RestoreError):
    """Exception raised when destination is live project or protected location."""
    pass


class IntegrityVerificationError(BackupError):
    """Exception raised when checksum or manifest verification fails."""
    pass


class ManifestSchemaError(BackupError):
    """Exception raised when manifest is corrupted or missing required keys."""
    pass


class RetentionError(BackupError):
    """Exception raised when retention policy validation fails."""
    pass


@dataclass
class SecretScanResult:
    is_clean: bool
    scanned_files: int
    violations: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class RetentionPolicy:
    max_backups: Optional[int] = None
    max_age_days: Optional[int] = None
    enabled: bool = False
    dry_run: bool = True

    def validate(self) -> None:
        if self.max_backups is not None and self.max_backups < 1:
            raise RetentionError(f"max_backups must be at least 1, got {self.max_backups}")
        if self.max_age_days is not None and self.max_age_days < 0:
            raise RetentionError(f"max_age_days must be non-negative, got {self.max_age_days}")


@dataclass
class BackupResult:
    success: bool
    backup_id: str
    archive_path: Path
    checksum_path: Path
    sha256: str
    file_count: int
    total_bytes: int
    manifest: Dict[str, Any]
    duration_seconds: float
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["archive_path"] = str(self.archive_path)
        d["checksum_path"] = str(self.checksum_path)
        return d


@dataclass
class VerificationResult:
    valid: bool
    backup_id: str
    archive_path: Path
    total_files: int
    total_bytes: int
    checked_files: int
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["archive_path"] = str(self.archive_path)
        return d


@dataclass
class RestoreResult:
    success: bool
    backup_id: str
    archive_path: Path
    target_dir: Path
    restored_files: int
    total_bytes: int
    duration_seconds: float
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["archive_path"] = str(self.archive_path)
        d["target_dir"] = str(self.target_dir)
        return d


@dataclass
class PruneResult:
    deleted_archives: List[str]
    kept_archives: List[str]
    dry_run: bool
    policy: Dict[str, Any]
    errors: List[str] = field(default_factory=list)


class SecretScanner:
    """Scans filenames and file contents to ensure zero unredacted secrets are backed up."""

    @staticmethod
    def is_secret_filename(path: Path) -> bool:
        name = path.name
        for pattern in SECRET_FILENAME_PATTERNS:
            if pattern.match(name):
                return True
        return False

    @staticmethod
    def scan_file_content(path: Path, max_bytes: int = 5 * 1024 * 1024) -> List[str]:
        """Inspect file content for private keys or cleartext credentials."""
        violations: List[str] = []
        try:
            if not path.is_file() or path.stat().st_size > max_bytes:
                return violations

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for rule_name, pattern in CONTENT_SECRET_PATTERNS:
                matches = pattern.findall(content)
                for match in matches:
                    text_str = match if isinstance(match, str) else str(match)
                    # Check if it contains allowable safe placeholder substrings
                    lower_text = text_str.lower()
                    if any(safe in lower_text for safe in SAFE_PLACEHOLDER_SUBSTRINGS):
                        continue
                    violations.append(f"{rule_name} detected in {path.name}")
        except Exception as e:
            violations.append(f"Content read error on {path.name}: {str(e)}")
        return violations

    @classmethod
    def scan_file_list(cls, root_dir: Path, rel_paths: List[Path]) -> SecretScanResult:
        violations: List[Dict[str, str]] = []
        scanned_count = 0

        for rel in rel_paths:
            full_path = root_dir / rel
            scanned_count += 1

            if cls.is_secret_filename(rel):
                violations.append({
                    "file": str(rel),
                    "reason": "Forbidden secret filename pattern",
                })
                continue

            content_issues = cls.scan_file_content(full_path)
            for issue in content_issues:
                violations.append({
                    "file": str(rel),
                    "reason": issue,
                })

        return SecretScanResult(
            is_clean=len(violations) == 0,
            scanned_files=scanned_count,
            violations=violations,
        )


def calculate_sha256(file_path: Path) -> str:
    """Stream file contents and return hexadecimal SHA-256 hash."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def calculate_bytes_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of bytes in memory."""
    return hashlib.sha256(data).hexdigest()


class BackupManager:
    """Manages creation, verification, listing, and retention of versioned backups."""

    def __init__(
        self,
        source_dir: Union[str, Path] = PROJECT_ROOT,
        backup_dir: Optional[Union[str, Path]] = None,
    ):
        self.source_dir = Path(source_dir).resolve()
        if backup_dir:
            self.backup_dir = Path(backup_dir).resolve()
        else:
            self.backup_dir = (self.source_dir / "logs" / "backups").resolve()

    def should_exclude(self, rel_path: Path) -> Tuple[bool, str]:
        """Evaluate if relative path should be excluded based on deterministic rules."""
        parts = rel_path.parts

        # Directory component exclusions
        for part in parts[:-1]:
            if part in DEFAULT_EXCLUDED_DIR_NAMES or "backups" in part:
                return True, f"Directory exclusion rule: '{part}'"
            if part.startswith(".") and part not in {".streamlit"}:
                return True, f"Hidden directory exclusion: '{part}'"

        # Check if file is inside backup directory itself (avoid recursion)
        full_path = self.source_dir / rel_path
        try:
            if full_path.is_relative_to(self.backup_dir):
                return True, "Path inside backup store"
        except ValueError:
            pass

        # Target file name exclusions
        file_name = rel_path.name
        if parts[-1] in DEFAULT_EXCLUDED_DIR_NAMES or "backups" in parts[-1]:
            return True, f"Directory name exclusion: '{parts[-1]}'"

        for pattern in DEFAULT_EXCLUDED_FILE_PATTERNS:
            if pattern.match(file_name):
                return True, f"Pattern exclusion: '{pattern.pattern}'"

        # Secret exclusions
        if SecretScanner.is_secret_filename(rel_path):
            return True, "Secret filename rule"

        return False, ""

    def collect_included_files(self) -> Tuple[List[Path], Dict[str, int]]:
        """Traverse source directory and return sorted relative paths of included files."""
        included: List[Path] = []
        exclusion_counts: Dict[str, int] = {
            "caches": 0,
            "venvs": 0,
            "git": 0,
            "secrets": 0,
            "logs_and_tmps": 0,
            "other": 0,
        }

        for root, dirs, files in os.walk(self.source_dir, topdown=True):
            rel_root = Path(root).relative_to(self.source_dir)

            # Prune excluded directories in-place to avoid deep traversals
            pruned_dirs = []
            for d in list(dirs):
                rel_d = rel_root / d if rel_root != Path(".") else Path(d)
                excluded, reason = self.should_exclude(rel_d)
                if excluded:
                    dirs.remove(d)
                    if any(c in d for c in ["cache", "__pycache__"]):
                        exclusion_counts["caches"] += 1
                    elif "venv" in d:
                        exclusion_counts["venvs"] += 1
                    elif ".git" in d:
                        exclusion_counts["git"] += 1
                    else:
                        exclusion_counts["other"] += 1

            for f in files:
                rel_f = rel_root / f if rel_root != Path(".") else Path(f)
                excluded, reason = self.should_exclude(rel_f)
                if excluded:
                    if "Secret" in reason:
                        exclusion_counts["secrets"] += 1
                    elif any(c in reason for c in [".log", ".tmp", ".bak", ".sock"]):
                        exclusion_counts["logs_and_tmps"] += 1
                    elif "cache" in reason:
                        exclusion_counts["caches"] += 1
                    else:
                        exclusion_counts["other"] += 1
                else:
                    included.append(rel_f)

        included.sort()
        return included, exclusion_counts

    def create_backup(
        self,
        output_dir: Optional[Path] = None,
        archive_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        verify_after_creation: bool = True,
    ) -> BackupResult:
        """Create an idempotent, tamper-evident compressed backup archive with manifest."""
        start_time = time.time()
        target_store = Path(output_dir).resolve() if output_dir else self.backup_dir
        self.backup_dir = target_store
        target_store.mkdir(parents=True, exist_ok=True)
        try:
            target_store.chmod(0o700)
        except OSError:
            pass

        now_utc = datetime.now(timezone.utc)
        timestamp_str = now_utc.strftime("%Y%m%d_%H%M%S")
        unique_suffix = hashlib.sha256(f"{timestamp_str}_{os.getpid()}".encode()).hexdigest()[:6]
        backup_id = f"linuxops_backup_{timestamp_str}_{unique_suffix}"

        if not archive_name:
            archive_name = f"{backup_id}.tar.gz"

        final_archive_path = target_store / archive_name
        final_checksum_path = target_store / f"{archive_name}.sha256"
        temp_archive_path = target_store / f".{archive_name}.tmp"

        if final_archive_path.exists():
            raise BackupError(f"Backup destination already exists: {final_archive_path}")

        # 1. Collect files
        included_files, exclusion_counts = self.collect_included_files()

        # 2. Secret scan
        scan_result = SecretScanner.scan_file_list(self.source_dir, included_files)
        if not scan_result.is_clean:
            raise SecurityViolationError(
                f"Secret scanner detected {len(scan_result.violations)} violation(s): "
                f"{json.dumps(scan_result.violations)}"
            )

        # 3. Calculate per-file hashes and total size
        files_manifest: Dict[str, Dict[str, Any]] = {}
        total_bytes = 0

        for rel in included_files:
            abs_path = self.source_dir / rel
            size = abs_path.stat().st_size
            total_bytes += size
            file_hash = calculate_sha256(abs_path)
            mode = oct(abs_path.stat().st_mode & 0o777)
            files_manifest[str(rel).replace("\\", "/")] = {
                "sha256": file_hash,
                "size_bytes": size,
                "mode": mode,
            }

        # 4. Read system version metadata
        version = "1.0.0"
        pyproject_path = self.source_dir / "pyproject.toml"
        if pyproject_path.exists():
            try:
                for line in pyproject_path.read_text(encoding="utf-8").splitlines():
                    if line.strip().startswith("version"):
                        version = line.split("=")[1].strip().strip('"').strip("'")
                        break
            except Exception:
                pass

        # 5. Build structured manifest
        manifest_data: Dict[str, Any] = {
            "manifest_version": "1.0.0",
            "backup_id": backup_id,
            "created_at_utc": now_utc.isoformat(),
            "linuxops_version": version,
            "source_root": str(self.source_dir),
            "file_count": len(files_manifest),
            "total_bytes": total_bytes,
            "files": files_manifest,
            "exclusions": {
                "rules": list(DEFAULT_EXCLUDED_DIR_NAMES),
                "counts": exclusion_counts,
            },
            "secret_scan": {
                "status": "PASSED",
                "scanned_files": scan_result.scanned_files,
                "violations": [],
            },
            "recovery_prerequisites": {
                "python_version": ">=3.10",
                "dependencies_file": "requirements-lock.txt",
                "environment_template": ".env.production.example",
                "recovery_kill_switch_required": "LINUXOPS_RECOVERY_DISABLED=1",
            },
        }
        if metadata:
            manifest_data["user_metadata"] = metadata

        manifest_json_bytes = json.dumps(manifest_data, indent=2).encode("utf-8")
        manifest_hash = calculate_bytes_sha256(manifest_json_bytes)

        # 6. Generate SHA256SUMS text
        sha256sums_lines = []
        for file_rel, f_meta in sorted(files_manifest.items()):
            sha256sums_lines.append(f"{f_meta['sha256']}  {file_rel}")
        sha256sums_lines.append(f"{manifest_hash}  manifest.json")
        sha256sums_bytes = ("\n".join(sha256sums_lines) + "\n").encode("utf-8")

        # 7. Write tarball atomically
        try:
            with tarfile.open(temp_archive_path, "w:gz", format=tarfile.PAX_FORMAT) as tar:
                # Add all files
                for rel in included_files:
                    abs_path = self.source_dir / rel
                    norm_name = str(rel).replace("\\", "/")
                    tar.add(abs_path, arcname=norm_name, recursive=False)

                # Add manifest.json
                ti_manifest = tarfile.TarInfo(name="manifest.json")
                ti_manifest.size = len(manifest_json_bytes)
                ti_manifest.mtime = int(now_utc.timestamp())
                ti_manifest.mode = 0o644
                import io
                tar.addfile(ti_manifest, io.BytesIO(manifest_json_bytes))

                # Add SHA256SUMS
                ti_sums = tarfile.TarInfo(name="SHA256SUMS")
                ti_sums.size = len(sha256sums_bytes)
                ti_sums.mtime = int(now_utc.timestamp())
                ti_sums.mode = 0o644
                tar.addfile(ti_sums, io.BytesIO(sha256sums_bytes))

            # Set restricted permissions on temp archive
            try:
                temp_archive_path.chmod(0o600)
            except OSError:
                pass

            # Calculate final archive sha256
            archive_sha256 = calculate_sha256(temp_archive_path)

            # Write companion checksum file
            checksum_content = f"{archive_sha256}  {archive_name}\n"
            final_checksum_path.write_text(checksum_content, encoding="utf-8")
            try:
                final_checksum_path.chmod(0o600)
            except OSError:
                pass

            # Atomic rename of temp archive to final archive
            temp_archive_path.replace(final_archive_path)

        except Exception as e:
            if temp_archive_path.exists():
                try:
                    temp_archive_path.unlink()
                except OSError:
                    pass
            if final_checksum_path.exists():
                try:
                    final_checksum_path.unlink()
                except OSError:
                    pass
            raise BackupError(f"Failed to create backup archive: {str(e)}") from e

        # 8. Verification after creation
        if verify_after_creation:
            verify_res = self.verify_backup(final_archive_path)
            if not verify_res.valid:
                raise IntegrityVerificationError(
                    f"Immediate verification failed for {final_archive_path}: {verify_res.errors}"
                )

        duration = time.time() - start_time
        return BackupResult(
            success=True,
            backup_id=backup_id,
            archive_path=final_archive_path,
            checksum_path=final_checksum_path,
            sha256=archive_sha256,
            file_count=len(files_manifest),
            total_bytes=total_bytes,
            manifest=manifest_data,
            duration_seconds=round(duration, 3),
        )

    def verify_backup(self, archive_path: Path) -> VerificationResult:
        """Inspect and verify archive readability, manifest validity, and sha256 checksums."""
        archive_path = Path(archive_path).resolve()
        errors: List[str] = []

        if not archive_path.is_file():
            return VerificationResult(
                valid=False,
                backup_id="UNKNOWN",
                archive_path=archive_path,
                total_files=0,
                total_bytes=0,
                checked_files=0,
                errors=[f"Archive file does not exist: {archive_path}"],
            )

        # Check companion sha256 if present
        companion_checksum = archive_path.parent / f"{archive_path.name}.sha256"
        if companion_checksum.is_file():
            try:
                content = companion_checksum.read_text(encoding="utf-8").strip()
                expected_hash = content.split()[0]
                actual_hash = calculate_sha256(archive_path)
                if expected_hash.lower() != actual_hash.lower():
                    errors.append(
                        f"Archive checksum mismatch: expected {expected_hash}, calculated {actual_hash}"
                    )
            except Exception as e:
                errors.append(f"Failed to verify companion checksum: {str(e)}")

        manifest_data: Optional[Dict[str, Any]] = None
        checked_count = 0
        total_files = 0
        total_bytes = 0
        backup_id = "UNKNOWN"

        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                # 1. Read manifest.json
                try:
                    manifest_member = tar.getmember("manifest.json")
                    manifest_file = tar.extractfile(manifest_member)
                    if manifest_file is None:
                        raise ManifestSchemaError("manifest.json member is not readable")
                    manifest_data = json.loads(manifest_file.read().decode("utf-8"))
                    backup_id = manifest_data.get("backup_id", "UNKNOWN")
                except KeyError:
                    errors.append("Archive missing required 'manifest.json' entry")
                    return VerificationResult(
                        valid=False,
                        backup_id=backup_id,
                        archive_path=archive_path,
                        total_files=0,
                        total_bytes=0,
                        checked_files=0,
                        errors=errors,
                    )
                except Exception as e:
                    errors.append(f"Invalid or corrupted manifest.json: {str(e)}")
                    return VerificationResult(
                        valid=False,
                        backup_id=backup_id,
                        archive_path=archive_path,
                        total_files=0,
                        total_bytes=0,
                        checked_files=0,
                        errors=errors,
                    )

                # Validate manifest schema
                required_fields = ["manifest_version", "backup_id", "files", "total_bytes"]
                for req in required_fields:
                    if req not in manifest_data:
                        errors.append(f"Manifest missing required schema field '{req}'")

                files_dict = manifest_data.get("files", {})
                total_files = len(files_dict)
                total_bytes = manifest_data.get("total_bytes", 0)

                # 2. Verify all member contents and checksums
                members = tar.getmembers()
                member_names = {m.name for m in members}

                for file_rel, expected_meta in files_dict.items():
                    if file_rel not in member_names:
                        errors.append(f"File '{file_rel}' listed in manifest but missing from archive")
                        continue

                    m = tar.getmember(file_rel)
                    f = tar.extractfile(m)
                    if f is None:
                        errors.append(f"Unable to read member '{file_rel}'")
                        continue

                    h = hashlib.sha256()
                    while chunk := f.read(65536):
                        h.update(chunk)
                    computed_hash = h.hexdigest()

                    expected_hash = expected_meta.get("sha256", "")
                    if computed_hash.lower() != expected_hash.lower():
                        errors.append(
                            f"Checksum mismatch for '{file_rel}': expected {expected_hash}, calculated {computed_hash}"
                        )
                    checked_count += 1

        except tarfile.ReadError as e:
            errors.append(f"Corrupted tar gzip archive: {str(e)}")
        except Exception as e:
            errors.append(f"Archive inspection error: {str(e)}")

        return VerificationResult(
            valid=len(errors) == 0,
            backup_id=backup_id,
            archive_path=archive_path,
            total_files=total_files,
            total_bytes=total_bytes,
            checked_files=checked_count,
            errors=errors,
        )

    def list_backups(self) -> List[Dict[str, Any]]:
        """List all valid backups present in the target backup directory."""
        if not self.backup_dir.is_dir():
            return []

        backups = []
        for item in sorted(self.backup_dir.glob("linuxops_backup_*.tar.gz")):
            stat = item.stat()
            backup_id = item.name.replace(".tar.gz", "")
            companion = item.parent / f"{item.name}.sha256"
            backups.append({
                "backup_id": backup_id,
                "file_name": item.name,
                "path": str(item),
                "size_bytes": stat.st_size,
                "created_at_epoch": stat.st_mtime,
                "created_at_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "has_companion_checksum": companion.is_file(),
            })
        return backups

    def prune_backups(self, policy: Optional[RetentionPolicy] = None) -> PruneResult:
        """Enforce backup retention policy safely without accidental deletions."""
        if policy is None:
            policy = RetentionPolicy(enabled=False, dry_run=True)

        policy.validate()
        all_backups = self.list_backups()
        if not all_backups:
            return PruneResult(
                deleted_archives=[],
                kept_archives=[],
                dry_run=policy.dry_run,
                policy=asdict(policy),
            )

        # Sort by creation time descending (newest first)
        all_backups.sort(key=lambda x: x["created_at_epoch"], reverse=True)

        now_epoch = time.time()
        to_delete: List[str] = []
        to_keep: List[str] = []

        for idx, b in enumerate(all_backups):
            delete_reason = None

            # Count-based retention
            if policy.max_backups is not None and idx >= policy.max_backups:
                delete_reason = f"Exceeds max_backups limit ({policy.max_backups})"

            # Age-based retention
            if policy.max_age_days is not None:
                age_days = (now_epoch - b["created_at_epoch"]) / 86400.0
                if age_days > policy.max_age_days:
                    delete_reason = f"Age ({age_days:.1f} days) exceeds max_age_days ({policy.max_age_days})"

            if delete_reason and policy.enabled:
                to_delete.append(b["path"])
            else:
                to_keep.append(b["path"])

        errors: List[str] = []
        deleted_success: List[str] = []

        if policy.enabled and not policy.dry_run:
            for path_str in to_delete:
                p = Path(path_str)
                # Extra safety check: must match backup pattern and be inside backup_dir
                if not p.name.startswith("linuxops_backup_") or not p.name.endswith(".tar.gz"):
                    errors.append(f"Refusing to delete non-backup file: {p}")
                    continue
                try:
                    p.unlink(missing_ok=True)
                    companion = p.parent / f"{p.name}.sha256"
                    companion.unlink(missing_ok=True)
                    deleted_success.append(path_str)
                except Exception as e:
                    errors.append(f"Failed to delete {path_str}: {str(e)}")
        else:
            deleted_success = to_delete

        return PruneResult(
            deleted_archives=deleted_success,
            kept_archives=to_keep,
            dry_run=policy.dry_run or not policy.enabled,
            policy=asdict(policy),
            errors=errors,
        )


class RestoreManager:
    """Safely restores backups into isolated destinations with strict security barriers."""

    def __init__(self, project_root: Union[str, Path] = PROJECT_ROOT):
        self.project_root = Path(project_root).resolve()

    def validate_destination_safety(self, target_dir: Path) -> None:
        """Strictly validates destination safety to prevent overwriting live systems."""
        resolved = target_dir.resolve()

        # 1. Must not match or be ancestor of live project root
        if resolved == self.project_root:
            raise DestinationSecurityError(
                f"SAFETY BLOCK: Destination '{resolved}' is the live project root!"
            )
        try:
            if self.project_root.is_relative_to(resolved):
                raise DestinationSecurityError(
                    f"SAFETY BLOCK: Destination '{resolved}' is a parent of live project root!"
                )
        except ValueError:
            pass

        # 2. Must not be inside protected system paths
        for protected in PROTECTED_SYSTEM_PATHS:
            if resolved == protected.resolve():
                raise DestinationSecurityError(
                    f"SAFETY BLOCK: Destination '{resolved}' is a protected system directory!"
                )

        # 3. If target directory exists, it MUST be completely empty
        if resolved.exists():
            if not resolved.is_dir():
                raise DestinationSecurityError(
                    f"Destination '{resolved}' exists and is not a directory!"
                )
            contents = list(resolved.iterdir())
            if contents:
                raise DestinationSecurityError(
                    f"SAFETY BLOCK: Destination '{resolved}' is NOT empty (contains {len(contents)} item(s))!"
                )

    @staticmethod
    def validate_member_safety(member: tarfile.TarInfo, target_dir: Path) -> None:
        """Validate member path against path-traversal attacks and absolute paths."""
        name = member.name

        # Reject absolute paths or Windows drive letters
        if name.startswith("/") or name.startswith("\\") or ":" in name:
            raise PathTraversalError(f"Member has unsafe absolute path or drive letter: '{name}'")

        # Reject path traversal tokens
        parts = Path(name).parts
        if ".." in parts:
            raise PathTraversalError(f"Path traversal detected in member name: '{name}'")

        # Ensure destination path resolves inside target_dir
        dest_path = (target_dir / name).resolve()
        try:
            if not dest_path.is_relative_to(target_dir.resolve()):
                raise PathTraversalError(f"Member path escapes target directory: '{name}'")
        except ValueError:
            raise PathTraversalError(f"Member path escapes target directory: '{name}'")

        # Check links
        if member.issym() or member.islnk():
            link_target = member.linkname
            if link_target.startswith("/") or ".." in link_target:
                raise PathTraversalError(f"Member link target is unsafe: '{link_target}'")

    def restore_backup(
        self,
        archive_path: Union[str, Path],
        target_dir: Union[str, Path],
        verify_first: bool = True,
        max_bytes: int = 500 * 1024 * 1024,
        max_files: int = 10000,
    ) -> RestoreResult:
        """Restore backup into designated isolated directory with atomic rollback on failure."""
        start_time = time.time()
        archive_path = Path(archive_path).resolve()
        target_dir = Path(target_dir).resolve()
        errors: List[str] = []

        # 1. Validate destination safety
        self.validate_destination_safety(target_dir)

        # 2. Pre-verification
        if verify_first:
            bm = BackupManager(source_dir=self.project_root)
            verify_res = bm.verify_backup(archive_path)
            if not verify_res.valid:
                raise IntegrityVerificationError(
                    f"Archive integrity verification failed before restore: {verify_res.errors}"
                )

        target_dir.mkdir(parents=True, exist_ok=True)
        extracted_files = 0
        total_extracted_bytes = 0
        manifest_data: Optional[Dict[str, Any]] = None

        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                members = tar.getmembers()

                # Safety checks across all members
                if len(members) > max_files:
                    raise RestoreError(f"Archive member count ({len(members)}) exceeds limit ({max_files})")

                for m in members:
                    self.validate_member_safety(m, target_dir)
                    total_extracted_bytes += m.size
                    if total_extracted_bytes > max_bytes:
                        raise RestoreError(
                            f"Archive extracted size exceeds safety limit ({max_bytes} bytes)"
                        )

                # Safe extraction with data filter where supported
                for m in members:
                    if hasattr(tarfile, "data_filter"):
                        tar.extract(m, path=target_dir, filter="data")
                    else:
                        tar.extract(m, path=target_dir)
                    if m.isfile() and m.name not in ("manifest.json", "SHA256SUMS"):
                        extracted_files += 1

            # Read manifest from extracted directory
            extracted_manifest_path = target_dir / "manifest.json"
            if not extracted_manifest_path.is_file():
                raise ManifestSchemaError("Restored archive is missing manifest.json")

            manifest_data = json.loads(extracted_manifest_path.read_text(encoding="utf-8"))
            backup_id = manifest_data.get("backup_id", "UNKNOWN")

            # Post-extraction checksum validation
            files_dict = manifest_data.get("files", {})
            for rel_path_str, expected_meta in files_dict.items():
                restored_file = target_dir / rel_path_str
                if not restored_file.is_file():
                    raise IntegrityVerificationError(f"Restored file missing: {rel_path_str}")

                actual_hash = calculate_sha256(restored_file)
                expected_hash = expected_meta.get("sha256", "")
                if actual_hash.lower() != expected_hash.lower():
                    raise IntegrityVerificationError(
                        f"Checksum mismatch on restored file '{rel_path_str}': "
                        f"expected {expected_hash}, calculated {actual_hash}"
                    )

        except Exception as e:
            # Atomic rollback: purge any partially extracted contents
            errors.append(str(e))
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            raise RestoreError(f"Isolated restore failed (clean rollback completed): {str(e)}") from e

        duration = time.time() - start_time
        return RestoreResult(
            success=True,
            backup_id=backup_id,
            archive_path=archive_path,
            target_dir=target_dir,
            restored_files=extracted_files,
            total_bytes=total_extracted_bytes,
            duration_seconds=round(duration, 3),
            errors=errors,
        )
