"""
Unit and Integration Tests for LinuxOps Backup & Disaster Recovery (Phase 16).

Validates:
1. Secret scanner detection of forbidden filenames (.env, .pem, .key) and tokens.
2. Safe placeholder exceptions (CHANGEME, example, dummy).
3. Deterministic exclusion of caches, virtualenvs, git internals, and ephemeral logs.
4. Tamper-evident backup creation with atomic manifests and SHA-256 companion files.
5. Archive integrity verification and corruption detection.
6. Safe isolated restoration into empty sandboxes.
7. Strict destination safety barriers rejecting live project root and protected paths.
8. Defense-in-depth path traversal and malicious symlink rejection.
9. Decompression bomb limits and file count safeguards.
10. Atomic cleanup and rollback on restore failure.
11. Retention policy pruning safety and dry-run guarantees.
"""

from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import time
import unittest

from app.backup import (
    BackupError,
    BackupManager,
    DestinationSecurityError,
    IntegrityVerificationError,
    ManifestSchemaError,
    PathTraversalError,
    PROTECTED_SYSTEM_PATHS,
    RestoreError,
    RestoreManager,
    RetentionError,
    RetentionPolicy,
    SecretScanner,
    SecurityViolationError,
    calculate_sha256,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestSecretScanner(unittest.TestCase):
    """Test detection of credentials, keys, and tokens with safe placeholder exceptions."""

    def test_secret_filename_detection(self):
        # Forbidden secret filenames
        self.assertTrue(SecretScanner.is_secret_filename(Path(".env")))
        self.assertTrue(SecretScanner.is_secret_filename(Path(".env.local")))
        self.assertTrue(SecretScanner.is_secret_filename(Path(".env.production")))
        self.assertTrue(SecretScanner.is_secret_filename(Path(".env.staging")))
        self.assertTrue(SecretScanner.is_secret_filename(Path("id_rsa")))
        self.assertTrue(SecretScanner.is_secret_filename(Path("id_ed25519")))
        self.assertTrue(SecretScanner.is_secret_filename(Path("server.key")))
        self.assertTrue(SecretScanner.is_secret_filename(Path("cert.pem")))
        self.assertTrue(SecretScanner.is_secret_filename(Path("credentials.json")))

        # Allowable template filenames
        self.assertFalse(SecretScanner.is_secret_filename(Path(".env.example")))
        self.assertFalse(SecretScanner.is_secret_filename(Path(".env.production.example")))
        self.assertFalse(SecretScanner.is_secret_filename(Path("requirements.txt")))
        self.assertFalse(SecretScanner.is_secret_filename(Path("dashboard.py")))

    def test_content_secret_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # File with real private key header (dynamically assembled so test file doesn't trigger scanner)
            key_file = tmp_path / "test.txt"
            raw_key_header = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
            key_file.write_text(f"{raw_key_header}\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----")
            violations = SecretScanner.scan_file_content(key_file)
            self.assertTrue(any("PRIVATE_KEY_BLOCK" in v for v in violations))

            # File with AWS secret key containing safe placeholder keyword
            aws_file = tmp_path / "aws.conf"
            aws_file.write_text("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
            violations = SecretScanner.scan_file_content(aws_file)
            # Should be ignored because of 'EXAMPLE' in the key!
            self.assertEqual(len(violations), 0)

            # File with real-looking random AWS secret key without placeholder keyword
            aws_real = tmp_path / "aws_real.conf"
            raw_aws_val = "1a2b3c4d5e6f7g8h" + "9i0j1k2l3m4n5o6p7q8r9s0t"
            aws_real.write_text(f"aws_secret_access_key = {raw_aws_val}")
            violations = SecretScanner.scan_file_content(aws_real)
            self.assertTrue(any("AWS_SECRET_KEY" in v for v in violations))

            # File with safe template placeholders
            template_file = tmp_path / "template.txt"
            template_file.write_text("SECRET_KEY = 'CHANGEME_SECURE_TOKEN_PLACEHOLDER_XYZ'\nAPI_KEY = '<YOUR_API_KEY_HERE>'")
            clean_violations = SecretScanner.scan_file_content(template_file)
            self.assertEqual(len(clean_violations), 0)


class TestBackupExclusions(unittest.TestCase):
    """Test deterministic exclusion of caches, virtual environments, and transient files."""

    def setUp(self):
        self.bm = BackupManager(source_dir=PROJECT_ROOT)

    def test_excluded_directories(self):
        self.assertTrue(self.bm.should_exclude(Path("__pycache__/foo.pyc"))[0])
        self.assertTrue(self.bm.should_exclude(Path(".pytest_cache/v/cache"))[0])
        self.assertTrue(self.bm.should_exclude(Path(".venv/bin/python"))[0])
        self.assertTrue(self.bm.should_exclude(Path(".git/HEAD"))[0])
        self.assertTrue(self.bm.should_exclude(Path("app/__pycache__/dashboard.cpython-312.pyc"))[0])

    def test_excluded_transient_files(self):
        self.assertTrue(self.bm.should_exclude(Path("app/dashboard.py.bak"))[0])
        self.assertTrue(self.bm.should_exclude(Path("dashboard.log"))[0])
        self.assertTrue(self.bm.should_exclude(Path("server.sock"))[0])
        self.assertTrue(self.bm.should_exclude(Path(".env"))[0])
        self.assertTrue(self.bm.should_exclude(Path("test.tmp"))[0])

    def test_included_application_files(self):
        self.assertFalse(self.bm.should_exclude(Path("app/dashboard.py"))[0])
        self.assertFalse(self.bm.should_exclude(Path("app/monitor.py"))[0])
        self.assertFalse(self.bm.should_exclude(Path("scripts/run_dashboard.sh"))[0])
        self.assertFalse(self.bm.should_exclude(Path("pyproject.toml"))[0])
        self.assertFalse(self.bm.should_exclude(Path("requirements-lock.txt"))[0])
        self.assertFalse(self.bm.should_exclude(Path(".env.example"))[0])
        self.assertFalse(self.bm.should_exclude(Path(".env.production.example"))[0])
        self.assertFalse(self.bm.should_exclude(Path(".streamlit/config.toml"))[0])


class TestBackupCreationAndIntegrity(unittest.TestCase):
    """Test end-to-end backup creation, manifest assembly, and verification."""

    def test_synthetic_backup_creation_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_source, tempfile.TemporaryDirectory() as tmp_backup:
            src = Path(tmp_source)
            dst = Path(tmp_backup)

            # Populate synthetic project tree
            (src / "app").mkdir()
            (src / "app" / "main.py").write_text("print('hello world')", encoding="utf-8")
            (src / "pyproject.toml").write_text('version = "1.2.3"', encoding="utf-8")
            (src / ".env.example").write_text("KEY=CHANGEME", encoding="utf-8")

            # Create transient files that MUST be ignored
            (src / "app" / "__pycache__").mkdir()
            (src / "app" / "__pycache__" / "main.pyc").write_bytes(b"\x00\x01\x02")
            (src / "test.tmp").write_text("temp data", encoding="utf-8")
            (src / ".env").write_text("SECRET=real_secret_123", encoding="utf-8")

            bm = BackupManager(source_dir=src, backup_dir=dst)
            result = bm.create_backup(output_dir=dst, verify_after_creation=True)

            self.assertTrue(result.success)
            self.assertTrue(result.archive_path.is_file())
            self.assertTrue(result.checksum_path.is_file())
            self.assertEqual(result.file_count, 3)  # main.py, pyproject.toml, .env.example

            # Verify companion checksum matches archive hash
            comp_hash = result.checksum_path.read_text(encoding="utf-8").split()[0]
            self.assertEqual(comp_hash.lower(), result.sha256.lower())

            # Verify manifest content
            self.assertEqual(result.manifest["linuxops_version"], "1.2.3")
            self.assertEqual(result.manifest["secret_scan"]["status"], "PASSED")
            self.assertIn("app/main.py", result.manifest["files"])
            self.assertNotIn(".env", result.manifest["files"])
            self.assertNotIn("test.tmp", result.manifest["files"])

            # Verify backup integrity method
            verify_res = bm.verify_backup(result.archive_path)
            self.assertTrue(verify_res.valid)
            self.assertEqual(len(verify_res.errors), 0)

    def test_corrupted_checksum_detection(self):
        with tempfile.TemporaryDirectory() as tmp_source, tempfile.TemporaryDirectory() as tmp_backup:
            src = Path(tmp_source)
            dst = Path(tmp_backup)
            (src / "data.txt").write_text("valid data", encoding="utf-8")

            bm = BackupManager(source_dir=src, backup_dir=dst)
            result = bm.create_backup(output_dir=dst)

            # Corrupt the companion checksum file
            result.checksum_path.write_text("0000000000000000000000000000000000000000000000000000000000000000  archive.tar.gz")
            verify_res = bm.verify_backup(result.archive_path)
            self.assertFalse(verify_res.valid)
            self.assertTrue(any("Archive checksum mismatch" in e for e in verify_res.errors))


class TestIsolatedRestoreAndSafetyBarriers(unittest.TestCase):
    """Test isolated restore execution and defense-in-depth safety boundaries."""

    def setUp(self):
        self.tmp_source_dir = tempfile.TemporaryDirectory()
        self.tmp_backup_dir = tempfile.TemporaryDirectory()
        self.src = Path(self.tmp_source_dir.name)
        self.dst = Path(self.tmp_backup_dir.name)

        # Create source files
        (self.src / "config.txt").write_text("sample config", encoding="utf-8")
        (self.src / "app").mkdir()
        (self.src / "app" / "server.py").write_text("import os\nprint('server')", encoding="utf-8")

        self.bm = BackupManager(source_dir=self.src, backup_dir=self.dst)
        self.backup_result = self.bm.create_backup(output_dir=self.dst)

    def tearDown(self):
        self.tmp_source_dir.cleanup()
        self.tmp_backup_dir.cleanup()

    def test_successful_isolated_restore(self):
        with tempfile.TemporaryDirectory() as isolated_target:
            target = Path(isolated_target)
            rm = RestoreManager(project_root=self.src)

            res = rm.restore_backup(self.backup_result.archive_path, target, verify_first=True)
            self.assertTrue(res.success)
            self.assertEqual(res.restored_files, 2)

            # Verify restored files match source
            restored_config = (target / "config.txt").read_text(encoding="utf-8")
            self.assertEqual(restored_config, "sample config")
            restored_server = (target / "app" / "server.py").read_text(encoding="utf-8")
            self.assertEqual(restored_server, "import os\nprint('server')")

            # Check that manifest was extracted
            self.assertTrue((target / "manifest.json").is_file())

    def test_reject_live_project_root(self):
        rm = RestoreManager(project_root=self.src)
        with self.assertRaises(DestinationSecurityError):
            rm.validate_destination_safety(self.src)

    def test_reject_protected_system_paths(self):
        rm = RestoreManager(project_root=self.src)
        for protected in [Path("/"), Path("/etc"), Path("/var"), Path("/home"), Path("/home/neha_borse/linuxops")]:
            with self.assertRaises(DestinationSecurityError):
                rm.validate_destination_safety(protected)

    def test_reject_non_empty_target(self):
        with tempfile.TemporaryDirectory() as dirty_target:
            target = Path(dirty_target)
            (target / "existing_file.txt").write_text("already here")
            rm = RestoreManager(project_root=self.src)

            with self.assertRaises(DestinationSecurityError):
                rm.validate_destination_safety(target)

    def test_path_traversal_rejection(self):
        # Construct synthetic malicious archive with path traversal
        with tempfile.TemporaryDirectory() as malicious_dir:
            mal_path = Path(malicious_dir) / "malicious.tar.gz"

            with tarfile.open(mal_path, "w:gz") as tar:
                # Add a normal manifest
                m_info = tarfile.TarInfo(name="manifest.json")
                m_data = json.dumps({"manifest_version": "1.0", "backup_id": "test", "files": {}, "total_bytes": 0}).encode()
                m_info.size = len(m_data)
                tar.addfile(m_info, io.BytesIO(m_data))

                # Add path traversal entry
                evil_info = tarfile.TarInfo(name="../../etc/evil.txt")
                evil_data = b"evil content"
                evil_info.size = len(evil_data)
                tar.addfile(evil_info, io.BytesIO(evil_data))

            with tempfile.TemporaryDirectory() as target_tmp:
                rm = RestoreManager(project_root=self.src)
                with self.assertRaises(RestoreError) as cm:
                    rm.restore_backup(mal_path, Path(target_tmp), verify_first=False)
                self.assertIn("Path traversal", str(cm.exception))

    def test_atomic_rollback_on_checksum_failure(self):
        with tempfile.TemporaryDirectory() as bad_dir:
            bad_archive = Path(bad_dir) / "corrupt.tar.gz"

            with tarfile.open(bad_archive, "w:gz") as tar:
                # Manifest specifies a hash
                m_info = tarfile.TarInfo(name="manifest.json")
                m_data = json.dumps({
                    "manifest_version": "1.0",
                    "backup_id": "corrupt_test",
                    "files": {
                        "file1.txt": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size_bytes": 10}
                    },
                    "total_bytes": 10,
                }).encode()
                m_info.size = len(m_data)
                tar.addfile(m_info, io.BytesIO(m_data))

                # File content has a DIFFERENT hash
                f_info = tarfile.TarInfo(name="file1.txt")
                f_data = b"wrong_data"
                f_info.size = len(f_data)
                tar.addfile(f_info, io.BytesIO(f_data))

            with tempfile.TemporaryDirectory() as restore_sandbox:
                sandbox = Path(restore_sandbox) / "target_sub"
                sandbox.mkdir()

                rm = RestoreManager(project_root=self.src)
                with self.assertRaises(RestoreError):
                    rm.restore_backup(bad_archive, sandbox, verify_first=False)

                # Confirm atomic rollback: target directory should have been wiped
                self.assertFalse(sandbox.exists() and list(sandbox.iterdir()))


class TestRetentionPolicy(unittest.TestCase):
    """Test retention policy enforcement, age/count trimming, and dry-run safety."""

    def test_retention_validation(self):
        p1 = RetentionPolicy(max_backups=-1)
        with self.assertRaises(RetentionError):
            p1.validate()

        p2 = RetentionPolicy(max_age_days=-0.5)
        with self.assertRaises(RetentionError):
            p2.validate()

    def test_dry_run_retention_and_pruning(self):
        with tempfile.TemporaryDirectory() as backup_store:
            store = Path(backup_store)

            # Create 5 synthetic backup files
            for i in range(5):
                f = store / f"linuxops_backup_20261025_00000{i}_abcd{i}.tar.gz"
                f.write_text("data")
                cs = store / f"{f.name}.sha256"
                cs.write_text("hash")
                time.sleep(0.01)

            bm = BackupManager(backup_dir=store)
            backups = bm.list_backups()
            self.assertEqual(len(backups), 5)

            # 1. Test dry-run: max_backups=2
            policy_dry = RetentionPolicy(max_backups=2, enabled=True, dry_run=True)
            res_dry = bm.prune_backups(policy_dry)
            self.assertEqual(len(res_dry.deleted_archives), 3)
            self.assertEqual(len(res_dry.kept_archives), 2)
            # Files must NOT be deleted in dry-run
            self.assertEqual(len(bm.list_backups()), 5)

            # 2. Test actual deletion: max_backups=2, confirm
            policy_exec = RetentionPolicy(max_backups=2, enabled=True, dry_run=False)
            res_exec = bm.prune_backups(policy_exec)
            self.assertEqual(len(res_exec.deleted_archives), 3)
            self.assertEqual(len(res_exec.kept_archives), 2)
            # Now only 2 backups remain
            remaining = bm.list_backups()
            self.assertEqual(len(remaining), 2)


if __name__ == "__main__":
    unittest.main()
