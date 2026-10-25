#!/usr/bin/env python3

"""
Production Security & Hardening Boundaries Test Suite (Phase 8).

Verifies DevSecOps boundaries for public deployment readiness:
1. Production authentication is strictly fail-closed.
2. Production role assignment prohibits prefix-based or unverified admin escalation.
3. Host agent ingestion validates HMAC-SHA256, enforces replay window, limits payload size,
   caps container capacity, rejects command injection, and strips credentials.
4. Multi-user session isolation prevents cross-user approval token reuse and session leakage.
5. Production deployment configurations enforce non-root execution and recovery kill-switch defaults.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import MagicMock, patch

from app.auth import (
    AuthenticatedUser,
    UserRole,
    authenticate_user,
    check_permission,
    get_auth_mode,
    get_configured_admin_emails,
    get_user_session_key,
    logout_current_user,
    render_login_gate,
    resolve_user_role,
)
from app.host_registry import (
    MAX_CONTAINERS_PER_REPORT,
    MAX_PAYLOAD_BYTES,
    MAX_TIMESTAMP_SKEW_SECONDS,
    HostRegistry,
    sanitize_container_telemetry,
)


class TestProductionAuthFailClosed(unittest.TestCase):
    """Test that production authentication strictly fails closed."""

    def test_cloud_environment_auto_detects_production(self):
        for cloud_var in ("RENDER", "DYNO", "FLY_APP_NAME", "KUBERNETES_PORT"):
            with patch.dict(os.environ, {cloud_var: "true"}, clear=True):
                self.assertEqual(get_auth_mode(), "production", f"Failed to detect {cloud_var}")

    def test_unauthenticated_session_in_production_returns_none(self):
        with patch.dict(os.environ, {"LINUXOPS_AUTH_MODE": "production"}):
            user = authenticate_user()
            self.assertIsNone(user)

    @patch("streamlit.error")
    @patch("streamlit.markdown")
    def test_render_login_gate_missing_oidc_fails_closed(self, mock_md, mock_err):
        """In production without secrets.toml auth, gate must show error and never return user."""
        with patch.dict(os.environ, {"LINUXOPS_AUTH_MODE": "production"}):
            user = render_login_gate()
            self.assertIsNone(user)
            mock_err.assert_called()


class TestProductionRoleEscalationDefense(unittest.TestCase):
    """Test that arbitrary role escalation is strictly blocked in production mode."""

    def test_email_prefix_attacks_fail_in_production(self):
        """Prefixes like admin-*, admin_*, or admin@attacker.com must NOT elevate in production."""
        with patch.dict(os.environ, {
            "LINUXOPS_AUTH_MODE": "production",
            "LINUXOPS_ADMIN_USERS": "lead-secops@enterprise.com,chief-operator@enterprise.com",
        }):
            # Attempted prefix attacks
            self.assertEqual(resolve_user_role("admin-attacker@evil.com"), UserRole.VIEWER)
            self.assertEqual(resolve_user_role("admin_hacker@evil.com"), UserRole.VIEWER)
            self.assertEqual(resolve_user_role("admin@evil.com"), UserRole.VIEWER)
            self.assertEqual(resolve_user_role("admin@linuxops.local"), UserRole.VIEWER)
            self.assertEqual(resolve_user_role("fake-lead-secops@enterprise.com"), UserRole.VIEWER)

            # Legitimate whitelisted users
            self.assertEqual(resolve_user_role("lead-secops@enterprise.com"), UserRole.ADMIN)
            self.assertEqual(resolve_user_role("chief-operator@enterprise.com"), UserRole.ADMIN)

    def test_empty_admin_list_in_production_grants_zero_admins(self):
        with patch.dict(os.environ, {"LINUXOPS_AUTH_MODE": "production", "LINUXOPS_ADMIN_USERS": ""}):
            self.assertEqual(resolve_user_role("admin@enterprise.com"), UserRole.VIEWER)
            self.assertEqual(resolve_user_role("root@enterprise.com"), UserRole.VIEWER)


class TestHostIngestionSecurityBoundaries(unittest.TestCase):
    """Test host agent ingestion limits, replay protections, and data sanitization."""

    def setUp(self):
        self.secret = "test-crypto-hmac-secret-64-characters-long-and-cryptographically-sound"
        self.registry = HostRegistry()

    def test_payload_size_ceiling(self):
        """Payloads exceeding MAX_PAYLOAD_BYTES must be immediately rejected."""
        oversized = "x" * (MAX_PAYLOAD_BYTES + 1024)
        ok, msg, report = self.registry.ingest_telemetry_payload(oversized, "fake-sig")
        self.assertFalse(ok)
        self.assertIn("exceeds maximum limit", msg)
        self.assertIsNone(report)

    def test_replay_protection_past_timestamp_skew_rejected(self):
        """Payload timestamp older than MAX_TIMESTAMP_SKEW_SECONDS must be rejected."""
        with patch.dict(os.environ, {"LINUXOPS_AGENT_SECRET": self.secret}):
            old_time = (datetime.now(timezone.utc) - timedelta(seconds=MAX_TIMESTAMP_SKEW_SECONDS + 60)).isoformat()
            data = {"host_id": "h1", "hostname": "web-1", "timestamp_iso": old_time, "containers": []}
            raw = json.dumps(data)
            sig = hmac.new(self.secret.encode(), raw.encode(), hashlib.sha256).hexdigest()

            ok, msg, report = self.registry.ingest_telemetry_payload(raw, sig)
            self.assertFalse(ok)
            self.assertIn("Replay Protection", msg)
            self.assertIsNone(report)

    def test_replay_protection_future_timestamp_skew_rejected(self):
        """Payload timestamp far in the future must be rejected."""
        with patch.dict(os.environ, {"LINUXOPS_AGENT_SECRET": self.secret}):
            future_time = (datetime.now(timezone.utc) + timedelta(seconds=MAX_TIMESTAMP_SKEW_SECONDS + 60)).isoformat()
            data = {"host_id": "h1", "hostname": "web-1", "timestamp_iso": future_time, "containers": []}
            raw = json.dumps(data)
            sig = hmac.new(self.secret.encode(), raw.encode(), hashlib.sha256).hexdigest()

            ok, msg, report = self.registry.ingest_telemetry_payload(raw, sig)
            self.assertFalse(ok)
            self.assertIn("Replay Protection", msg)
            self.assertIsNone(report)

    def test_container_capacity_limit_enforced(self):
        """Reports containing more than MAX_CONTAINERS_PER_REPORT must be rejected."""
        with patch.dict(os.environ, {"LINUXOPS_AGENT_SECRET": self.secret}):
            containers = [{"id": f"c_{i}", "name": f"cont-{i}", "state": "running"} for i in range(MAX_CONTAINERS_PER_REPORT + 5)]
            data = {
                "host_id": "h1",
                "hostname": "big-node",
                "timestamp_iso": datetime.now(timezone.utc).isoformat(),
                "containers": containers,
            }
            raw = json.dumps(data)
            sig = hmac.new(self.secret.encode(), raw.encode(), hashlib.sha256).hexdigest()

            ok, msg, report = self.registry.ingest_telemetry_payload(raw, sig)
            self.assertFalse(ok)
            self.assertIn("exceeds capacity limit", msg)
            self.assertIsNone(report)

    def test_missing_agent_secret_in_production_fails_closed(self):
        """In production mode, an ingestion attempt without a configured LINUXOPS_AGENT_SECRET must fail closed."""
        with patch.dict(os.environ, {"LINUXOPS_AUTH_MODE": "production", "LINUXOPS_AGENT_SECRET": ""}):
            raw = json.dumps({"host_id": "h1", "timestamp_iso": datetime.now(timezone.utc).isoformat(), "containers": []})
            ok, msg, report = self.registry.ingest_telemetry_payload(raw, "any-sig")
            self.assertFalse(ok)
            self.assertIn("Server Security Misconfiguration", msg)
            self.assertIsNone(report)

    def test_command_injection_directives_rejected(self):
        """Payloads containing remote command execution directives must fail closed."""
        with patch.dict(os.environ, {"LINUXOPS_AGENT_SECRET": self.secret}):
            for injection_key in ("command", "execute", "eval", "action"):
                data = {
                    "host_id": "malicious-node",
                    "timestamp_iso": datetime.now(timezone.utc).isoformat(),
                    injection_key: "cat /etc/passwd",
                    "containers": [],
                }
                raw = json.dumps(data)
                sig = hmac.new(self.secret.encode(), raw.encode(), hashlib.sha256).hexdigest()

                ok, msg, report = self.registry.ingest_telemetry_payload(raw, sig)
                self.assertFalse(ok)
                self.assertIn("Security Violation", msg)


class TestCrossUserApprovalIsolation(unittest.TestCase):
    """Test user session scoping and cross-user approval isolation."""

    def test_distinct_session_keys_per_user(self):
        user_alpha = AuthenticatedUser("alpha@corp.com", "Alpha", UserRole.ADMIN)
        user_beta = AuthenticatedUser("beta@corp.com", "Beta", UserRole.ADMIN)

        key_alpha = get_user_session_key("active_approval_token", user_alpha)
        key_beta = get_user_session_key("active_approval_token", user_beta)

        self.assertNotEqual(key_alpha, key_beta)
        self.assertIn("alpha@corp.com", key_alpha)
        self.assertIn("beta@corp.com", key_beta)

    @patch("streamlit.session_state", new_callable=dict)
    def test_logout_wipes_all_user_and_legacy_tokens(self, mock_state):
        user = AuthenticatedUser("alice@corp.com", "Alice", UserRole.ADMIN)
        mock_state["usr_alice@corp.com_active_approval_token"] = "tok-alice"
        mock_state["usr_alice@corp.com_approved_plan_hash"] = "hash-alice"
        mock_state["active_approval_token"] = "tok-alice"
        mock_state["approved_plan_hash"] = "hash-alice"
        mock_state["_authenticated_dev_user"] = {"email": "alice@corp.com"}

        with patch("streamlit.rerun"):
            logout_current_user(user)

        self.assertNotIn("usr_alice@corp.com_active_approval_token", mock_state)
        self.assertNotIn("usr_alice@corp.com_approved_plan_hash", mock_state)
        self.assertNotIn("active_approval_token", mock_state)
        self.assertNotIn("approved_plan_hash", mock_state)
        self.assertNotIn("_authenticated_dev_user", mock_state)


class TestProductionConfigurationFiles(unittest.TestCase):
    """Test deployment configuration files and security scripts."""

    def setUp(self):
        self.repo_root = Path(__file__).resolve().parent.parent

    def test_run_production_script_exists_and_executable(self):
        prod_script = self.repo_root / "scripts" / "run_production.sh"
        self.assertTrue(prod_script.is_file(), "scripts/run_production.sh must exist")
        mode = os.stat(prod_script).st_mode
        self.assertTrue(bool(mode & stat.S_IXUSR), "scripts/run_production.sh must be executable by owner")

        content = prod_script.read_text(encoding="utf-8")
        self.assertIn("LINUXOPS_AUTH_MODE", content)
        self.assertIn("LINUXOPS_RECOVERY_DISABLED", content)
        self.assertIn("--server.address", content)
        self.assertIn("--server.port", content)
        self.assertIn("--server.headless true", content)

    def test_render_yaml_validity(self):
        render_yaml = self.repo_root / "render.yaml"
        self.assertTrue(render_yaml.is_file(), "render.yaml must exist")
        content = render_yaml.read_text(encoding="utf-8")
        self.assertIn("healthCheckPath: \"/_stcore/health\"", content)
        self.assertIn("LINUXOPS_AUTH_MODE", content)
        self.assertIn("LINUXOPS_RECOVERY_DISABLED", content)
        self.assertIn("sync: false", content)

    def test_procfile_validity(self):
        procfile = self.repo_root / "Procfile"
        self.assertTrue(procfile.is_file(), "Procfile must exist")
        content = procfile.read_text(encoding="utf-8").strip()
        self.assertEqual(content, "web: ./scripts/run_production.sh")

    def test_dockerfile_security_invariants(self):
        dockerfile = self.repo_root / "Dockerfile"
        self.assertTrue(dockerfile.is_file(), "Dockerfile must exist")
        content = dockerfile.read_text(encoding="utf-8")
        self.assertIn("USER linuxops", content, "Container must run as non-root user")
        self.assertIn("HEALTHCHECK", content, "Dockerfile must define a health check")
        self.assertIn("/_stcore/health", content)

    def test_production_env_template_contains_only_placeholders(self):
        env_example = self.repo_root / ".env.production.example"
        self.assertTrue(env_example.is_file(), ".env.production.example must exist")
        content = env_example.read_text(encoding="utf-8")
        self.assertIn("REPLACE_WITH_", content)
        self.assertIn("LINUXOPS_AUTH_MODE=production", content)
        self.assertIn("LINUXOPS_RECOVERY_DISABLED=1", content)
        # Verify no real secrets leaked
        self.assertNotIn("ghp_", content)
        self.assertNotIn("AKIA", content)
        self.assertNotIn("AIza", content)


if __name__ == "__main__":
    unittest.main()
