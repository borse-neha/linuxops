#!/usr/bin/env python3

"""
Unit Tests for LinuxOps Authentication & Multi-User Isolation (Phase 2).

Verifies:
- Fail-closed security when unauthenticated
- OpenID Connect and Local Dev authentication detection
- Role resolution (Admin vs Viewer) based on configuration
- Permission matrix enforcement across operations
- User-scoped session state isolation
- Logout session clearing
- Remediation approval ownership restrictions
"""

import os
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
    resolve_user_role,
)


class TestAuthBasics(unittest.TestCase):
    """Test basic authentication parsing and role assignment."""

    def test_default_auth_mode(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(get_auth_mode(), "local_dev")

        with patch.dict(os.environ, {"LINUXOPS_AUTH_MODE": "production"}):
            self.assertEqual(get_auth_mode(), "production")

    def test_resolve_user_role(self):
        with patch.dict(os.environ, {"LINUXOPS_ADMIN_USERS": "admin@company.com,lead@company.com"}):
            self.assertEqual(resolve_user_role("admin@company.com"), UserRole.ADMIN)
            self.assertEqual(resolve_user_role("lead@company.com"), UserRole.ADMIN)
            self.assertEqual(resolve_user_role("viewer@company.com"), UserRole.VIEWER)
            self.assertEqual(resolve_user_role("guest@external.org"), UserRole.VIEWER)

    def test_admin_prefix_convention(self):
        with patch.dict(os.environ, {"LINUXOPS_ADMIN_USERS": ""}):
            self.assertEqual(resolve_user_role("admin@linuxops.local"), UserRole.ADMIN)
            self.assertEqual(resolve_user_role("admin-team@corp.net"), UserRole.ADMIN)
            self.assertEqual(resolve_user_role("user@corp.net"), UserRole.VIEWER)


class TestAuthorizationPermissions(unittest.TestCase):
    """Test role-based authorization matrix."""

    def setUp(self):
        self.admin = AuthenticatedUser(
            email="admin@test.com",
            name="Admin User",
            role=UserRole.ADMIN,
        )
        self.viewer = AuthenticatedUser(
            email="viewer@test.com",
            name="Viewer User",
            role=UserRole.VIEWER,
        )

    def test_unauthenticated_has_no_permissions(self):
        self.assertFalse(check_permission(None, "observability.view"))
        self.assertFalse(check_permission(None, "remediation.approve"))
        self.assertFalse(check_permission(None, "remediation.execute"))
        self.assertFalse(check_permission(None, "system.freeze_toggle"))

    def test_viewer_permissions(self):
        # Viewer can observe and browse
        self.assertTrue(check_permission(self.viewer, "observability.view"))
        self.assertTrue(check_permission(self.viewer, "scenarios.switch"))

        # Viewer cannot mutate or approve
        self.assertFalse(check_permission(self.viewer, "remediation.approve"))
        self.assertFalse(check_permission(self.viewer, "remediation.execute"))
        self.assertFalse(check_permission(self.viewer, "system.freeze_toggle"))
        self.assertFalse(check_permission(self.viewer, "host.configure"))

    def test_admin_permissions(self):
        # Admin has full operational capabilities
        self.assertTrue(check_permission(self.admin, "observability.view"))
        self.assertTrue(check_permission(self.admin, "scenarios.switch"))
        self.assertTrue(check_permission(self.admin, "remediation.approve"))
        self.assertTrue(check_permission(self.admin, "remediation.execute"))
        self.assertTrue(check_permission(self.admin, "system.freeze_toggle"))
        self.assertTrue(check_permission(self.admin, "host.configure"))


class TestSessionIsolationAndScoping(unittest.TestCase):
    """Test session state isolation across different users."""

    def test_user_session_scoping_keys(self):
        user_a = AuthenticatedUser("alice@test.com", "Alice", UserRole.ADMIN)
        user_b = AuthenticatedUser("bob@test.com", "Bob", UserRole.ADMIN)

        key_a = get_user_session_key("approval_token", user_a)
        key_b = get_user_session_key("approval_token", user_b)
        key_anon = get_user_session_key("approval_token", None)

        self.assertEqual(key_a, "usr_alice@test.com_approval_token")
        self.assertEqual(key_b, "usr_bob@test.com_approval_token")
        self.assertEqual(key_anon, "usr_anonymous_approval_token")
        self.assertNotEqual(key_a, key_b)

    @patch("streamlit.session_state", new_callable=dict)
    def test_logout_clears_user_scoped_session(self, mock_session):
        user = AuthenticatedUser("alice@test.com", "Alice", UserRole.ADMIN, auth_provider="local_dev")

        # Set up session state
        mock_session["_authenticated_dev_user"] = {"email": "alice@test.com", "role": "admin"}
        mock_session["usr_alice@test.com_active_approval_token"] = "tok_123"
        mock_session["usr_alice@test.com_approved_plan_hash"] = "hash_xyz"
        mock_session["global_theme"] = "dark"  # Unrelated key

        with patch("streamlit.rerun"):
            logout_current_user(user)

        self.assertNotIn("_authenticated_dev_user", mock_session)
        self.assertNotIn("usr_alice@test.com_active_approval_token", mock_session)
        self.assertNotIn("usr_alice@test.com_approved_plan_hash", mock_session)
        self.assertIn("global_theme", mock_session)


class TestFailClosedProductionAuth(unittest.TestCase):
    """Test fail-closed behavior in production auth mode."""

    @patch("streamlit.session_state", new_callable=dict)
    def test_production_mode_fails_closed_when_not_logged_in(self, mock_session):
        with patch.dict(os.environ, {"LINUXOPS_AUTH_MODE": "production"}):
            # No st.user or is_logged_in = False
            user = authenticate_user()
            self.assertIsNone(user)

    @patch("streamlit.user", create=True)
    def test_production_mode_authenticates_valid_oidc_user(self, mock_st_user):
        mock_st_user.is_logged_in = True
        mock_st_user.email = "lead-dev@corp.com"
        mock_st_user.name = "Lead Developer"
        mock_st_user.sub = "oidc-sub-12345"

        with patch.dict(os.environ, {
            "LINUXOPS_AUTH_MODE": "production",
            "LINUXOPS_ADMIN_USERS": "lead-dev@corp.com",
        }):
            user = authenticate_user()
            self.assertIsNotNone(user)
            self.assertEqual(user.email, "lead-dev@corp.com")
            self.assertEqual(user.role, UserRole.ADMIN)
            self.assertEqual(user.auth_provider, "oidc")


if __name__ == "__main__":
    unittest.main()
