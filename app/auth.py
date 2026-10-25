#!/usr/bin/env python3

"""
LinuxOps Authentication & Role-Based Access Control (RBAC) Module.

Provides enterprise-grade security for internet and intranet deployments:
- Native Streamlit OpenID Connect (OIDC) integration for production (st.login / st.logout / st.user).
- Deterministic role-based authorization (ADMIN vs VIEWER).
- Fail-closed security: unauthenticated access is strictly blocked.
- User session isolation: approvals, tokens, and settings scoped to the authenticated identity.
- Local development authentication mode for offline testing and automated verification.
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import os
from typing import Any
import streamlit as st


class UserRole(str, Enum):
    """User authorization roles."""
    ADMIN = "admin"
    VIEWER = "viewer"


@dataclass
class AuthenticatedUser:
    """Represents an authenticated user identity and authorization claims."""
    email: str
    name: str
    role: UserRole
    auth_provider: str = "oidc"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN

    @property
    def is_viewer(self) -> bool:
        return self.role == UserRole.VIEWER


def get_auth_mode() -> str:
    """
    Retrieve configured authentication mode.
    Modes:
      - 'production': Strictly enforces OpenID Connect via Streamlit auth.
      - 'local_dev': Interactive development login for local WSL/test environments.
    Auto-detects cloud platforms (Render, Fly.io, Heroku) or default to 'production' if configured.
    """
    explicit = os.environ.get("LINUXOPS_AUTH_MODE", "").strip().lower()
    if explicit:
        return explicit

    # Auto-detect managed cloud hosting environments to fail closed
    if any(k in os.environ for k in ("RENDER", "DYNO", "FLY_APP_NAME", "KUBERNETES_PORT")):
        return "production"
    if os.environ.get("ENV", "").lower() == "production" or os.environ.get("PRODUCTION") == "1":
        return "production"

    return "local_dev"


def get_configured_admin_emails() -> set[str]:
    """Retrieve list of admin email addresses from environment or secrets."""
    raw = os.environ.get("LINUXOPS_ADMIN_USERS", "")
    if not raw:
        try:
            if hasattr(st, "secrets") and "auth" in st.secrets:
                raw = st.secrets.get("auth", {}).get("admin_users", "")
        except Exception:
            raw = ""
    
    admins = {e.strip().lower() for e in str(raw).split(",") if e.strip()}
    # Always include standard admin identities in local_dev if empty
    if not admins and get_auth_mode() == "local_dev":
        admins.update({"admin@linuxops.local", "neha@linuxops.local"})
    return admins


def resolve_user_role(email: str) -> UserRole:
    """
    Determine role for an authenticated user email based on admin configuration.
    In production mode: ONLY explicitly configured emails in LINUXOPS_ADMIN_USERS / secrets are granted ADMIN.
    Arbitrary email prefixes (e.g. admin-attacker@evil.com) are NEVER granted Admin in production.
    """
    clean_email = email.strip().lower()
    admin_emails = get_configured_admin_emails()

    if clean_email in admin_emails:
        return UserRole.ADMIN

    # In local development mode ONLY, allow convenience admin aliases
    if get_auth_mode() == "local_dev":
        user_part = clean_email.split("@")[0] if "@" in clean_email else clean_email
        if user_part == "admin" or user_part.startswith("admin-") or user_part.startswith("admin_"):
            return UserRole.ADMIN

    return UserRole.VIEWER


def check_permission(user: AuthenticatedUser | None, permission: str) -> bool:
    """
    Check if user has permission to perform an operational action.
    Permissions:
      - 'remediation.approve': Approve proposed remediation plans
      - 'remediation.execute': Simulate/execute approved remediations
      - 'system.freeze_toggle': Activate or deactivate global recovery freeze switch
      - 'host.configure': Add, remove, or modify monitored host endpoints
      - 'observability.view': View container metrics, logs, and telemetry
    """
    if not user:
        return False
    
    if permission in {
        "remediation.approve",
        "remediation.execute",
        "system.freeze_toggle",
        "host.configure",
    }:
        return user.is_admin

    if permission in {"observability.view", "scenarios.switch"}:
        return True

    return False


def get_user_session_key(base_key: str, user: AuthenticatedUser | None) -> str:
    """Scope session state keys to the active user to prevent cross-user contamination."""
    user_id = user.email if user else "anonymous"
    return f"usr_{user_id}_{base_key}"


def authenticate_user() -> AuthenticatedUser | None:
    """
    Evaluate user authentication according to configured auth mode.
    Returns AuthenticatedUser if validly authenticated, or None if unauthenticated.
    """
    mode = get_auth_mode()

    # 1. Production Mode: Streamlit OpenID Connect
    if mode == "production":
        # Check if Streamlit OIDC connection is active
        if hasattr(st, "user") and getattr(st.user, "is_logged_in", False):
            email = getattr(st.user, "email", None) or "authenticated@oidc.local"
            name = getattr(st.user, "name", None) or email.split("@")[0]
            role = resolve_user_role(email)
            return AuthenticatedUser(
                email=email,
                name=name,
                role=role,
                auth_provider="oidc",
                metadata={"sub": getattr(st.user, "sub", None)},
            )
        return None

    # 2. Local Development Mode: Session-state backed dev login
    session_user = st.session_state.get("_authenticated_dev_user")
    if session_user and isinstance(session_user, dict):
        return AuthenticatedUser(
            email=session_user["email"],
            name=session_user.get("name", "Local Operator"),
            role=UserRole(session_user.get("role", UserRole.VIEWER.value)),
            auth_provider="local_dev",
            metadata=session_user.get("metadata", {}),
        )

    return None


def render_login_gate() -> AuthenticatedUser | None:
    """
    Render login interface when unauthenticated.
    Fails closed: private dashboard views must not render until this returns an AuthenticatedUser.
    """
    mode = get_auth_mode()

    st.markdown(
        """
        <div style="max-width: 520px; margin: 40px auto; padding: 24px; background: #0f172a; border: 1px solid #334155; border-radius: 12px; text-align: center; box-shadow: 0 4px 16px rgba(0,0,0,0.5);">
            <div style="font-size: 2.2rem; margin-bottom: 8px;">🔒</div>
            <div style="font-size: 1.4rem; font-weight: 800; color: #f8fafc;">LinuxOps Security Gate</div>
            <div style="font-size: 0.88rem; color: #94a3b8; margin-top: 6px; line-height: 1.4;">
                Authentication required. Unauthenticated access to operations, container telemetry, and incident diagnostics is blocked.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if mode == "production":
        # Check if secrets.toml has [auth] configured
        has_oidc_config = False
        try:
            has_oidc_config = hasattr(st, "secrets") and "auth" in st.secrets
        except Exception:
            has_oidc_config = False

        if not has_oidc_config:
            st.error(
                "🚨 **Production Authentication Configuration Missing**\n\n"
                "LinuxOps is running in `production` authentication mode, but no OpenID Connect provider "
                "is configured in `.streamlit/secrets.toml` or environment. Access failed closed."
            )
            return None

        # Offer Streamlit OIDC Login trigger
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if hasattr(st, "login"):
                if st.button("🔑 Sign in with Corporate SSO / OpenID Connect", type="primary", use_container_width=True):
                    st.login()
            else:
                st.error("Streamlit native OIDC login is not supported in this runtime.")
        return None

    # Local Development Authentication UI
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown(
            "<div style='text-align: center; color: #38bdf8; font-size: 0.82rem; font-weight: 600; margin-bottom: 12px;'>"
            "🛠️ Local Development Session Auth"
            "</div>",
            unsafe_allow_html=True,
        )

        with st.form("dev_auth_form"):
            selected_identity = st.selectbox(
                "Select Development Identity & Role",
                [
                    "Admin Operator (admin@linuxops.local) — Full Control & Remediation",
                    "Security Auditor / Viewer (viewer@linuxops.local) — Read-Only Observability",
                ],
                index=0,
            )
            custom_email = st.text_input(
                "Or Custom Email (Optional)",
                placeholder="operator@company.com",
            )
            submit_login = st.form_submit_button("🚀 Authenticate & Enter Console", type="primary", use_container_width=True)

            if submit_login:
                if custom_email.strip():
                    email = custom_email.strip().lower()
                    name = email.split("@")[0].capitalize()
                    role = resolve_user_role(email)
                elif "Admin" in selected_identity:
                    email = "admin@linuxops.local"
                    name = "Admin Operator"
                    role = UserRole.ADMIN
                else:
                    email = "viewer@linuxops.local"
                    name = "Security Auditor"
                    role = UserRole.VIEWER

                st.session_state["_authenticated_dev_user"] = {
                    "email": email,
                    "name": name,
                    "role": role.value,
                    "metadata": {"login_time": "local_session"},
                }
                st.rerun()

    return None


def logout_current_user(user: AuthenticatedUser) -> None:
    """Clear session authentication state and trigger provider logout."""
    # Clear dev auth state
    st.session_state.pop("_authenticated_dev_user", None)

    # Clear global/legacy approval tokens to prevent cross-user leakage
    st.session_state.pop("active_approval_token", None)
    st.session_state.pop("approved_plan_hash", None)
    st.session_state.pop("approved_container", None)

    # Clear user-scoped approval keys
    keys_to_remove = [k for k in st.session_state.keys() if str(k).startswith(f"usr_{user.email}")]
    for k in keys_to_remove:
        st.session_state.pop(k, None)

    # Native Streamlit OIDC logout
    if user.auth_provider == "oidc" and hasattr(st, "logout"):
        st.logout()
    else:
        st.rerun()
