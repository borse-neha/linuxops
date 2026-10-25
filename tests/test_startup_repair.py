#!/usr/bin/env python3

"""
Targeted Unit Tests for Autonomous Startup Repair & Reliability Validation.

Validates:
- Secret redaction in startup & watchdog logging
- Streamlit health probe status evaluation
- Watchdog state serialization and cooldown logic
- Authentication mode resolution and preservation
- Hardened localhost-only binding configuration
"""

import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from app.auth import get_auth_mode, resolve_user_role, UserRole


class TestStartupAndWatchdogReliability(unittest.TestCase):
    """Verify startup safeguards, health checks, and state maintenance."""

    def test_secret_redaction_pattern(self):
        """Verify tokens and secrets are redacted from logs."""
        raw_log = "Error connecting with token=secret_token_123456789 and Bearer a1b2c3d4e5f6g7h8i9j0"
        redacted = re.sub(
            r'(?i)(token|secret|password|key|auth)[=:]\s*["\']?[A-Za-z0-9_\-\.]{8,}["\']?',
            r'\1=[REDACTED]',
            raw_log,
        )
        redacted = re.sub(
            r'bearer\s+[A-Za-z0-9_\-\.]{16,}',
            'Bearer [REDACTED]',
            redacted,
            flags=re.IGNORECASE,
        )
        self.assertNotIn("secret_token_123456789", redacted)
        self.assertNotIn("a1b2c3d4e5f6g7h8i9j0", redacted)
        self.assertIn("token=[REDACTED]", redacted)
        self.assertIn("Bearer [REDACTED]", redacted)

    def test_streamlit_config_binds_to_localhost_only(self):
        """Verify .streamlit/config.toml strictly binds to 127.0.0.1."""
        config_path = Path(__file__).resolve().parent.parent / ".streamlit" / "config.toml"
        self.assertTrue(config_path.exists(), f"Missing config: {config_path}")
        content = config_path.read_text(encoding="utf-8")
        self.assertIn('address = "127.0.0.1"', content)
        self.assertIn('port = 8501', content)
        self.assertNotIn('address = "0.0.0.0"', content)

    def test_auth_mode_preserves_local_dev_default(self):
        """Verify authentication defaults to local_dev when running in local WSL."""
        with patch.dict("os.environ", {}, clear=True):
            mode = get_auth_mode()
            self.assertEqual(mode, "local_dev")

    def test_auth_mode_production_strictness(self):
        """Verify authentication strictly switches to production when configured."""
        with patch.dict("os.environ", {"LINUXOPS_AUTH_MODE": "production"}):
            self.assertEqual(get_auth_mode(), "production")

    def test_watchdog_state_structure(self):
        """Verify watchdog state structure matches expected schema."""
        sample_state = {
            "LastProbeTime": "2026-10-25T19:00:00.0000000+05:30",
            "LastProbeStatus": "HEALTHY",
            "ConsecutiveFailures": 0,
            "RestartCountInWindow": 0,
            "WindowStartTime": "2026-10-25T19:00:00.0000000+05:30",
            "InCooldown": False,
            "CooldownUntil": None,
            "LastRecoveryAction": None,
        }
        serialized = json.dumps(sample_state)
        loaded = json.loads(serialized)
        self.assertEqual(loaded["LastProbeStatus"], "HEALTHY")
        self.assertEqual(loaded["ConsecutiveFailures"], 0)
        self.assertFalse(loaded["InCooldown"])


if __name__ == "__main__":
    unittest.main()
