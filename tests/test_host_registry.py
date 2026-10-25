#!/usr/bin/env python3

"""
Unit Tests for LinuxOps Secure Host Registry & Ingestion Interface (Phase 4).

Verifies:
- Configured host lifecycle tracking (CONNECTED, STALE, UNREACHABLE, UNCONFIGURED)
- HMAC-SHA256 authentication of outbound telemetry payloads
- Rejection of tampered signatures and missing credentials
- Security enforcement: rejection of remote command injection attempts
- Sanitization of container environment variables and sensitive log contents
"""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import unittest
from unittest.mock import MagicMock, patch

from app.host_registry import (
    DEFAULT_HOST_STALE_THRESHOLD_SECONDS,
    HostConnectionStatus,
    HostRegistry,
    HostTelemetryReport,
    sanitize_container_telemetry,
)
from scripts.linuxops_agent import build_telemetry_payload


class TestHostRegistrySecurity(unittest.TestCase):
    """Test HMAC authorization and security boundaries of host ingestion."""

    def setUp(self):
        self.secret = "test-agent-hmac-secret-32-chars-long"
        self.registry = HostRegistry()

    def test_tampered_payload_rejected(self):
        with patch.dict(os.environ, {"LINUXOPS_AGENT_SECRET": self.secret}):
            raw_payload = json.dumps({"host_id": "node-1", "hostname": "web-prod-1", "containers": []})
            valid_sig = hmac.new(self.secret.encode(), raw_payload.encode(), hashlib.sha256).hexdigest()

            # Tamper payload
            tampered_payload = json.dumps({"host_id": "node-1", "hostname": "malicious-host", "containers": []})

            ok, msg, report = self.registry.ingest_telemetry_payload(tampered_payload, valid_sig)
            self.assertFalse(ok)
            self.assertIn("Invalid HMAC", msg)
            self.assertIsNone(report)

    def test_missing_signature_rejected_when_secret_set(self):
        with patch.dict(os.environ, {"LINUXOPS_AGENT_SECRET": self.secret}):
            raw_payload = json.dumps({"host_id": "node-1", "containers": []})
            ok, msg, report = self.registry.ingest_telemetry_payload(raw_payload, "")
            self.assertFalse(ok)
            self.assertIn("Missing HMAC", msg)
            self.assertIsNone(report)

    def test_valid_signature_accepted(self):
        with patch.dict(os.environ, {"LINUXOPS_AGENT_SECRET": self.secret}):
            data = {
                "host_id": "prod-east-1",
                "hostname": "srv-prod-east-1",
                "distribution": "Fedora 44",
                "podman_version": "5.1.0",
                "kernel_version": "6.8.0",
                "timestamp_iso": datetime.now(timezone.utc).isoformat(),
                "host_metrics": {"memory_usage_percent": 45.2},
                "containers": [
                    {
                        "id": "c101",
                        "name": "api-service",
                        "state": "running",
                        "health_status": "healthy",
                        "env": ["SECRET_KEY=supersecret"],
                        "logs": ["Connected successfully with token=abc123secret"],
                    }
                ],
            }
            raw = json.dumps(data)
            sig = hmac.new(self.secret.encode(), raw.encode(), hashlib.sha256).hexdigest()

            ok, msg, report = self.registry.ingest_telemetry_payload(raw, sig)
            self.assertTrue(ok)
            self.assertIsNotNone(report)
            self.assertEqual(report.host_id, "prod-east-1")
            self.assertEqual(report.running_count, 1)

            # Confirm environment variables were stripped
            sanitized_c = report.containers[0]
            self.assertEqual(sanitized_c["env"], ["REDACTED"])
            # Confirm logs were scrubbed
            self.assertNotIn("abc123secret", sanitized_c["logs"][0])

    def test_remote_command_injection_rejected(self):
        """Telemetry payloads with command or execution directives must fail closed."""
        with patch.dict(os.environ, {"LINUXOPS_AGENT_SECRET": self.secret}):
            data = {
                "host_id": "compromised-node",
                "command": "rm -rf /",
                "containers": [],
            }
            raw = json.dumps(data)
            sig = hmac.new(self.secret.encode(), raw.encode(), hashlib.sha256).hexdigest()

            ok, msg, report = self.registry.ingest_telemetry_payload(raw, sig)
            self.assertFalse(ok)
            self.assertIn("Security Violation", msg)
            self.assertIsNone(report)


class TestHostStatusLifecycle(unittest.TestCase):
    """Test host status progression based on scan freshness."""

    def test_host_freshness_status(self):
        registry = HostRegistry()
        host = registry.register_host("host-alpha", "Alpha Node")

        # Initial status before any scan
        hosts = registry.list_hosts()
        self.assertEqual(hosts[0].status, HostConnectionStatus.UNREACHABLE)

        # Fresh telemetry received 10 seconds ago
        now = datetime.now(timezone.utc)
        fresh_ts = (now - timedelta(seconds=10)).isoformat()
        host.last_seen_iso = fresh_ts
        self.assertEqual(registry._calculate_status(host, now), HostConnectionStatus.CONNECTED)

        # Stale telemetry received 90 seconds ago (threshold is 60s)
        stale_ts = (now - timedelta(seconds=90)).isoformat()
        host.last_seen_iso = stale_ts
        self.assertEqual(registry._calculate_status(host, now), HostConnectionStatus.STALE)

        # Unreachable telemetry received 400 seconds ago
        unreachable_ts = (now - timedelta(seconds=400)).isoformat()
        host.last_seen_iso = unreachable_ts
        self.assertEqual(registry._calculate_status(host, now), HostConnectionStatus.UNREACHABLE)


class TestAgentPayloadBuilder(unittest.TestCase):
    """Test host agent telemetry collection and redaction."""

    def test_build_telemetry_payload_schema(self):
        with patch("scripts.linuxops_agent.query_podman_telemetry", return_value=([
            {"id": "c1", "name": "web", "state": "running", "health_status": "healthy", "env": ["REDACTED"]}
        ], "5.0.0")):
            payload = build_telemetry_payload("test-host-id")
            self.assertEqual(payload["host_id"], "test-host-id")
            self.assertIn("hostname", payload)
            self.assertIn("host_metrics", payload)
            self.assertIn("containers", payload)
            self.assertEqual(len(payload["containers"]), 1)
            self.assertEqual(payload["containers"][0]["env"], ["REDACTED"])


if __name__ == "__main__":
    unittest.main()
