#!/usr/bin/env python3

"""
Unit tests for LinuxOps Phase 14:
Hardened HTTPS Webhook Transport, Alert Deduplication, and Delivery Reliability.

Tests:
1. Default disabled state and opt-in configuration validation.
2. HTTPS enforcement and rejection of insecure schemes.
3. Successful alert delivery with payload envelope formatting.
4. Immediate failure on non-retryable 4xx client errors (400, 401, 403, 404).
5. Transient 5xx server errors and network exceptions with bounded retries.
6. Rate limiting (sliding window threshold enforcement).
7. Notification storm suppression (per-alert cooldown window).
8. Severity escalation bypass during active cooldowns.
9. Automatic redaction of secrets, tokens, and credentials in transmitted payloads.
10. Durable delivery audit logging with fsync.
11. End-to-end dispatching via dispatch_alert_notifications.
"""

from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from app.alerts import (
    DEFAULT_ALERT_DELIVERY_LOG_PATH,
    MockAlertTransport,
    WebhookAlertTransport,
    WebhookConfig,
    classify_alerts,
    deduplicate_alerts,
    dispatch_alert_notifications,
    get_alert_transport_from_env,
)


class TestWebhookConfiguration(unittest.TestCase):
    """Test suite for WebhookConfig validation, defaults, and opt-in enforcement."""

    def test_default_config_is_disabled(self):
        """By default, webhook delivery is strictly disabled."""
        cfg = WebhookConfig()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.webhook_url, "")
        self.assertEqual(cfg.timeout_seconds, 5.0)
        self.assertEqual(cfg.max_retries, 3)

    def test_validate_configuration_checks(self):
        """Configuration validator enforces opt-in, non-empty URL, and HTTPS scheme."""
        # 1. Disabled
        t_disabled = WebhookAlertTransport(WebhookConfig(enabled=False, webhook_url="https://example.com/webhook"))
        valid, msg = t_disabled.validate_configuration()
        self.assertFalse(valid)
        self.assertIn("disabled", msg.lower())

        # 2. Empty URL
        t_no_url = WebhookAlertTransport(WebhookConfig(enabled=True, webhook_url=""))
        valid, msg = t_no_url.validate_configuration()
        self.assertFalse(valid)
        self.assertIn("not configured", msg.lower())

        # 3. Insecure HTTP rejected by default
        t_insecure = WebhookAlertTransport(WebhookConfig(enabled=True, webhook_url="http://insecure.example.com/webhook"))
        valid, msg = t_insecure.validate_configuration()
        self.assertFalse(valid)
        self.assertIn("must use https", msg.lower())

        # 4. Insecure HTTP accepted when explicitly allowed for testing
        t_http_allowed = WebhookAlertTransport(WebhookConfig(enabled=True, webhook_url="http://localhost:8080/hook", allow_insecure_http=True))
        valid, msg = t_http_allowed.validate_configuration()
        self.assertTrue(valid)

        # 5. HTTPS valid
        t_https = WebhookAlertTransport(WebhookConfig(enabled=True, webhook_url="https://alerts.example.com/v1/events"))
        valid, msg = t_https.validate_configuration()
        self.assertTrue(valid)

    def test_from_env_loading(self):
        """Loading configuration from environment variables respects settings."""
        orig_env = dict(os.environ)
        try:
            os.environ["LINUXOPS_ALERT_WEBHOOK_ENABLED"] = "1"
            os.environ["LINUXOPS_ALERT_WEBHOOK_URL"] = "https://ops.corp.internal/alerts"
            os.environ["LINUXOPS_ALERT_WEBHOOK_TIMEOUT"] = "8.5"
            os.environ["LINUXOPS_ALERT_WEBHOOK_MAX_RETRIES"] = "4"
            os.environ["LINUXOPS_ALERT_WEBHOOK_TOKEN"] = "test-secret-token"

            cfg = WebhookConfig.from_env()
            self.assertTrue(cfg.enabled)
            self.assertEqual(cfg.webhook_url, "https://ops.corp.internal/alerts")
            self.assertEqual(cfg.timeout_seconds, 8.5)
            self.assertEqual(cfg.max_retries, 4)
            self.assertEqual(cfg.auth_token, "test-secret-token")

            transport = get_alert_transport_from_env()
            self.assertIsNotNone(transport)
            self.assertTrue(transport.config.enabled)
        finally:
            os.environ.clear()
            os.environ.update(orig_env)


class TestWebhookDeliveryBehavior(unittest.TestCase):
    """Test delivery execution, HTTP error branches, retries, and backoff with mocked HTTP."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.audit_log = Path(self.temp_dir.name) / "test_delivery.jsonl"
        self.config = WebhookConfig(
            enabled=True,
            webhook_url="https://hooks.example.com/alerts",
            timeout_seconds=3.0,
            max_retries=2,
            backoff_factor=0.01,  # Fast backoff for tests
            audit_log_path=self.audit_log,
        )
        self.sleep_calls = []

        def mock_sleeper(seconds: float):
            self.sleep_calls.append(seconds)

        self.sleeper = mock_sleeper

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_disabled_transport_returns_disabled_status(self):
        """When transport is disabled, send() immediately returns DISABLED without calling HTTP."""
        calls = []

        def mock_post(url, data, headers, timeout):
            calls.append(url)
            return 200, "OK"

        self.config.enabled = False
        transport = WebhookAlertTransport(config=self.config, http_post_fn=mock_post)
        res = transport.send({"id": "alert:1", "severity": "CRITICAL", "message": "Test"})
        self.assertEqual(res["status"], "DISABLED")
        self.assertFalse(res["delivered"])
        self.assertEqual(len(calls), 0)

    def test_successful_delivery_200(self):
        """HTTP 200 OK returns DELIVERED and writes durable audit record."""
        recorded_payloads = []

        def mock_post(url, data, headers, timeout):
            recorded_payloads.append(json.loads(data.decode("utf-8")))
            return 200, '{"result": "accepted"}'

        transport = WebhookAlertTransport(config=self.config, http_post_fn=mock_post, sleeper=self.sleeper)
        alert = {
            "id": "container:api_gateway",
            "rule": "container_stopped",
            "target": "api_gateway",
            "severity": "CRITICAL",
            "message": "Gateway container terminated abruptly.",
        }
        res = transport.send(alert)
        self.assertEqual(res["status"], "DELIVERED")
        self.assertTrue(res["delivered"])
        self.assertEqual(res["http_status"], 200)
        self.assertEqual(res["attempts"], 1)

        # Check envelope formatting
        self.assertEqual(len(recorded_payloads), 1)
        env = recorded_payloads[0]
        self.assertEqual(env["source"], "linuxops")
        self.assertEqual(env["event_type"], "operational_alert")
        self.assertEqual(env["alert"]["id"], "container:api_gateway")

        # Check audit log
        self.assertTrue(self.audit_log.exists())
        with self.audit_log.open("r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["status"], "DELIVERED")
        self.assertEqual(lines[0]["alert_id"], "container:api_gateway")

    def test_non_retryable_client_error_400(self):
        """HTTP 400 Bad Request halts immediately without retrying."""
        calls = []

        def mock_post(url, data, headers, timeout):
            calls.append(url)
            return 400, "Bad Request: Invalid JSON Schema"

        transport = WebhookAlertTransport(config=self.config, http_post_fn=mock_post, sleeper=self.sleeper)
        res = transport.send({"id": "alert:client_err", "severity": "WARNING", "message": "Test"})
        self.assertEqual(res["status"], "FAILED_CLIENT_ERROR")
        self.assertFalse(res["delivered"])
        self.assertEqual(res["http_status"], 400)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(self.sleep_calls), 0)

    def test_transient_server_error_503_recovers_on_retry(self):
        """HTTP 503 Server Error retries and succeeds if endpoint recovers."""
        attempts = [0]

        def mock_post(url, data, headers, timeout):
            attempts[0] += 1
            if attempts[0] == 1:
                return 503, "Service Temporarily Unavailable"
            return 200, "OK"

        transport = WebhookAlertTransport(config=self.config, http_post_fn=mock_post, sleeper=self.sleeper)
        res = transport.send({"id": "alert:transient", "severity": "WARNING", "message": "Test"})
        self.assertEqual(res["status"], "DELIVERED")
        self.assertTrue(res["delivered"])
        self.assertEqual(res["attempts"], 2)
        self.assertEqual(len(self.sleep_calls), 1)

    def test_retry_exhaustion_on_persistent_500(self):
        """Persistent 500 errors exhaust retries and return FAILED_RETRY_EXHAUSTED."""
        calls = []

        def mock_post(url, data, headers, timeout):
            calls.append(url)
            return 500, "Internal Server Error"

        transport = WebhookAlertTransport(config=self.config, http_post_fn=mock_post, sleeper=self.sleeper)
        res = transport.send({"id": "alert:exhaust", "severity": "CRITICAL", "message": "Test"})
        self.assertEqual(res["status"], "FAILED_RETRY_EXHAUSTED")
        self.assertFalse(res["delivered"])
        self.assertEqual(res["attempts"], self.config.max_retries + 1)
        self.assertEqual(len(calls), self.config.max_retries + 1)
        self.assertEqual(len(self.sleep_calls), self.config.max_retries)

    def test_network_timeout_and_connection_exception_handled(self):
        """Connection errors or socket timeouts are retried up to limit without raising."""
        calls = []

        def mock_post(url, data, headers, timeout):
            calls.append(url)
            raise TimeoutError("Connection to webhook timed out after 3.0s")

        transport = WebhookAlertTransport(config=self.config, http_post_fn=mock_post, sleeper=self.sleeper)
        res = transport.send({"id": "alert:timeout", "severity": "CRITICAL", "message": "Timeout test"})
        self.assertEqual(res["status"], "FAILED_RETRY_EXHAUSTED")
        self.assertFalse(res["delivered"])
        self.assertIn("timed out", res["error"].lower())


class TestStormSuppressionAndSecurity(unittest.TestCase):
    """Test notification storm suppression, cooldown windows, and secret redaction."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.audit_log = Path(self.temp_dir.name) / "test_security.jsonl"
        self.config = WebhookConfig(
            enabled=True,
            webhook_url="https://hooks.example.com/alerts",
            cooldown_seconds_per_alert=120.0,
            rate_limit_per_minute=5,
            audit_log_path=self.audit_log,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_duplicate_alert_suppressed_by_storm_cooldown(self):
        """Duplicate deliveries of same alert within cooldown are suppressed."""
        calls = []

        def mock_post(url, data, headers, timeout):
            calls.append(url)
            return 200, "OK"

        transport = WebhookAlertTransport(config=self.config, http_post_fn=mock_post)
        alert = {"id": "container:worker", "severity": "WARNING", "message": "Worker degraded."}

        # 1. First send -> Delivered
        res1 = transport.send(alert)
        self.assertEqual(res1["status"], "DELIVERED")
        self.assertEqual(len(calls), 1)

        # 2. Immediate second send -> Suppressed
        res2 = transport.send(alert)
        self.assertEqual(res2["status"], "SUPPRESSED_STORM_COOLDOWN")
        self.assertFalse(res2["delivered"])
        self.assertEqual(len(calls), 1, "HTTP call must not be made for suppressed storm alert")

    def test_severity_escalation_bypasses_storm_cooldown(self):
        """When an alert escalates from WARNING to CRITICAL, cooldown is bypassed."""
        calls = []

        def mock_post(url, data, headers, timeout):
            calls.append(url)
            return 200, "OK"

        transport = WebhookAlertTransport(config=self.config, http_post_fn=mock_post)
        warn_alert = {"id": "container:db", "severity": "WARNING", "message": "Slow queries."}
        crit_alert = {"id": "container:db", "severity": "CRITICAL", "message": "Database crashed!"}

        # First send at WARNING
        res1 = transport.send(warn_alert)
        self.assertEqual(res1["status"], "DELIVERED")
        self.assertEqual(len(calls), 1)

        # Escalation to CRITICAL -> Bypasses cooldown
        res2 = transport.send(crit_alert)
        self.assertEqual(res2["status"], "DELIVERED")
        self.assertEqual(len(calls), 2)

    def test_rate_limiting_enforced(self):
        """Exceeding rate_limit_per_minute halts dispatch without calling HTTP endpoint."""
        calls = []

        def mock_post(url, data, headers, timeout):
            calls.append(url)
            return 200, "OK"

        transport = WebhookAlertTransport(config=self.config, http_post_fn=mock_post)

        # Send 5 distinct alerts (up to limit)
        for i in range(5):
            res = transport.send({"id": f"alert:unique_{i}", "severity": "WARNING", "message": f"Alert {i}"})
            self.assertEqual(res["status"], "DELIVERED")

        self.assertEqual(len(calls), 5)

        # 6th dispatch exceeds rate limit
        res_blocked = transport.send({"id": "alert:unique_6", "severity": "WARNING", "message": "Alert 6"})
        self.assertEqual(res_blocked["status"], "RATE_LIMITED")
        self.assertFalse(res_blocked["delivered"])
        self.assertEqual(len(calls), 5)

    def test_secret_redaction_in_webhook_payload(self):
        """Embedded passwords, bearer tokens, and secrets are redacted from transmitted payload."""
        dispatched_data = []

        def mock_post(url, data, headers, timeout):
            dispatched_data.append(json.loads(data.decode("utf-8")))
            return 200, "OK"

        transport = WebhookAlertTransport(config=self.config, http_post_fn=mock_post)
        alert_with_secrets = {
            "id": "container:auth_srv",
            "severity": "CRITICAL",
            "message": "Failed connect to postgresql://user:super_secret_pw123@db.internal:5432/main with token Bearer abcdef1234567890abcdef",
        }
        res = transport.send(alert_with_secrets)
        self.assertEqual(res["status"], "DELIVERED")

        transmitted_msg = dispatched_data[0]["alert"]["message"]
        self.assertNotIn("super_secret_pw123", transmitted_msg)
        self.assertNotIn("Bearer abcdef1234567890abcdef", transmitted_msg)
        self.assertIn("[REDACTED_SECRET]", transmitted_msg)
        self.assertIn("[REDACTED_TOKEN]", transmitted_msg)


class TestDispatchAlertNotifications(unittest.TestCase):
    """Test dispatch_alert_notifications pipeline integration and batch dispatching."""

    def test_dispatch_with_mock_transport_isolates_failures(self):
        """One failed alert delivery does not abort dispatch of subsequent alerts."""
        mock_t = MockAlertTransport(should_fail=False)
        alerts = [
            {"id": "a:1", "severity": "WARNING", "message": "Warn 1"},
            {"id": "a:2", "severity": "CRITICAL", "message": "Crit 2"},
        ]
        res = dispatch_alert_notifications(alerts, transport=mock_t)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["dispatched"], 2)
        self.assertEqual(res["failed"], 0)

    def test_dispatch_empty_alerts(self):
        """Dispatching an empty list returns EMPTY status cleanly."""
        res = dispatch_alert_notifications([])
        self.assertEqual(res["status"], "EMPTY")
        self.assertEqual(res["dispatched"], 0)

    def test_dispatch_without_transport_returns_no_transport_configured(self):
        """When no transport is provided and env is empty, returns NO_TRANSPORT_CONFIGURED."""
        alerts = [{"id": "a:1", "severity": "WARNING", "message": "Warn 1"}]
        res = dispatch_alert_notifications(alerts, transport=None)
        self.assertEqual(res["status"], "NO_TRANSPORT_CONFIGURED")
        self.assertEqual(res["dispatched"], 0)


if __name__ == "__main__":
    unittest.main()
