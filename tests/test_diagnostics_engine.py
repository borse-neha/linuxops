#!/usr/bin/env python3

"""
Unit tests for LinuxOps Root-Cause Diagnostics & Incident Analysis Engine (Phase 2).
Tests cover secret redaction, bounded log tailing, all 10 diagnostic rules,
evidence certainty scoring, port conflict detection, and incident aggregation.
"""

import unittest
from unittest.mock import MagicMock

from app import diagnostics_engine


class TestSecretRedaction(unittest.TestCase):
    """Test credential and token redaction rules."""

    def test_redact_bearer_and_auth_tokens(self):
        """Bearer tokens and Authorization headers are masked."""
        raw_bearer = "Token header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz123"
        redacted_bearer = diagnostics_engine.redact_sensitive_text(raw_bearer)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted_bearer)
        self.assertIn("[REDACTED_TOKEN]", redacted_bearer)

        raw_auth = "Authorization: CustomTokenSecret12345678"
        redacted_auth = diagnostics_engine.redact_sensitive_text(raw_auth)
        self.assertNotIn("CustomTokenSecret12345678", redacted_auth)
        self.assertIn("[REDACTED_AUTH]", redacted_auth)

    def test_redact_aws_keys(self):
        """AWS access key IDs and secret access keys are masked."""
        raw = "Error connecting to S3 using AKIAIOSFODNN7EXAMPLE with aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        redacted = diagnostics_engine.redact_sensitive_text(raw)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertNotIn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", redacted)
        self.assertIn("[REDACTED_AWS_KEY]", redacted)

    def test_redact_environment_passwords_and_secrets(self):
        """Key-value secret assignments in environment or logs are masked."""
        raw = "Starting service with DB_PASSWORD=SuperSecretPass!123 and api_key=ab12cd34ef56gh78ij90"
        redacted = diagnostics_engine.redact_sensitive_text(raw)
        self.assertNotIn("SuperSecretPass!123", redacted)
        self.assertNotIn("ab12cd34ef56gh78ij90", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_redact_empty_or_non_string(self):
        """Empty or invalid inputs return empty string without error."""
        self.assertEqual(diagnostics_engine.redact_sensitive_text(""), "")
        self.assertEqual(diagnostics_engine.redact_sensitive_text(None), "")

    def test_incident_automatic_secret_redaction(self):
        """Incident record builder automatically redacts secrets from probable_cause and evidence."""
        inc = diagnostics_engine.build_incident(
            container_name="db-prod",
            container_id="c123",
            rule_id="SAMPLE_RULE",
            category="security",
            severity="CRITICAL",
            probable_cause="Failed using Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token",
            confidence=0.9,
            evidence=["Connection error: password=SuperSecretPass!123", "key=AKIAIOSFODNN7EXAMPLE"],
            recommended_action="Rotate token=my_secret_token_123 immediately",
        )
        self.assertNotIn("SuperSecretPass!123", str(inc["evidence"]))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", str(inc["evidence"]))
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token", inc["probable_cause"])
        self.assertNotIn("my_secret_token_123", inc["recommended_action"])
        self.assertIn("[REDACTED_SECRET]", str(inc["evidence"]))


class TestBoundedLogTailing(unittest.TestCase):
    """Test bounded log retrieval with redaction and character caps."""

    def test_log_tailing_redaction_and_bounds(self):
        """Logs are truncated to character cap and sensitive tokens are redacted."""
        fake_log = "Logging user request with token=secret_auth_token_value_long\n" * 50
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = fake_log
        mock_runner.return_value.stderr = ""

        output, ok = diagnostics_engine.tail_container_logs(
            "test-worker",
            max_lines=20,
            max_chars=200,
            runner=mock_runner,
        )
        self.assertTrue(ok)
        self.assertTrue(len(output) <= 300)  # capped
        self.assertNotIn("secret_auth_token_value_long", output)

    def test_log_tailing_timeout_handling(self):
        """Timeout during log retrieval fails closed without raising exceptions."""
        import subprocess
        mock_runner = MagicMock(side_effect=subprocess.TimeoutExpired(["podman", "logs"], 5.0))
        output, ok = diagnostics_engine.tail_container_logs("test-worker", runner=mock_runner)
        self.assertFalse(ok)
        self.assertIn("timed out", output)


class TestDiagnosticRules(unittest.TestCase):
    """Test all 10 diagnostic rules individually."""

    def test_rule1_normal_stopped_container(self):
        """Container exited cleanly with exit code 0 produces INFO incident."""
        container = {
            "name": "backup-job",
            "id": "c111",
            "state": "exited",
            "exit_code": 0,
            "oom_killed": False,
        }
        incidents = diagnostics_engine.diagnose_container_record(container)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["rule_id"], "CONTAINER_STOPPED_NORMAL")
        self.assertEqual(incidents[0]["severity"], "INFO")
        self.assertTrue(incidents[0]["confidence"] >= 0.8)

    def test_rule1_nonzero_exit_code(self):
        """Container exited with non-zero exit code produces WARNING incident."""
        container = {
            "name": "worker-1",
            "id": "c222",
            "state": "exited",
            "exit_code": 2,
            "oom_killed": False,
        }
        incidents = diagnostics_engine.diagnose_container_record(container)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["rule_id"], "CONTAINER_NONZERO_EXIT")
        self.assertEqual(incidents[0]["severity"], "WARNING")

    def test_rule2_crash_loop_detected(self):
        """Container with restart_count >= 3 triggers CRITICAL crash loop rule."""
        container = {
            "name": "flapping-api",
            "id": "c333",
            "state": "running",
            "restart_count": 5,
        }
        incidents = diagnostics_engine.diagnose_container_record(container)
        crash_incs = [i for i in incidents if i["rule_id"] == "CRASH_LOOP_DETECTED"]
        self.assertEqual(len(crash_incs), 1)
        self.assertEqual(crash_incs[0]["severity"], "CRITICAL")
        self.assertIn("restart_count=5", crash_incs[0]["evidence"][0])

    def test_rule3_healthcheck_failing(self):
        """Container with health_status == 'unhealthy' produces CRITICAL incident."""
        container = {
            "name": "unhealthy-db",
            "id": "c444",
            "state": "running",
            "health_status": "unhealthy",
        }
        incidents = diagnostics_engine.diagnose_container_record(container)
        health_incs = [i for i in incidents if i["rule_id"] == "HEALTHCHECK_FAILING"]
        self.assertEqual(len(health_incs), 1)
        self.assertEqual(health_incs[0]["severity"], "CRITICAL")

    def test_rule4_oom_killed(self):
        """Container with oom_killed == True triggers CRITICAL OOM incident."""
        container = {
            "name": "memory-hog",
            "id": "c555",
            "state": "exited",
            "exit_code": 137,
            "oom_killed": True,
        }
        incidents = diagnostics_engine.diagnose_container_record(container)
        oom_incs = [i for i in incidents if i["rule_id"] == "OOM_KILLED"]
        self.assertEqual(len(oom_incs), 1)
        self.assertEqual(oom_incs[0]["severity"], "CRITICAL")
        self.assertEqual(oom_incs[0]["confidence"], 1.0)

    def test_rule4_memory_pressure_critical(self):
        """Running container with memory usage >= 95% triggers memory pressure incident."""
        container = {
            "name": "cache-service",
            "id": "c666",
            "state": "running",
            "metrics": {
                "memory_percent": {"value": 97.5, "status": "ok"},
            },
        }
        incidents = diagnostics_engine.diagnose_container_record(container)
        mem_incs = [i for i in incidents if i["rule_id"] == "MEMORY_PRESSURE_CRITICAL"]
        self.assertEqual(len(mem_incs), 1)
        self.assertEqual(mem_incs[0]["severity"], "CRITICAL")

    def test_rule5_invalid_swap_limit(self):
        """Memory-swap smaller than memory limit triggers configuration incident."""
        container = {
            "name": "bad-limits",
            "id": "c777",
            "state": "running",
            "resource_limits": {
                "memory_bytes": 100 * 1024 * 1024,
                "memory_swap_bytes": 50 * 1024 * 1024,  # swap < memory!
            },
        }
        incidents = diagnostics_engine.diagnose_container_record(container)
        swap_incs = [i for i in incidents if i["rule_id"] == "INVALID_SWAP_LIMIT"]
        self.assertEqual(len(swap_incs), 1)
        self.assertEqual(swap_incs[0]["severity"], "WARNING")

    def test_rule6_missing_bind_mount_source(self):
        """Bind mount whose host source path does not exist triggers CRITICAL incident."""
        container = {
            "name": "storage-app",
            "id": "c888",
            "state": "running",
            "mounts": [
                {
                    "type": "bind",
                    "source": "/non/existent/host/data_dir",
                    "destination": "/app/data",
                }
            ],
        }
        # Fake checker returning False for missing path
        mock_checker = lambda p: False
        incidents = diagnostics_engine.diagnose_container_record(
            container,
            host_source_checker=mock_checker,
        )
        mount_incs = [i for i in incidents if i["rule_id"] == "MISSING_BIND_MOUNT_SOURCE"]
        self.assertEqual(len(mount_incs), 1)
        self.assertEqual(mount_incs[0]["severity"], "CRITICAL")
        self.assertIn("/non/existent/host/data_dir", mount_incs[0]["probable_cause"])

    def test_rule8_port_conflict_detected(self):
        """Two running containers binding the same host port triggers port conflict incident."""
        c1 = {
            "name": "app-v1",
            "id": "c1",
            "state": "running",
            "ports": {"80/tcp": ["0.0.0.0:8080"]},
        }
        c2 = {
            "name": "app-v2",
            "id": "c2",
            "state": "running",
            "ports": {"80/tcp": ["0.0.0.0:8080"]},
        }
        incidents = diagnostics_engine.diagnose_container_record(c1, all_containers=[c1, c2])
        port_incs = [i for i in incidents if i["rule_id"] == "PORT_CONFLICT_DETECTED"]
        self.assertEqual(len(port_incs), 1)
        self.assertEqual(port_incs[0]["severity"], "CRITICAL")
        self.assertIn("app-v2", port_incs[0]["probable_cause"])

    def test_rule10_runtime_inspection_failure(self):
        """Container record with inspection_status='failed' triggers runtime inspection incident."""
        container = {
            "name": "disappeared-worker",
            "id": "c999",
            "inspection_status": "failed",
            "error": "Podman daemon inspect error (container deleted concurrently)",
        }
        incidents = diagnostics_engine.diagnose_container_record(container)
        insp_incs = [i for i in incidents if i["rule_id"] == "RUNTIME_INSPECTION_FAILURE"]
        self.assertEqual(len(insp_incs), 1)
        self.assertEqual(insp_incs[0]["severity"], "WARNING")


class TestIncidentAggregation(unittest.TestCase):
    """Test incident aggregation across multiple container records."""

    def test_diagnose_all_containers_summary(self):
        """Aggregated report computes incident counts, severities, and container mappings."""
        containers = [
            {"name": "c1", "id": "1", "state": "exited", "exit_code": 0, "oom_killed": False},
            {"name": "c2", "id": "2", "state": "running", "restart_count": 4},
            {"name": "c3", "id": "3", "state": "exited", "exit_code": 137, "oom_killed": True},
        ]
        report = diagnostics_engine.diagnose_all_containers(containers)
        self.assertEqual(report["total_incidents"], 3)
        self.assertEqual(report["critical_count"], 2)  # crash loop + OOM
        self.assertEqual(report["info_count"], 1)      # normal exit
        self.assertEqual(report["affected_containers_count"], 3)
        self.assertIn("c2", report["incidents_by_container"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
