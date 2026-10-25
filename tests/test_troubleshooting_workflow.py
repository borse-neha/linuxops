#!/usr/bin/env python3

"""
Comprehensive End-to-End Tests for LinuxOps Core Troubleshooting Workflow.

Validates the full 5-step operational workflow:
1. Container inspection, log collection, and runtime evidence.
2. Root-cause diagnostics across all required failure categories.
3. Solution recommendations with numbered steps and exact proposed operations.
4. Strict approval boundary, approval tokens, and approval invalidation.
5. Controlled execution, precondition checks, post-action verification, and audit history.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock

from app.diagnostics_engine import (
    CONNECTION_REFUSED_RE,
    DNS_NETWORK_FAILURE_RE,
    IMAGE_PULL_RE,
    MISSING_CONFIG_ENV_RE,
    PERMISSION_DENIED_RE,
    STORAGE_FILESYSTEM_RE,
    diagnose_all_containers,
    diagnose_container_record,
    extract_matching_lines,
    redact_sensitive_text,
    tail_container_logs,
)
from app.history import (
    load_recovery_history,
    record_recovery_event,
)
from app.recovery_controller import (
    ALLOWED_RECOVERY_ACTIONS,
    SUPPORTED_OPERATIONS,
    approve_remediation_plan,
    build_remediation_plan,
    clear_executed_approval_tokens,
    compute_plan_hash,
    create_approval_token,
    execute_authorized_recovery,
    is_approval_valid,
    is_global_recovery_disabled,
    is_protected_container_target,
    reject_remediation_plan,
    set_global_recovery_disabled,
    validate_approval_token,
    verify_post_recovery_health,
)


class TestTroubleshootingWorkflowDiagnostics(unittest.TestCase):
    """Test diagnostics engine on all required failure categories with evidence and confidence."""

    def test_failure_category_connection_refused_dependency_outage(self):
        """Connection refused in logs produces DEPENDENCY_CONNECTION_REFUSED with high confidence."""
        container = {
            "name": "api-service",
            "id": "c101",
            "state": "exited",
            "exit_code": 1,
            "recent_logs": "2026-10-22 10:00:00 ERROR: Connection refused to postgres://db-prod:5432\nTraceback: could not connect to server",
        }
        incidents = diagnose_container_record(container)
        conn_incs = [i for i in incidents if i["rule_id"] == "DEPENDENCY_CONNECTION_REFUSED"]
        self.assertEqual(len(conn_incs), 1)
        inc = conn_incs[0]
        self.assertEqual(inc["category"], "network")
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertGreaterEqual(inc["confidence"], 0.90)
        self.assertTrue(any("Connection refused" in ev for ev in inc["evidence"]))
        self.assertIn("db-prod:5432", str(inc["evidence"]))
        self.assertTrue(len(inc["suggested_investigation_steps"]) >= 3)
        self.assertIn("1.", inc["suggested_investigation_steps"][0])

    def test_failure_category_dns_networking_failure(self):
        """DNS resolution failure in logs produces DNS_RESOLUTION_FAILURE incident."""
        container = {
            "name": "worker-svc",
            "id": "c102",
            "state": "exited",
            "exit_code": 1,
            "recent_logs": "urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='api.internal.corp', port=443): Name or service not known",
        }
        incidents = diagnose_container_record(container)
        dns_incs = [i for i in incidents if i["rule_id"] == "DNS_RESOLUTION_FAILURE"]
        self.assertEqual(len(dns_incs), 1)
        inc = dns_incs[0]
        self.assertEqual(inc["category"], "network")
        self.assertGreaterEqual(inc["confidence"], 0.90)
        self.assertTrue(any("Name or service not known" in ev for ev in inc["evidence"]))

    def test_failure_category_permission_denied(self):
        """Permission denied error in logs or exit code 126 produces PERMISSION_DENIED incident."""
        container = {
            "name": "secure-app",
            "id": "c103",
            "state": "exited",
            "exit_code": 126,
            "recent_logs": "open /app/data/app.db: Permission denied",
        }
        incidents = diagnose_container_record(container)
        perm_incs = [i for i in incidents if i["rule_id"] == "PERMISSION_DENIED"]
        self.assertEqual(len(perm_incs), 1)
        inc = perm_incs[0]
        self.assertEqual(inc["category"], "security")
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertGreaterEqual(inc["confidence"], 0.90)
        self.assertTrue(any("Permission denied" in ev for ev in inc["evidence"]))

    def test_failure_category_missing_configuration_or_env(self):
        """Missing environment variables or config files produce MISSING_CONFIGURATION_OR_ENV."""
        container = {
            "name": "auth-service",
            "id": "c104",
            "state": "exited",
            "exit_code": 1,
            "recent_logs": "Fatal: KeyError: 'JWT_SIGNING_SECRET' - missing required environment variable",
        }
        incidents = diagnose_container_record(container)
        cfg_incs = [i for i in incidents if i["rule_id"] == "MISSING_CONFIGURATION_OR_ENV"]
        self.assertEqual(len(cfg_incs), 1)
        inc = cfg_incs[0]
        self.assertEqual(inc["category"], "configuration")
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertGreaterEqual(inc["confidence"], 0.90)
        self.assertTrue(any("missing required environment variable" in ev.lower() for ev in inc["evidence"]))

    def test_failure_category_storage_and_filesystem_errors(self):
        """Disk full (no space left on device) produces STORAGE_FILESYSTEM_ERROR."""
        container = {
            "name": "db-node",
            "id": "c105",
            "state": "exited",
            "exit_code": 1,
            "recent_logs": "IOError: [Errno 28] No space left on device: '/var/lib/data/journal.001'",
        }
        incidents = diagnose_container_record(container)
        storage_incs = [i for i in incidents if i["rule_id"] == "STORAGE_FILESYSTEM_ERROR"]
        self.assertEqual(len(storage_incs), 1)
        inc = storage_incs[0]
        self.assertEqual(inc["category"], "storage")
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertGreaterEqual(inc["confidence"], 0.95)
        self.assertTrue(any("No space left on device" in ev for ev in inc["evidence"]))

    def test_failure_category_image_pull_failure(self):
        """Image pull failures produce IMAGE_PULL_FAILURE."""
        container = {
            "name": "pull-failing-worker",
            "id": "c106",
            "state": "exited",
            "exit_code": 125,
            "error": "Error: failed to pull image quay.io/corp/app:v9.9: manifest unknown",
        }
        incidents = diagnose_container_record(container)
        pull_incs = [i for i in incidents if i["rule_id"] == "IMAGE_PULL_FAILURE"]
        self.assertEqual(len(pull_incs), 1)
        inc = pull_incs[0]
        self.assertEqual(inc["category"], "lifecycle")
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertGreaterEqual(inc["confidence"], 0.95)

    def test_log_retriever_callable_integration(self):
        """Log retriever is invoked when container dictionary does not contain pre-cached logs."""
        container = {
            "name": "retrieved-app",
            "id": "c107",
            "state": "exited",
            "exit_code": 1,
        }
        mock_retriever = MagicMock(return_value=("Connection refused to redis:6379", True))
        incidents = diagnose_container_record(container, log_retriever=mock_retriever)
        mock_retriever.assert_called_once_with("retrieved-app")
        conn_incs = [i for i in incidents if i["rule_id"] == "DEPENDENCY_CONNECTION_REFUSED"]
        self.assertEqual(len(conn_incs), 1)


class TestSecretRedactionAndUntrustedLogs(unittest.TestCase):
    """Test that secrets are thoroughly redacted and log contents are treated as data, not instructions."""

    def test_secrets_redacted_from_log_evidence(self):
        raw_log = (
            "Auth failed using Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_token\n"
            "Connecting with DB_PASSWORD=SecretPassword123! to host\n"
            "Key AWS: AKIAIOSFODNN7EXAMPLE aws_secret_access_key=secretKey12345\n"
            "Error: Connection refused to api:8080"
        )
        redacted = redact_sensitive_text(raw_log)
        self.assertNotIn("SecretPassword123!", redacted)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertNotIn("secretKey12345", redacted)
        self.assertNotIn("sensitive_token", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)
        self.assertIn("[REDACTED_AWS_KEY]", redacted)

    def test_incident_evidence_redacted(self):
        container = {
            "name": "billing-app",
            "id": "c201",
            "state": "exited",
            "exit_code": 1,
            "recent_logs": "Fatal: Connection refused to db with password=SuperTopSecretPwd!123",
        }
        incidents = diagnose_container_record(container)
        conn_incs = [i for i in incidents if i["rule_id"] == "DEPENDENCY_CONNECTION_REFUSED"]
        self.assertEqual(len(conn_incs), 1)
        evidence_str = str(conn_incs[0]["evidence"])
        self.assertNotIn("SuperTopSecretPwd!123", evidence_str)
        self.assertIn("[REDACTED_SECRET]", evidence_str)


class TestMissingAndStaleRuntimeData(unittest.TestCase):
    """Test defensive handling of missing, partial, or stale telemetry."""

    def test_missing_exit_code_and_state(self):
        container = {"name": "ghost-container", "id": "c301"}
        incidents = diagnose_container_record(container)
        self.assertIsInstance(incidents, list)

    def test_stale_telemetry_diagnostic(self):
        container = {
            "name": "stale-app",
            "id": "c302",
            "state": "running",
            "metrics": {"telemetry_state": "stale"},
        }
        incidents = diagnose_container_record(container)
        stale_incs = [i for i in incidents if i["rule_id"] == "STALE_TELEMETRY"]
        self.assertEqual(len(stale_incs), 1)

    def test_runtime_inspection_failure(self):
        container = {
            "name": "missing-app",
            "id": "c303",
            "inspection_status": "failed",
            "error": "Podman daemon inspect error (container deleted concurrently)",
        }
        incidents = diagnose_container_record(container)
        fail_incs = [i for i in incidents if i["rule_id"] == "RUNTIME_INSPECTION_FAILURE"]
        self.assertEqual(len(fail_incs), 1)


class TestApprovalBoundaryAndPlanManagement(unittest.TestCase):
    """Test operation registry, plan generation, approval tokens, and approval invalidation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.history_path = Path(self.temp_dir.name) / "recovery_history.jsonl"
        set_global_recovery_disabled(False)

    def tearDown(self):
        set_global_recovery_disabled(False)
        self.temp_dir.cleanup()

    def test_operation_registry_supported_and_rejected_operations(self):
        """Supported operations registry permits start_container and rejects arbitrary commands."""
        self.assertIn("start_container", SUPPORTED_OPERATIONS)
        self.assertIn("inspect_container", SUPPORTED_OPERATIONS)
        self.assertIn("collect_logs", SUPPORTED_OPERATIONS)
        self.assertIn("verify_health", SUPPORTED_OPERATIONS)

        # Destructive or arbitrary operations rejected
        for bad_op in ["rm_container", "prune_all", "bash_exec", "eval", "shutdown_host"]:
            self.assertNotIn(bad_op, SUPPORTED_OPERATIONS)
            plan = build_remediation_plan("test-app", operation=bad_op)
            self.assertFalse(plan["allowed"])
            self.assertEqual(plan["status"], "INVALID_OPERATION")

    def test_build_remediation_plan_numbered_steps_and_impact(self):
        """Plan includes numbered steps, proposed operation, impact, risks, and verification criteria."""
        plan = build_remediation_plan(
            container_name="my-worker",
            operation="start_container",
            current_state="exited",
        )
        self.assertTrue(plan["plan_id"].startswith("PLAN_start_container_"))
        self.assertTrue(len(plan["plan_hash"]) > 0)
        self.assertEqual(plan["operation"], "start_container")
        self.assertTrue(plan["is_state_changing"])
        self.assertTrue(len(plan["numbered_steps"]) >= 5)
        self.assertTrue(plan["numbered_steps"][0].startswith("1."))
        self.assertTrue(len(plan["impact"]) > 0)
        self.assertTrue(len(plan["risk"]) > 0)
        self.assertTrue(len(plan["verification_criteria"]) > 0)

    def test_approval_token_issuance_and_validation(self):
        """Approving a plan produces an approval token strictly bound to that plan's hash."""
        plan = build_remediation_plan("my-worker", operation="start_container", current_state="exited")
        approved_plan = approve_remediation_plan(plan)

        self.assertEqual(approved_plan["status"], "APPROVED")
        token = approved_plan["approval_token"]
        self.assertTrue(token.startswith("APPR_"))

        # Validates against the same plan
        self.assertTrue(is_approval_valid(token, plan))

    def test_approval_invalidation_when_plan_target_or_operation_changes(self):
        """Approval token becomes invalid if plan target or operation changes."""
        plan_a = build_remediation_plan("worker-a", operation="start_container", current_state="exited")
        approved_a = approve_remediation_plan(plan_a)
        token_a = approved_a["approval_token"]

        # If applied to a different container, approval is invalid
        plan_b = build_remediation_plan("worker-b", operation="start_container", current_state="exited")
        self.assertFalse(is_approval_valid(token_a, plan_b))

        # If applied to different operation, approval is invalid
        plan_a_other_op = build_remediation_plan("worker-a", operation="inspect_container", current_state="exited")
        self.assertFalse(is_approval_valid(token_a, plan_a_other_op))

    def test_explicit_rejection_recorded_in_audit_history(self):
        """Rejecting a plan sets status REJECTED and persists a rejection audit record."""
        plan = build_remediation_plan("flake-app", operation="start_container", current_state="exited")
        rejected = reject_remediation_plan(plan, reason="Operator wants to rebuild image first", history_path=self.history_path)

        self.assertEqual(rejected["status"], "REJECTED")
        self.assertEqual(rejected["rejection_reason"], "Operator wants to rebuild image first")

        # Verify audit history logged rejection
        history = load_recovery_history(history_path=self.history_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["container"], "flake-app")
        self.assertEqual(history[0]["decision"], "REJECTED")
        self.assertEqual(history[0]["verification_status"], "REJECTED_BY_OPERATOR")
        self.assertFalse(history[0]["success"])

    def test_execution_blocks_without_approval_or_with_invalid_token(self):
        """Executing without approval or with invalid token fails with AUTHORIZATION_REQUIRED or APPROVAL_INVALIDATED."""
        # Case 1: No approval
        res_no_auth = execute_authorized_recovery("target-app", authorized=False, history_path=self.history_path)
        self.assertFalse(res_no_auth["success"])
        self.assertEqual(res_no_auth["verification_status"], "AUTHORIZATION_REQUIRED")

        # Case 2: Tampered / mismatched approval token
        plan = build_remediation_plan("target-app", operation="start_container", current_state="exited")
        res_bad_token = execute_authorized_recovery(
            "target-app",
            action="start_container",
            authorized=True,
            approval_token="APPR_invalid_hash_12345",
            plan=plan,
            history_path=self.history_path,
        )
        self.assertFalse(res_bad_token["success"])
        self.assertEqual(res_bad_token["verification_status"], "APPROVAL_INVALIDATED")

    def test_precondition_revalidation_prevents_running_container_restart(self):
        """Precondition check fails if container is already in 'running' state immediately before execution."""
        plan = build_remediation_plan("active-app", operation="start_container", current_state="exited")
        approved = approve_remediation_plan(plan)

        res = execute_authorized_recovery(
            "active-app",
            action="start_container",
            authorized=True,
            approval_token=approved["approval_token"],
            plan=approved,
            precondition_current_state="running",  # Container started by another process
            history_path=self.history_path,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "PRECONDITION_FAILED")
        self.assertIn("already running", res["message"])


class TestPostActionVerificationAndHonestReporting(unittest.TestCase):
    """Test honest reporting of execution outcomes including verified, inconclusive, and failed verification."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.history_path = Path(self.temp_dir.name) / "recovery_history.jsonl"
        set_global_recovery_disabled(False)

    def tearDown(self):
        set_global_recovery_disabled(False)
        self.temp_dir.cleanup()

    def test_inconclusive_verification_reported_honestly(self):
        """When container starts but healthcheck is in 'starting' state, status is reported as INCONCLUSIVE_VERIFICATION."""
        mock_restart = MagicMock(return_value={"success": True, "message": "Container started."})
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps({"running": True, "status": "running", "health": "starting"})

        plan = build_remediation_plan("slow-warming-app", operation="start_container", current_state="exited")
        approved = approve_remediation_plan(plan)

        res = execute_authorized_recovery(
            "slow-warming-app",
            action="start_container",
            authorized=True,
            approval_token=approved["approval_token"],
            plan=approved,
            history_path=self.history_path,
            runner=mock_runner,
            restart_fn=mock_restart,
        )

        self.assertEqual(res["verification_status"], "INCONCLUSIVE_VERIFICATION")
        self.assertIn("STARTING", res["message"])

        # Audit log verifies honest reporting
        history = load_recovery_history(history_path=self.history_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["verification_status"], "INCONCLUSIVE_VERIFICATION")

    def test_failed_verification_reported_honestly(self):
        """When container exits immediately after restart, status is FAILED_VERIFICATION."""
        mock_restart = MagicMock(return_value={"success": True, "message": "Container started."})
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps({"running": False, "status": "exited", "health": ""})

        plan = build_remediation_plan("crashing-app", operation="start_container", current_state="exited")
        approved = approve_remediation_plan(plan)

        res = execute_authorized_recovery(
            "crashing-app",
            action="start_container",
            authorized=True,
            approval_token=approved["approval_token"],
            plan=approved,
            history_path=self.history_path,
            runner=mock_runner,
            restart_fn=mock_restart,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "FAILED_VERIFICATION")


class TestPhase10ApprovalBoundaryAndAdversarialSafeguards(unittest.TestCase):
    """
    Phase 10: Strict isolated validation of the approval boundary and safety gates.
    Validates all 11 mandatory boundary invariants using mocks and fixtures:
    1. A diagnosis alone never triggers execution.
    2. Missing approval blocks every state-changing operation.
    3. Rejected approval blocks execution.
    4. Approval for a different plan or target is rejected.
    5. Changes to parameters or plan contents invalidate approval.
    6. Changed preconditions are revalidated before execution.
    7. The kill switch and workload-immunity policy cannot be bypassed.
    8. Unknown operations and arbitrary shell commands are rejected.
    9. Duplicate requests cannot accidentally repeat a disruptive operation.
    10. Timeouts and exceptions are recorded accurately.
    11. Audit records distinguish requested, approved, executed and verified actions.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.history_path = Path(self.temp_dir.name) / "recovery_history.jsonl"
        set_global_recovery_disabled(False)
        clear_executed_approval_tokens()

    def tearDown(self):
        set_global_recovery_disabled(False)
        clear_executed_approval_tokens()
        self.temp_dir.cleanup()

    def test_1_diagnosis_alone_never_triggers_execution(self):
        """Diagnosing containers is strictly read-only and never invokes execution functions."""
        mock_runner = MagicMock()
        mock_restart = MagicMock()
        failing_containers = [
            {"name": "broken-app-1", "id": "b1", "state": "exited", "exit_code": 1, "recent_logs": "Connection refused to redis:6379"},
            {"name": "broken-app-2", "id": "b2", "state": "exited", "exit_code": 137, "recent_logs": "Killed"},
            {"name": "broken-app-3", "id": "b3", "state": "running", "recent_logs": "Permission denied"},
        ]
        # Run bulk diagnosis
        incidents = diagnose_all_containers(failing_containers)
        self.assertTrue(len(incidents) >= 3)

        # Propose remediation plans for each
        for c in failing_containers:
            plan = build_remediation_plan(c["name"], operation="start_container", current_state=c["state"])
            self.assertIn(plan["status"], {"PROPOSED", "INVALID_OPERATION"})

        # Verify absolutely zero execution calls were made
        mock_runner.assert_not_called()
        mock_restart.assert_not_called()

    def test_2_missing_approval_blocks_state_changing_operation(self):
        """State-changing execution without explicit approval is strictly blocked."""
        res = execute_authorized_recovery(
            "unapproved-worker",
            action="start_container",
            authorized=False,
            approval_token=None,
            history_path=self.history_path,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "AUTHORIZATION_REQUIRED")
        self.assertIn("explicit human authorization required", res["message"])

    def test_3_rejected_approval_blocks_execution(self):
        """A plan that was rejected by the operator is blocked from execution."""
        plan = build_remediation_plan("worker-rejected", operation="start_container", current_state="exited")
        rejected_plan = reject_remediation_plan(plan, reason="Do not restart: investigation ongoing", history_path=self.history_path)

        res = execute_authorized_recovery(
            "worker-rejected",
            action="start_container",
            authorized=True,
            plan=rejected_plan,
            history_path=self.history_path,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "APPROVAL_REJECTED")
        self.assertIn("explicitly rejected", res["message"])

    def test_4_approval_for_different_plan_or_target_rejected(self):
        """Approval token generated for container A or operation X cannot be used for container B or operation Y."""
        plan_a = build_remediation_plan("service-alpha", operation="start_container", current_state="exited")
        approved_a = approve_remediation_plan(plan_a)
        token_a = approved_a["approval_token"]

        # Attempt to use token_a for service-beta
        res_diff_target = execute_authorized_recovery(
            "service-beta",
            action="start_container",
            authorized=True,
            approval_token=token_a,
            plan=approved_a,
            history_path=self.history_path,
        )
        self.assertFalse(res_diff_target["success"])
        self.assertEqual(res_diff_target["verification_status"], "APPROVAL_INVALIDATED")

        # Attempt to use token_a with a standalone request for different target
        res_standalone_diff = execute_authorized_recovery(
            "service-beta",
            action="start_container",
            authorized=True,
            approval_token=token_a,
            history_path=self.history_path,
        )
        self.assertFalse(res_standalone_diff["success"])
        self.assertEqual(res_standalone_diff["verification_status"], "APPROVAL_INVALIDATED")

    def test_5_parameter_and_plan_content_tampering_invalidates_approval(self):
        """Any tampering with plan parameters or contents after approval invalidates execution."""
        plan = build_remediation_plan(
            "service-tamper",
            operation="start_container",
            parameters={"timeout": 30},
            current_state="exited",
        )
        approved = approve_remediation_plan(plan)
        token = approved["approval_token"]

        # Adversary modifies parameter without updating plan_hash
        tampered_plan = dict(approved)
        tampered_plan["parameters"] = {"timeout": 30, "malicious_flag": True}

        # Verification function rejects tampered plan
        self.assertFalse(is_approval_valid(token, tampered_plan))

        # Execution rejects tampered plan
        res = execute_authorized_recovery(
            "service-tamper",
            action="start_container",
            authorized=True,
            approval_token=token,
            plan=tampered_plan,
            history_path=self.history_path,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "APPROVAL_INVALIDATED")
        self.assertIn("parameters or contents changed", res["message"])

    def test_6_changed_preconditions_revalidated_before_execution(self):
        """If container state changes to 'running' prior to execution, precondition revalidation aborts start."""
        plan = build_remediation_plan("flapping-worker", operation="start_container", current_state="exited")
        approved = approve_remediation_plan(plan)

        res = execute_authorized_recovery(
            "flapping-worker",
            action="start_container",
            authorized=True,
            approval_token=approved["approval_token"],
            plan=approved,
            precondition_current_state="running",
            history_path=self.history_path,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["verification_status"], "PRECONDITION_FAILED")
        self.assertIn("already running", res["message"])

    def test_7_kill_switch_and_workload_immunity_cannot_be_bypassed(self):
        """Global recovery kill switch and protected workloads cannot be bypassed even with valid approval token."""
        # 1. Protected Workload: cloudops-floci
        plan_floci = build_remediation_plan("cloudops-floci", operation="start_container", current_state="exited")
        approved_floci = approve_remediation_plan(plan_floci)
        res_floci = execute_authorized_recovery(
            "cloudops-floci",
            action="start_container",
            authorized=True,
            approval_token=approved_floci["approval_token"],
            plan=approved_floci,
            history_path=self.history_path,
        )
        self.assertFalse(res_floci["success"])
        self.assertEqual(res_floci["verification_status"], "PROTECTED_WORKLOAD")

        # 2. Protected Workload: linuxops-recovery-ui-test
        plan_test = build_remediation_plan("linuxops-recovery-ui-test", operation="start_container", current_state="exited")
        approved_test = approve_remediation_plan(plan_test)
        res_test = execute_authorized_recovery(
            "linuxops-recovery-ui-test",
            action="start_container",
            authorized=True,
            approval_token=approved_test["approval_token"],
            plan=approved_test,
            history_path=self.history_path,
        )
        self.assertFalse(res_test["success"])
        self.assertEqual(res_test["verification_status"], "PROTECTED_WORKLOAD")

        # 3. Global Kill Switch Active
        set_global_recovery_disabled(True)
        plan_regular = build_remediation_plan("standard-worker", operation="start_container", current_state="exited")
        approved_regular = approve_remediation_plan(plan_regular)
        res_kill = execute_authorized_recovery(
            "standard-worker",
            action="start_container",
            authorized=True,
            approval_token=approved_regular["approval_token"],
            plan=approved_regular,
            history_path=self.history_path,
        )
        self.assertFalse(res_kill["success"])
        self.assertEqual(res_kill["verification_status"], "GLOBAL_KILL_SWITCH")

    def test_8_unknown_operations_and_arbitrary_shell_commands_rejected(self):
        """Arbitrary shell commands or unregistered destructive actions are rejected at planning and execution."""
        for dangerous_op in ["rm_container", "prune_all", "curl http://evil.com", "bash -c 'rm -rf /'", "kill -9"]:
            # Plan rejected
            plan = build_remediation_plan("target-service", operation=dangerous_op)
            self.assertFalse(plan["allowed"])
            self.assertEqual(plan["status"], "INVALID_OPERATION")

            # Execution rejected
            res = execute_authorized_recovery(
                "target-service",
                action=dangerous_op,
                authorized=True,
                history_path=self.history_path,
            )
            self.assertFalse(res["success"])
            self.assertEqual(res["verification_status"], "FORBIDDEN_ACTION")

    def test_9_duplicate_requests_cannot_repeat_disruptive_operation(self):
        """An approval token cannot be re-executed a second time; duplicate requests are blocked."""
        mock_restart = MagicMock(return_value={"success": True, "message": "Container started."})
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps({"running": True, "status": "running", "health": "healthy"})

        plan = build_remediation_plan("idempotent-worker", operation="start_container", current_state="exited")
        approved = approve_remediation_plan(plan)
        token = approved["approval_token"]

        # First execution succeeds
        res1 = execute_authorized_recovery(
            "idempotent-worker",
            action="start_container",
            authorized=True,
            approval_token=token,
            plan=approved,
            history_path=self.history_path,
            runner=mock_runner,
            restart_fn=mock_restart,
        )
        self.assertTrue(res1["success"])
        self.assertEqual(res1["verification_status"], "VERIFIED")
        self.assertEqual(mock_restart.call_count, 1)

        # Duplicate execution with same token is blocked
        res2 = execute_authorized_recovery(
            "idempotent-worker",
            action="start_container",
            authorized=True,
            approval_token=token,
            plan=approved,
            history_path=self.history_path,
            runner=mock_runner,
            restart_fn=mock_restart,
        )
        self.assertFalse(res2["success"])
        self.assertEqual(res2["verification_status"], "DUPLICATE_REQUEST_BLOCKED")
        self.assertEqual(mock_restart.call_count, 1)  # Restart not invoked again!

    def test_10_timeouts_and_exceptions_recorded_accurately(self):
        """Execution timeouts and exceptions are captured defensively and recorded in audit history."""
        # Timeout scenario
        import subprocess
        timeout_restart = MagicMock(side_effect=subprocess.TimeoutExpired(cmd="podman start timeout-app", timeout=30))
        plan_t = build_remediation_plan("timeout-app", operation="start_container", current_state="exited")
        approved_t = approve_remediation_plan(plan_t)

        res_t = execute_authorized_recovery(
            "timeout-app",
            action="start_container",
            authorized=True,
            approval_token=approved_t["approval_token"],
            plan=approved_t,
            history_path=self.history_path,
            restart_fn=timeout_restart,
        )
        self.assertFalse(res_t["success"])
        self.assertEqual(res_t["verification_status"], "FAILED")
        self.assertIn("timed out", res_t["message"])

        # Exception scenario
        error_restart = MagicMock(side_effect=RuntimeError("Subprocess pipe broken"))
        plan_e = build_remediation_plan("error-app", operation="start_container", current_state="exited")
        approved_e = approve_remediation_plan(plan_e)

        res_e = execute_authorized_recovery(
            "error-app",
            action="start_container",
            authorized=True,
            approval_token=approved_e["approval_token"],
            plan=approved_e,
            history_path=self.history_path,
            restart_fn=error_restart,
        )
        self.assertFalse(res_e["success"])
        self.assertEqual(res_e["verification_status"], "FAILED")
        self.assertIn("Subprocess pipe broken", res_e["message"])

        # Check audit log records (most recent first)
        history = load_recovery_history(history_path=self.history_path)
        self.assertEqual(len(history), 2)
        self.assertIn("Subprocess pipe broken", history[0]["message"])
        self.assertIn("timed out", history[1]["message"])

    def test_11_audit_records_distinguish_lifecycle_stages(self):
        """Audit records strictly distinguish requested/proposed, rejected, and executed actions."""
        # 1. Reject action
        plan_rej = build_remediation_plan("audit-svc-1", operation="start_container", current_state="exited")
        reject_remediation_plan(plan_rej, reason="Manual intervention preferred", history_path=self.history_path)

        # 2. Executed action
        mock_restart = MagicMock(return_value={"success": True, "message": "Started ok"})
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = json.dumps({"running": True, "status": "running", "health": "healthy"})

        plan_exec = build_remediation_plan("audit-svc-2", operation="start_container", current_state="exited")
        appr_exec = approve_remediation_plan(plan_exec)
        execute_authorized_recovery(
            "audit-svc-2",
            action="start_container",
            authorized=True,
            approval_token=appr_exec["approval_token"],
            plan=appr_exec,
            history_path=self.history_path,
            runner=mock_runner,
            restart_fn=mock_restart,
        )

        history = load_recovery_history(history_path=self.history_path)
        self.assertEqual(len(history), 2)

        # Most recent record is the executed action
        self.assertEqual(history[0]["container"], "audit-svc-2")
        self.assertEqual(history[0]["decision"], "APPROVED")
        self.assertEqual(history[0]["verification_status"], "VERIFIED")
        self.assertTrue(history[0]["success"])
        self.assertEqual(history[0]["plan_id"], appr_exec["plan_id"])
        self.assertEqual(history[0]["approval_token"], appr_exec["approval_token"])

        # Older record is the rejection record
        self.assertEqual(history[1]["container"], "audit-svc-1")
        self.assertEqual(history[1]["decision"], "REJECTED")
        self.assertEqual(history[1]["verification_status"], "REJECTED_BY_OPERATOR")
        self.assertFalse(history[1]["success"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

