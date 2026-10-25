#!/usr/bin/env python3

"""
Unit tests for LinuxOps Demo Mode & Synthetic Scenarios (app/demo_data.py).

Validates:
- All scenario schemas and required metadata
- Clear labelling and demo indicators on all synthetic records
- Direct execution through the production diagnostics engine
- Simulation safety: ensuring demo data cannot trigger real recovery actions
"""

import unittest

from app.dashboard import filter_and_paginate_containers
from app.demo_data import (
    get_demo_scenario,
    get_demo_scenario_keys,
    is_demo_target,
    simulate_demo_approval,
    simulate_demo_execution,
)
from app.diagnostics_engine import diagnose_all_containers
from app.recovery_controller import build_remediation_plan


class TestDemoModeScenarios(unittest.TestCase):

    def test_demo_scenario_keys_and_schemas(self):
        """All expected scenario keys must exist and return complete metadata schemas."""
        expected_keys = [
            "nominal",
            "db_connection_refused",
            "crash_loop_oom",
            "failing_health_check",
            "stopped_container",
            "scale_105_benchmark",
        ]
        actual_keys = get_demo_scenario_keys()
        for k in expected_keys:
            self.assertIn(k, actual_keys, f"Scenario '{k}' missing from demo registry")

            sc = get_demo_scenario(k)
            self.assertEqual(sc["key"], k)
            self.assertIn("title", sc)
            self.assertIn("badge", sc)
            self.assertIn("summary", sc)
            self.assertIn("demonstration_focus", sc)
            self.assertIsInstance(sc["demonstration_focus"], list)
            self.assertGreater(len(sc["demonstration_focus"]), 0)
            self.assertIn("containers", sc)
            self.assertIsInstance(sc["containers"], list)
            self.assertGreater(len(sc["containers"]), 0)
            self.assertIn("system", sc)
            self.assertIn("metrics_samples", sc)
            self.assertIn("summary_counts", sc)

    def test_demo_container_labelling_and_guardrails(self):
        """Every synthetic container record must carry clear demo identifiers and labels."""
        for k in get_demo_scenario_keys():
            sc = get_demo_scenario(k)
            for c in sc["containers"]:
                c_name = c.get("name", "")
                c_id = c.get("id", "")
                labels = c.get("labels", {})

                # Demo indicators
                self.assertTrue(c_name.startswith("demo-"), f"Container '{c_name}' in scenario '{k}' lacks 'demo-' prefix")
                self.assertTrue(c_id.startswith("demo-"), f"Container ID '{c_id}' in scenario '{k}' lacks 'demo-' prefix")
                self.assertTrue(c.get("is_demo"), f"Container '{c_name}' in scenario '{k}' missing 'is_demo' flag")
                self.assertEqual(labels.get("linuxops.demo"), "true", f"Container '{c_name}' lacks 'linuxops.demo' label")

                # is_demo_target helper
                self.assertTrue(is_demo_target(c_name))
                self.assertTrue(is_demo_target(c_id))

        # Real container names must not be classified as demo
        self.assertFalse(is_demo_target("cloudops-floci"))
        self.assertFalse(is_demo_target("production-postgres"))
        self.assertFalse(is_demo_target("nginx-edge"))

    def test_nominal_scenario_diagnostics(self):
        """Nominal scenario must yield zero critical or warning incidents."""
        sc = get_demo_scenario("nominal")
        self.assertEqual(len(sc["containers"]), 8)
        diag = diagnose_all_containers(sc["containers"])
        self.assertEqual(diag["critical_count"], 0)
        self.assertEqual(diag["warning_count"], 0)
        self.assertEqual(diag["total_incidents"], 0)

    def test_db_connection_refused_diagnostics(self):
        """Database outage scenario must trigger DEPENDENCY_CONNECTION_REFUSED on dependent services and correlate catalog-db."""
        sc = get_demo_scenario("db_connection_refused")
        diag = diagnose_all_containers(sc["containers"])

        incidents = diag["incidents"]
        rule_ids = {i["rule_id"] for i in incidents}
        self.assertIn("DEPENDENCY_CONNECTION_REFUSED", rule_ids)

        affected_conts = {i["container_name"] for i in incidents if i["rule_id"] == "DEPENDENCY_CONNECTION_REFUSED"}
        self.assertIn("demo-order-processor", affected_conts)
        self.assertIn("demo-auth-service", affected_conts)

        # Check evidence contains log text and correlated containers contains demo-catalog-db
        order_inc = next(i for i in incidents if i["container_name"] == "demo-order-processor" and i["rule_id"] == "DEPENDENCY_CONNECTION_REFUSED")
        self.assertEqual(order_inc["severity"], "CRITICAL")
        self.assertTrue(any("connection refused" in ev.lower() for ev in order_inc["evidence"]))
        self.assertIn("demo-catalog-db", order_inc["correlated_containers"])

        auth_inc = next(i for i in incidents if i["container_name"] == "demo-auth-service" and i["rule_id"] == "DEPENDENCY_CONNECTION_REFUSED")
        self.assertIn("demo-catalog-db", auth_inc["correlated_containers"])

        # Check catalog-db incident correlates downstream affected services
        db_inc = next(i for i in incidents if i["container_name"] == "demo-catalog-db")
        self.assertIn("demo-order-processor", db_inc["correlated_containers"])
        self.assertIn("demo-auth-service", db_inc["correlated_containers"])

    def test_crash_loop_oom_diagnostics(self):
        """Memory exhaustion scenario must trigger OOM_KILLED and CRASH_LOOP_DETECTED with bounded trend metrics."""
        sc = get_demo_scenario("crash_loop_oom")
        diag = diagnose_all_containers(sc["containers"])

        incidents = diag["incidents"]
        rule_ids = {i["rule_id"] for i in incidents}
        self.assertIn("OOM_KILLED", rule_ids)
        self.assertIn("CRASH_LOOP_DETECTED", rule_ids)
        self.assertIn("MEMORY_PRESSURE_CRITICAL", rule_ids)

        # Analytics engine has both OOM and crash loop
        analytics_rules = {i["rule_id"] for i in incidents if i["container_name"] == "demo-analytics-engine"}
        self.assertIn("OOM_KILLED", analytics_rules)
        self.assertIn("CRASH_LOOP_DETECTED", analytics_rules)

        # Report generator has memory pressure
        report_rules = {i["rule_id"] for i in incidents if i["container_name"] == "demo-report-generator"}
        self.assertIn("MEMORY_PRESSURE_CRITICAL", report_rules)

        # Verify policy gate denies and escalates restart for analytics engine
        analytics_cont = next(c for c in sc["containers"] if c["name"] == "demo-analytics-engine")
        analytics_inc = next(i for i in incidents if i["container_name"] == "demo-analytics-engine" and i["rule_id"] == "OOM_KILLED")
        plan = build_remediation_plan(
            container_name=analytics_cont["name"],
            operation="start_container",
            current_state=analytics_cont["state"],
            incident=analytics_inc,
            container_id=analytics_cont["id"],
        )
        self.assertFalse(plan.get("allowed"))
        self.assertTrue(plan.get("escalated"))
        self.assertEqual(plan.get("decision"), "DENY")
        self.assertIn("OOM", plan.get("reason", ""))

        # Verify metrics samples are readable and bounded (<= 100%)
        samples = sc["metrics_samples"]
        self.assertGreater(len(samples), 5)
        for s in samples:
            self.assertGreaterEqual(s["cpu_usage_percent"], 0.0)
            self.assertLessEqual(s["cpu_usage_percent"], 100.0)
            self.assertGreaterEqual(s["memory"]["usage_percent"], 0.0)
            self.assertLessEqual(s["memory"]["usage_percent"], 100.0)

    def test_healthy_running_workload_safety(self):
        """Healthy running workload must not receive a state-changing recovery or start recommendation."""
        sc = get_demo_scenario("nominal")
        frontend_cont = next(c for c in sc["containers"] if c["name"] == "demo-frontend-web")
        self.assertEqual(frontend_cont["state"], "running")
        self.assertEqual(frontend_cont["health_status"], "healthy")

        # Diagnostics must be clean
        diag = diagnose_all_containers(sc["containers"])
        frontend_incs = [i for i in diag["incidents"] if i["container_name"] == "demo-frontend-web"]
        self.assertEqual(len(frontend_incs), 0)

    def test_failing_health_check_diagnostics(self):
        """Failing probe scenario must trigger HEALTHCHECK_FAILING for payment service."""
        sc = get_demo_scenario("failing_health_check")
        diag = diagnose_all_containers(sc["containers"])

        incidents = diag["incidents"]
        rule_ids = {i["rule_id"] for i in incidents}
        self.assertIn("HEALTHCHECK_FAILING", rule_ids)

        payment_inc = next(i for i in incidents if i["container_name"] == "demo-payment-service")
        self.assertEqual(payment_inc["severity"], "CRITICAL")
        self.assertIn("health_status='unhealthy'", payment_inc["evidence"])

    def test_stopped_container_diagnostics(self):
        """Gracefully stopped container must be classified as CONTAINER_STOPPED_NORMAL (INFO)."""
        sc = get_demo_scenario("stopped_container")
        diag = diagnose_all_containers(sc["containers"])

        incidents = diag["incidents"]
        batch_inc = next((i for i in incidents if i["container_name"] == "demo-batch-sync-worker"), None)
        self.assertIsNotNone(batch_inc)
        self.assertEqual(batch_inc["rule_id"], "CONTAINER_STOPPED_NORMAL")
        self.assertEqual(batch_inc["severity"], "INFO")

    def test_scale_105_pagination_and_search(self):
        """105 container benchmark must paginate cleanly and support fast filtering."""
        sc = get_demo_scenario("scale_105_benchmark")
        conts = sc["containers"]
        self.assertEqual(len(conts), 105)

        # Page 1 (25 items)
        p1, total, pages = filter_and_paginate_containers(conts, page=1, page_size=25)
        self.assertEqual(total, 105)
        self.assertEqual(pages, 5)
        self.assertEqual(len(p1), 25)

        # Page 5 (remaining 5 items)
        p5, _, _ = filter_and_paginate_containers(conts, page=5, page_size=25)
        self.assertEqual(len(p5), 5)

        # Text search
        p_search, total_s, _ = filter_and_paginate_containers(conts, search_query="node-042")
        self.assertEqual(total_s, 1)
        self.assertEqual(p_search[0]["name"], "demo-svc-node-042")

    def test_simulated_approval_and_execution(self):
        """Simulated remediation workflow must bind to plan hash and verify outcome safely."""
        sc = get_demo_scenario("stopped_container")
        cont = next(c for c in sc["containers"] if c["name"] == "demo-batch-sync-worker")

        # Build plan
        plan = build_remediation_plan(
            container_name=cont["name"],
            operation="start_container",
            current_state=cont["state"],
            incident=None,
            container_id=cont["id"],
        )
        self.assertTrue(plan.get("allowed"))
        self.assertIn("plan_hash", plan)

        # Simulate approval
        approval_rec = simulate_demo_approval(plan)
        token = approval_rec["approval_token"]
        self.assertTrue(token.startswith("SIMULATED-APPROVAL-TOKEN-"))
        self.assertTrue(approval_rec.get("simulated"))

        # Simulate execution
        exec_res = simulate_demo_execution(plan, token)
        self.assertTrue(exec_res["success"])
        self.assertTrue(exec_res["simulated"])
        self.assertEqual(exec_res["verification_status"], "VERIFIED")
        self.assertIn("[SIMULATED OUTCOME]", exec_res["message"])

        # Tampered or invalid token is rejected
        bad_res = simulate_demo_execution(plan, "INVALID-TOKEN")
        self.assertFalse(bad_res["success"])
        self.assertEqual(bad_res["verification_status"], "APPROVAL_INVALIDATED")

    def test_incident_table_evidence_vs_resolution_distinction(self):
        """Evidence verification must be distinguished from incident resolution; never resolved without verified recovery."""
        from app.dashboard import format_incident_rows

        incidents = [
            {
                "incident_id": "INC-TEST-001",
                "container_name": "demo-order-processor",
                "rule_id": "DEPENDENCY_CONNECTION_REFUSED",
                "severity": "CRITICAL",
                "probable_cause": "Database offline",
                "confidence": 0.90,
                "evidence": ["connect: connection refused"],
                "recommended_action": "Start database",
                "verification_status": "VERIFIED",
                "timestamp": "2026-10-24T18:00:00Z",
            }
        ]

        # 1. Without recovery: evidence is confirmed, but incident remains OPEN
        rows_unresolved = format_incident_rows(incidents)
        self.assertEqual(len(rows_unresolved), 1)
        self.assertEqual(rows_unresolved[0]["Evidence Status"], "🔍 Confirmed Telemetry")
        self.assertIn("OPEN", rows_unresolved[0]["Incident Status"])
        self.assertNotIn("RESOLVED", rows_unresolved[0]["Incident Status"])

        # 2. With verified recovery: incident status transitions to RESOLVED
        recovery_success = {
            "container": "demo-order-processor",
            "verification_status": "SIMULATED_VERIFIED",
            "success": True,
            "message": "Probe verified healthy.",
        }
        rows_resolved = format_incident_rows(incidents, last_recovery=recovery_success)
        self.assertEqual(rows_resolved[0]["Evidence Status"], "🔍 Confirmed Telemetry")
        self.assertIn("RESOLVED", rows_resolved[0]["Incident Status"])

    def test_scenario_switching_invalidates_approval(self):
        """Switching scenarios must invalidate any previous approval token due to plan hash divergence."""
        sc_stopped = get_demo_scenario("stopped_container")
        batch_cont = next(c for c in sc_stopped["containers"] if c["name"] == "demo-batch-sync-worker")
        plan_a = build_remediation_plan(
            container_name=batch_cont["name"],
            operation="start_container",
            current_state=batch_cont["state"],
            incident=None,
            container_id=batch_cont["id"],
        )
        approval_a = simulate_demo_approval(plan_a)
        token_a = approval_a["approval_token"]

        # In another scenario (e.g. database outage or nominal), container and plan hash differ
        sc_db = get_demo_scenario("db_connection_refused")
        db_cont = next(c for c in sc_db["containers"] if c["name"] == "demo-catalog-db")
        plan_b = build_remediation_plan(
            container_name=db_cont["name"],
            operation="start_container",
            current_state=db_cont["state"],
            incident=None,
            container_id=db_cont["id"],
        )
        self.assertNotEqual(plan_a["plan_hash"], plan_b["plan_hash"])
        self.assertNotEqual(approval_a["container_name"], plan_b["container_name"])
        self.assertNotEqual(approval_a["approved_plan_hash"], plan_b["plan_hash"])

    def test_streamlit_apptest_demo_mode_ui(self):
        """Verify the Streamlit dashboard enforces authentication and renders Simulation Lab when authenticated."""
        from pathlib import Path
        from streamlit.testing.v1 import AppTest

        dashboard_file = str(Path(__file__).resolve().parent.parent / "app" / "dashboard.py")

        # 1. Verify unauthenticated access fails closed and blocks metrics
        at_unauth = AppTest.from_file(dashboard_file).run(timeout=15)
        self.assertFalse(at_unauth.exception, f"AppTest unauthenticated threw: {[e.value for e in at_unauth.exception]}")
        self.assertEqual(len(at_unauth.metric), 0, "Metrics must never be displayed to unauthenticated sessions")
        unauth_texts = [m.value for m in at_unauth.markdown]
        self.assertTrue(any("LinuxOps Security Gate" in t or "Authentication required" in t for t in unauth_texts))

        # 2. Verify authenticated session renders complete console
        at = AppTest.from_file(dashboard_file)
        at.session_state["_authenticated_dev_user"] = {
            "email": "admin@linuxops.local",
            "name": "Admin Operator",
            "role": "admin",
        }
        at.run(timeout=30)
        self.assertFalse(at.exception, f"AppTest threw unhandled exception: {[e.value for e in at.exception]}")

        # Check Operational Mode radio is present and defaults to Simulation Lab / Demo Mode
        self.assertGreater(len(at.radio), 0)
        self.assertTrue("Simulation" in at.radio[0].value or "Demo" in at.radio[0].value)

        # Check DEMO DATA / SIMULATION LAB indicator is displayed
        markdown_texts = [m.value for m in at.markdown]
        self.assertTrue(any("DEMO DATA ACTIVE" in t or "SIMULATION LAB" in t for t in markdown_texts))

        # Check metrics cards are present
        self.assertGreater(len(at.metric), 5)


if __name__ == "__main__":
    unittest.main()

