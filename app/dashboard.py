#!/usr/bin/env python3

"""
LinuxOps Operations Center Dashboard.

Interactive Streamlit dashboard for:
- System monitoring metrics
- Podman container inventory and diagnostics
- Safe dry-run recovery policy preview
- Verified manual container recovery
- Isolated audit logs for recovery executions and policy evaluations
"""

import pandas as pd
import streamlit as st

from app.combined_monitor import collect_combined_report
from app.diagnosis import diagnose_container
from app.history import (
    format_policy_history_rows,
    format_recovery_history_rows,
    load_policy_history,
    load_recovery_history,
    record_recovery_event,
)
from app.policy_service import evaluate_container_policy
from app.recovery import restart_container

st.set_page_config(
    page_title="LinuxOps Operations Center",
    page_icon="🖥️",
    layout="wide",
)

st.title("🖥️ LinuxOps")
st.subheader("Container Monitoring & Recovery Platform")

st.caption(
    "Monitor system resources, investigate Podman containers, "
    "and perform verified recovery operations."
)

if st.button("🔄 Refresh Monitoring", type="primary"):
    st.rerun()

try:
    report = collect_combined_report()

    system = report["system"]
    memory = system["memory"]
    disk = system["disk"]
    container_summary = report["container_summary"]
    containers = report["containers"]

    # 1. Operations Overview
    st.markdown("## Operations Overview")

    status = report["overall_status"]

    if status == "CRITICAL":
        st.error(f"System Health: {status}")
    elif status == "WARNING":
        st.warning(f"System Health: {status}")
    else:
        st.success(f"System Health: {status}")

    st.caption(f"Last checked: {report['timestamp']}")

    total_col, running_col, stopped_col = st.columns(3)
    total_col.metric("Total Containers", container_summary["total"])
    running_col.metric("Running", container_summary["running"])
    stopped_col.metric("Stopped", container_summary["stopped"])

    # 2. System Resource Cards
    st.markdown("## System Resources")

    cpu_col, memory_col, disk_col = st.columns(3)

    with cpu_col:
        st.metric("CPU Usage", f"{system['cpu_usage_percent']:.2f}%")
        st.progress(
            min(max(system["cpu_usage_percent"] / 100, 0), 1)
        )
        st.caption(f"Health: {system['health_checks']['cpu']}")

    with memory_col:
        st.metric("Memory Usage", f"{memory['usage_percent']:.2f}%")
        st.progress(
            min(max(memory["usage_percent"] / 100, 0), 1)
        )
        st.caption(
            f"{memory['used_mb']:.0f} MB / "
            f"{memory['total_mb']:.0f} MB"
        )
        st.caption(f"Health: {system['health_checks']['memory']}")

    with disk_col:
        st.metric("Disk Usage", f"{disk['usage_percent']:.2f}%")
        st.progress(
            min(max(disk["usage_percent"] / 100, 0), 1)
        )
        st.caption(
            f"{disk['used_gb']:.2f} GB / "
            f"{disk['total_gb']:.2f} GB"
        )
        st.caption(f"Health: {system['health_checks']['disk']}")

    with st.expander("System Information"):
        st.write(f"**Hostname:** {system['hostname']}")
        st.write(f"**Operating system:** {system['operating_system']}")
        st.write(f"**Kernel:** {system['kernel']}")

    # 3. Container Inventory
    st.markdown("## Container Inventory")

    if container_summary.get("error"):
        st.error(f"Container inventory error: {container_summary['error']}")
    elif containers:
        st.dataframe(
            pd.DataFrame(containers),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No Podman containers were found.")

    # 4. Container Diagnosis Center
    st.markdown("## 🔎 Container Diagnosis Center")

    if containers:
        container_names = [
            container["name"] for container in containers
        ]

        selected_diagnosis_name = st.selectbox(
            "Select a container to investigate",
            container_names,
            key="diagnosis_container",
        )

        if st.button(
            "Run Diagnosis",
            type="primary",
            key="run_diagnosis",
        ):
            result = diagnose_container(selected_diagnosis_name)

            if result["success"]:
                st.session_state["last_diagnosis"] = result
                st.session_state["last_diagnosis_name"] = (
                    selected_diagnosis_name
                )
            else:
                st.session_state.pop("last_diagnosis", None)
                st.error(result["message"])

        diagnosis = st.session_state.get("last_diagnosis")
        diagnosis_name = st.session_state.get("last_diagnosis_name")

        if diagnosis and diagnosis_name == selected_diagnosis_name:
            st.markdown("### Diagnosis Report")

            result_col1, result_col2, result_col3 = st.columns(3)

            result_col1.metric("State", diagnosis["state"].upper())
            result_col2.metric("Exit Code", diagnosis["exit_code"])
            result_col3.metric(
                "OOM Killed",
                "Yes" if diagnosis["oom_killed"] else "No",
            )

            st.info(diagnosis["diagnosis"])

            recommendation = diagnosis["recommendation"]

            st.markdown("**Recommended action**")
            if recommendation in {"HUMAN_REVIEW", "INVESTIGATE"}:
                st.warning(recommendation.replace("_", " "))
            elif recommendation == "CHECK_LOGS":
                st.error("CHECK LOGS")
            else:
                st.success(recommendation.replace("_", " "))

            with st.expander("Recent container logs", expanded=True):
                if diagnosis["recent_logs"]:
                    st.code(diagnosis["recent_logs"], language="text")
                else:
                    st.caption("No recent logs were returned.")

            st.caption(
                "Diagnosis is advisory. Review the evidence before "
                "making configuration or resource changes."
            )
    else:
        st.info("Create or run a container to use diagnosis.")

    # 5. Recovery Policy Preview (Phase B Step 4 — Dry-Run Only)
    st.markdown("## 🛡️ Recovery Policy Preview (Dry-Run)")
    st.caption(
        "Evaluate recovery safety policies (cooldowns, retry limits, and OOM protection) "
        "before initiating recovery. Policy preview is strictly dry-run and will NOT restart any container."
    )

    if containers:
        policy_container_names = [c["name"] for c in containers]
        selected_policy_name = st.selectbox(
            "Select a container to evaluate against policy",
            policy_container_names,
            key="policy_container",
        )

        selected_cont_info = next(
            (c for c in containers if c["name"] == selected_policy_name),
            None,
        )
        current_cont_state = (
            selected_cont_info.get("state", "unknown")
            if selected_cont_info
            else "unknown"
        )

        st.write(f"**Current Container State:** `{current_cont_state.upper()}`")

        if st.button("🛡️ Evaluate Recovery Policy", type="secondary", key="run_policy_eval"):
            with st.spinner("Evaluating policy safeguards..."):
                pol_decision = evaluate_container_policy(
                    container_name=selected_policy_name,
                    current_state=current_cont_state,
                )
                st.session_state["last_policy_result"] = pol_decision
                st.session_state["last_policy_name"] = selected_policy_name

        last_pol = st.session_state.get("last_policy_result")
        last_pol_name = st.session_state.get("last_policy_name")

        if last_pol and last_pol_name == selected_policy_name:
            is_allowed = last_pol.get("allowed", False)

            if is_allowed:
                st.success(f"**Policy Decision: ALLOW (Dry-Run)** — {last_pol.get('reason')}")
            else:
                st.error(f"**Policy Decision: DENY (Dry-Run)** — {last_pol.get('reason')}")

            # Safeguard checks breakdown
            checks = last_pol.get("checks", {})
            if checks:
                check_cols = st.columns(len(checks))
                check_labels = {
                    "name_valid": "Name Syntax",
                    "state_eligible": "State Eligibility",
                    "oom_safeguard_satisfied": "OOM Protection",
                    "cooldown_satisfied": "Cooldown Period",
                    "within_retry_limit": "Retry Limit",
                }
                for col, (chk_key, chk_val) in zip(check_cols, checks.items()):
                    lbl = check_labels.get(chk_key, chk_key)
                    icon = "✅ Passed" if chk_val else "❌ Failed"
                    col.metric(lbl, icon)

            # Details: failed attempts & cooldown remaining
            detail_col1, detail_col2, detail_col3 = st.columns(3)
            detail_col1.metric("Recent Failed Attempts", last_pol.get("attempts_in_window", 0))
            detail_col2.metric(
                "Cooldown Remaining",
                f"{last_pol.get('cooldown_remaining_seconds', 0.0):.1f}s",
            )
            detail_col3.metric("Execution Mode", "DRY-RUN (Safe)")

            if last_pol.get("log_error"):
                st.warning(last_pol["log_error"])
    else:
        st.info("No containers available to evaluate.")

    # 6. Container Recovery (Manual execution)
    st.markdown("## 🛠️ Container Recovery")

    last_recovery = st.session_state.get("last_recovery_result")
    if last_recovery:
        if last_recovery.get("success"):
            st.success(
                f"**{last_recovery.get('container', 'Container')}**: "
                f"{last_recovery.get('message', 'Recovery succeeded.')}"
            )
        else:
            st.error(
                f"**{last_recovery.get('container', 'Container')}**: "
                f"{last_recovery.get('message', 'Recovery failed.')}"
            )

        if last_recovery.get("log_error"):
            st.warning(last_recovery["log_error"])

    stopped_containers = [
        container for container in containers
        if container["state"] in {"exited", "stopped"}
    ]

    if stopped_containers:
        container_names = [
            container["name"] for container in stopped_containers
        ]

        selected_recovery_name = st.selectbox(
            "Select a stopped container",
            container_names,
            key="recovery_container",
        )

        confirm_recovery = st.checkbox(
            f"I approve starting '{selected_recovery_name}'.",
            key="confirm_recovery",
        )

        if st.button(
            "▶️ Start Selected Container",
            disabled=not confirm_recovery,
            key="start_container",
        ):
            result = restart_container(selected_recovery_name)

            log_error = None
            try:
                record_recovery_event(selected_recovery_name, result)
            except Exception as write_err:
                log_error = f"Audit log recording failed: {write_err}"

            st.session_state["last_recovery_result"] = {
                "container": selected_recovery_name,
                "success": bool(result.get("success", False)),
                "message": str(result.get("message", "No message provided.")),
                "log_error": log_error,
            }

            st.rerun()
    else:
        st.info("No stopped containers are available for recovery.")

    # 7. Policy Decision History (Dry-Run Audit Trail)
    st.markdown("## 📋 Policy Decision Audit History (Dry-Run)")

    try:
        policy_history_events = load_policy_history(limit=20)
        if policy_history_events:
            st.dataframe(
                pd.DataFrame(format_policy_history_rows(policy_history_events)),
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("No policy evaluation decisions recorded yet.")
    except Exception as pol_hist_error:
        st.warning(f"Unable to load policy audit history: {pol_hist_error}")

    # 8. Recovery Execution History
    st.markdown("## 📜 Recovery History")

    try:
        history_events = load_recovery_history(limit=20)
        if history_events:
            st.dataframe(
                pd.DataFrame(format_recovery_history_rows(history_events)),
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("No recovery events recorded yet.")
    except Exception as history_error:
        st.warning(f"Unable to load recovery history: {history_error}")

    # 9. Threshold Information
    with st.expander("Monitoring thresholds"):
        st.write("CPU: warning at 70%, critical at 90%.")
        st.write("Memory: warning at 80%, critical at 90%.")
        st.write("Disk: warning at 80%, critical at 90%.")

except Exception as error:
    st.error("Monitoring could not be completed.")
    st.exception(error)
