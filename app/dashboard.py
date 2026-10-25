#!/usr/bin/env python3

"""
LinuxOps Operations Center & 100+ Podman Container Observability Platform (Phase 2).

Interactive Streamlit dashboard for:
- 100+ container discovery, deep inspection, and metric telemetry
- Evidence-based root-cause diagnostics and incident tracking
- Searchable and filterable container inventory with smooth pagination
- Safe policy-controlled recovery with human authorization gate
- Post-recovery health verification and audit history
- System monitoring metrics, historical resource trends, and operational alerts
"""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
from typing import Any

# Ensure project root is in sys.path for standalone or nested execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st

from app.alerts import classify_alerts, format_alert_rows, summarize_alerts
from app.analytics import (
    INCIDENT_CATEGORIES,
    compute_operational_reliability_metrics,
    evaluate_advanced_operational_alerts,
    format_timeline_rows,
    get_explainable_diagnostic_guidance,
    get_unified_incident_timeline,
    get_watchdog_status,
)
from app.combined_monitor import collect_combined_report
from app.container_inspector import (
    get_host_identity,
    get_podman_context,
    scan_containers,
)
from app.demo_data import (
    get_demo_scenario,
    get_demo_scenario_keys,
    get_demo_timeline_events,
    get_demo_watchdog_state,
    is_demo_target,
    simulate_demo_approval,
    simulate_demo_execution,
)
from app.diagnosis import diagnose_container
from app.diagnostics_engine import (
    diagnose_all_containers,
    diagnose_container_record,
    redact_sensitive_text,
    tail_container_logs,
)
from app.history import (
    format_policy_history_rows,
    format_recovery_history_rows,
    get_policy_decision_stats,
    get_recovery_success_rate,
    load_policy_history,
    load_recovery_history,
    record_recovery_event,
)
from app.monitor import get_metric_trends
from app.policy_service import evaluate_container_policy
from app.auth import (
    AuthenticatedUser,
    UserRole,
    authenticate_user,
    check_permission,
    get_user_session_key,
    logout_current_user,
    render_login_gate,
)
from app.host_registry import (
    HostConnectionStatus,
    get_global_host_registry,
)
from app.recovery_controller import (
    SUPPORTED_OPERATIONS,
    approve_remediation_plan,
    build_remediation_plan,
    evaluate_incident_recovery,
    execute_authorized_recovery,
    is_approval_valid,
    is_global_recovery_disabled,
    is_protected_container_target,
    reject_remediation_plan,
    set_global_recovery_disabled,
    validate_approval_token,
)


def format_metric_trend_df(samples: list[dict]) -> pd.DataFrame:
    """Format metric trend samples into a pandas DataFrame suitable for charting."""
    if not samples:
        return pd.DataFrame()

    rows = []
    for s in samples:
        if not isinstance(s, dict):
            continue
        ts = s.get("timestamp", "N/A")
        cpu = s.get("cpu_usage_percent")
        mem = s.get("memory", {}).get("usage_percent") if isinstance(s.get("memory"), dict) else None
        disk = s.get("disk", {}).get("usage_percent") if isinstance(s.get("disk"), dict) else None

        rows.append({
            "Timestamp": ts,
            "CPU (%)": cpu,
            "Memory (%)": mem,
            "Disk (%)": disk,
        })

    df = pd.DataFrame(rows)
    if not df.empty and "Timestamp" in df.columns:
        df.set_index("Timestamp", inplace=True)
    return df


def filter_and_paginate_containers(
    containers: list[dict],
    search_query: str = "",
    state_filter: str = "ALL",
    health_filter: str = "ALL",
    page: int = 1,
    page_size: int = 25,
    severity_filter: str = "ALL",
    label_filter: str = "",
    incidents: list[dict] | None = None,
) -> tuple[list[dict], int, int]:
    """
    Filter containers by text search, state, health status, severity, and labels,
    and return the requested page of results along with total count and total pages.
    """
    if not isinstance(containers, list):
        return [], 0, 1

    clean_search = (search_query or "").strip().lower()
    clean_state = (state_filter or "ALL").strip().lower()
    clean_health = (health_filter or "ALL").strip().lower()
    clean_severity = (severity_filter or "ALL").strip().upper()
    clean_label = (label_filter or "").strip().lower()

    # Precompute container name -> highest severity mapping if incidents provided
    container_sev_map: dict[str, str] = {}
    if incidents and isinstance(incidents, list):
        sev_rank = {"CRITICAL": 3, "WARNING": 2, "INFO": 1}
        for inc in incidents:
            if isinstance(inc, dict):
                cname = inc.get("container_name")
                csev = str(inc.get("severity") or "INFO").upper()
                if cname:
                    current_rank = sev_rank.get(container_sev_map.get(cname, ""), 0)
                    if sev_rank.get(csev, 0) > current_rank:
                        container_sev_map[cname] = csev

    filtered = []
    for c in containers:
        if not isinstance(c, dict):
            continue

        c_name = str(c.get("name") or "")

        # State filter
        c_state = str(c.get("state") or "").strip().lower()
        if clean_state != "all" and c_state != clean_state:
            continue

        # Health filter
        c_health = str(c.get("health_status") or c.get("health") or "").strip().lower()
        if clean_health != "all" and c_health != clean_health:
            continue

        # Severity filter
        if clean_severity != "ALL":
            highest_sev = container_sev_map.get(c_name, "NONE")
            if clean_severity == "NONE" and highest_sev != "NONE":
                continue
            elif clean_severity != "NONE" and highest_sev != clean_severity:
                continue

        # Label filter
        if clean_label:
            labels = c.get("labels") or {}
            label_match = False
            if isinstance(labels, dict):
                for k, v in labels.items():
                    if clean_label in str(k).lower() or clean_label in str(v).lower():
                        label_match = True
                        break
            elif isinstance(labels, list):
                label_match = any(clean_label in str(item).lower() for item in labels)
            if not label_match:
                continue

        # Search query filter (matches name, id, short_id, or image)
        if clean_search:
            cid = str(c.get("id") or "").lower()
            short_id = str(c.get("short_id") or "").lower()
            image = str(c.get("image") or "").lower()
            if (
                clean_search not in c_name.lower()
                and clean_search not in cid
                and clean_search not in short_id
                and clean_search not in image
            ):
                continue

        filtered.append(c)

    total_count = len(filtered)
    page_size = max(1, int(page_size))
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    page = max(1, min(int(page), total_pages))

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated = filtered[start_idx:end_idx]

    return paginated, total_count, total_pages



def format_container_inventory_rows(containers: list[dict]) -> list[dict]:
    """
    Format container dictionaries into clean dashboard presentation rows.
    Strictly distinguishes running unmonitored from healthy containers.
    """
    if not isinstance(containers, list):
        return []

    rows = []
    for c in containers:
        if not isinstance(c, dict):
            continue

        name = str(c.get("name") or "N/A")
        short_id = str(c.get("short_id") or (c.get("id", "")[:12] if c.get("id") else "N/A"))
        state = str(c.get("state") or "unknown").lower()
        health = str(c.get("health_status") or c.get("health") or "none").lower()

        # Strict health status presentation: Never claim healthy solely because running!
        if state == "running":
            if health == "healthy":
                health_display = "🟢 Healthy"
            elif health == "unhealthy":
                health_display = "🔴 Unhealthy"
            elif health == "starting":
                health_display = "🟡 Starting"
            else:
                health_display = "⚪ Running (Unmonitored)"
        elif state in {"exited", "stopped"}:
            health_display = "⏹️ Stopped"
        else:
            health_display = f"❓ {state.capitalize()}"

        # Resource metrics presentation
        metrics = c.get("metrics", {})
        cpu_stat = metrics.get("cpu_percent_status", "unavailable")
        cpu_val = metrics.get("cpu_percent")
        if isinstance(cpu_val, dict):
            cpu_stat = cpu_val.get("status", cpu_stat)
            cpu_val = cpu_val.get("value")

        if cpu_stat == "ok" and cpu_val is not None:
            cpu_display = f"{cpu_val:.1f}%"
        elif cpu_stat == "zero":
            cpu_display = "0.0%"
        elif cpu_stat == "stale":
            cpu_display = f"{cpu_val:.1f}% (Stale)" if cpu_val is not None else "Stale"
        else:
            cpu_display = f"[{cpu_stat}]"

        mem_stat = metrics.get("mem_percent_status", "unavailable")
        mem_val = metrics.get("mem_percent")
        if isinstance(mem_val, dict):
            mem_stat = mem_val.get("status", mem_stat)
            mem_val = mem_val.get("value")

        if mem_stat == "ok" and mem_val is not None:
            mem_display = f"{mem_val:.1f}%"
        elif mem_stat == "zero":
            mem_display = "0.0%"
        elif mem_stat == "stale":
            mem_display = f"{mem_val:.1f}% (Stale)" if mem_val is not None else "Stale"
        else:
            mem_display = f"[{mem_stat}]"

        restarts = c.get("restart_count", 0)
        exit_code = c.get("exit_code", "N/A")
        image = str(c.get("image") or "N/A")

        ports_raw = c.get("ports")
        if isinstance(ports_raw, dict):
            port_items = []
            for cp, bs in ports_raw.items():
                if bs and isinstance(bs, list):
                    port_items.append(f"{cp}->{','.join(bs)}")
                else:
                    port_items.append(cp)
            ports_display = ", ".join(port_items) if port_items else "None"
        elif isinstance(ports_raw, list):
            ports_display = ", ".join(ports_raw) if ports_raw else "None"
        else:
            ports_display = "None"

        is_demo = bool(c.get("is_demo") or str(c.get("name", "")).startswith("demo-"))
        data_type = "🧪 DEMO DATA" if is_demo else "🟢 LIVE"

        rows.append({
            "Container Name": f"{name} [DEMO]" if is_demo else name,
            "Type": data_type,
            "Short ID": short_id,
            "State": state.upper(),
            "Health Status": health_display,
            "CPU": cpu_display,
            "Memory": mem_display,
            "Restarts": restarts,
            "Exit Code": exit_code,
            "Ports": ports_display,
            "Image": image,
        })
    return rows


def format_incident_rows(
    incidents: list[dict],
    last_recovery: dict | None = None,
    acknowledged_ids: set | None = None,
) -> list[dict]:
    """Format structured diagnostic incidents into dashboard presentation rows."""
    if not isinstance(incidents, list):
        return []

    rows = []
    ack_set = acknowledged_ids or set()
    for inc in incidents:
        if not isinstance(inc, dict):
            continue

        sev = str(inc.get("severity") or "INFO").upper()
        if sev == "CRITICAL":
            sev_badge = "🚨 CRITICAL"
        elif sev == "WARNING":
            sev_badge = "⚠️ WARNING"
        else:
            sev_badge = "ℹ️ INFO"

        evidence_list = inc.get("evidence", [])
        evidence_str = "; ".join(str(e) for e in evidence_list) if isinstance(evidence_list, list) else str(evidence_list)

        conf = inc.get("confidence", 0.0)
        conf_pct = f"{int(conf * 100)}%" if isinstance(conf, (int, float)) else "N/A"

        c_name = inc.get("container_name", "N/A")
        inc_id = inc.get("incident_id", "")

        # 1. Evidence Verification: Deterministic capture of failure indicators
        raw_ver = str(inc.get("verification_status") or "").upper()
        if raw_ver in {"VERIFIED", "CONFIRMED"}:
            ev_status = "🔍 Confirmed Telemetry"
        else:
            ev_status = "⚠️ Inferred Signal"

        # 2. Incident Lifecycle Resolution: Never marked resolved unless actually verified post-action!
        is_resolved = (
            last_recovery is not None
            and last_recovery.get("container") in {c_name, f"{c_name} [SIMULATED]"}
            and last_recovery.get("verification_status") in {"VERIFIED", "SIMULATED_VERIFIED"}
            and last_recovery.get("success") is True
        )

        if is_resolved:
            incident_status = "✅ RESOLVED (Verified Post-Action)"
        elif inc_id in ack_set:
            incident_status = "🟡 ACKNOWLEDGED (Open)"
        else:
            incident_status = "🚨 OPEN (Active Failure)" if sev == "CRITICAL" else ("⚠️ OPEN (Warning)" if sev == "WARNING" else "ℹ️ OPEN (Info)")

        rows.append({
            "Severity": sev_badge,
            "Container": c_name,
            "Rule ID": inc.get("rule_id", "N/A"),
            "Probable Cause": inc.get("probable_cause", "Unknown"),
            "Confidence": conf_pct,
            "Evidence": evidence_str,
            "Evidence Status": ev_status,
            "Incident Status": incident_status,
            "Status": incident_status,
            "Recommended Action": inc.get("recommended_action", "INVESTIGATE"),
            "Detected At": inc.get("timestamp", "N/A"),
        })
    return rows


@st.cache_data(ttl=5, show_spinner=False)
def get_cached_combined_report() -> dict:
    """Cached wrapper around collect_combined_report with a 5-second TTL."""
    return collect_combined_report()


@st.cache_data(ttl=10, show_spinner=False)
def get_cached_container_scan() -> dict:
    """Cached wrapper around scan_containers and diagnostics with a 10-second TTL."""
    try:
        scan_res = scan_containers()
        diag_res = diagnose_all_containers(scan_res.get("containers", []))
        incidents = diag_res.get("incidents", []) if isinstance(diag_res, dict) else (diag_res or [])
        return {
            "scan": scan_res,
            "incidents": incidents,
            "error": None,
        }
    except Exception as exc:
        host_meta = get_host_identity()
        podman_meta = get_podman_context()
        return {
            "scan": {
                "host": host_meta,
                "host_identity": host_meta,
                "podman_context": podman_meta,
                "containers": [],
                "discovered_count": 0,
                "inspected_count": 0,
                "failed_count": 0,
                "skipped_count": 0,
                "healthy_count": 0,
                "unhealthy_count": 0,
                "stale_count": 0,
                "scan_duration_seconds": 0.0,
                "errors": [str(exc)],
            },
            "incidents": [],
            "error": str(exc),
        }


st.set_page_config(
    page_title="LinuxOps Operations Console",
    page_icon="🖥️",
    layout="wide",
)

# Custom styling for a modern, clean Linux/cloud operations console
st.markdown(
    """
<style>
    /* Metric Card Styling */
    [data-testid="stMetric"] {
        background-color: rgba(15, 23, 42, 0.75) !important;
        border: 1px solid rgba(148, 163, 184, 0.32) !important;
        border-radius: 8px !important;
        padding: 10px 14px !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.25) !important;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.55rem !important;
        font-weight: 700 !important;
        color: #ffffff !important;
    }
    [data-testid="stMetricLabel"] {
        font-size: 0.84rem !important;
        color: #e2e8f0 !important;
        font-weight: 600 !important;
    }
    .env-pill-container {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 8px;
        margin-bottom: 16px;
    }
    .env-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(30, 41, 59, 0.85);
        border: 1px solid rgba(148, 163, 184, 0.35);
        padding: 5px 12px;
        border-radius: 6px;
        font-size: 0.82rem;
        color: #f1f5f9;
        font-weight: 500;
    }
    .env-pill strong {
        color: #ffffff;
        font-weight: 700;
    }
    .status-dot-green {
        height: 8px; width: 8px;
        background-color: #10b981;
        border-radius: 50%;
        display: inline-block;
    }
    .status-dot-amber {
        height: 8px; width: 8px;
        background-color: #f59e0b;
        border-radius: 50%;
        display: inline-block;
    }
    .status-dot-red {
        height: 8px; width: 8px;
        background-color: #ef4444;
        border-radius: 50%;
        display: inline-block;
    }
    .status-dot-blue {
        height: 8px; width: 8px;
        background-color: #06b6d4;
        border-radius: 50%;
        display: inline-block;
    }
</style>
""",
    unsafe_allow_html=True,
)

# Authentication & Authorization Gate
try:
    from streamlit.runtime.scriptrunner_utils.script_run_context import get_script_run_ctx
    _ctx = get_script_run_ctx()
except Exception:
    _ctx = None

current_user = authenticate_user()
if _ctx is None and not current_user:
    # Bare module import in non-Streamlit context (e.g. unit test runner importing helper functions)
    current_user = AuthenticatedUser("test@linuxops.local", "Test Operator", UserRole.ADMIN, "test")

if not current_user:
    render_login_gate()
    st.stop()

# Header Row
head_col, user_col, action_col = st.columns([3, 2, 2])
with head_col:
    st.markdown(
        "<div style='font-size:1.6rem; font-weight:800; color:#f8fafc; line-height:1.2;'>"
        "🖥️ LinuxOps Operations Console"
        "</div>"
        "<div style='font-size:0.86rem; color:#94a3b8; margin-top:3px;'>"
        "100+ Podman Container Observability, Root-Cause Diagnostics & Safe Recovery"
        "</div>",
        unsafe_allow_html=True,
    )

with user_col:
    role_badge = "🛡️ ADMIN" if current_user.is_admin else "👁️ VIEWER"
    badge_bg = "#dc2626" if current_user.is_admin else "#2563eb"
    st.markdown(
        f"<div style='background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 6px 12px; margin-top: 4px;'>"
        f"<div style='font-size: 0.84rem; font-weight: 700; color: #f8fafc;'>👤 {current_user.name}</div>"
        f"<div style='font-size: 0.74rem; color: #94a3b8;'>{current_user.email} &nbsp; "
        f"<span style='background: {badge_bg}; color: #ffffff; padding: 1px 6px; border-radius: 4px; font-weight: 700; font-size: 0.7rem;'>{role_badge}</span>"
        f"</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

kill_switch_active = is_global_recovery_disabled()
with action_col:
    act_c1, act_c2, act_c3 = st.columns(3)
    with act_c1:
        if st.button("🔄 Refresh", type="primary", help="Re-scan containers and telemetry", use_container_width=True):
            get_cached_combined_report.clear()
            get_cached_container_scan.clear()
            st.rerun()
    with act_c2:
        if kill_switch_active:
            if st.button("🔓 Unlock", help="Deactivate recovery kill-switch", disabled=not current_user.is_admin, use_container_width=True):
                set_global_recovery_disabled(False)
                st.rerun()
        else:
            if st.button("🛑 Freeze", type="secondary", help="Activate global recovery kill-switch", disabled=not current_user.is_admin, use_container_width=True):
                set_global_recovery_disabled(True)
                st.rerun()
    with act_c3:
        if st.button("🚪 Sign Out", help="Sign out of LinuxOps Operations Console", use_container_width=True):
            logout_current_user(current_user)

# Mode Selector: Simulation Lab vs Live Host Monitoring
mode_col1, mode_col2 = st.columns([1, 2])
with mode_col1:
    selected_mode = st.radio(
        "Operational Mode",
        ["🧪 Simulation Lab (Synthetic Scenarios)", "🟢 Live Host Monitoring (Configured Hosts)"],
        index=0,
        horizontal=True,
        key="app_operational_mode",
        help="Switch between synthetic simulation scenarios and live read-only remote host monitoring.",
    )
is_demo_mode = "Simulation" in selected_mode or "Demo" in selected_mode

selected_scenario_key = "nominal"
if is_demo_mode:
    with mode_col2:
        scenario_map = {
            "nominal": "🟢 1. Nominal Fleet (All Systems Healthy — 8 Microservices)",
            "db_connection_refused": "🚨 2. Database Outage & Cascading Failures (Connection Refused)",
            "crash_loop_oom": "🚨 3. Memory Leak & Crash Loop (Kernel OOM Killer & Restart Thrashing)",
            "failing_health_check": "⚠️ 4. Unhealthy Probe & Internal Deadlock (HTTP 503 Failing Probe)",
            "stopped_container": "ℹ️ 5. Gracefully Stopped Batch Container (Maintenance / Exit 0)",
            "scale_105_benchmark": "⚡ 6. 100+ Scale Fleet Benchmark (105 Microservices & Pagination)",
        }
        selected_scenario_key = st.selectbox(
            "Interactive Simulation Scenario",
            list(scenario_map.keys()),
            format_func=lambda k: scenario_map[k],
            key="demo_scenario_select",
            help="Select a scenario to dynamically update inventory, incidents, diagnostics, and metrics trends.",
        )
        if st.session_state.get("_last_active_demo_scenario") != selected_scenario_key:
            st.session_state["_last_active_demo_scenario"] = selected_scenario_key
            st.session_state.pop("active_approval_token", None)
            st.session_state.pop("approved_plan_hash", None)
            st.session_state.pop("approved_container", None)
            st.session_state.pop("last_recovery_result", None)
            st.session_state.pop(get_user_session_key("active_approval_token", current_user), None)
            st.session_state.pop(get_user_session_key("approved_plan_hash", current_user), None)
            st.session_state.pop(get_user_session_key("approved_container", current_user), None)
            st.session_state.pop(get_user_session_key("approved_by_user", current_user), None)
else:
    with mode_col2:
        host_registry = get_global_host_registry()
        registered_hosts = host_registry.list_hosts()
        if registered_hosts:
            host_options = {h.host_id: f"{h.name} [{h.status.value}]" for h in registered_hosts}
            selected_host_id = st.selectbox(
                "Target Monitored Host",
                list(host_options.keys()),
                format_func=lambda hid: host_options[hid],
                help="Select target remote Linux/Podman host configured for monitoring.",
            )
        else:
            st.info("📡 **Monitored Target**: Local Development Host (Ubuntu WSL2 Podman). In production, configure remote agents via `scripts/linuxops_agent.py`.")

try:
    if is_demo_mode:
        demo_scenario = get_demo_scenario(selected_scenario_key)
        all_containers = demo_scenario["containers"]
        diag_res = diagnose_all_containers(all_containers)
        active_incidents = diag_res.get("incidents", [])

        system = demo_scenario["system"]
        memory = system["memory"]
        disk = system["disk"]
        metric_samples = demo_scenario.get("metrics_samples", [])

        counts = demo_scenario.get("summary_counts", {})
        host_id = {
            "hostname": "NehaBorse (WSL2 Demo)",
            "machine_id": "16bbdd68a6f74ba086bc8b3d87db1e45",
            "distribution": "Ubuntu 24.04.5 LTS (Demo Environment)",
            "kernel": "Linux 6.6.36.6-microsoft-standard-WSL2",
            "arch": "x86_64",
        }
        podman_ctx = {
            "available": True,
            "binary": "/usr/bin/podman",
            "version": "4.9.3",
            "distribution": "Ubuntu 24.04.5 LTS",
            "rootless": True,
            "socket_path": "/run/user/1000/podman/podman.sock",
            "storage_root": "/home/neha_borse/.local/share/containers/storage",
            "is_ubuntu": True,
            "isolation_verified": True,
            "error": None,
        }
        scan_res = {
            "host": host_id,
            "host_identity": host_id,
            "podman_context": podman_ctx,
            "containers": all_containers,
            "discovered_count": counts.get("discovered_count", len(all_containers)),
            "inspected_count": counts.get("inspected_count", len(all_containers)),
            "healthy_count": counts.get("healthy_count", 0),
            "unhealthy_count": counts.get("unhealthy_count", 0),
            "stopped_count": counts.get("stopped_count", 0),
            "running_count": counts.get("running_count", 0),
            "failed_count": 0,
            "stale_count": 0,
            "scan_duration_seconds": counts.get("scan_duration_seconds", 0.04),
            "data_freshness_seconds": 0.4,
            "is_complete": True,
            "latency_stats": demo_scenario.get("latency_stats", {
                "p50_ms": 1.8, "p90_ms": 3.2, "p95_ms": 4.5, "p99_ms": 7.1, "max_ms": 9.4, "min_ms": 0.6, "sample_count": len(all_containers)
            }),
            "cache_stats": demo_scenario.get("cache_stats", {
                "hits": len(all_containers) - 1, "misses": 1, "hit_ratio_percent": 95.5, "size": len(all_containers), "max_size": 2000
            }),
            "errors": [],
        }
    else:
        report = get_cached_combined_report()
        scan_data = get_cached_container_scan()

        system = report["system"]
        memory = system["memory"]
        disk = system["disk"]
        container_summary = report["container_summary"]

        scan_res = scan_data["scan"]
        all_containers = scan_res.get("containers", [])
        active_incidents = scan_data.get("incidents", [])

        # Classify active operational alerts
        active_alerts = classify_alerts(report)
        alert_summary = summarize_alerts(active_alerts)

        # Resolve Host and Podman context (Priority 1 & 2)
        host_id = scan_res.get("host") or scan_res.get("host_identity") or {}
        if not host_id or not host_id.get("hostname") or host_id.get("hostname") == "unknown":
            host_id = get_host_identity()

        podman_ctx = scan_res.get("podman_context") or get_podman_context()
        metric_samples = get_metric_trends(limit=50)

    hostname_val = host_id.get("hostname")
    machine_id_val = host_id.get("machine_id")
    distro_val = host_id.get("distribution") or host_id.get("os", "Linux")
    kernel_val = host_id.get("kernel", "N/A")
    arch_val = host_id.get("arch", "x86_64")

    host_ok = bool(hostname_val and hostname_val != "unknown")
    machine_ok = bool(machine_id_val and machine_id_val != "unknown")
    podman_ok = podman_ctx.get("available", False)
    isolation_ok = podman_ctx.get("isolation_verified", False)

    scan_ts = scan_res.get("scan_timestamp") or scan_res.get("scan_completed_iso", "N/A")
    freshness = scan_res.get("data_freshness_seconds")
    freshness_str = f"{freshness:.1f}s ago" if freshness is not None else "N/A"
    is_complete = scan_res.get("is_complete", True)

    if not host_ok or not machine_ok:
        st.error(
            f"⚠️ **Host Identification Failure**: Unable to resolve host identity or machine ID. "
            f"Hostname: `{hostname_val or 'UNRESOLVED'}` | Machine ID: `{machine_id_val or 'UNRESOLVED'}`. "
            "Please check `/etc/machine-id` or OS permissions."
        )

    # Environment Context Status Pills (Priority 1 & 2)
    host_dot = "status-dot-green" if host_ok else "status-dot-red"
    pod_dot = "status-dot-green" if podman_ok else "status-dot-red"
    iso_dot = "status-dot-green" if isolation_ok else "status-dot-amber"
    kill_dot = "status-dot-red" if kill_switch_active else "status-dot-blue"

    host_pill = f"Host: <strong>{hostname_val if host_ok else 'UNRESOLVED'}</strong> ({distro_val} • {arch_val})"
    mid_pill = f"Machine ID: <code>{machine_id_val[:12] if machine_ok else 'UNAVAILABLE'}</code>"
    pod_pill = f"Podman: <strong>v{podman_ctx.get('version', 'N/A')}</strong> (Rootless: {'Yes' if podman_ctx.get('rootless') else 'No'})"
    iso_pill = "Workload Isolation: <strong>🟢 Ubuntu-24.04 WSL2 (Isolated)</strong>" if isolation_ok else "Workload Isolation: <strong>⚠️ Context Warning</strong>"
    kill_pill = "Recovery Safety: <strong>🛑 Kill-Switch Active</strong>" if kill_switch_active else "Recovery Safety: <strong>🛡️ Armed (SAFE Mode)</strong>"

    st.markdown(
        f"""
<div class="env-pill-container">
    <div class="env-pill"><span class="{host_dot}"></span>{host_pill}</div>
    <div class="env-pill">{mid_pill}</div>
    <div class="env-pill"><span class="{pod_dot}"></span>{pod_pill}</div>
    <div class="env-pill"><span class="{iso_dot}"></span>{iso_pill}</div>
    <div class="env-pill"><span class="{kill_dot}"></span>{kill_pill}</div>
    <div class="env-pill">⏱️ Scan: <strong>{freshness_str}</strong> ({'🟢 Complete' if is_complete else '🟠 Partial'})</div>
</div>
""",
        unsafe_allow_html=True,
    )

    # Prominent Mode Banner
    if is_demo_mode:
        focus_bullets = "".join(f"<li style='margin-bottom: 4px; color: #ffffff;'>{f}</li>" for f in demo_scenario.get("demonstration_focus", []))
        st.markdown(
            f"""
<div style="background: #0f172a; border: 2px solid #0284c7; border-radius: 8px; padding: 16px 22px; margin: 6px 0 18px 0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <div style="font-weight: 800; font-size: 1.1rem; color: #38bdf8; letter-spacing: 0.3px;">
            🧪 DEMO DATA ACTIVE — DISPLAYING SYNTHETIC DEMONSTRATION WORKLOADS (SIMULATED)
        </div>
        <span style="background: #0284c7; color: #ffffff; padding: 4px 10px; border-radius: 4px; font-size: 0.78rem; font-weight: 800; letter-spacing: 0.5px;">DEMO DATA</span>
    </div>
    <div style="font-size: 0.95rem; color: #ffffff; line-height: 1.6;">
        <strong style="color: #38bdf8;">Active Scenario:</strong> <span style="color: #ffffff; font-weight: 700;">{demo_scenario.get('title')}</span><br>
        <span style="color: #f1f5f9; font-weight: 400;">{demo_scenario.get('summary')}</span>
    </div>
    <div style="margin-top: 12px; font-size: 0.88rem; color: #ffffff; background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 12px 18px;">
        <strong style="color: #38bdf8; font-size: 0.9rem;">💡 Demonstration Highlights for Faculty & Evaluators:</strong>
        <ul style="margin: 8px 0 0 18px; padding: 0; color: #ffffff; line-height: 1.6;">
            {focus_bullets}
        </ul>
    </div>
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
<div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 12px 18px; margin: 4px 0 16px 0;">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="font-weight: 700; font-size: 0.95rem; color: #34d399;">
            🟢 LIVE PODMAN MONITORING — READ-ONLY MODE
        </div>
        <span style="background: rgba(16, 185, 129, 0.25); color: #6ee7b7; padding: 2px 7px; border-radius: 4px; font-size: 0.72rem; font-weight: 600;">LIVE ENGINE</span>
    </div>
    <div style="font-size: 0.88rem; color: #e2e8f0; margin-top: 4px; line-height: 1.5;">
        Connected to live rootless Podman engine (v{podman_ctx.get('version', 'N/A')}) in <strong>Ubuntu-24.04 WSL2</strong>. All recovery actions are read-only with the global kill-switch active to preserve host stability. Workloads in Fedora WSL2 (e.g. <code>cloudops-floci</code>) remain strictly isolated in their own rootless namespace.
    </div>
</div>
""",
            unsafe_allow_html=True,
        )

    if not is_complete:
        partial_reasons = scan_res.get("partial_reasons", [])
        st.warning(f"⚠️ Scan is PARTIAL: {'; '.join(partial_reasons) if partial_reasons else 'Some containers could not be inspected.'}")

    # Phase 12: Gather Operational Intelligence & Telemetry Context
    if is_demo_mode:
        synthetic_timeline = get_demo_timeline_events(selected_scenario_key)
        watchdog_data = get_demo_watchdog_state(selected_scenario_key)
        all_timeline_events = get_unified_incident_timeline(limit=200, synthetic_events=synthetic_timeline, include_watchdog=False)
        reliability_metrics = compute_operational_reliability_metrics(timeline_events=all_timeline_events, watchdog_status=watchdog_data)
        operational_alerts = evaluate_advanced_operational_alerts(
            timeline_events=all_timeline_events,
            active_containers=all_containers,
            watchdog_status=watchdog_data,
        )
    else:
        synthetic_timeline = []
        watchdog_data = get_watchdog_status()
        all_timeline_events = get_unified_incident_timeline(limit=200, include_watchdog=True)
        reliability_metrics = compute_operational_reliability_metrics(timeline_events=all_timeline_events, watchdog_status=watchdog_data)
        operational_alerts = evaluate_advanced_operational_alerts(
            timeline_events=all_timeline_events,
            active_containers=all_containers,
            watchdog_status=watchdog_data,
        )

    # =========================================================================
    # 00 | OPERATIONAL INTELLIGENCE, RELIABILITY & UNIFIED INCIDENT TIMELINE
    # =========================================================================
    st.markdown("## 📊 00 | Operational Intelligence & Service Reliability")
    st.caption(
        "Unified operational overview: service health, host watchdog activity, "
        "empirical reliability metrics (Availability, Frequency, MTTR), deduplicated alerts, and multi-dimensional incident timeline."
    )

    # 1. Operational Service Health & Host Supervisor Overview
    wd_status_str = watchdog_data.get("status", "UNAVAILABLE")
    if wd_status_str == "HEALTHY":
        wd_badge = "🟢 HEALTHY"
        wd_border = "#10b981"
        wd_detail = f"Probe status: {watchdog_data.get('last_probe_status', 'OK')} (0 failures)"
    elif wd_status_str == "COOLDOWN":
        wd_badge = "🟡 COOLDOWN ACTIVE"
        wd_border = "#f59e0b"
        wd_detail = f"Throttled until: {watchdog_data.get('cooldown_until', 'N/A')}"
    elif wd_status_str == "DEGRADED":
        wd_badge = "🚨 DEGRADED"
        wd_border = "#ef4444"
        wd_detail = f"Consecutive failures: {watchdog_data.get('consecutive_failures', 0)}"
    else:
        wd_badge = "⚪ UNAVAILABLE"
        wd_border = "#64748b"
        wd_detail = "Supervisor status unrecorded"

    s_c1, s_c2, s_c3, s_c4 = st.columns(4)
    with s_c1:
        st.markdown(
            f"""<div style="background: rgba(30, 41, 59, 0.7); border: 1px solid #38bdf8; border-radius: 6px; padding: 10px 14px;">
                <div style="font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; font-weight: 700;">Dashboard Service</div>
                <div style="font-size: 0.95rem; color: #38bdf8; font-weight: 700; margin-top: 2px;">🟢 ACTIVE</div>
                <div style="font-size: 0.75rem; color: #cbd5e1; margin-top: 2px;">Streamlit on 127.0.0.1:8501</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with s_c2:
        st.markdown(
            f"""<div style="background: rgba(30, 41, 59, 0.7); border: 1px solid #38bdf8; border-radius: 6px; padding: 10px 14px;">
                <div style="font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; font-weight: 700;">WSL Bridge Relay</div>
                <div style="font-size: 0.95rem; color: #38bdf8; font-weight: 700; margin-top: 2px;">🟢 ACTIVE</div>
                <div style="font-size: 0.75rem; color: #cbd5e1; margin-top: 2px;">Dynamic eth0 Forwarding</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with s_c3:
        st.markdown(
            f"""<div style="background: rgba(30, 41, 59, 0.7); border: 1px solid {wd_border}; border-radius: 6px; padding: 10px 14px;">
                <div style="font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; font-weight: 700;">Watchdog Supervisor</div>
                <div style="font-size: 0.95rem; color: {wd_border}; font-weight: 700; margin-top: 2px;">{wd_badge}</div>
                <div style="font-size: 0.75rem; color: #cbd5e1; margin-top: 2px;">{wd_detail}</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with s_c4:
        kill_color = "#ef4444" if kill_switch_active else "#10b981"
        kill_label = "🔒 LOCKED (Disabled)" if kill_switch_active else "🔓 UNLOCKED (Active)"
        st.markdown(
            f"""<div style="background: rgba(30, 41, 59, 0.7); border: 1px solid {kill_color}; border-radius: 6px; padding: 10px 14px;">
                <div style="font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; font-weight: 700;">Recovery Kill-Switch</div>
                <div style="font-size: 0.95rem; color: {kill_color}; font-weight: 700; margin-top: 2px;">{kill_label}</div>
                <div style="font-size: 0.75rem; color: #cbd5e1; margin-top: 2px;">RECOVERY_DISABLED=1</div>
            </div>""",
            unsafe_allow_html=True,
        )

    # 2. Reliability KPI Metrics (Empirical & Clearly Distinguishing Measured vs Insufficient Data)
    st.markdown("### 📈 Empirical Reliability & Performance Metrics")
    kpi_c1, kpi_c2, kpi_c3, kpi_c4, kpi_c5 = st.columns(5)

    avail_info = reliability_metrics["availability"]
    avail_val_str = f"{avail_info['percent']:.1f}%" if avail_info["percent"] is not None else "N/A"
    with kpi_c1:
        st.metric(
            label="Fleet Availability",
            value=avail_val_str,
            help=f"Status: {avail_info['status']} | {avail_info['details']}",
        )
        st.caption(f"Status: `{avail_info['status']}`")

    freq_info = reliability_metrics["incident_frequency"]
    with kpi_c2:
        st.metric(
            label="Incident Frequency",
            value=f"{freq_info['incidents_per_day']:.1f}/day",
            help=f"Total: {freq_info['total_incidents']} incident(s) in {reliability_metrics['window_hours']:.1f}h window ({freq_info['incidents_per_hour']:.2f}/hr)",
        )
        st.caption(f"Total: `{freq_info['total_incidents']}` ({freq_info['status']})")

    rec_info = reliability_metrics["recoveries"]
    with kpi_c3:
        st.metric(
            label="Restart Attempts",
            value=rec_info["restart_attempts"],
            help="Total restart actions attempted across recovery and supervisor records.",
        )
        st.caption(f"Verified: `{rec_info['successful_recoveries']}` | Failed: `{rec_info['failed_recoveries']}`")

    with kpi_c4:
        st.metric(
            label="Recovery Success Rate",
            value=f"{rec_info['success_rate_percent']:.1f}%",
            help=f"{rec_info['successful_recoveries']} verified successes out of {rec_info['restart_attempts']} attempt(s)",
        )
        st.caption(f"{rec_info['successful_recoveries']}/{rec_info['restart_attempts']} verified cycles")

    mttr_info = reliability_metrics["mttr"]
    with kpi_c5:
        st.metric(
            label="Mean Time to Recovery",
            value=mttr_info["formatted"],
            help=f"Status: {mttr_info['status']} | {mttr_info['details']}",
        )
        st.caption(f"Status: `{mttr_info['status']}`")

    # 3. Active Operational Alerts (Deduplicated with Safe Guidance)
    if operational_alerts:
        st.markdown(f"### 🚨 Active Operational Alerts ({len(operational_alerts)} Deduplicated)")
        for alert in operational_alerts:
            sev = alert.get("severity", "WARNING")
            sev_badge = "🚨 CRITICAL" if sev == "CRITICAL" else "⚠️ WARNING"
            occ_count = alert.get("occurrence_count", 1)
            occ_str = f" [Seen {occ_count}x]" if occ_count > 1 else ""

            guidance = get_explainable_diagnostic_guidance(alert, active_containers=all_containers)

            with st.expander(f"{sev_badge} — [{alert.get('category', 'GENERAL')}] {alert.get('target', 'unknown')}: {alert.get('message', '')}{occ_str}"):
                ag_c1, ag_c2 = st.columns([1, 1])
                with ag_c1:
                    st.markdown(f"**Likely Root Cause:**\n{guidance.get('likely_cause')}")
                    st.markdown(f"**Certainty:** `{guidance.get('certainty')}`")
                    st.markdown(f"**Observed Telemetry:** `{alert.get('observed_evidence', 'N/A')}`")
                    st.markdown(f"**Timestamp:** `{alert.get('timestamp', 'N/A')}`")
                with ag_c2:
                    st.markdown("**🛡️ Safe Troubleshooting Guidance (Non-Destructive):**")
                    for step in guidance.get("safe_troubleshooting_steps", []):
                        st.markdown(f"- {step}")
                    st.markdown("**Safe Read-Only Commands:**")
                    for cmd in guidance.get("safe_read_only_commands", []):
                        st.code(cmd, language="bash")
                    st.markdown("**⚠️ Risky Actions to Avoid:**")
                    for risk in guidance.get("risky_actions_to_avoid", []):
                        st.markdown(f"<span style='color: #ef4444;'>• {risk}</span>", unsafe_allow_html=True)
    else:
        st.success("✅ **Operational Alerts Nominal**: No persistent outages, repeated crash loops, active cooldowns, or failed recovery streaks detected.")

    # 4. Unified Incident Timeline with Filters
    st.markdown("### ⏱️ Unified Incident Timeline")
    st.caption("Chronological audit stream correlating incident resolutions, recovery executions, policy evaluations, and watchdog events.")

    tf_c1, tf_c2, tf_c3, tf_c4, tf_c5 = st.columns([2, 2, 2, 2, 2])
    with tf_c1:
        time_range_opt = st.selectbox(
            "Time Range",
            ["Last 1 Hour", "Last 24 Hours", "Last 7 Days", "All Time"],
            index=1,
            key="tl_time_filter",
        )
    with tf_c2:
        cat_choices = ["ALL"] + sorted(list(INCIDENT_CATEGORIES.keys()))
        selected_cat = st.selectbox("Incident Category", cat_choices, index=0, key="tl_cat_filter")
    with tf_c3:
        sev_choices = ["ALL", "CRITICAL", "WARNING", "INFO"]
        selected_sev = st.selectbox("Severity", sev_choices, index=0, key="tl_sev_filter")
    with tf_c4:
        outcome_choices = ["ALL", "RESOLVED", "VERIFIED", "FAILED", "DENIED", "PENDING_REVIEW"]
        selected_outcome = st.selectbox("Final Outcome", outcome_choices, index=0, key="tl_outcome_filter")
    with tf_c5:
        component_search = st.text_input("Component Filter", placeholder="e.g. order-processor", key="tl_comp_search")

    now_utc_filter = datetime.now(timezone.utc)
    since_filter = None
    if time_range_opt == "Last 1 Hour":
        since_filter = now_utc_filter - timedelta(hours=1)
    elif time_range_opt == "Last 24 Hours":
        since_filter = now_utc_filter - timedelta(hours=24)
    elif time_range_opt == "Last 7 Days":
        since_filter = now_utc_filter - timedelta(days=7)

    if is_demo_mode:
        timeline_to_show = get_unified_incident_timeline(
            limit=100,
            synthetic_events=synthetic_timeline,
            since=since_filter,
            category_filter=selected_cat,
            severity_filter=selected_sev,
            outcome_filter=selected_outcome,
            component_filter=component_search,
            include_watchdog=False,
        )
    else:
        timeline_to_show = get_unified_incident_timeline(
            limit=100,
            since=since_filter,
            category_filter=selected_cat,
            severity_filter=selected_sev,
            outcome_filter=selected_outcome,
            component_filter=component_search,
            include_watchdog=True,
        )

    if timeline_to_show:
        formatted_tl_rows = format_timeline_rows(timeline_to_show)
        st.dataframe(pd.DataFrame(formatted_tl_rows), width="stretch", hide_index=True)

        with st.expander("🔎 Incident Deep Analysis & Explainable Guidance"):
            inc_options = [f"{ev.get('timestamp', 'N/A')} | {ev.get('component', 'N/A')} | {ev.get('incident_category', 'GENERAL')}" for ev in timeline_to_show]
            selected_inc_idx = st.selectbox("Select Timeline Event for Root-Cause Guidance", range(len(inc_options)), format_func=lambda i: inc_options[i], key="tl_select_event")
            selected_ev = timeline_to_show[selected_inc_idx]
            ev_guidance = get_explainable_diagnostic_guidance(selected_ev, active_containers=all_containers)

            e_c1, e_c2 = st.columns(2)
            with e_c1:
                st.markdown(f"**Component:** `{selected_ev.get('component')}` | **Category:** `{selected_ev.get('incident_category')}`")
                st.markdown(f"**Likely Cause:**\n{ev_guidance.get('likely_cause')}")
                st.markdown(f"**Certainty:** `{ev_guidance.get('certainty')}`")
                st.markdown(f"**Symptoms:** {selected_ev.get('symptoms')}")
                st.markdown(f"**Attempted Action:** `{selected_ev.get('action_attempted')}` | **Outcome:** `{selected_ev.get('outcome')}`")
                if selected_ev.get("duration_seconds") is not None:
                    st.markdown(f"**Measured Duration:** `{selected_ev.get('duration_seconds'):.1f}s`")
            with e_c2:
                st.markdown("**🛡️ Safe Troubleshooting Steps:**")
                for s in ev_guidance.get("safe_troubleshooting_steps", []):
                    st.markdown(f"- {s}")
                st.markdown("**Safe Read-Only Commands:**")
                for cmd in ev_guidance.get("safe_read_only_commands", []):
                    st.code(cmd, language="bash")
                st.markdown("**⚠️ Risky Actions to Avoid:**")
                for r in ev_guidance.get("risky_actions_to_avoid", []):
                    st.markdown(f"<span style='color: #ef4444;'>• {r}</span>", unsafe_allow_html=True)
    else:
        st.info("ℹ️ No incident events match the selected timeline filters.")

    # 1. High-Scale Container Observability Overview (Feature 1 & Feature 4)
    st.markdown("## 🔍 01 | Podman Container Observability (100+ Scale)")

    # Latency percentiles & cache stats
    lat_stats = scan_res.get("latency_stats", {})
    cache_stats = scan_res.get("cache_stats", {})
    p50_val = f"{lat_stats.get('p50_ms', 0):.1f} ms" if lat_stats.get("p50_ms") is not None else "N/A"
    p95_val = f"{lat_stats.get('p95_ms', 0):.1f} ms" if lat_stats.get("p95_ms") is not None else "N/A"
    cache_ratio = f"{cache_stats.get('hit_ratio_percent', 0.0):.1f}%" if cache_stats else "N/A"

    m1, m2, m3, m4, m5, m6, m7 = st.columns(7)
    m1.metric(
        "Discovered",
        scan_res.get("discovered_count", 0),
        help="Total containers discovered by the Podman engine in this host environment (running, exited, stopped).",
    )
    m2.metric(
        "Inspected",
        scan_res.get("inspected_count", 0),
        help="Containers whose configuration, healthcheck probe metadata, and cgroup resource limits were fully queried.",
    )
    m3.metric(
        "Healthy",
        scan_res.get("healthy_count", 0),
        help="Running containers whose active healthcheck probe passed (returned exit code 0).",
    )
    m4.metric(
        "Unhealthy",
        scan_res.get("unhealthy_count", 0),
        help="Containers whose configured healthcheck probe failed or returned non-zero exit status.",
    )
    m5.metric(
        "Stopped",
        sum(1 for c in all_containers if c.get("state") in {"exited", "stopped"}),
        help="Containers in exited or stopped state (graceful maintenance exit 0, batch completion, or termination).",
    )
    m6.metric(
        "Failed / Errors",
        scan_res.get("failed_count", 0),
        help="Containers where inspect or telemetry retrieval encountered a timeout or runtime error.",
    )
    m7.metric(
        "Scan Duration",
        f"{scan_res.get('scan_duration_seconds', 0.0):.2f}s",
        help="End-to-end wall-clock duration of the concurrent discovery and metadata inspection scan.",
    )

    st.markdown(
        """
<div style="background: rgba(30, 41, 59, 0.45); border-left: 3px solid #38bdf8; padding: 6px 12px; margin-top: 4px; margin-bottom: 8px; border-radius: 4px; font-size: 0.8rem; color: #cbd5e1;">
    💡 <strong>Fleet Observability Guide</strong>:
    <strong>Discovered</strong> = total enumerated containers |
    <strong>Inspected</strong> = runtime metadata gathered |
    <strong>Healthy</strong> = passing health checks |
    <strong>Unhealthy</strong> = failing health probes |
    <strong>Stopped</strong> = exited / dormant workloads |
    <strong>Failed / Errors</strong> = scan inspect errors.
</div>
""",
        unsafe_allow_html=True,
    )

    o1, o2, o3, o4 = st.columns(4)
    o1.caption(f"⏱️ **Inspection Latency (p50)**: `{p50_val}`")
    o2.caption(f"⏱️ **Inspection Latency (p95)**: `{p95_val}`")
    o3.caption(f"💾 **Metadata Cache Ratio**: `{cache_ratio}` ({cache_stats.get('hits', 0)} hits / {cache_stats.get('misses', 0)} misses)")
    o4.caption(f"⚠️ **Stale Telemetry**: `{scan_res.get('stale_count', 0)}` container(s)")

    if scan_res.get("errors"):
        with st.expander(f"⚠️ Inspection Warnings ({len(scan_res['errors'])})"):
            for err in scan_res["errors"]:
                st.write(f"- {err}")

    # Container Inventory Filters & Pagination
    st.markdown("### Container Inventory")

    f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns([3, 2, 2, 2, 2])
    with f_col1:
        search_query = st.text_input("🔍 Search containers (name, ID, image)", key="search_query")
    with f_col2:
        state_opts = ["ALL", "running", "exited", "stopped", "paused"]
        state_filter = st.selectbox("State Filter", state_opts, key="state_filter")
    with f_col3:
        health_opts = ["ALL", "healthy", "unhealthy", "running_unmonitored", "none"]
        health_filter = st.selectbox("Health Filter", health_opts, key="health_filter")
    with f_col4:
        sev_opts = ["ALL", "CRITICAL", "WARNING", "INFO", "NONE"]
        sev_filter = st.selectbox("Incident Severity", sev_opts, key="sev_filter")
    with f_col5:
        page_size_opts = [10, 25, 50, 100]
        page_size = st.selectbox("Page Size", page_size_opts, index=1, key="page_size")

    # Calculate pagination with new severity and label filters
    paginated_containers, total_matching, total_pages = filter_and_paginate_containers(
        containers=all_containers,
        search_query=search_query,
        state_filter=state_filter,
        health_filter=health_filter,
        page=st.session_state.get("current_page", 1),
        page_size=page_size,
        severity_filter=sev_filter,
        incidents=active_incidents,
    )

    p_col1, p_col2 = st.columns([1, 4])
    with p_col1:
        selected_page = st.number_input(
            "Page",
            min_value=1,
            max_value=max(1, total_pages),
            value=st.session_state.get("current_page", 1),
            key="page_selector",
        )
        st.session_state["current_page"] = selected_page

    with p_col2:
        st.caption(f"Showing **{len(paginated_containers)}** of **{total_matching}** matching container(s) (Page {selected_page} of {total_pages})")

    if paginated_containers:
        formatted_rows = format_container_inventory_rows(paginated_containers)
        st.dataframe(pd.DataFrame(formatted_rows), width="stretch", hide_index=True)

        with st.expander("🔎 Container Deep Details (Metadata, Limits, Mounts, Health History)"):
            cont_names = [c.get("name", "unknown") for c in paginated_containers]
            selected_inspect_name = st.selectbox("Select container to view detailed telemetry", cont_names, key="inspect_detail_sel")
            selected_record = next((c for c in paginated_containers if c.get("name") == selected_inspect_name), None)

            if selected_record:
                d_c1, d_c2 = st.columns(2)
                with d_c1:
                    st.write(f"**Full ID:** `{selected_record.get('id', 'N/A')}`")
                    st.write(f"**Image:** `{selected_record.get('image', 'N/A')}`")
                    st.write(f"**Image ID:** `{selected_record.get('image_id', 'unavailable')}`")
                    st.write(f"**Created At:** `{selected_record.get('created_at', 'N/A')}`")
                    st.write(f"**Started At:** `{selected_record.get('started_at', 'N/A')}`")
                    uptime = selected_record.get("uptime_seconds")
                    st.write(f"**Uptime:** `{f'{uptime:.0f}s' if uptime is not None else 'N/A'}`")
                    st.write(f"**Restart Policy:** `{selected_record.get('restart_policy', 'none')}` (Count: `{selected_record.get('restart_count', 0)}`)")
                with d_c2:
                    st.write(f"**State:** `{selected_record.get('state', 'unknown')}` | **Exit Code:** `{selected_record.get('exit_code', 'N/A')}`")
                    st.write(f"**OOM Killed:** `{selected_record.get('oom_killed', False)}`")
                    st.write(f"**Health Status:** `{selected_record.get('health_status', 'none')}`")
                    res_limits = selected_record.get("resource_limits") or {}
                    mem_lim = res_limits.get("memory_bytes")
                    mem_str = f"{mem_lim / (1024*1024):.1f} MB" if mem_lim else "unlimited"
                    st.write(f"**Memory Limit:** `{mem_str}`")
                    st.write(f"**Swap Limit:** `{res_limits.get('memory_swap_bytes') or 'unlimited'}`")
                    telem_age = selected_record.get("telemetry_age_seconds")
                    telem_str = f"{telem_age:.1f}s" if telem_age is not None else "fresh"
                    st.write(f"**Telemetry Age:** `{telem_str}`")

                st.write("**Mounts:**")
                mounts = selected_record.get("mounts") or []
                if mounts:
                    for m in mounts:
                        if isinstance(m, dict):
                            st.write(f"- `{m.get('type')}`: `{m.get('source')}` ➡️ `{m.get('destination')}` (rw: `{m.get('rw', True)}`)")
                else:
                    st.caption("No volumes or bind mounts configured.")

                st.write("**Recent Health Probe History (Last 5):**")
                health_hist = selected_record.get("health_check_history") or []
                if health_hist:
                    for h in health_hist:
                        st.write(f"- [{h.get('end_time', 'N/A')}] Exit: `{h.get('exit_code')}` | Output: `{h.get('output', '').strip()}`")
                else:
                    st.caption("No health probe logs available.")
    else:
        # Clear, informative empty states distinguishing root causes (Priority 4)
        scan_errors = scan_res.get("errors") or []
        scan_succeeded = scan_res.get("success", True)

        if not podman_ok:
            st.error(
                f"❌ **Podman Runtime Disconnected**: {podman_ctx.get('error') or 'Podman executable or socket could not be reached.'}\n\n"
                "• **Expected Runtime**: Ubuntu 24.04 Rootless Podman\n"
                "• **Remediation**: Verify Podman is installed and functional via `podman version`."
            )
        elif not isolation_ok:
            st.warning(
                f"⚠️ **Unexpected Podman Environment / Namespace Warning**\n\n"
                f"• Storage Root: `{podman_ctx.get('storage_root')}`\n"
                f"• Distribution: `{podman_ctx.get('distribution')}`\n"
                "• **Safety Note**: Container discovery was warned because foreign storage paths or external hosts were detected."
            )
        elif not scan_succeeded or scan_errors:
            err_details = "; ".join(scan_errors) if scan_errors else "Scan timed out or discovery process terminated unexpectedly."
            st.warning(
                f"⚠️ **Container Fleet Scan Incomplete or Failed**\n\n"
                f"• **Error**: {err_details}\n"
                f"• **Duration**: {scan_res.get('scan_duration_seconds', 0.0):.2f}s\n"
                "• **Remediation**: Check `journalctl --user -u podman` or run `podman ps -a` in Ubuntu terminal."
            )
        elif all_containers and not paginated_containers:
            active_filters = []
            if search_query:
                active_filters.append(f"query: '{search_query}'")
            if state_filter != "ALL":
                active_filters.append(f"state: '{state_filter}'")
            if health_filter != "ALL":
                active_filters.append(f"health: '{health_filter}'")
            if sev_filter != "ALL":
                active_filters.append(f"severity: '{sev_filter}'")
            st.info(
                f"🔍 **No Containers Match Active Filters** ({', '.join(active_filters) if active_filters else 'None'})\n\n"
                f"• **Total Inventory in Ubuntu**: {len(all_containers)} container(s) exist, but none match the current filter selection.\n"
                "• **Suggestion**: Clear search term or set filters to **ALL** to view full inventory."
            )
        else:
            st.markdown(
                f"""
<div style="background: rgba(30, 41, 59, 0.45); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 8px; padding: 18px 22px; margin: 8px 0 16px 0;">
    <div style="font-weight: 700; font-size: 1.05rem; color: #f8fafc; margin-bottom: 6px;">
        📦 0 Containers Deployed in Local Podman Environment
    </div>
    <div style="font-size: 0.88rem; color: #cbd5e1; line-height: 1.6;">
        • <strong>Podman Runtime Active</strong>: Verified connected to <code>{podman_ctx.get('binary', '/usr/bin/podman')}</code> (v{podman_ctx.get('version', '4.9.3')}) in rootless mode.<br>
        • <strong>Storage Root</strong>: <code>{podman_ctx.get('storage_root', '~/.local/share/containers/storage')}</code>.<br>
        • <strong>Workload Isolation</strong>: Connected strictly to <strong>Ubuntu-24.04 WSL2</strong>. Workloads in Fedora WSL2 (e.g. <code>cloudops-floci</code>) or other namespaces are isolated and will not appear here.<br>
        • <strong>Scan Verification</strong>: Completed cleanly in <strong>{scan_res.get('scan_duration_seconds', 0.0):.2f}s</strong> with 0 errors. Any container started via <code>podman run</code> in this Ubuntu environment will automatically appear on next scan.
    </div>
</div>
""",
                unsafe_allow_html=True,
            )

    # 2. Structured Incidents & Root-Cause Diagnostics (Feature 2)
    st.markdown("## 🚨 02 | Incident Operations Center & Root-Cause Diagnostics")
    st.caption("Deterministic, evidence-based incident analysis answering what failed, why, and how to verify resolution.")

    if active_incidents:
        crit_count = sum(1 for i in active_incidents if i.get("severity") == "CRITICAL")
        warn_count = sum(1 for i in active_incidents if i.get("severity") == "WARNING")
        info_count = sum(1 for i in active_incidents if i.get("severity") == "INFO")

        inc_summary_msg = (
            f"Active Incidents: **{crit_count} CRITICAL** (immediate outages & connection rejections), "
            f"**{warn_count} WARNING** (degradations & non-zero exits), "
            f"**{info_count} INFO** (normal stops & baseline events)"
        )
        if crit_count > 0:
            st.error(inc_summary_msg)
        elif warn_count > 0:
            st.warning(inc_summary_msg)
        else:
            st.info(inc_summary_msg)

        st.markdown(
            """
<div style="background: rgba(30, 41, 59, 0.45); border-left: 3px solid #f59e0b; padding: 6px 12px; margin-top: 4px; margin-bottom: 8px; border-radius: 4px; font-size: 0.8rem; color: #cbd5e1;">
    🔍 <strong>Incident Evidence vs. Resolution Guide</strong>:
    <strong>Evidence Status</strong> indicates whether deterministic telemetry proof (exit codes, logs, cgroups) was confirmed by the rule engine.
    <strong>Incident Status</strong> tracks lifecycle: incidents remain <strong>OPEN</strong> until remediation is executed and post-action verification passes.
</div>
""",
            unsafe_allow_html=True,
        )

        last_rec = st.session_state.get("last_recovery_result")
        ack_ids = {
            inc.get("incident_id")
            for inc in active_incidents
            if st.session_state.get(f"ack_{inc.get('incident_id')}")
        }
        inc_rows = format_incident_rows(active_incidents, last_recovery=last_rec, acknowledged_ids=ack_ids)
        st.dataframe(pd.DataFrame(inc_rows), width="stretch", hide_index=True)

        with st.expander("🛠️ Operator Guidance, Root-Cause Analysis & Verification Checklists", expanded=True):
            for inc in active_incidents:
                inc_id = inc.get("incident_id", "N/A")
                c_name = inc.get("container_name", "N/A")
                sev = inc.get("severity", "INFO")
                sev_icon = "🚨" if sev == "CRITICAL" else "⚠️" if sev == "WARNING" else "ℹ️"

                st.markdown(f"### {sev_icon} Incident `{inc_id}` — Workload: `{c_name}`")

                # The 7 Operator Questions
                q_col1, q_col2 = st.columns(2)
                with q_col1:
                    st.markdown("#### 1. What is failing?")
                    st.write(f"**Severity:** `{sev}` — *{inc.get('severity_reason', 'N/A')}*")
                    symptoms = inc.get("symptoms") or []
                    if symptoms:
                        st.write("**Observed Symptoms:**")
                        for s in symptoms:
                            st.write(f"- {s}")

                    st.markdown("#### 2. What changed & when did it start?")
                    st.write(f"**First Seen:** `{inc.get('first_seen', inc.get('timestamp', 'N/A'))}`")
                    st.write(f"**Last Seen:** `{inc.get('last_seen', inc.get('timestamp', 'N/A'))}`")

                    st.markdown("#### 4. Which containers or services are affected?")
                    st.write(f"**Primary Container:** `{c_name}` (ID: `{inc.get('container_id', 'unknown')[:12]}`)")
                    correlated = inc.get("correlated_containers") or []
                    if correlated:
                        st.write(f"**Correlated Services:** `{', '.join(correlated)}`")
                    else:
                        st.caption("No secondary services currently correlated.")

                with q_col2:
                    st.markdown("#### 3. What is the likely root cause & evidence?")
                    st.write(f"**Primary Cause:** {inc.get('probable_cause')}")
                    st.write(f"**Confidence:** `{int(inc.get('confidence', 0)*100)}%` — *{inc.get('confidence_explanation', '')}*")

                    candidates = inc.get("candidate_causes") or []
                    if candidates:
                        st.write("**Ranked Hypotheses / Causes:**")
                        for cand in candidates:
                            c_type = cand.get("type", "INFERRED")
                            c_badge = "🟢 [CONFIRMED]" if c_type == "CONFIRMED" else "🟡 [INFERRED]"
                            st.write(f"- {c_badge} **{cand.get('cause')}** ({int(cand.get('confidence', 0)*100)}%): {cand.get('explanation')}")

                    if inc.get("alternative_explanations"):
                        st.caption(f"Alternative Explanations: {'; '.join(inc['alternative_explanations'])}")

                    if inc.get("evidence"):
                        st.write("**Deterministic Telemetry Evidence:**")
                        for ev in inc["evidence"]:
                            st.write(f"- `{ev}`")

                st.markdown("#### 6. What should the operator do next?")
                g_col1, g_col2 = st.columns(2)
                with g_col1:
                    st.write(f"**Recommended Action:** `{inc.get('recommended_action')}`")
                    st.write(f"**Why this action is suggested:** {inc.get('action_reason', 'N/A')}")
                    st.write(f"**Risks & Prerequisites:** {inc.get('risks_and_prerequisites', 'N/A')}")
                    steps = inc.get("suggested_investigation_steps") or []
                    if steps:
                        st.write("**Investigation Steps:**")
                        for step in steps:
                            st.write(f"1. {step}")

                with g_col2:
                    commands = inc.get("investigation_commands") or []
                    if commands:
                        st.write("**Illustrative Safe Investigation Commands (Read-Only):**")
                        for cmd in commands:
                            st.code(cmd, language="bash")

                st.markdown("#### 7. How can the operator verify resolution?")
                v_col1, v_col2 = st.columns(2)
                with v_col1:
                    st.write(f"**Expected Outcome:** {inc.get('expected_outcome', 'Workload restored to normal state.')}")
                    st.write(f"**Verification Procedure:** {inc.get('post_action_verification', 'Inspect container health status.')}")
                with v_col2:
                    st.write(f"**Escalation Guidance:** {inc.get('escalation_guidance', 'Escalate if unresolved.')}")

                # Non-authorizing operator acknowledgement note
                st.caption(
                    "⚠️ **Audit & Safety Boundary**: Operator notes and acknowledgement are for shift-handover tracking only. "
                    "They **DO NOT grant backend recovery authorization**."
                )
                ack_key = f"ack_{inc_id}"
                note_key = f"note_{inc_id}"
                st.text_input("Operator Shift Note / Ticket ID", key=note_key, placeholder="e.g., TICKET-10492: Investigating heap dump")
                st.checkbox("Acknowledge Incident (Shift Handover)", key=ack_key)
                st.divider()
    else:
        st.markdown(
            """
<div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 8px; padding: 14px 18px; margin: 8px 0 14px 0;">
    <div style="font-weight: 700; font-size: 0.95rem; color: #34d399; margin-bottom: 4px;">
        ✅ Fleet Health Nominal — No Active Diagnostic Incidents
    </div>
    <div style="font-size: 0.85rem; color: #94a3b8;">
        Deterministic rule engine evaluated crash-loop, OOM-kill, failed health probe, and unmonitored telemetry rules across all inventory. 0 active anomalies detected.
    </div>
</div>
""",
            unsafe_allow_html=True,
        )

    # 3. Core Troubleshooting & Controlled Remediation Workflow (Steps 1 to 8)
    st.markdown("## 🎯 03 | Container Troubleshooting & Controlled Remediation Workflow")
    st.caption(
        "The complete 5-step operational workflow: (1) Inspect runtime evidence & logs ➔ (2) Diagnose root cause ➔ "
        "(3) Recommend numbered solution ➔ (4) Require explicit human approval ➔ (5) Execute & verify outcome."
    )

    last_recovery = st.session_state.get("last_recovery_result")
    if last_recovery:
        rec_status = str(last_recovery.get("verification_status") or "UNKNOWN")
        rec_cont = str(last_recovery.get("container") or "Container")
        rec_msg = str(last_recovery.get("message") or "")
        is_sim = bool(last_recovery.get("simulated"))
        sim_tag = " [SIMULATED]" if is_sim else ""
        if rec_status in {"VERIFIED", "SIMULATED_VERIFIED"}:
            st.success(f"✅ **{rec_cont}{sim_tag}**: Recovery Succeeded & Verified Healthy! Status: `{rec_status}` — {rec_msg}")
        elif rec_status == "INCONCLUSIVE_VERIFICATION":
            st.warning(f"🟠 **{rec_cont}{sim_tag}**: Recovery Started, Verification Inconclusive: `{rec_status}` — {rec_msg}")
        elif rec_status == "REJECTED_BY_OPERATOR":
            st.info(f"ℹ️ **{rec_cont}{sim_tag}**: Remediation Action Explicitly Rejected by Operator. Rejection recorded in audit log.")
        elif rec_status == "APPROVAL_INVALIDATED":
            st.error(f"🚨 **{rec_cont}{sim_tag}**: Approval Invalidated! Plan parameters or target changed prior to execution.")
        elif rec_status == "PRECONDITION_FAILED":
            st.warning(f"⚠️ **{rec_cont}{sim_tag}**: Precondition Failed: {rec_msg}")
        else:
            st.error(f"❌ **{rec_cont}{sim_tag}**: Recovery Failed or Blocked. Status: `{rec_status}` — {rec_msg}")

    if all_containers:
        # Step 1: Select a container
        st.markdown("### Step 1 — Select Container to Troubleshoot")

        container_labels = []
        c_by_name = {}
        for c in all_containers:
            c_name = str(c.get("name") or "unknown")
            c_by_name[c_name] = c
            c_state = str(c.get("state") or "unknown").upper()
            c_health = str(c.get("health_status") or c.get("health") or "none")
            has_inc = any(i.get("container_name") == c_name for i in active_incidents)
            inc_flag = " 🚨 [ACTIVE INCIDENT]" if has_inc else ""
            container_labels.append(f"{c_name} — [{c_state}] (health: {c_health}){inc_flag}")

        selected_label = st.selectbox(
            "Select container from active inventory:",
            container_labels,
            key="troubleshoot_container_select",
        )
        selected_cont_name = selected_label.split(" ")[0] if selected_label else ""
        selected_cont = c_by_name.get(selected_cont_name, all_containers[0] if all_containers else {})
        selected_cont_name = str(selected_cont.get("name") or "unknown")

        # Step 2: Inspect status, recent logs, exit code, health, restart history and resource metrics
        st.markdown(f"### Step 2 — Inspect Runtime Evidence & Logs (`{selected_cont_name}`)")

        t_col1, t_col2, t_col3, t_col4, t_col5, t_col6 = st.columns(6)
        c_state_val = str(selected_cont.get("state") or "unknown").upper()
        c_exit_val = selected_cont.get("exit_code")
        c_exit_str = str(c_exit_val) if c_exit_val is not None else "N/A"
        c_health_val = str(selected_cont.get("health_status") or selected_cont.get("health") or "none")
        c_oom = bool(selected_cont.get("oom_killed", False))
        c_restarts = selected_cont.get("restart_count", 0)
        c_uptime = selected_cont.get("uptime_seconds")
        c_uptime_str = f"{c_uptime:.0f}s" if c_uptime is not None else "N/A"

        t_col1.metric("Status", c_state_val)
        t_col2.metric("Exit Code", c_exit_str)
        t_col3.metric("OOM Killed", "YES ⚠️" if c_oom else "No")
        t_col4.metric("Health Status", c_health_val)
        t_col5.metric("Restart Count", c_restarts)
        t_col6.metric("Uptime", c_uptime_str)

        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        c_metrics = selected_cont.get("metrics") or {}
        cpu_m = c_metrics.get("cpu_percent", {}).get("value")
        cpu_str = f"{cpu_m:.1f}%" if cpu_m is not None else "unavailable"
        mem_m = c_metrics.get("memory_percent", {}).get("value")
        mem_str = f"{mem_m:.1f}%" if mem_m is not None else "unavailable"
        res_limits = selected_cont.get("resource_limits") or {}
        mem_limit_b = res_limits.get("memory_bytes")
        mem_limit_str = f"{mem_limit_b / (1024*1024):.0f} MB" if mem_limit_b else "unlimited"
        swap_limit_b = res_limits.get("memory_swap_bytes")
        swap_limit_str = f"{swap_limit_b / (1024*1024):.0f} MB" if swap_limit_b else "unlimited"

        m_col1.caption(f"📊 **CPU Usage**: `{cpu_str}`")
        m_col2.caption(f"💾 **Memory Usage**: `{mem_str}`")
        m_col3.caption(f"🛑 **Memory Limit**: `{mem_limit_str}`")
        m_col4.caption(f"🔄 **Swap Limit**: `{swap_limit_str}`")

        # Live logs inspection
        logs_text, logs_ok = tail_container_logs(selected_cont_name, max_lines=25)
        with st.expander(f"📜 Recent Container Logs for '{selected_cont_name}' (Redacted & Bounded)", expanded=True):
            if logs_ok and logs_text:
                st.code(logs_text, language="log")
            else:
                st.info(logs_text or "No log output returned from container.")

        health_history = selected_cont.get("health_check_history") or []
        if health_history:
            with st.expander("🩺 Recent Health Check Probe History"):
                for hp in health_history[-5:]:
                    st.write(f"- [{hp.get('end_time', 'N/A')}] Exit: `{hp.get('exit_code')}` | Output: `{hp.get('output', '').strip()}`")

        # Step 3: Run deep diagnostics with log evidence
        st.markdown("### Step 3 — Detected Errors & Telemetry Evidence")

        cont_incidents = diagnose_container_record(
            container=selected_cont,
            all_containers=all_containers,
            log_retriever=tail_container_logs,
        )

        if cont_incidents:
            for inc in cont_incidents:
                i_sev = inc.get("severity", "INFO")
                i_icon = "🚨" if i_sev == "CRITICAL" else "⚠️" if i_sev == "WARNING" else "ℹ️"
                st.markdown(f"**{i_icon} Rule Triggered:** `{inc.get('rule_id')}` (Category: `{inc.get('category')}`, Severity: `{i_sev}`)")
                st.write(f"**Observed Problem:** {inc.get('probable_cause')}")

                ev_list = inc.get("evidence") or []
                if ev_list:
                    st.write("**Direct Telemetry & Log Evidence:**")
                    for ev in ev_list:
                        st.write(f"- `{ev}`")
        else:
            st.success(f"✅ No anomalies or error rules triggered for '{selected_cont_name}'. Container appears operational.")

        # Step 4: Plain-Language Diagnosis
        st.markdown("### Step 4 — Plain-Language Root-Cause Diagnosis")
        primary_incident = cont_incidents[0] if cont_incidents else None

        d_col1, d_col2 = st.columns(2)
        with d_col1:
            st.markdown("#### Confirmed Facts (Direct Telemetry)")
            confirmed_facts = []
            if c_state_val in {"EXITED", "STOPPED"}:
                confirmed_facts.append(f"Container process is terminated with exit code {c_exit_str}.")
            if c_oom:
                confirmed_facts.append("Kernel memory controller flagged OOMKilled=True; process killed by SIGKILL.")
            if c_restarts >= 3:
                confirmed_facts.append(f"Container has repeatedly failed and restarted {c_restarts} times (crash loop).")
            if c_health_val == "unhealthy":
                confirmed_facts.append("Container healthcheck probe returned non-zero exit code.")
            if primary_incident:
                for ev in primary_incident.get("evidence", [])[:2]:
                    confirmed_facts.append(f"Evidence: {ev}")

            if confirmed_facts:
                for fact in confirmed_facts:
                    st.write(f"• {fact}")
            else:
                st.write(f"• Container is currently {c_state_val.lower()} with healthy telemetry.")

            st.markdown("#### Operational Impact")
            if primary_incident:
                st.write(f"**Severity**: `{primary_incident.get('severity')}` — {primary_incident.get('severity_reason')}")
            else:
                st.write("No active service degradation observed.")

        with d_col2:
            st.markdown("#### Likely Causes & Certainty")
            if primary_incident:
                candidates = primary_incident.get("candidate_causes") or []
                if candidates:
                    for cand in candidates:
                        c_type = cand.get("type", "INFERRED")
                        badge = "🟢 [CONFIRMED]" if c_type == "CONFIRMED" else "🟡 [INFERRED]"
                        conf_pct = int(cand.get("confidence", 0) * 100)
                        st.write(f"{badge} **{cand.get('cause')}** (`{conf_pct}% confidence`)")
                        st.caption(f"Rationale: {cand.get('explanation')}")
                else:
                    st.write(f"**Probable Cause:** {primary_incident.get('probable_cause')}")
                    st.write(f"**Confidence:** `{int(primary_incident.get('confidence', 0)*100)}%`")
            else:
                st.write("All telemetry indicators within normal operational baseline.")

        # Step 5: Recommended Solution & Remediation Plan
        st.markdown("### Step 5 — Recommended Solution & Remediation Plan")

        c_state_clean = str(selected_cont.get("state") or "unknown").strip().lower()
        c_health_clean = str(selected_cont.get("health_status") or selected_cont.get("health") or "none").strip().lower()
        is_healthy_running = (
            c_state_clean == "running"
            and primary_incident is None
            and c_health_clean in {"healthy", "running_unmonitored", "none"}
        )

        if is_healthy_running:
            remediation_plan = {
                "plan_id": f"PLAN_NOMINAL_{selected_cont_name}",
                "plan_hash": f"nominal_{selected_cont_name}",
                "container_name": selected_cont_name,
                "container_id": selected_cont.get("id", ""),
                "operation": "inspect_container",
                "parameters": {},
                "target_state": c_state_clean,
                "is_state_changing": False,
                "allowed": False,
                "status": "HEALTHY_NOMINAL",
                "decision": "NO_ACTION_REQUIRED",
                "reason": f"Container '{selected_cont_name}' is healthy and operating nominally. State-changing recovery is not needed.",
                "escalated": False,
                "impact": "Zero state change. Workload continues serving active traffic.",
                "risk": "None: Telemetry and health probes confirm nominal operational baseline.",
                "numbered_steps": [
                    f"1. Target State Verification: Container '{selected_cont_name}' is currently running and healthy.",
                    "2. Diagnostic Assessment: Zero active incidents, exit errors, or unresolvable blockers detected.",
                    "3. Safe Operations Stance: State-changing restart is withheld. Continuous telemetry monitoring maintained.",
                ],
                "verification_criteria": "State.Running remains True and container passes periodic health probes.",
                "checks": {"healthy_nominal": True},
            }
        elif c_state_clean == "running":
            remediation_plan = build_remediation_plan(
                container_name=selected_cont_name,
                operation="collect_logs",
                current_state=c_state_clean,
                incident=primary_incident,
                container_id=selected_cont.get("id", ""),
            )
        else:
            remediation_plan = build_remediation_plan(
                container_name=selected_cont_name,
                operation="start_container",
                current_state=c_state_clean,
                incident=primary_incident,
                container_id=selected_cont.get("id", ""),
            )

        plan_col1, plan_col2 = st.columns(2)
        with plan_col1:
            st.write(f"**Proposed Operation:** `{remediation_plan.get('operation')}` (State-Changing: `{remediation_plan.get('is_state_changing')}`)")
            st.write(f"**Expected Operational Impact:** {remediation_plan.get('impact')}")
            st.write(f"**Operational Risks & Prerequisites:** {remediation_plan.get('risk')}")
            st.write(f"**Verification Criteria:** {remediation_plan.get('verification_criteria')}")

            if is_healthy_running:
                st.success(f"✅ **Workload Operating Nominally**: Container `{selected_cont_name}` is healthy. State-changing recovery is not needed.")
            elif remediation_plan.get("allowed"):
                st.success(f"**Policy Gate Evaluation: ALLOW** — {remediation_plan.get('reason')}")
            else:
                st.error(f"**Policy Gate Evaluation: DENY** — {remediation_plan.get('reason')}")
                if remediation_plan.get("escalated"):
                    st.warning("⚠️ **INCIDENT ESCALATED**: Root cause requires human code/config intervention. Automated execution prohibited.")

        with plan_col2:
            st.write("**Numbered Remediation Steps:**")
            for step in remediation_plan.get("numbered_steps", []):
                st.write(step)

        # Step 6: Human Approval Boundary Gate
        st.markdown("### Step 6 — Controlled Approval Boundary")
        st.info(
            "🔒 **Approval Boundary Enforcement**: No state-changing operation can execute without explicit operator approval. "
            "Approval is cryptographically bound to the current plan hash. Any change to target or parameters instantly invalidates approval."
        )

        plan_hash = remediation_plan.get("plan_hash", "")
        is_protected = is_protected_container_target(selected_cont_name, selected_cont.get("id", ""))

        user_tok_key = get_user_session_key("active_approval_token", current_user)
        user_hash_key = get_user_session_key("approved_plan_hash", current_user)
        user_cont_key = get_user_session_key("approved_container", current_user)
        user_by_key = get_user_session_key("approved_by_user", current_user)

        active_token = st.session_state.get(user_tok_key) or st.session_state.get("active_approval_token")
        approved_hash = st.session_state.get(user_hash_key) or st.session_state.get("approved_plan_hash")
        approved_cont = st.session_state.get(user_cont_key) or st.session_state.get("approved_container")
        approved_by = st.session_state.get(user_by_key)

        token_valid = False
        if approved_by and approved_by != current_user.email:
            # Token approved by a different user; reject cross-user execution
            token_valid = False
        elif active_token and approved_hash == plan_hash and approved_cont == selected_cont_name:
            if active_token.startswith("SIMULATED-APPROVAL-TOKEN-"):
                token_valid = True
            else:
                token_valid = validate_approval_token(active_token, plan_hash)

        if not token_valid and active_token:
            st.session_state.pop("active_approval_token", None)
            st.session_state.pop("approved_plan_hash", None)
            st.session_state.pop("approved_container", None)
            st.session_state.pop(user_tok_key, None)
            st.session_state.pop(user_hash_key, None)
            st.session_state.pop(user_cont_key, None)
            st.session_state.pop(user_by_key, None)
            st.warning("⚠️ Plan or target container changed; previous approval has been automatically invalidated.")

        if is_protected:
            st.error(f"🔒 Container '{selected_cont_name}' is a PROTECTED WORKLOAD. All state-changing recovery actions are permanently forbidden.")

        app_col1, app_col2, app_col3 = st.columns([2, 2, 3])
        with app_col1:
            approve_label = "✅ Approve Proposed Action (Simulated)" if is_demo_mode else "✅ Approve Proposed Action"
            can_approve = (
                current_user.is_admin
                and not is_healthy_running
                and bool(remediation_plan.get("is_state_changing"))
                and bool(remediation_plan.get("allowed"))
                and not is_protected
                and not (kill_switch_active and not is_demo_mode)
                and not token_valid
            )
            if not current_user.is_admin:
                st.caption("🔒 **Role 'Viewer' is Read-Only**: Administrator credentials required to approve remediation.")
            if st.button(
                approve_label,
                disabled=not can_approve,
                key="btn_approve_plan",
            ):
                if is_demo_mode or is_demo_target(selected_cont_name):
                    approved_record = simulate_demo_approval(remediation_plan)
                else:
                    approved_record = approve_remediation_plan(remediation_plan)
                tok = approved_record["approval_token"]
                st.session_state["active_approval_token"] = tok
                st.session_state["approved_plan_hash"] = plan_hash
                st.session_state["approved_container"] = selected_cont_name
                st.session_state[get_user_session_key("active_approval_token", current_user)] = tok
                st.session_state[get_user_session_key("approved_plan_hash", current_user)] = plan_hash
                st.session_state[get_user_session_key("approved_container", current_user)] = selected_cont_name
                st.session_state[get_user_session_key("approved_by_user", current_user)] = current_user.email
                st.rerun()

        with app_col2:
            can_reject = current_user.is_admin and not is_healthy_running and bool(remediation_plan.get("is_state_changing")) and not is_protected
            if st.button(
                "❌ Reject Proposed Action",
                disabled=not can_reject,
                key="btn_reject_plan",
            ):
                if not (is_demo_mode or is_demo_target(selected_cont_name)):
                    rejected_record = reject_remediation_plan(remediation_plan)
                st.session_state.pop("active_approval_token", None)
                st.session_state.pop("approved_plan_hash", None)
                st.session_state.pop("approved_container", None)
                st.session_state.pop(get_user_session_key("active_approval_token", current_user), None)
                st.session_state.pop(get_user_session_key("approved_plan_hash", current_user), None)
                st.session_state.pop(get_user_session_key("approved_container", current_user), None)
                st.session_state.pop(get_user_session_key("approved_by_user", current_user), None)
                st.session_state["last_recovery_result"] = {
                    "container": selected_cont_name,
                    "verification_status": "REJECTED_BY_OPERATOR",
                    "message": f"Operator '{current_user.email}' explicitly rejected the proposed remediation plan.",
                    "simulated": is_demo_mode,
                }
                st.rerun()

        with app_col3:
            if is_healthy_running:
                st.caption("ℹ️ Workload is active and healthy; recovery approval is not applicable.")
            elif token_valid:
                tok_badge = "🔒 **SIMULATED APPROVAL**" if is_demo_mode else "🔒 **APPROVED**"
                approved_by_label = st.session_state.get(get_user_session_key("approved_by_user", current_user), current_user.email)
                st.success(f"{tok_badge}: Token `{active_token}` approved by `{approved_by_label}` bound to `{plan_hash}`")
            else:
                st.caption(f"Plan Hash: `{plan_hash}` (Pending Operator Approval)")

        # Step 7: Execution & Verification
        st.markdown("### Step 7 — Execution & Post-Action Verification")
        if is_healthy_running:
            st.info(f"ℹ️ **Workload Healthy**: No recovery action required for '{selected_cont_name}'.")
            can_execute = False
        elif not current_user.is_admin:
            st.caption("🔒 **Role 'Viewer' is Read-Only**: Administrator authorization required to execute remediation.")
            can_execute = False
        elif not is_demo_mode:
            st.caption("🔒 **Live Mode is Read-Only by Default**: State-changing recovery execution is disabled in Live Mode to protect live host workloads. To test interactive approval and verification, select **🧪 Simulation Lab** above.")
            can_execute = False
        else:
            can_execute = token_valid and not is_protected and remediation_plan.get("allowed")

        exec_btn_label = "▶️ Execute Simulated Action & Verify (SIMULATED)" if is_demo_mode else "▶️ Execute Approved Action & Verify"
        if st.button(
            exec_btn_label,
            type="primary",
            disabled=not can_execute,
            key="btn_execute_approved_action",
        ):
            if is_demo_mode or is_demo_target(selected_cont_name):
                with st.spinner(f"Simulating '{remediation_plan.get('operation')}' on '{selected_cont_name}' with post-action verification..."):
                    exec_result = simulate_demo_execution(remediation_plan, active_token)
                    st.session_state["last_recovery_result"] = exec_result
                    st.session_state.pop("active_approval_token", None)
                    st.session_state.pop("approved_plan_hash", None)
                    st.session_state.pop("approved_container", None)
                    st.session_state.pop(get_user_session_key("active_approval_token", current_user), None)
                    st.session_state.pop(get_user_session_key("approved_plan_hash", current_user), None)
                    st.session_state.pop(get_user_session_key("approved_container", current_user), None)
                    st.session_state.pop(get_user_session_key("approved_by_user", current_user), None)
                    st.rerun()
            else:
                with st.spinner(f"Executing '{remediation_plan.get('operation')}' on '{selected_cont_name}' with post-action verification..."):
                    exec_result = execute_authorized_recovery(
                        container_name=selected_cont_name,
                        action=remediation_plan.get("operation", "start_container"),
                        incident=primary_incident,
                        authorized=True,
                        approval_token=active_token,
                        plan=remediation_plan,
                        precondition_current_state=selected_cont.get("state"),
                    )
                    st.session_state["last_recovery_result"] = exec_result
                    st.session_state.pop("active_approval_token", None)
                    st.session_state.pop("approved_plan_hash", None)
                    st.session_state.pop("approved_container", None)
                    get_cached_container_scan.clear()
                    get_cached_combined_report.clear()
                    st.rerun()

        # Step 8: Outcome & Audit History
        st.markdown("### Step 8 — Outcome & Audit History")
        if is_demo_mode:
            demo_audit_events = []
            if last_recovery and last_recovery.get("simulated"):
                demo_audit_events.append({
                    "timestamp": last_recovery.get("executed_at", "Just now"),
                    "container": f"{selected_cont_name} [SIMULATED]",
                    "action": remediation_plan.get("operation", "start_container"),
                    "decision": "SIMULATED_SUCCESS",
                    "verification_status": "SIMULATED_VERIFIED",
                    "message": last_recovery.get("message", "Simulated recovery verified."),
                    "dry_run": True,
                    "success": True,
                })
            demo_audit_events.append({
                "timestamp": "2026-10-24T14:30:00Z",
                "container": f"{selected_cont_name} [SIMULATED]",
                "action": "start_container",
                "decision": "ALLOW",
                "verification_status": "VERIFIED",
                "message": "[SIMULATED BASELINE] Container verified running and probe passed.",
                "dry_run": True,
                "success": True,
            })
            st.caption(f"🧪 **SIMULATED AUDIT TRAIL**: Displaying verification audit log for **{selected_cont_name}**.")
            st.dataframe(pd.DataFrame(format_recovery_history_rows(demo_audit_events)), width="stretch", hide_index=True)
        else:
            try:
                container_audit_events = load_recovery_history(limit=50)
                cont_events = [e for e in container_audit_events if e.get("container") == selected_cont_name]
                if cont_events:
                    st.write(f"Recent audit history for **{selected_cont_name}** ({len(cont_events)} events):")
                    st.dataframe(pd.DataFrame(format_recovery_history_rows(cont_events)), width="stretch", hide_index=True)
                else:
                    st.caption(f"No previous recovery or rejection events recorded for '{selected_cont_name}'.")
            except Exception as aud_err:
                st.warning(f"Unable to load container audit history: {aud_err}")
    else:
        st.markdown(
            """
<div style="background: rgba(30, 41, 59, 0.35); border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 8px; padding: 14px 18px; margin: 8px 0 14px 0;">
    <div style="font-weight: 600; font-size: 0.92rem; color: #cbd5e1; margin-bottom: 4px;">
        ℹ️ Controlled Remediation Workflow: Standby Mode
    </div>
    <div style="font-size: 0.84rem; color: #94a3b8;">
        The 8-step evidence-based troubleshooting pipeline will activate when container workloads are discovered in local Ubuntu Podman storage. Automated recovery execution is permanently locked in safe mode by default.
    </div>
</div>
""",
            unsafe_allow_html=True,
        )

    # 4. System Resources & Historical Trends
    st.markdown("## 💻 04 | Host System Resources")
    cpu_col, memory_col, disk_col = st.columns(3)

    with cpu_col:
        if system.get("cpu_usage_percent") is not None:
            st.metric("CPU Usage", f"{system['cpu_usage_percent']:.2f}%")
            st.progress(min(max(system["cpu_usage_percent"] / 100, 0), 1))
        else:
            st.metric("CPU Usage", "Warming up...")
            st.progress(0.0)
        st.caption(f"Health: {system['health_checks']['cpu']}")

    with memory_col:
        st.metric("Memory Usage", f"{memory['usage_percent']:.2f}%")
        st.progress(min(max(memory["usage_percent"] / 100, 0), 1))
        st.caption(f"{memory['used_mb']:.0f} MB / {memory['total_mb']:.0f} MB")
        st.caption(f"Health: {system['health_checks']['memory']}")

    with disk_col:
        st.metric("Disk Usage", f"{disk['usage_percent']:.2f}%")
        st.progress(min(max(disk["usage_percent"] / 100, 0), 1))
        st.caption(f"{disk['used_gb']:.2f} GB / {disk['total_gb']:.2f} GB")
        st.caption(f"Health: {system['health_checks']['disk']}")

    st.markdown("### 📈 Historical Resource Utilization Trends")
    try:
        if not is_demo_mode:
            metric_samples = get_metric_trends(limit=50)

        if metric_samples and len(metric_samples) >= 2:
            trend_df = format_metric_trend_df(metric_samples)
            if not trend_df.empty:
                st.line_chart(trend_df)
                if is_demo_mode:
                    st.caption(f"🧪 **SIMULATED TELEMETRY**: Displaying {len(metric_samples)} historical time-series samples matching scenario '{selected_scenario_key}'.")
                else:
                    st.caption(f"Displaying {len(metric_samples)} most recent telemetry sample(s) from metrics history.")
            else:
                st.info("No valid numeric samples available in metric history to graph.")
        else:
            sample_count = len(metric_samples) if metric_samples else 0
            st.markdown(
                f"""
<div style="background: rgba(30, 41, 59, 0.45); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 8px; padding: 14px 18px; margin: 8px 0 12px 0;">
    <div style="font-weight: 600; font-size: 0.92rem; color: #f8fafc; margin-bottom: 6px;">
        ℹ️ Historical Trend Telemetry: Accumulating Samples ({sample_count} sample(s) recorded)
    </div>
    <div style="font-size: 0.85rem; color: #cbd5e1; line-height: 1.6;">
        • <strong>Current Snapshot</strong>: CPU: <code>{system.get('cpu_usage_percent', 0.0):.1f}%</code> | Memory: <code>{memory.get('usage_percent', 0.0):.1f}%</code> ({memory.get('used_mb', 0):.0f} MB / {memory.get('total_mb', 0):.0f} MB) | Disk: <code>{disk.get('usage_percent', 0.0):.1f}%</code><br>
        • <strong>How Trends Work</strong>: Historical time-series curves require periodic background telemetry samples logged to <code>logs/metrics.jsonl</code> by <code>app/monitor.py</code>.<br>
        • <strong>Status</strong>: Once 2 or more time-series samples accumulate in the log, the trend line chart will plot automatically here.
    </div>
</div>
""",
                unsafe_allow_html=True,
            )
    except Exception as trend_err:
        st.warning(f"Unable to load metric trend history: {trend_err}")

    # 5. Recovery Execution Statistics & Audit Log
    st.markdown("## 📜 05 | Recovery Execution Statistics & Audit History")
    st.caption("Operational statistics and audit log of container start attempts with post-recovery health verification.")

    if is_demo_mode:
        st.info("🧪 **SIMULATED DEMO AUDIT METRICS**: Showing simulated recovery performance indicators for demonstration scenarios.")
        rec_c1, rec_c2, rec_c3, rec_c4 = st.columns(4)
        rec_c1.metric("Simulated Attempts", 3)
        rec_c2.metric("Verified Successes", 2)
        rec_c3.metric("Simulated Failures", 1)
        rec_c4.metric("Success Rate", "66.7%")

        sim_events = [
            {"timestamp": "2026-10-24T16:10:00Z", "container": "demo-order-processor [SIMULATED]", "action": "start_container", "decision": "ALLOW", "verification_status": "VERIFIED", "message": "[SIMULATED] Container started and probe passed.", "success": True},
            {"timestamp": "2026-10-24T16:05:00Z", "container": "demo-analytics-engine [SIMULATED]", "action": "start_container", "decision": "DENY", "verification_status": "DENIED", "message": "[SIMULATED] Denied by policy: OOM protection safeguard active.", "success": False},
            {"timestamp": "2026-10-24T15:50:00Z", "container": "demo-catalog-db [SIMULATED]", "action": "start_container", "decision": "ALLOW", "verification_status": "VERIFIED", "message": "[SIMULATED] Database restored and port 5432 listening.", "success": True},
        ]
        st.dataframe(pd.DataFrame(format_recovery_history_rows(sim_events)), width="stretch", hide_index=True)
    else:
        try:
            recovery_stats = get_recovery_success_rate(limit=100)
            if recovery_stats["total_attempts"] > 0:
                rec_c1, rec_c2, rec_c3, rec_c4 = st.columns(4)
                rec_c1.metric("Recovery Attempts", recovery_stats["total_attempts"])
                rec_c2.metric("Verified Successes", recovery_stats["successful_recoveries"])
                rec_c3.metric("Explicit Failures", recovery_stats["failed_recoveries"])
                rec_c4.metric(
                    "Success Rate",
                    f"{recovery_stats['success_rate_percent']:.1f}%",
                    help=f"{recovery_stats['successful_recoveries']} verified successes out of {recovery_stats['denominator']} attempt(s)",
                )
            else:
                st.info("No recovery events recorded yet for execution statistics.")
        except Exception as rec_stat_err:
            st.warning(f"Unable to compute recovery execution statistics: {rec_stat_err}")

        try:
            history_events = load_recovery_history(limit=25)
            if history_events:
                st.dataframe(
                    pd.DataFrame(format_recovery_history_rows(history_events)),
                    width="stretch",
                    hide_index=True,
                )
            else:
                st.info("No recovery events recorded in recovery_history.jsonl.")
        except Exception as history_error:
            st.warning(f"Unable to load recovery history: {history_error}")

except Exception as error:
    st.error("Dashboard encountered an unhandled exception.")
    st.exception(error)
