"""SecureBank Network Defense Simulator - Streamlit Cloud App (SIMULATOR ONLY).

Runs entirely in-process on synthetic dummy data. It performs zero raw network I/O,
requires no system privileges, and never starts external services. Every metric
and event shown in cloud mode is deterministically SIMULATED.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

# Ensure project root is in sys.path regardless of execution context
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st

from src import cia_tests
from src.controls import DEFAULT_RULES, Firewall, ZONES
from src.metrics import compare_results, layer_attribution, result_to_rows, rows_to_csv, validate_csv_header
from src.schemas import (CONTROL_FLAGS, CONTROL_LABELS, CSV_COLUMNS, ControlConfig, MODE_LOCAL, MODE_SIM,
                         SCENARIO_LABELS, SCENARIOS)
from src.simulator import (ABLATION_COLUMNS, MAX_REQUESTS, run_before_after, run_layer_ablation)

# ------------------------------------------------------------------ Page Configuration
st.set_page_config(
    page_title="SecureBank Network Defense Simulator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ------------------------------------------------------------------ Design System & CSS
APP_CSS = """
<style>
/* Root CSS Variables for Cyber SOC Aesthetic */
:root {
    --bg-primary: #0b1120;
    --bg-secondary: #111c35;
    --bg-card: rgba(17, 28, 53, 0.85);
    --border-card: rgba(56, 189, 248, 0.15);
    --border-subtle: rgba(255, 255, 255, 0.08);
    --accent-blue: #0284c7;
    --accent-cyan: #38bdf8;
    --accent-emerald: #10b981;
    --accent-crimson: #ef4444;
    --accent-amber: #f59e0b;
    --text-primary: #f8fafc;
    --text-muted: #94a3b8;
}

/* Base Spacing & Typography */
.block-container {
    padding-top: 1.6rem;
    padding-bottom: 3.5rem;
    max-width: 1400px;
}

/* Cyber Header Styling */
.soc-header {
    background: linear-gradient(135deg, rgba(17, 28, 53, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%);
    border: 1px solid var(--border-card);
    border-radius: 14px;
    padding: 1.25rem 1.75rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 8px 24px -4px rgba(0, 0, 0, 0.4);
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
}

.soc-header-title {
    font-size: 1.65rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: #f8fafc;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin: 0;
}

.soc-header-subtitle {
    font-size: 0.88rem;
    color: #94a3b8;
    margin-top: 0.35rem;
    margin-bottom: 0;
    line-height: 1.4;
}

.soc-status-bar {
    display: flex;
    align-items: center;
    gap: 0.85rem;
    flex-wrap: wrap;
}

/* Badge Tags */
.badge {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    padding: 3px 11px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.76rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    white-space: nowrap;
}

.badge-sim {
    background: rgba(245, 158, 11, 0.15);
    color: #fbbf24;
    border: 1px solid rgba(245, 158, 11, 0.35);
}

.badge-local {
    background: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.35);
}

.badge-pass {
    background: rgba(16, 185, 129, 0.18);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.4);
}

.badge-fail {
    background: rgba(239, 68, 68, 0.18);
    color: #f87171;
    border: 1px solid rgba(239, 68, 68, 0.4);
}

.badge-info {
    background: rgba(56, 189, 248, 0.15);
    color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.35);
}

/* Card Containers */
.kpi-container {
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 1.1rem 1.25rem;
    transition: transform 0.15s ease, border-color 0.15s ease;
    height: 100%;
}

.kpi-container:hover {
    border-color: rgba(56, 189, 248, 0.35);
}

.kpi-label {
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #94a3b8;
    margin-bottom: 0.4rem;
    display: flex;
    align-items: center;
    gap: 0.4rem;
}

.kpi-value {
    font-size: 1.55rem;
    font-weight: 800;
    color: #f8fafc;
    letter-spacing: -0.02em;
    margin-bottom: 0.25rem;
}

.kpi-delta-good {
    font-size: 0.8rem;
    font-weight: 700;
    color: #34d399;
    display: flex;
    align-items: center;
    gap: 0.25rem;
}

.kpi-delta-neutral {
    font-size: 0.8rem;
    font-weight: 600;
    color: #94a3b8;
}

/* Pipeline Flow Ribbon */
.pipeline-ribbon {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid var(--border-subtle);
    border-radius: 10px;
    padding: 0.85rem 1rem;
    margin: 1rem 0 1.5rem 0;
    overflow-x: auto;
}

.pipeline-node {
    display: inline-flex;
    align-items: center;
    padding: 6px 12px;
    border-radius: 8px;
    font-size: 0.8rem;
    font-weight: 700;
    white-space: nowrap;
    background: rgba(30, 41, 59, 0.8);
    color: #e2e8f0;
    border: 1px solid rgba(255, 255, 255, 0.1);
}

.pipeline-node.active {
    background: rgba(2, 132, 199, 0.25);
    color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.45);
}

.pipeline-node.target {
    background: rgba(16, 185, 129, 0.2);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.4);
}

.pipeline-arrow {
    color: #64748b;
    font-weight: 900;
    font-size: 0.85rem;
}

/* Section Header Bar */
.section-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 0.6rem;
    margin-bottom: 1rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.section-bar h3 {
    margin: 0;
    font-size: 1.22rem;
    font-weight: 700;
    color: #f1f5f9;
}

/* Tab tweaks */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background-color: rgba(15, 23, 42, 0.5);
    padding: 6px;
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.06);
}

.stTabs [data-baseweb="tab"] {
    border-radius: 8px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 0.88rem;
    color: #94a3b8;
    transition: all 0.15s ease;
}

.stTabs [aria-selected="true"] {
    background-color: rgba(2, 132, 199, 0.22) !important;
    color: #38bdf8 !important;
    border: 1px solid rgba(56, 189, 248, 0.3) !important;
}

/* Streamlit Native Container Styling overrides */
div[data-testid="stMetricValue"] {
    font-size: 1.6rem !important;
    font-weight: 800 !important;
    color: #f8fafc !important;
}
div[data-testid="stMetricLabel"] {
    font-size: 0.82rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.04em !important;
    color: #94a3b8 !important;
}
</style>
"""
st.markdown(APP_CSS, unsafe_allow_html=True)


# ------------------------------------------------------------------ Helpers & Badges
def badge_html(mode: str) -> str:
    """Return an accessible, styled badge HTML snippet."""
    if mode == MODE_SIM:
        return '<span class="badge badge-sim">⚡ SIMULATED</span>'
    elif mode == MODE_LOCAL:
        return '<span class="badge badge-local">🔬 LOCAL MEASURED</span>'
    return f'<span class="badge badge-info">{mode}</span>'


def status_pill(status: str) -> str:
    s_upper = str(status).upper()
    if s_upper in ("PASS", "AVAILABLE", "ALLOW", "TRUE"):
        return f'<span class="badge badge-pass">✓ {s_upper}</span>'
    elif s_upper in ("FAIL", "DEGRADED", "DENY", "FALSE", "POISONED"):
        return f'<span class="badge badge-fail">✕ {s_upper}</span>'
    return f'<span class="badge badge-info">{s_upper}</span>'


FRIENDLY_METRIC_LABELS = {
    "caches_poisoned": "ARP Caches Poisoned",
    "diversion_rate_pct": "Traffic Diversion Rate (%)",
    "forged_frames_sent": "Forged Frames Transmitted",
    "detection_count": "IDS Signature Detections",
    "block_count": "IPS Enforced Blocks",
    "frames_dropped_arp_guard": "Frames Dropped by ARP Guard",
    "frames_dropped_segmentation": "Frames Dropped by Segmentation",
    "messages_read_by_attacker": "Plaintext Messages Intercepted",
    "messages_tampered": "Messages Altered in Transit",
    "tampered_accepted": "Tampered Messages Accepted",
    "tampered_detected": "Tampered Messages Caught",
    "legit_success_rate_pct": "Legitimate Success Rate (%)",
    "request_success_rate_pct": "Overall Request Success Rate (%)",
    "avg_latency_ms_legit": "Mean Legit Latency (ms)",
    "p95_latency_ms_legit": "P95 Legit Latency (ms)",
    "availability_pct": "Service Availability Index (%)",
    "requests_rejected_by_controls": "Filtered Requests (Defensive)",
    "simulated_service_status": "Simulated Service Health",
    "integrity_check_outcome": "HMAC Integrity Status",
}

KEY_METRICS = {
    "arp_spoofing": ["caches_poisoned", "diversion_rate_pct", "forged_frames_sent", "detection_count", "block_count",
                     "frames_dropped_arp_guard", "frames_dropped_segmentation"],
    "mitm": ["messages_read_by_attacker", "messages_tampered", "tampered_accepted", "tampered_detected",
             "detection_count", "block_count"],
    "ddos": ["legit_success_rate_pct", "avg_latency_ms_legit", "p95_latency_ms_legit", "availability_pct",
             "requests_rejected_by_controls", "detection_count", "block_count"],
}

CONTROL_HELP = {
    "segmentation": (
        "Logical zone policy (internet, user-lan, dmz, db-zone). Cross-zone traffic is restricted to explicitly whitelisted paths.",
        "Limits attack blast radius across tiers; does not prevent attacks originating inside the same zone.",
        "🌐 Network Layer"
    ),
    "firewall": (
        "First-match, default-deny application-layer access matrix inspecting source zone, target zone, and URI path.",
        "Allowed paths can still be overloaded or abused (e.g., volumetric floods targeting permitted endpoints).",
        "🛡️ App Layer"
    ),
    "arp_protection": (
        "Validates gateway and host IP-to-MAC bindings against an authoritative trusted directory (DAI-equivalent).",
        "Requires static table upkeep or switch hardware integration in real physical infrastructures.",
        "🔌 Layer 2"
    ),
    "ids": (
        "Signature inspection engine: RATE_EXCEEDED, REPEATED_FAILURES, ARP_MAPPING_CONFLICT, INTEGRITY_FAILURE. Alerts only.",
        "Fixed thresholds; passive surveillance only; never drops or drops frames by itself without an IPS.",
        "👁️ Detection"
    ),
    "ips": (
        "Automated countermeasure layer: triggers immediate blocking of offending sources, forged frames, or compromised packets.",
        "Aggressive thresholds risk blocking valid users (false positives / denial of service by defense).",
        "🛑 Prevention"
    ),
    "rate_limit": (
        "Sliding/fixed-window token throttle per client source IP/ID (requests allowed per simulated second).",
        "Ineffective when an adversary commands hundreds of distinct distributed bot IPs.",
        "⏱️ Throttling"
    ),
    "access_control": (
        "Cryptographic bearer-token verification. Demands explicit ownership authorization per account touched.",
        "Does not mitigate volumetric floods composed of authenticated legitimate client queries.",
        "🔑 Auth / IAM"
    ),
    "hmac_integrity": (
        "Cryptographic message authentication using HMAC-SHA256 signatures over request payloads.",
        "Shared demonstration key in lab; requires secure key management (KMS/HSM) and TLS in production.",
        "🔒 Crypto"
    ),
    "encryption": (
        "Simulated transport encryption barrier preventing eavesdropping on message contents in transit.",
        "Simulated model flag for confidentiality; real deployments mandate audited TLS 1.3.",
        "🔐 Confidentiality"
    ),
}


# ------------------------------------------------------------------ Application State & Caching
@st.cache_data(show_spinner=False)
def cached_ablation(scenario: str, seed: int) -> list[dict]:
    """Cache layer ablation results for interactive responsiveness."""
    return run_layer_ablation(scenario, seed)


def init_state():
    """Initialize session state defaults deterministically."""
    if "inited" in st.session_state:
        return
    st.session_state.inited = True
    st.session_state.seed = 42
    for f in CONTROL_FLAGS:
        st.session_state[f"ctl_{f}"] = True
    st.session_state.rate_limit_per_tick = 5
    st.session_state.ids_rate_threshold = 30
    st.session_state.runs = {}
    st.session_state.cia = {}
    st.session_state.params = {}
    run_all_scenarios()
    st.session_state.cia = cia_tests.run_all_cia(st.session_state.seed)


def current_controls() -> ControlConfig:
    """Extract the current ControlConfig from session state toggles."""
    return ControlConfig(
        **{f: st.session_state[f"ctl_{f}"] for f in CONTROL_FLAGS},
        rate_limit_per_tick=st.session_state.rate_limit_per_tick,
        ids_rate_threshold=st.session_state.ids_rate_threshold,
    )


def run_all_scenarios():
    """Execute all three threat scenarios with current controls and seed."""
    ctl, seed = current_controls(), st.session_state.seed
    for s in SCENARIOS:
        st.session_state.runs[s] = run_before_after(
            s, ctl, seed, **st.session_state.params.get(s, {})
        )


def set_preset(kind: str):
    """Preset toggle callback for turning all defenses ON or OFF."""
    for f in CONTROL_FLAGS:
        st.session_state[f"ctl_{f}"] = (kind == "all")


def all_events_df() -> pd.DataFrame:
    """Aggregate all generated event dictionaries into a single DataFrame."""
    rows = []
    for s, (b, p) in st.session_state.runs.items():
        for res in (b, p):
            rows += [e.to_dict() for e in res.events]
    return pd.DataFrame(rows)


def export_rows() -> list[dict]:
    """Generate structured long-format rows for standard CSV export."""
    rows = []
    for s, (b, p) in st.session_state.runs.items():
        for res in (b, p):
            rows += result_to_rows(res, f"sim-{s}-seed{res.seed}")
    for key, r in st.session_state.cia.items():
        rows += cia_tests.cia_rows(r, f"sim-cia-{key}-seed{st.session_state.seed}", st.session_state.seed)
    return rows


init_state()

# ------------------------------------------------------------------ Header & Brand Banner
active_layers_count = len(current_controls().active())
status_color = "#34d399" if active_layers_count >= 7 else ("#fbbf24" if active_layers_count >= 3 else "#f87171")
posture_label = "FULLY HARDENED" if active_layers_count == len(CONTROL_FLAGS) else (
    "PARTIALLY DEFENDED" if active_layers_count > 0 else "ZERO DEFENSE BASELINE"
)

header_html = f"""
<div class="soc-header">
    <div>
        <div class="soc-header-title">
            <span>🛡️</span> SecureBank Network Defense Simulator
        </div>
        <div class="soc-header-subtitle">
            Enterprise Security Operations Center & Simulation Testbed &bull; Unit 4 Network & Security
        </div>
    </div>
    <div class="soc-status-bar">
        {badge_html(MODE_SIM)}
        <span class="badge" style="background: rgba(30, 41, 59, 0.8); border: 1px solid rgba(255, 255, 255, 0.12); color: {status_color};">
            ● {posture_label} ({active_layers_count}/{len(CONTROL_FLAGS)} LAYERS)
        </span>
        <span class="badge" style="background: rgba(30, 41, 59, 0.8); border: 1px solid rgba(255, 255, 255, 0.12); color: #cbd5e1;">
            🎲 SEED: {st.session_state.seed}
        </span>
    </div>
</div>
"""
st.markdown(header_html, unsafe_allow_html=True)

# ------------------------------------------------------------------ Navigation Tabs
tabs = st.tabs([
    "📊 Executive Dashboard",
    "⚔️ Attack Scenarios",
    "🛡️ Defense Controls",
    "📐 CIA Triad Evaluation",
    "⚖️ Before vs After Delta",
    "📜 Event Ledger & Methodology"
])


# ================================================================== 1. Executive Dashboard
with tabs[0]:
    st.markdown('<div class="section-bar"><h3>Operational Security Posture Overview</h3></div>', unsafe_allow_html=True)

    mode_choice = st.radio(
        "Simulation Mode Selector",
        ["Cloud Simulator Sandbox (In-Process Synthetic)", "Local Hardware Lab (Import Real Measurement CSV)"],
        horizontal=True,
        label_visibility="collapsed"
    )

    if not mode_choice.startswith("Cloud"):
        st.info(
            "🔬 **Local Hardware Lab Mode Selected:** Run the isolated harness on your local workstation "
            "(see *Event Ledger & Methodology*), then upload your telemetry CSV in the **Before vs After Delta** tab. "
            "The Streamlit Cloud application executes strictly in-process and never connects to external sockets."
        )

    # Key metrics from DDoS & ARP runs
    b_ddos, p_ddos = st.session_state.runs["ddos"]
    b_arp, p_arp = st.session_state.runs["arp_spoofing"]
    b_mitm, p_mitm = st.session_state.runs["mitm"]

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="kpi-container">
            <div class="kpi-label">💥 DDoS Defense Resilience</div>
            <div class="kpi-value">{p_ddos.metrics['legit_success_rate_pct']}%</div>
            <div class="kpi-delta-good">Baseline: {b_ddos.metrics['legit_success_rate_pct']}% &bull; Δ +{round(p_ddos.metrics['legit_success_rate_pct'] - b_ddos.metrics['legit_success_rate_pct'], 1)}%</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="kpi-container">
            <div class="kpi-label">🌐 Service Health Status</div>
            <div class="kpi-value" style="font-size: 1.35rem;">{p_ddos.metrics['simulated_service_status']}</div>
            <div class="kpi-delta-neutral">Baseline was: <span style="color: #f87171;">{b_ddos.metrics['simulated_service_status']}</span></div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        arp_delta = b_arp.metrics['caches_poisoned'] - p_arp.metrics['caches_poisoned']
        st.markdown(f"""
        <div class="kpi-container">
            <div class="kpi-label">🔌 ARP Caches Compromised</div>
            <div class="kpi-value">{p_arp.metrics['caches_poisoned']}</div>
            <div class="kpi-delta-good">Mitigated: {arp_delta} hosts protected</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="kpi-container">
            <div class="kpi-label">🕵️ Tampered Msgs Accepted</div>
            <div class="kpi-value">{p_mitm.metrics['tampered_accepted']}</div>
            <div class="kpi-delta-good">Intercepted at baseline: {b_mitm.metrics['tampered_accepted']}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    subcol1, subcol2, subcol3, subcol4 = st.columns(4)
    total_detections = sum(r[1].metrics.get("detection_count", 0) for r in st.session_state.runs.values())
    total_blocks = sum(r[1].metrics.get("block_count", 0) for r in st.session_state.runs.values())

    subcol1.metric("🚨 Total IDS Detections", total_detections, help="Count of signature-based alerts across all runs")
    subcol2.metric("🛑 Total IPS Enforced Blocks", total_blocks, help="Count of malicious requests or frames blocked")
    subcol3.metric("🛡️ Active Defense Layers", f"{active_layers_count} / {len(CONTROL_FLAGS)}", help="Number of enabled controls")
    subcol4.metric("📈 Mean Legit Latency", f"{p_ddos.metrics['avg_latency_ms_legit']} ms",
                   delta=f"{round(p_ddos.metrics['avg_latency_ms_legit'] - b_ddos.metrics['avg_latency_ms_legit'], 1)} ms",
                   delta_color="inverse")

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Executive Threat Horizon Matrix
    st.markdown("#### Threat Horizon Assessment Matrix")
    matrix_rows = [
        {
            "Threat Vector": "ARP Cache Poisoning (Layer 2)",
            "Target Vulnerability": "Flat broadcast domain, gratuitous ARP spoofing",
            "Baseline Impact": f"{b_arp.metrics['caches_poisoned']} Hosts Poisoned ({b_arp.metrics['diversion_rate_pct']}% diverted)",
            "Protected Outcome": f"{p_arp.metrics['caches_poisoned']} Poisoned ({p_arp.metrics['diversion_rate_pct']}% diverted)",
            "Status": "PROTECTED" if p_arp.metrics['caches_poisoned'] == 0 else "PARTIAL",
        },
        {
            "Threat Vector": "Man-in-the-Middle (MITM)",
            "Target Vulnerability": "Plaintext communication, lack of message integrity verification",
            "Baseline Impact": f"{b_mitm.metrics['messages_read_by_attacker']} Read, {b_mitm.metrics['tampered_accepted']} Tampered Accepted",
            "Protected Outcome": f"{p_mitm.metrics['messages_read_by_attacker']} Read, {p_mitm.metrics['tampered_accepted']} Tampered Accepted",
            "Status": "PROTECTED" if p_mitm.metrics['tampered_accepted'] == 0 else "EXPOSED",
        },
        {
            "Threat Vector": "DDoS Volumetric Flooding",
            "Target Vulnerability": "Worker capacity exhaustion, buffer queue overload",
            "Baseline Impact": f"{b_ddos.metrics['legit_success_rate_pct']}% Served ({b_ddos.metrics['avg_latency_ms_legit']} ms latency)",
            "Protected Outcome": f"{p_ddos.metrics['legit_success_rate_pct']}% Served ({p_ddos.metrics['avg_latency_ms_legit']} ms latency)",
            "Status": "PROTECTED" if p_ddos.metrics['legit_success_rate_pct'] >= 90 else "DEGRADED",
        },
    ]
    st.dataframe(pd.DataFrame(matrix_rows), hide_index=True, use_container_width=True)

    st.caption(
        "⚖️ **Academic Disclaimer & Methodology:** This simulator is an educational teaching prototype operating strictly on synthetic data. "
        "It contains no weaponized payloads or live socket traffic. Reproducible determinism is guaranteed by the random seed."
    )


# ================================================================== 2. Attack Scenarios
with tabs[1]:
    st.markdown('<div class="section-bar"><h3>Bounded Attack Scenario Simulations</h3></div>', unsafe_allow_html=True)

    cfg_col, act_col = st.columns([3, 1])
    with cfg_col:
        scen = st.radio(
            "Select Threat Scenario to Inspect",
            SCENARIOS,
            format_func=lambda s: SCENARIO_LABELS[s],
            horizontal=True
        )
    with act_col:
        st.session_state.seed = st.number_input("Random Seed (Determinism)", 0, 1_000_000, st.session_state.seed, 1)

    # Parameters accordion
    with st.expander("⚙️ Scenario Tuning Parameters & Safety Boundaries", expanded=False):
        params = {}
        if scen == "ddos":
            p_c1, p_c2, p_c3 = st.columns(3)
            with p_c1:
                params["bots"] = st.slider("Synthetic Bot Sources", 0, 50, 5, help="Number of simulated bot endpoints")
            with p_c2:
                params["bot_rate"] = st.slider("Requests / Bot / Second", 1, 200, 40, help="Burst intensity per bot")
            with p_c3:
                params["ticks"] = st.slider("Simulated Duration (Seconds)", 5, 60, 20)
            st.caption(f"🔒 **Safety Boundary Active:** Capped at {MAX_REQUESTS:,} maximum requests per run.")
        elif scen == "arp_spoofing":
            p_c1, p_c2 = st.columns(2)
            with p_c1:
                params["ticks"] = st.slider("Simulation Seconds", 4, 30, 10)
            with p_c2:
                params["messages_per_tick"] = st.slider("Frames / Host / Second", 1, 10, 3)
        else:
            p_c1, p_c2 = st.columns(2)
            with p_c1:
                params["messages"] = st.slider("Synthetic Banking Messages", 5, 200, 20)
            with p_c2:
                params["tamper_probability"] = st.slider("Attacker Tamper Probability", 0.0, 1.0, 0.4, 0.05)

    ctl = current_controls()
    active_str = ", ".join(ctl.active()) if ctl.any_active() else "None (All layers inactive)"
    st.markdown(f"**Current Active Defensive Layers for Execution:** `{active_str}`")

    btn_col1, btn_col2 = st.columns([1, 1])
    with btn_col1:
        if st.button("🚀 Execute Selected Scenario", type="primary", use_container_width=True):
            st.session_state.params[scen] = params
            st.session_state.runs[scen] = run_before_after(scen, ctl, st.session_state.seed, **params)
            st.toast(f"Execution complete for {SCENARIO_LABELS[scen]}!", icon="🛡️")
    with btn_col2:
        if st.button("🔄 Re-run All 3 Scenarios with Active Controls", use_container_width=True):
            run_all_scenarios()
            st.toast("All 3 threat scenarios re-calculated!", icon="✅")

    base, post = st.session_state.runs[scen]

    # Side-by-side execution display
    st.markdown("---")
    col_base, col_post = st.columns(2)

    with col_base:
        st.markdown(f"#### 🔴 Baseline (Zero Defenses) {badge_html(base.mode)}", unsafe_allow_html=True)
        st.caption("Active Controls: `None (Unprotected Environment)`")

        show_base = {k: v for k, v in base.metrics.items() if k in KEY_METRICS[scen]}
        formatted_base = [
            {"Metric": FRIENDLY_METRIC_LABELS.get(k, k), "Value": str(v)}
            for k, v in show_base.items()
        ]
        st.dataframe(pd.DataFrame(formatted_base), hide_index=True, use_container_width=True)

        ev_base = pd.DataFrame([e.to_dict() for e in base.events])
        if not ev_base.empty:
            with st.expander("📋 Baseline Event Telemetry (First 30)", expanded=False):
                st.dataframe(ev_base[["tick", "layer", "action", "source", "detail"]].head(30), hide_index=True)

    with col_post:
        st.markdown(f"#### 🟢 Hardened (With Controls) {badge_html(post.mode)}", unsafe_allow_html=True)
        st.caption(f"Active Controls: `{', '.join(post.controls_active()) or 'None'}`")

        show_post = {k: v for k, v in post.metrics.items() if k in KEY_METRICS[scen]}
        formatted_post = [
            {"Metric": FRIENDLY_METRIC_LABELS.get(k, k), "Value": str(v)}
            for k, v in show_post.items()
        ]
        st.dataframe(pd.DataFrame(formatted_post), hide_index=True, use_container_width=True)

        ev_post = pd.DataFrame([e.to_dict() for e in post.events])
        if not ev_post.empty:
            with st.expander("📋 Hardened Event Telemetry (First 30)", expanded=False):
                st.dataframe(ev_post[["tick", "layer", "action", "source", "detail"]].head(30), hide_index=True)

    # Scenario-specific deep-dive displays
    if scen == "arp_spoofing":
        st.markdown("#### 🔍 Host ARP Cache Table State (Gateway 10.0.0.1 Binding)")
        trusted_gw = base.details.get("trusted_binding", {}).get("10.0.0.1", "00:00:5e:00:01:01")
        atk_mac = base.details.get("attacker_mac", "aa:bb:cc:dd:ee:ff")

        caches_list = []
        for h in base.details.get("final_arp_caches", {}):
            base_val = base.details["final_arp_caches"][h].get("10.0.0.1", "unknown")
            post_val = post.details["final_arp_caches"][h].get("10.0.0.1", "unknown")
            caches_list.append({
                "Host Identifier": h,
                "Baseline Binding": f"{base_val} ({'POISONED ⚠️' if base_val == atk_mac else 'SAFE ✓'})",
                "Protected Binding": f"{post_val} ({'SAFE ✓' if post_val == trusted_gw else 'POISONED ⚠️'})",
                "Defense Integrity": "RESTORED ✓" if (base_val == atk_mac and post_val == trusted_gw) else "INTACT ✓"
            })
        st.dataframe(pd.DataFrame(caches_list), hide_index=True, use_container_width=True)
        st.caption(f"Authoritative Gateway MAC: `{trusted_gw}` | Rogue Attacker MAC: `{atk_mac}`")

    # Threat assumptions & residual risk
    st.markdown("---")
    r1, r2 = st.columns(2)
    with r1:
        with st.container(border=True):
            st.markdown("##### 📌 Simulation Model Assumptions")
            for a in base.assumptions:
                st.markdown(f"- {a}")
    with r2:
        with st.container(border=True):
            st.markdown("##### ⚠️ Residual Threat Exposure")
            for r in post.residual_risk:
                st.markdown(f"- {r}")


# ================================================================== 3. Security Controls
with tabs[2]:
    st.markdown('<div class="section-bar"><h3>Defense-in-Depth Layer Architecture</h3></div>', unsafe_allow_html=True)

    # Interactive Pipeline Flow Ribbon
    st.markdown("""
    <div class="pipeline-ribbon">
        <span style="font-weight:700; color:#94a3b8; font-size:0.8rem; margin-right:4px;">INBOUND TRAFFIC:</span>
        <span class="pipeline-node active">1. Segmentation</span>
        <span class="pipeline-arrow">➔</span>
        <span class="pipeline-node active">2. App Firewall</span>
        <span class="pipeline-arrow">➔</span>
        <span class="pipeline-node active">3. IPS Filter</span>
        <span class="pipeline-arrow">➔</span>
        <span class="pipeline-node active">4. IDS Signatures</span>
        <span class="pipeline-arrow">➔</span>
        <span class="pipeline-node active">5. Rate Limiter</span>
        <span class="pipeline-arrow">➔</span>
        <span class="pipeline-node active">6. Access Control</span>
        <span class="pipeline-arrow">➔</span>
        <span class="pipeline-node target">7. Banking Service Queue</span>
    </div>
    """, unsafe_allow_html=True)

    col_btn1, col_btn2, _ = st.columns([1, 1, 3])
    with col_btn1:
        st.button("✅ Enable All Defenses", on_click=set_preset, args=("all",), use_container_width=True)
    with col_btn2:
        st.button("❌ Disable All Defenses", on_click=set_preset, args=("none",), use_container_width=True)

    # 3-column grid for defense controls
    c_cols = st.columns(3)
    for idx, f in enumerate(CONTROL_FLAGS):
        target_col = c_cols[idx % 3]
        desc, limit, category = CONTROL_HELP[f]
        with target_col:
            with st.container(border=True):
                st.checkbox(f"**{CONTROL_LABELS[f]}**", key=f"ctl_{f}")
                st.markdown(f"<span class='badge badge-info'>{category}</span>", unsafe_allow_html=True)
                st.markdown(f"<p style='font-size:0.82rem; color:#cbd5e1; margin-top:6px;'><b>Function:</b> {desc}</p>", unsafe_allow_html=True)
                st.markdown(f"<p style='font-size:0.78rem; color:#94a3b8;'><b>Limitation:</b> {limit}</p>", unsafe_allow_html=True)

    st.markdown("#### Dynamic Throttling & Detection Thresholds")
    th1, th2 = st.columns(2)
    with th1:
        st.session_state.rate_limit_per_tick = st.number_input(
            "Rate Limit Throttle (Requests / Source / Second)",
            1, 100, st.session_state.rate_limit_per_tick,
            help="Maximum burst allowed per source before HTTP 429 throttling"
        )
    with th2:
        st.session_state.ids_rate_threshold = st.number_input(
            "IDS RATE_EXCEEDED Alert Threshold (Requests / Source / Second)",
            1, 500, st.session_state.ids_rate_threshold,
            help="Signature detection trigger threshold for automated alerting"
        )

    if st.button("💾 Apply Defensive Configuration & Re-run Scenarios", type="primary", use_container_width=True):
        run_all_scenarios()
        st.toast("Security layers re-applied and simulations updated!", icon="🛡️")

    st.markdown("---")
    # Application Firewall Rule Engine Simulator
    st.markdown("#### 🛡️ Application-Layer Firewall Inspector (First-Match, Default-Deny)")
    fw_col1, fw_col2, fw_col3, fw_col4 = st.columns([1, 1, 1, 1.2])
    with fw_col1:
        src_zone = st.selectbox("Source Zone", ZONES, index=0)
    with fw_col2:
        dst_zone = st.selectbox("Destination Zone", ZONES, index=2)
    with fw_col3:
        target_path = st.selectbox("Target Path", ["/health", "/balance", "/transfer-simulated", "/admin", "/db-query"])
    with fw_col4:
        decision = Firewall().evaluate(src_zone, dst_zone, target_path)
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if decision.allowed:
            st.markdown(f"<div style='padding: 8px 12px; border-radius: 8px; background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #34d399; font-weight:700;'>✓ ALLOW ({decision.rule_id})</div>", unsafe_allow_html=True)
        else:
            st.markdown(f"<div style='padding: 8px 12px; border-radius: 8px; background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #f87171; font-weight:700;'>✕ DENY ({decision.rule_id})</div>", unsafe_allow_html=True)

    with st.expander("📋 Active Firewall Rule Base Table", expanded=False):
        st.dataframe(pd.DataFrame([r.__dict__ for r in DEFAULT_RULES]), hide_index=True, use_container_width=True)

    # Layer Ablation View
    st.markdown("---")
    st.markdown("#### 🔬 Defense-in-Depth Layer Ablation Study (Single Layer vs All Layers)")
    ab_scen = st.selectbox("Threat Scenario for Ablation Analysis", SCENARIOS, format_func=lambda s: SCENARIO_LABELS[s])
    ab_df = pd.DataFrame(cached_ablation(ab_scen, st.session_state.seed))
    st.dataframe(ab_df, hide_index=True, use_container_width=True)
    st.caption("Layer ablation reveals independent mitigation efficacy. For instance, an IPS cannot drop malicious packets without IDS alerts, and HMAC validation operates upon payload tampering.")


# ================================================================== 4. CIA Triad Evaluation
with tabs[3]:
    st.markdown('<div class="section-bar"><h3>CIA Triad Formal Security Audit</h3></div>', unsafe_allow_html=True)

    if st.button("▶️ Execute Full CIA Triad Verification", type="primary"):
        st.session_state.cia = cia_tests.run_all_cia(st.session_state.seed)
        st.toast("CIA Triad verification suite executed!", icon="📐")

    cia_items = [
        ("confidentiality", "Confidentiality Audit: Token Access Control & Data Isolation", "🔒"),
        ("integrity", "Integrity Audit: Cryptographic HMAC-SHA256 Payload Validation", "🛡️"),
        ("availability", "Availability Audit: Volumetric Stress Resistance & Latency Stability", "⚡"),
    ]

    for key, label, icon in cia_items:
        res = st.session_state.cia[key]
        status_pass = res["passed"]
        badge_status = status_pill("PASS" if status_pass else "FAIL")

        with st.container(border=True):
            head_col, status_col = st.columns([4, 1])
            with head_col:
                st.markdown(f"#### {icon} {label}")
                st.markdown(f"<p style='color:#94a3b8; font-size:0.9rem;'>{res['summary']}</p>", unsafe_allow_html=True)
            with status_col:
                st.markdown(f"<div style='text-align: right;'>{badge_status}</div>", unsafe_allow_html=True)

            # Test cases table
            st.dataframe(pd.DataFrame(res["cases"]), hide_index=True, use_container_width=True)

            if key == "availability":
                st.markdown("##### Availability Phase Performance Metrics")
                chart_data = pd.DataFrame({
                    ph: {
                        "Legitimate Success Rate (%)": v["legit_success_rate_pct"],
                        "Average Latency (ms)": v["avg_latency_ms_legit"]
                    }
                    for ph, v in res["phases"].items()
                }).T
                c_ch1, c_ch2 = st.columns(2)
                with c_ch1:
                    st.bar_chart(chart_data[["Legitimate Success Rate (%)"]])
                with c_ch2:
                    st.bar_chart(chart_data[["Average Latency (ms)"]])

    st.warning(
        "🔑 **Cryptographic Note:** The HMAC demonstration key is packaged in the repository for local and test reproducability. "
        "Production banking architectures mandate audited Hardware Security Modules (HSM), automated key rotation, and TLS 1.3 encapsulation."
    )


# ================================================================== 5. Before vs After Delta
with tabs[4]:
    st.markdown('<div class="section-bar"><h3>Before vs After Security Delta Comparison</h3></div>', unsafe_allow_html=True)

    for s in SCENARIOS:
        b_res, p_res = st.session_state.runs[s]
        with st.container(border=True):
            st.markdown(f"#### {SCENARIO_LABELS[s]}")
            comp_table = pd.DataFrame(compare_results(b_res, p_res))
            keyed_table = comp_table[comp_table["metric"].isin(KEY_METRICS[s])].copy()

            ch_col, tab_col = st.columns([1, 1])
            with ch_col:
                chart_df = keyed_table.set_index("metric")[["baseline", "with_controls"]].apply(pd.to_numeric, errors="coerce")
                st.bar_chart(chart_df)
            with tab_col:
                formatted_comp = comp_table.copy()
                formatted_comp["metric"] = formatted_comp["metric"].apply(lambda m: FRIENDLY_METRIC_LABELS.get(m, m))
                st.dataframe(formatted_comp.astype(str), hide_index=True, height=290, use_container_width=True)

    st.markdown("---")
    st.markdown(f"### 🔬 Import Local Laboratory Telemetry {badge_html(MODE_LOCAL)}", unsafe_allow_html=True)
    st.caption("Upload a `.csv` produced by `local_lab/test_harness.py` to compare measured real-world loopback timings against the simulation.")

    up = st.file_uploader("Drop Local Lab CSV File (local_lab/results/*.csv)", type="csv")
    if up is not None:
        try:
            df_upload = pd.read_csv(io.BytesIO(up.getvalue()))
            if not validate_csv_header(list(df_upload.columns)):
                st.error(f"Invalid CSV structure. Expected headers: {CSV_COLUMNS}")
            elif set(df_upload["mode"]) != {MODE_LOCAL}:
                st.error("Uploaded CSV is not stamped with mode 'LOCAL MEASURED'. Simulation CSVs cannot be imported as hardware runs.")
            else:
                st.success("✓ Verified authentic LOCAL MEASURED telemetry payload.")
                pivot_tbl = df_upload.pivot_table(index="metric", columns="phase", values="value", aggfunc="first")
                st.dataframe(pivot_tbl, use_container_width=True)

                num_tbl = pivot_tbl.apply(pd.to_numeric, errors="coerce").dropna(how="all")
                if not num_tbl.empty:
                    target_rows = [m for m in ["legit_success_rate_pct", "legit_avg_latency_ms", "legit_p95_latency_ms", "burst_accepted"] if m in num_tbl.index]
                    if target_rows:
                        st.bar_chart(num_tbl.loc[target_rows])
        except Exception as e:
            st.error(f"Error reading telemetry file: {e}")


# ================================================================== 6. Event Ledger & Methodology
with tabs[5]:
    st.markdown('<div class="section-bar"><h3>Security Event Ledger & Methodology</h3></div>', unsafe_allow_html=True)

    ev_df = all_events_df()
    if not ev_df.empty:
        f_c1, f_c2, f_c3 = st.columns(3)
        with f_c1:
            sc_sel = st.multiselect("Filter Scenarios", sorted(ev_df["scenario"].unique()), default=sorted(ev_df["scenario"].unique()))
        with f_c2:
            ph_sel = st.multiselect("Filter Phase", sorted(ev_df["phase"].unique()), default=sorted(ev_df["phase"].unique()))
        with f_c3:
            ly_sel = st.multiselect("Filter Defensive Layer", sorted(ev_df["layer"].unique()), default=sorted(ev_df["layer"].unique()))

        filtered_events = ev_df[
            ev_df["scenario"].isin(sc_sel) &
            ev_df["phase"].isin(ph_sel) &
            ev_df["layer"].isin(ly_sel)
        ]

        st.dataframe(filtered_events, hide_index=True, height=320, use_container_width=True)
        st.caption(f"Displaying {len(filtered_events):,} of {len(ev_df):,} recorded events. All events labelled {MODE_SIM}.")

    dl_col1, dl_col2 = st.columns(2)
    with dl_col1:
        st.download_button(
            "📥 Export Aggregated Metrics CSV",
            rows_to_csv(export_rows()),
            file_name="securebank_simulated_metrics.csv",
            mime="text/csv",
            use_container_width=True
        )
    with dl_col2:
        st.download_button(
            "📥 Export Granular Event Ledger CSV",
            ev_df.to_csv(index=False),
            file_name="securebank_simulated_events.csv",
            mime="text/csv",
            use_container_width=True
        )

    st.markdown("---")
    st.markdown("#### 📚 Theoretical Methodology & Viva Prompts")

    readme_candidates = [
        PROJECT_ROOT / "README.md",
        Path("README.md"),
    ]
    readme_text = ""
    for r_cand in readme_candidates:
        if r_cand.exists():
            readme_text = r_cand.read_text(encoding="utf-8")
            break

    if "<!--METHODOLOGY-->" in readme_text:
        methodology_body = readme_text.split("<!--METHODOLOGY-->")[-1]
        st.markdown(methodology_body)
    else:
        st.markdown("Refer to project `README.md` for comprehensive threat model and examination prompts.")
