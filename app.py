"""SecureBank Network Defense Simulator - Streamlit Cloud app (SIMULATOR ONLY).

Runs entirely in-process on dummy data. It performs no network I/O, needs no privileges,
and never starts the local lab. Every number shown here is SIMULATED.
"""
from __future__ import annotations

import io
from pathlib import Path

import pandas as pd
import streamlit as st

from src import cia_tests
from src.controls import DEFAULT_RULES, Firewall, ZONES
from src.metrics import compare_results, layer_attribution, result_to_rows, rows_to_csv, validate_csv_header
from src.schemas import (CONTROL_FLAGS, CONTROL_LABELS, CSV_COLUMNS, ControlConfig, MODE_LOCAL, MODE_SIM,
                         SCENARIO_LABELS, SCENARIOS)
from src.simulator import (ABLATION_COLUMNS, MAX_REQUESTS, run_before_after, run_layer_ablation)

st.set_page_config(page_title="SecureBank Network Defense Simulator", page_icon="🛡️", layout="wide")

BADGE_CSS = """
<style>
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-weight:700;font-size:0.8rem;letter-spacing:.04em;color:#fff}
.sim{background:#b45309}.local{background:#047857}
</style>"""
st.markdown(BADGE_CSS, unsafe_allow_html=True)


def badge(mode: str) -> str:
    cls = "sim" if mode == MODE_SIM else "local"
    return f'<span class="badge {cls}">{mode}</span>'


KEY_METRICS = {
    "arp_spoofing": ["caches_poisoned", "diversion_rate_pct", "forged_frames_sent", "detection_count", "block_count",
                     "frames_dropped_arp_guard", "frames_dropped_segmentation"],
    "mitm": ["messages_read_by_attacker", "messages_tampered", "tampered_accepted", "tampered_detected",
             "detection_count", "block_count"],
    "ddos": ["legit_success_rate_pct", "avg_latency_ms_legit", "p95_latency_ms_legit", "availability_pct",
             "requests_rejected_by_controls", "detection_count", "block_count"],
}

CONTROL_HELP = {
    "segmentation": ("Zone policy (internet / user-lan / dmz / db-zone). Cross-zone traffic is allowed only on listed paths. "
                     "SIMULATED enforcement in code; coloured boxes alone would not be segmentation.",
                     "Limits blast radius; does not stop attacks inside one zone."),
    "firewall": ("First-match, default-deny allow/deny rules (table below). APPLICATION-LAYER policy, not a network firewall.",
                 "Allowed paths can still be abused (e.g. flooding /balance)."),
    "arp_protection": ("Accepts a gateway binding only if it matches the trusted table (static entries / DAI-like).",
                       "Needs switch support and upkeep in real networks."),
    "ids": ("Explicit signatures: RATE_EXCEEDED, REPEATED_FAILURES, ARP_MAPPING_CONFLICT, INTEGRITY_FAILURE. Alerts only.",
            "Fixed thresholds; not a production IDS; detects, never prevents by itself."),
    "ips": ("Acts on IDS signals: blocks the offending source / frame / message. Does nothing without IDS alerts.",
            "Wrong thresholds block legitimate users (false positives)."),
    "rate_limit": ("Fixed-window per-source limit (requests per simulated second).",
                   "Weak against many distinct sources."),
    "access_control": ("Requests must carry a valid token for the account they touch (fictional tokens).",
                       "Does not stop floods of authenticated requests."),
    "hmac_integrity": ("HMAC-SHA256 over each dummy message with a local demonstration key.",
                       "Shared demo key = not real key management; no replay protection."),
    "encryption": ("SIMULATED flag: on-path attacker cannot read message content.",
                   "A flag, not real TLS; confidentiality only in this model."),
}


# ------------------------------------------------------------------ state
@st.cache_data(show_spinner=False)
def cached_ablation(scenario: str, seed: int):
    return run_layer_ablation(scenario, seed)


def init_state():
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
    return ControlConfig(**{f: st.session_state[f"ctl_{f}"] for f in CONTROL_FLAGS},
                         rate_limit_per_tick=st.session_state.rate_limit_per_tick,
                         ids_rate_threshold=st.session_state.ids_rate_threshold)


def run_all_scenarios():
    ctl, seed = current_controls(), st.session_state.seed
    for s in SCENARIOS:
        st.session_state.runs[s] = run_before_after(s, ctl, seed, **st.session_state.params.get(s, {}))


def set_preset(kind: str):
    for f in CONTROL_FLAGS:
        st.session_state[f"ctl_{f}"] = kind == "all"


def all_events_df() -> pd.DataFrame:
    rows = []
    for s, (b, p) in st.session_state.runs.items():
        for res in (b, p):
            rows += [e.to_dict() for e in res.events]
    return pd.DataFrame(rows)


def export_rows() -> list[dict]:
    rows = []
    for s, (b, p) in st.session_state.runs.items():
        for res in (b, p):
            rows += result_to_rows(res, f"sim-{s}-seed{res.seed}")
    for key, r in st.session_state.cia.items():
        rows += cia_tests.cia_rows(r, f"sim-cia-{key}-seed{st.session_state.seed}", st.session_state.seed)
    return rows


init_state()

# ------------------------------------------------------------------ header
st.title("SecureBank Network Defense Simulator")
st.markdown(f"{badge(MODE_SIM)}&nbsp; Cloud simulator - all events and metrics are **SIMULATED** from scenario code on "
            f"fictional data. This app does not inspect its own hosting network and does not detect real ARP, MITM or DDoS activity. "
            f"{badge(MODE_LOCAL)}&nbsp; appears only for results you import from the local lab.", unsafe_allow_html=True)

tabs = st.tabs(["Dashboard", "Attack Scenarios", "Security Controls", "CIA Triad", "Before vs After",
                "Event Logs & Methodology"])

# ============================================================ 1. Dashboard
with tabs[0]:
    st.subheader("Dashboard")
    mode = st.radio("Selected mode", ["Cloud simulator (SIMULATED)", "Local lab (import results in 'Before vs After')"],
                    horizontal=True)
    st.markdown(badge(MODE_SIM if mode.startswith("Cloud") else MODE_LOCAL), unsafe_allow_html=True)
    if not mode.startswith("Cloud"):
        st.info("Run the local lab on your own machine (see 'Event Logs & Methodology'), then upload the CSV in the "
                "'Before vs After' tab. The Cloud app never starts or contacts a local service.")
    b, p = st.session_state.runs["ddos"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Simulated service status (baseline)", b.metrics["simulated_service_status"])
    c2.metric("Simulated service status (with controls)", p.metrics["simulated_service_status"])
    c3.metric("Legit success rate (before -> after)", f"{b.metrics['legit_success_rate_pct']}% -> {p.metrics['legit_success_rate_pct']}%")
    c4.metric("Active control layers", len(current_controls().active()))
    d1, d2, d3, d4 = st.columns(4)
    a_b, a_p = st.session_state.runs["arp_spoofing"]
    m_b, m_p = st.session_state.runs["mitm"]
    d1.metric("ARP caches poisoned", f"{a_b.metrics['caches_poisoned']} -> {a_p.metrics['caches_poisoned']}")
    d2.metric("MITM tampered msgs accepted", f"{m_b.metrics['tampered_accepted']} -> {m_p.metrics['tampered_accepted']}")
    d3.metric("IDS detections (all scenarios)", sum(r[1].metrics["detection_count"] for r in st.session_state.runs.values()))
    d4.metric("IPS blocks (all scenarios)", sum(r[1].metrics["block_count"] for r in st.session_state.runs.values()))
    st.caption(f"Seed {st.session_state.seed}. Same seed = identical results. Values come from the scenario runs shown in the "
               "other tabs, not from constants.")
    st.markdown("**Disclaimer:** teaching prototype with fictional data. Not a secure banking product, not a real IDS, "
                "not live threat intelligence. Demonstrations belong only in an isolated, instructor-approved lab.")

# ============================================================ 2. Attack Scenarios
with tabs[1]:
    st.subheader("Attack Scenarios (bounded, SIMULATED)")
    st.markdown(badge(MODE_SIM), unsafe_allow_html=True)
    st.session_state.seed = st.number_input("Random seed", 0, 10 ** 6, st.session_state.seed, 1)
    scen = st.radio("Scenario", SCENARIOS, format_func=lambda s: SCENARIO_LABELS[s], horizontal=False)
    params = {}
    with st.expander("Scenario parameters (hard-capped)", expanded=False):
        if scen == "ddos":
            params = {"bots": st.slider("Synthetic bot sources", 0, 50, 5),
                      "bot_rate": st.slider("Requests per bot per simulated second", 1, 200, 40),
                      "ticks": st.slider("Simulated seconds", 5, 60, 20)}
            st.caption(f"Safety cap: at most {MAX_REQUESTS:,} simulated requests per run (excess is clamped).")
        elif scen == "arp_spoofing":
            params = {"ticks": st.slider("Simulated seconds", 4, 30, 10),
                      "messages_per_tick": st.slider("Messages per host per second", 1, 10, 3)}
        else:
            params = {"messages": st.slider("Dummy messages", 5, 200, 20),
                      "tamper_probability": st.slider("Attacker tamper probability", 0.0, 1.0, 0.4, 0.05)}
    ctl = current_controls()
    st.write("**Controls that will be active in the 'with controls' run:** "
             + (", ".join(ctl.active()) if ctl.any_active() else "none (set them in the Security Controls tab)"))
    cA, cB = st.columns(2)
    if cA.button("Run selected scenario (baseline + with controls)", type="primary"):
        st.session_state.params[scen] = params
        st.session_state.runs[scen] = run_before_after(scen, ctl, st.session_state.seed, **params)
    if cB.button("Re-run all three with current controls"):
        run_all_scenarios()
    base, post = st.session_state.runs[scen]
    st.markdown("### Setup and assumptions")
    for a in base.assumptions:
        st.write("- " + a)
    col1, col2 = st.columns(2)
    for col, res, title in ((col1, base, "Baseline - no controls"), (col2, post, "Controls activated")):
        with col:
            st.markdown(f"#### {title} {badge(res.mode)}", unsafe_allow_html=True)
            st.write("Controls: " + (", ".join(res.controls_active()) or "none"))
            show = {k: v for k, v in res.metrics.items() if k in KEY_METRICS[scen]}
            st.dataframe(pd.DataFrame({"metric": list(show), "value": [str(v) for v in show.values()]}),
                         hide_index=True)
            st.caption("Layer attribution (events per layer): " + str(layer_attribution(res.events) or "none"))
            ev_df = pd.DataFrame([e.to_dict() for e in res.events])
            if not ev_df.empty:
                st.dataframe(ev_df[["tick", "layer", "action", "source", "detail"]].head(60),
                             hide_index=True)
    if scen == "arp_spoofing":
        st.markdown("#### Final synthetic ARP caches")
        caches = pd.DataFrame([{"host": h, "baseline": base.details["final_arp_caches"][h]["10.0.0.1"],
                                "with_controls": post.details["final_arp_caches"][h]["10.0.0.1"]}
                               for h in base.details["final_arp_caches"]])
        st.dataframe(caches, hide_index=True)
        st.caption(f"Trusted gateway MAC: {base.details['trusted_binding']['10.0.0.1']}; "
                   f"simulated attacker MAC: {base.details['attacker_mac']}.")
    st.markdown("### Residual risk")
    for r in post.residual_risk:
        st.write("- " + r)

# ============================================================ 3. Security Controls
with tabs[2]:
    st.subheader("Security Controls")
    st.markdown(badge(MODE_SIM), unsafe_allow_html=True)
    b1, b2, _ = st.columns([1, 1, 4])
    b1.button("All layers ON", on_click=set_preset, args=("all",))
    b2.button("All layers OFF", on_click=set_preset, args=("none",))
    for f in CONTROL_FLAGS:
        with st.container(border=True):
            st.checkbox(CONTROL_LABELS[f], key=f"ctl_{f}")
            desc, limit = CONTROL_HELP[f]
            st.caption(f"**Effect:** {desc}  \n**Limitation:** {limit}")
    st.session_state.rate_limit_per_tick = st.number_input("Rate limit: requests per source per simulated second", 1, 100,
                                                           st.session_state.rate_limit_per_tick)
    st.session_state.ids_rate_threshold = st.number_input("IDS: RATE_EXCEEDED threshold (requests/source/second)", 1, 500,
                                                          st.session_state.ids_rate_threshold)
    st.info("After changing controls, go to **Attack Scenarios** and re-run, or press the button below.")
    if st.button("Apply: re-run all three scenarios"):
        run_all_scenarios()
        st.success("Re-run complete. See Dashboard / Before vs After.")
    st.markdown("#### Firewall rule engine (application-layer, first match wins, default deny)")
    st.dataframe(pd.DataFrame([r.__dict__ for r in DEFAULT_RULES]), hide_index=True)
    t1, t2, t3 = st.columns(3)
    s_z = t1.selectbox("Source zone", ZONES, index=0)
    d_z = t2.selectbox("Destination zone", ZONES, index=2)
    pth = t3.selectbox("Path", ["/health", "/balance", "/transfer-simulated", "/admin", "/db-query"])
    dec = Firewall().evaluate(s_z, d_z, pth)
    (st.success if dec.allowed else st.error)(f"{'ALLOW' if dec.allowed else 'DENY'} by {dec.rule_id}: {dec.reason}")
    st.markdown("#### Defence-in-depth: which layer helps? (each control alone vs all)")
    ab_s = st.selectbox("Scenario for layer view", SCENARIOS, format_func=lambda s: SCENARIO_LABELS[s])
    ab = pd.DataFrame(cached_ablation(ab_s, st.session_state.seed))
    st.dataframe(ab, hide_index=True)
    st.caption("Layers are independent: an IPS has nothing to act on without IDS signals, and HMAC only helps once a "
               "message is actually altered. Compare rows to see which layer blocks or detects each scenario.")

# ============================================================ 4. CIA Triad
with tabs[3]:
    st.subheader("CIA Triad checks")
    st.markdown(badge(MODE_SIM), unsafe_allow_html=True)
    if st.button("Run all CIA checks"):
        st.session_state.cia = cia_tests.run_all_cia(st.session_state.seed)
    for key, label in (("confidentiality", "Confidentiality - unauthorised access to dummy accounts"),
                       ("integrity", "Integrity - tampered message vs HMAC-SHA256"),
                       ("availability", "Availability - normal load vs burst, before/after rate limiting")):
        r = st.session_state.cia[key]
        with st.container(border=True):
            st.markdown(f"**{label}** - {'PASS' if r['passed'] else 'FAIL'} (protected configuration)")
            st.caption(r["summary"])
            st.dataframe(pd.DataFrame(r["cases"]), hide_index=True)
            if key == "availability":
                chart = pd.DataFrame({ph: {"legit success %": v["legit_success_rate_pct"],
                                           "avg latency (ms)": v["avg_latency_ms_legit"]}
                                      for ph, v in r["phases"].items()}).T
                st.bar_chart(chart[["legit success %"]])
                st.bar_chart(chart[["avg latency (ms)"]])
    st.warning("Integrity demo key is stored in the repository on purpose. Real systems need proper key management "
               "(KMS/HSM, rotation, per-session keys) and TLS. This is a teaching prototype, not a secure banking product.")

# ============================================================ 5. Before vs After
with tabs[4]:
    st.subheader("Before vs After")
    st.markdown(badge(MODE_SIM), unsafe_allow_html=True)
    for s in SCENARIOS:
        b, p = st.session_state.runs[s]
        st.markdown(f"### {SCENARIO_LABELS[s]}")
        table = pd.DataFrame(compare_results(b, p))
        keyed = table[table["metric"].isin(KEY_METRICS[s])].copy()
        c1, c2 = st.columns([1, 1])
        with c1:
            chart_df = keyed.set_index("metric")[["baseline", "with_controls"]].apply(pd.to_numeric, errors="coerce")
            st.bar_chart(chart_df)
        with c2:
            st.dataframe(table.astype({"baseline": str, "with_controls": str}), hide_index=True,
                         height=300)
    st.divider()
    st.markdown(f"### Import local lab results {badge(MODE_LOCAL)}", unsafe_allow_html=True)
    up = st.file_uploader("CSV written by local_lab/test_harness.py (local_lab/results/*.csv)", type="csv")
    if up is not None:
        df = pd.read_csv(io.BytesIO(up.getvalue()))
        if not validate_csv_header(list(df.columns)):
            st.error(f"Unexpected columns. Expected: {CSV_COLUMNS}")
        elif set(df["mode"]) != {MODE_LOCAL}:
            st.error("This file is not labelled LOCAL MEASURED, so it is not shown here.")
        else:
            piv = df.pivot_table(index="metric", columns="phase", values="value", aggfunc="first")
            st.dataframe(piv)
            num = piv.apply(pd.to_numeric, errors="coerce").dropna(how="all")
            if not num.empty:
                st.bar_chart(num.loc[[m for m in ["legit_success_rate_pct", "legit_avg_latency_ms", "legit_p95_latency_ms",
                                                  "burst_accepted"] if m in num.index]])
            st.caption("LOCAL MEASURED: real timings from the dummy service on the machine that ran the harness.")

# ============================================================ 6. Logs & Methodology
with tabs[5]:
    st.subheader("Event Logs & Methodology")
    st.markdown(badge(MODE_SIM), unsafe_allow_html=True)
    ev = all_events_df()
    f1, f2, f3 = st.columns(3)
    sc_f = f1.multiselect("Scenario", sorted(ev["scenario"].unique()), default=sorted(ev["scenario"].unique()))
    ph_f = f2.multiselect("Phase", sorted(ev["phase"].unique()), default=sorted(ev["phase"].unique()))
    ly_f = f3.multiselect("Layer", sorted(ev["layer"].unique()), default=sorted(ev["layer"].unique()))
    view = ev[ev["scenario"].isin(sc_f) & ev["phase"].isin(ph_f) & ev["layer"].isin(ly_f)]
    st.dataframe(view, hide_index=True, height=300)
    st.caption(f"{len(view)} of {len(ev)} events shown. Every event carries mode=SIMULATED.")
    st.download_button("Download results CSV (mode/source included)", rows_to_csv(export_rows()),
                       file_name="securebank_simulated_results.csv", mime="text/csv")
    st.download_button("Download event log CSV", ev.to_csv(index=False), file_name="securebank_simulated_events.csv",
                       mime="text/csv")
    st.markdown(Path("README.md").read_text(encoding="utf-8").split("<!--METHODOLOGY-->")[-1]
                if Path("README.md").exists() and "<!--METHODOLOGY-->" in Path("README.md").read_text(encoding="utf-8")
                else "See README.md for methodology.")
