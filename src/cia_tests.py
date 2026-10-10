"""Concrete CIA Triad checks on dummy data. All results are SIMULATED / in-process.

Each check returns a dict:
  name, mode, passed, summary, cases (list of dicts), phases ({phase: {metric: value}}).
`passed` refers to the protected configuration behaving correctly.
"""
from __future__ import annotations

from .controls import AccessControl, sign_message, verify_message
from .schemas import ControlConfig, MODE_SIM
from .simulator import run_ddos

BASELINE = "baseline"
PROTECTED = "with_controls"


# ------------------------------------------------------------- Confidentiality

def _confidentiality_cases(enforce: bool) -> list[dict]:
    acl = AccessControl()
    probes = [
        ("Owner (Alice) reads own account", "DEMO-TOKEN-ALICE", "ACC-1001", True),
        ("No token reads Alice's account", None, "ACC-1001", False),
        ("Invalid token reads Alice's account", "NOT-A-REAL-TOKEN", "ACC-1001", False),
        ("Alice's token reads Bob's account", "DEMO-TOKEN-ALICE", "ACC-1002", False),
    ]
    out = []
    for label, token, acct, should_allow in probes:
        allowed, reason, data = acl.request_balance(token, acct, enforce=enforce)
        out.append({"case": label, "expected": "ALLOW" if should_allow else "DENY",
                    "actual": "ALLOW" if allowed else "DENY", "correct": allowed == should_allow,
                    "data_exposed": bool(data) and not should_allow, "reason": reason})
    return out


def run_confidentiality_check() -> dict:
    phases, cases = {}, []
    for phase, enforce in ((BASELINE, False), (PROTECTED, True)):
        c = _confidentiality_cases(enforce)
        phases[phase] = {"cases_total": len(c), "cases_correct": sum(x["correct"] for x in c),
                         "unauthorized_data_leaks": sum(x["data_exposed"] for x in c)}
        cases += [{"phase": phase, **x} for x in c]
    return {"name": "Confidentiality", "mode": MODE_SIM,
            "passed": phases[PROTECTED]["cases_correct"] == phases[PROTECTED]["cases_total"]
                      and phases[PROTECTED]["unauthorized_data_leaks"] == 0,
            "summary": "Unauthorised requests cannot retrieve dummy account data when access control is on.",
            "cases": cases, "phases": phases}


# ------------------------------------------------------------------ Integrity

def run_integrity_check() -> dict:
    original = {"from": "ACC-1001", "to": "ACC-1002", "amount": 100, "memo": "rent"}
    mac = sign_message(original)
    tampered_amt = dict(original, amount=10_000)
    tampered_memo = dict(original, memo="rent-and-more")
    probes = [
        ("Untouched message", original, mac, True),
        ("Amount modified in transit", tampered_amt, mac, False),
        ("Memo modified in transit", tampered_memo, mac, False),
        ("Wrong key used by forger", tampered_amt, sign_message(tampered_amt, key=b"attacker-guess"), False),
    ]
    phases, cases = {}, []
    for phase, check in ((BASELINE, False), (PROTECTED, True)):
        phase_cases = []
        for label, msg, m, should_pass in probes:
            accepted = verify_message(msg, m) if check else True  # baseline: nothing is verified
            phase_cases.append({"phase": phase, "case": label,
                                "expected": "ACCEPT" if should_pass else "REJECT",
                                "actual": "ACCEPT" if accepted else "REJECT",
                                "correct": accepted == should_pass})
        cases += phase_cases
        phases[phase] = {"cases_total": len(phase_cases),
                         "cases_correct": sum(c["correct"] for c in phase_cases),
                         "tampered_accepted": sum(1 for c in phase_cases
                                                  if c["expected"] == "REJECT" and c["actual"] == "ACCEPT")}
    return {"name": "Integrity", "mode": MODE_SIM,
            "passed": phases[PROTECTED]["tampered_accepted"] == 0
                      and phases[PROTECTED]["cases_correct"] == phases[PROTECTED]["cases_total"],
            "summary": "HMAC-SHA256 with a local demonstration key detects modified messages. "
                       "Key management is NOT production grade (shared, stored in repo).",
            "cases": cases, "phases": phases}


# --------------------------------------------------------------- Availability

def run_availability_check(seed: int = 42) -> dict:
    """Normal bounded workload vs controlled burst, before and after rate limiting."""
    normal = run_ddos(ControlConfig.none(), seed=seed, attack=False, phase="normal_load")
    burst = run_ddos(ControlConfig.none(), seed=seed, attack=True, phase="burst_baseline")
    limited = run_ddos(ControlConfig(rate_limit=True), seed=seed, attack=True, phase="burst_with_rate_limit")
    keys = ["total_requests", "legit_success_rate_pct", "request_success_rate_pct", "avg_latency_ms_legit",
            "p95_latency_ms_legit", "availability_pct", "requests_rejected_by_controls", "block_count"]
    phases = {r.phase: {k: r.metrics.get(k) for k in keys} for r in (normal, burst, limited)}
    cases = [{"phase": ph, **vals} for ph, vals in phases.items()]
    lim, base = phases["burst_with_rate_limit"], phases["burst_baseline"]
    passed = (lim["legit_success_rate_pct"] or 0) >= 90 and \
             (lim["legit_success_rate_pct"] or 0) > (base["legit_success_rate_pct"] or 0)
    return {"name": "Availability", "mode": MODE_SIM, "passed": passed,
            "summary": "Rate limiting keeps legitimate users served during a simulated burst.",
            "cases": cases, "phases": phases, "runs": [normal, burst, limited]}


def run_all_cia(seed: int = 42) -> dict:
    return {"confidentiality": run_confidentiality_check(),
            "integrity": run_integrity_check(),
            "availability": run_availability_check(seed)}


def cia_rows(result: dict, run_id: str, seed: int = 42) -> list[dict]:
    """Flatten a CIA result to the standard CSV schema."""
    from .schemas import SOURCE_SIM
    rows = []
    for phase, metrics in result["phases"].items():
        for k, v in metrics.items():
            rows.append({"run_id": run_id, "mode": result["mode"], "source": SOURCE_SIM,
                         "scenario": "cia_" + result["name"].lower(), "phase": phase, "metric": k,
                         "value": "" if v is None else v, "seed": seed,
                         "controls_active": "access_control" if result["name"] == "Confidentiality"
                         else "hmac_integrity" if result["name"] == "Integrity" else "rate_limit"})
    return rows
