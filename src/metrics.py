"""Metric calculation and CSV export. All numbers are derived from run outputs."""
from __future__ import annotations

import csv
import io
import math
from collections import Counter
from typing import Iterable

from .schemas import CSV_COLUMNS, Event, RunResult, SOURCE_SIM, MODE_SIM

# Request outcomes produced by the simulator pipeline.
OUTCOME_SERVED = "served"
CONTROL_OUTCOMES = ("denied_segmentation", "denied_firewall", "blocked_ips",
                    "rejected_rate_limit", "rejected_auth")
FAILURE_OUTCOMES = ("dropped_overload", "timeout")

OUTCOME_LAYER = {
    "denied_segmentation": "segmentation",
    "denied_firewall": "firewall",
    "blocked_ips": "ips",
    "rejected_rate_limit": "rate_limit",
    "rejected_auth": "access_control",
    "dropped_overload": "service",
    "timeout": "service",
}


def percentile(values: Iterable[float], p: float) -> float | None:
    """Linear-interpolation percentile (p in 0..100). None for empty input."""
    xs = sorted(values)
    if not xs:
        return None
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return float(xs[lo])
    return float(xs[lo] + (xs[hi] - xs[lo]) * (k - lo))


def _rate(num: int, den: int) -> float | None:
    return round(100.0 * num / den, 2) if den else None


def summarize_requests(records: list[dict], ticks: int) -> dict:
    """Compute request-level metrics from per-request records."""
    c = Counter(r["outcome"] for r in records)
    legit = [r for r in records if r["legit"]]
    attack = [r for r in records if not r["legit"]]
    legit_served = [r for r in legit if r["outcome"] == OUTCOME_SERVED]
    attack_served = [r for r in attack if r["outcome"] == OUTCOME_SERVED]
    lat = [r["latency_ms"] for r in legit_served]

    # Availability: share of ticks in which >=90% of legitimate requests were served.
    per_tick: dict[int, list[int]] = {}
    for r in legit:
        s = per_tick.setdefault(r["tick"], [0, 0])
        s[1] += 1
        s[0] += r["outcome"] == OUTCOME_SERVED
    good_ticks = sum(1 for s, t in per_tick.values() if t and s / t >= 0.9)
    avg = round(sum(lat) / len(lat), 2) if lat else None
    p95 = percentile(lat, 95)

    m = {
        "total_requests": len(records),
        "legit_requests": len(legit),
        "attack_requests": len(attack),
        "requests_served": c[OUTCOME_SERVED],
        "requests_rejected_by_controls": sum(c[o] for o in CONTROL_OUTCOMES),
        "requests_dropped_or_timed_out": sum(c[o] for o in FAILURE_OUTCOMES),
        "request_success_rate_pct": _rate(c[OUTCOME_SERVED], len(records)),
        "legit_success_rate_pct": _rate(len(legit_served), len(legit)),
        "attack_requests_served": len(attack_served),
        "avg_latency_ms_legit": avg,
        "p95_latency_ms_legit": round(p95, 2) if p95 is not None else None,
        "availability_pct": _rate(good_ticks, len(per_tick)),
    }
    for o in CONTROL_OUTCOMES + FAILURE_OUTCOMES:
        m[f"count_{o}"] = c[o]
    return m


def layer_attribution(events: list[Event]) -> dict[str, int]:
    """How many deny/block/detect events each layer produced (defence-in-depth view)."""
    out: Counter = Counter()
    for e in events:
        if e.action in ("deny", "block", "detect", "throttle"):
            out[e.layer] += 1
    return dict(out)


# ----------------------------------------------------------------- CSV export

def result_to_rows(res: RunResult, run_id: str, source: str = SOURCE_SIM) -> list[dict]:
    ctl = "|".join(res.controls_active()) or "none"
    rows = []
    for k, v in res.metrics.items():
        if isinstance(v, (dict, list)):
            continue
        rows.append({
            "run_id": run_id, "mode": res.mode, "source": source, "scenario": res.scenario,
            "phase": res.phase, "metric": k, "value": "" if v is None else v,
            "seed": res.seed, "controls_active": ctl,
        })
    return rows


def rows_to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({c: r.get(c, "") for c in CSV_COLUMNS})
    return buf.getvalue()


def validate_csv_header(header: list[str]) -> bool:
    return list(header) == CSV_COLUMNS


def compare_results(base: RunResult, post: RunResult) -> list[dict]:
    """Side-by-side metric table derived directly from the two runs."""
    rows = []
    for k in base.metrics:
        b, p = base.metrics.get(k), post.metrics.get(k)
        if isinstance(b, (dict, list)) or isinstance(p, (dict, list)):
            continue
        change = None
        if isinstance(b, (int, float)) and isinstance(p, (int, float)) \
                and not isinstance(b, bool) and not isinstance(p, bool):
            change = round(p - b, 2)
        rows.append({"metric": k, "baseline": b, "with_controls": p, "change": change})
    return rows
