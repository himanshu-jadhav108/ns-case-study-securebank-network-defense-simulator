"""SAFE local test harness for the DUMMY banking service.

Hard limits (cannot be raised from the CLI):
  * at most HARD_MAX_REQUESTS requests per phase and HARD_MAX_SECONDS seconds
  * target must be loopback (or a host listed in LAB_ALLOWED_TARGETS, for the Docker lab)
  * stop control: Ctrl+C, or create the file local_lab/STOP
It never contacts anything except the dummy service. Measurements are real (LOCAL MEASURED).

Examples
  python local_lab/test_harness.py --checks          # confidentiality / integrity checks
  python local_lab/test_harness.py --compare         # baseline vs controls on an in-process service
  python local_lab/test_harness.py --load --target http://127.0.0.1:8080 --phase-label with_controls
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from local_lab.banking_service import BankingService, ServiceConfig, make_server  # noqa: E402
from src.controls import sign_message  # noqa: E402
from src.metrics import percentile, rows_to_csv  # noqa: E402
from src.schemas import MODE_LOCAL, SOURCE_LOCAL  # noqa: E402

HARD_MAX_REQUESTS = 500
HARD_MAX_SECONDS = 30.0
HARD_MAX_THREADS = 8
STOP_FILE = Path(__file__).resolve().parent / "STOP"
RESULTS_DIR = Path(__file__).resolve().parent / "results"
ALICE = "DEMO-TOKEN-ALICE"


def check_target(url: str) -> str:
    host = urlparse(url).hostname or ""
    allowed = {"127.0.0.1", "localhost", "::1"} | {h.strip() for h in
                                                    os.environ.get("LAB_ALLOWED_TARGETS", "").split(",") if h.strip()}
    if host not in allowed:
        raise SystemExit(f"Refusing target host {host!r}. Only loopback (or LAB_ALLOWED_TARGETS) is permitted.")
    return url.rstrip("/")


def clamp_plan(burst_requests: int, legit_requests: int, seconds: float, threads: int):
    legit = max(1, min(int(legit_requests), 100))
    burst = max(0, min(int(burst_requests), HARD_MAX_REQUESTS - legit))
    return burst, legit, max(1.0, min(float(seconds), HARD_MAX_SECONDS)), max(1, min(int(threads), HARD_MAX_THREADS))


def http(method: str, url: str, headers: dict | None = None, body: dict | None = None, timeout: float = 5.0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read()
    except (urllib.error.URLError, TimeoutError, OSError):
        code, raw = 0, b"{}"
    ms = (time.perf_counter() - t0) * 1000.0
    try:
        return code, json.loads(raw or b"{}"), ms
    except ValueError:
        return code, {}, ms


def run_load_phase(base: str, burst_requests=300, legit_requests=40, seconds=15.0, threads=6,
                   legit_interval=0.05, stop: threading.Event | None = None) -> dict:
    """One legitimate client (steady, authenticated) + one burst client (capped, authenticated)."""
    base = check_target(base)
    burst_requests, legit_requests, seconds, threads = clamp_plan(burst_requests, legit_requests, seconds, threads)
    stop = stop or threading.Event()
    deadline = time.monotonic() + seconds
    legit, burst = [], []
    lock = threading.Lock()

    def halted() -> bool:
        return stop.is_set() or time.monotonic() > deadline or STOP_FILE.exists()

    def legit_worker():
        for _ in range(legit_requests):
            if halted():
                return
            code, _, ms = http("GET", f"{base}/balance?account=ACC-1001",
                               {"X-Demo-Token": ALICE, "X-Client-Id": "legit-user"})
            with lock:
                legit.append((code, ms))
            time.sleep(legit_interval)

    per_thread = burst_requests // threads if burst_requests else 0

    def burst_worker():
        for _ in range(per_thread):
            if halted():
                return
            code, _, ms = http("GET", f"{base}/balance?account=ACC-1001",
                               {"X-Demo-Token": ALICE, "X-Client-Id": "burst-bot"})
            with lock:
                burst.append((code, ms))

    ts = [threading.Thread(target=legit_worker, daemon=True)]
    if per_thread:
        ts += [threading.Thread(target=burst_worker, daemon=True) for _ in range(threads)]
    t0 = time.monotonic()
    try:
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=seconds + 5)
    except KeyboardInterrupt:
        stop.set()
        print("stop requested; halting test")
    elapsed = time.monotonic() - t0
    _, mon, _ = http("GET", f"{base}/_monitor")
    lat = [ms for code, ms in legit if code == 200]
    ok_burst = sum(1 for c, _ in burst if c == 200)
    p95 = percentile(lat, 95)
    return {
        "total_requests_sent": len(legit) + len(burst),
        "legit_requests": len(legit),
        "legit_success_rate_pct": round(100 * len(lat) / len(legit), 2) if legit else None,
        "legit_avg_latency_ms": round(sum(lat) / len(lat), 2) if lat else None,
        "legit_p95_latency_ms": round(p95, 2) if p95 is not None else None,
        "burst_requests_sent": len(burst),
        "burst_accepted": ok_burst,
        "burst_rejected_or_blocked": sum(1 for c, _ in burst if c in (403, 429)),
        "detection_count": mon.get("detections"),
        "block_count": mon.get("blocked"),
        "elapsed_seconds": round(elapsed, 2),
        "stopped_early": bool(stop.is_set() or STOP_FILE.exists()),
    }


def to_rows(metrics: dict, phase: str, controls: str, run_id: str, scenario: str = "ddos") -> list[dict]:
    return [{"run_id": run_id, "mode": MODE_LOCAL, "source": SOURCE_LOCAL, "scenario": scenario,
             "phase": phase, "metric": k, "value": "" if v is None else v, "seed": "",
             "controls_active": controls} for k, v in metrics.items()]


def run_checks(base: str) -> list[dict]:
    """Confidentiality + integrity probes against the dummy service. Returns case dicts."""
    base = check_target(base)
    msg = {"from": "ACC-1001", "to": "ACC-1002", "amount": 25, "memo": "lunch"}
    good = dict(msg, mac=sign_message(msg))
    bad = dict(good, amount=900)  # modified after signing
    cases = [
        ("Owner reads own balance", "GET", "/balance?account=ACC-1001", {"X-Demo-Token": ALICE}, None, 200),
        ("No token -> denied", "GET", "/balance?account=ACC-1001", {}, None, 401),
        ("Other user's account -> denied", "GET", "/balance?account=ACC-1002", {"X-Demo-Token": ALICE}, None, 403),
        ("Signed transfer accepted", "POST", "/transfer-simulated", {"X-Demo-Token": ALICE}, good, 200),
        ("Tampered transfer rejected", "POST", "/transfer-simulated", {"X-Demo-Token": ALICE}, bad, 400),
    ]
    out = []
    for name, method, path, hdr, body, expect in cases:
        code, _, ms = http(method, base + path, {**hdr, "X-Client-Id": "checks"}, body)
        out.append({"case": name, "expected_status": expect, "actual_status": code,
                    "passed": code == expect, "latency_ms": round(ms, 2)})
    return out


def _in_process(cfg: ServiceConfig):
    svc = BankingService(cfg)
    srv = make_server(svc, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return svc, srv, f"http://127.0.0.1:{srv.server_address[1]}"


def compare(burst, legit, seconds, threads) -> list[dict]:
    """Baseline (all controls OFF) vs controls ON, each on a fresh in-process dummy service."""
    rows, run_id = [], time.strftime("local-%Y%m%d-%H%M%S")
    setups = [("baseline", "none", ServiceConfig(access_control=False, integrity=False, rate_limit=False,
                                                 ids=False, ips=False)),
              ("with_controls", "access_control|integrity|rate_limit|ids|ips", ServiceConfig())]
    for phase, ctl, cfg in setups:
        svc, srv, url = _in_process(cfg)
        try:
            m = run_load_phase(url, burst, legit, seconds, threads)
        finally:
            srv.shutdown()
            srv.server_close()
        print(f"\n[{phase}] (LOCAL MEASURED)")
        for k, v in m.items():
            print(f"  {k}: {v}")
        rows += to_rows(m, phase, ctl, run_id)
    return rows


def write_csv(rows: list[dict], name: str = "local_results.csv") -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    p = RESULTS_DIR / name
    p.write_text(rows_to_csv(rows), encoding="utf-8")
    return p


def main() -> None:
    ap = argparse.ArgumentParser(description="Safe harness for the DUMMY local service (bounded).")
    ap.add_argument("--checks", action="store_true", help="run confidentiality/integrity checks")
    ap.add_argument("--compare", action="store_true", help="baseline vs controls on an in-process service")
    ap.add_argument("--load", action="store_true", help="single bounded phase against --target")
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    ap.add_argument("--phase-label", default="with_controls")
    ap.add_argument("--burst", type=int, default=300)
    ap.add_argument("--legit", type=int, default=40)
    ap.add_argument("--seconds", type=float, default=15.0)
    ap.add_argument("--threads", type=int, default=6)
    a = ap.parse_args()
    if STOP_FILE.exists():
        STOP_FILE.unlink()
    if not (a.checks or a.compare or a.load):
        a.checks = a.compare = True
    if a.checks:
        svc, srv, url = _in_process(ServiceConfig(rate_limit=False))
        try:
            res = run_checks(url)
        finally:
            srv.shutdown()
            srv.server_close()
        print("Checks against in-process DUMMY service (LOCAL MEASURED):")
        for r in res:
            print(f"  [{'PASS' if r['passed'] else 'FAIL'}] {r['case']}: expected {r['expected_status']}, got {r['actual_status']}")
    if a.compare:
        rows = compare(a.burst, a.legit, a.seconds, a.threads)
        print(f"\nCSV written to {write_csv(rows)}")
    if a.load:
        m = run_load_phase(a.target, a.burst, a.legit, a.seconds, a.threads)
        print(json.dumps(m, indent=2))
        rows = to_rows(m, a.phase_label, "see service flags", time.strftime("local-%Y%m%d-%H%M%S"))
        print(f"CSV written to {write_csv(rows, f'local_{a.phase_label}.csv')}")


if __name__ == "__main__":
    main()
