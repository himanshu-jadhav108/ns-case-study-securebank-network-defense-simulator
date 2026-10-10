"""LOCAL DUMMY BANKING SERVICE - teaching only.

* Fictional accounts, no real payments, no real credentials, no personal data.
* Binds to loopback (127.0.0.1) only, unless LAB_CONTAINER=1 is set for the optional
  isolated-Docker lab.
* Controls: access control, input validation, rate limiting, IDS (rule based), IPS
  (temporary block), HMAC integrity checking, event logging.
* Client identity is the self-asserted X-Client-Id header (falls back to the socket IP).
  That is fine for a lab but trivially spoofable in the real world.

Run:  python local_lab/banking_service.py --port 8080
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.controls import (AccessControl, IDS, IPS, RateLimiter, validate_account_id,  # noqa: E402
                          validate_transfer, verify_message)
from src.metrics import percentile  # noqa: E402

MAX_BODY_BYTES = 2048
LOOPBACK = ("127.0.0.1", "localhost", "::1")


@dataclass
class ServiceConfig:
    access_control: bool = True
    integrity: bool = True
    rate_limit: bool = True
    ids: bool = True
    ips: bool = True
    rate_limit_per_sec: int = 20
    ids_rate_threshold: int = 50
    ids_failed_threshold: int = 5
    ips_block_seconds: float = 30.0
    capacity: int = 2          # concurrent workers (limited on purpose so bursts queue)
    work_ms: int = 25          # artificial processing time per real request
    log_path: str | None = None


class BankingService:
    """Transport-independent core so it can be unit-tested without sockets."""

    def __init__(self, cfg: ServiceConfig | None = None):
        self.cfg = cfg or ServiceConfig()
        self.acl = AccessControl()
        self.limiter = RateLimiter(self.cfg.rate_limit_per_sec, 1.0)
        self.ids = IDS(self.cfg.ids_rate_threshold, self.cfg.ids_failed_threshold)
        self.ips = IPS(self.cfg.ips_block_seconds)
        self._sem = threading.BoundedSemaphore(max(1, self.cfg.capacity))
        self._lock = threading.Lock()
        self.events: deque = deque(maxlen=5000)
        self.latencies: deque = deque(maxlen=20000)
        self.stats = {"requests": 0, "ok": 0, "denied": 0, "rate_limited": 0, "blocked": 0,
                      "bad_request": 0, "detections": 0, "ip_blocks": 0}

    # -- logging (never logs tokens) -----------------------------------------
    def _log(self, kind: str, client: str, detail: str) -> None:
        rec = {"ts": round(time.time(), 3), "kind": kind, "client": client, "detail": detail}
        with self._lock:
            self.events.append(rec)
        if self.cfg.log_path:
            try:
                with open(self.cfg.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
            except OSError:
                pass

    def _count(self, key: str) -> None:
        with self._lock:
            self.stats[key] += 1

    def _alert(self, alert, client: str, now: float) -> None:
        self._count("detections")
        self._log("IDS_ALERT", client, f"{alert.signature}: {alert.detail}")
        if self.cfg.ips:
            self.ips.block(client, now, alert.signature)
            self._count("ip_blocks")
            self._log("IPS_BLOCK", client, f"blocked {self.cfg.ips_block_seconds:.0f}s after {alert.signature}")

    def monitor(self) -> dict:
        with self._lock:
            lat = list(self.latencies)
            s = dict(self.stats)
            recent = list(self.events)[-25:]
        s.update({"avg_latency_ms": round(sum(lat) / len(lat), 2) if lat else None,
                  "p95_latency_ms": round(percentile(lat, 95), 2) if lat else None,
                  "mode": "LOCAL MEASURED", "config": self.cfg.__dict__, "recent_events": recent})
        return s

    # -- request handling ----------------------------------------------------
    def handle(self, method: str, raw_path: str, headers: dict, body: bytes, client_ip: str):
        t0 = time.perf_counter()
        status, payload = self._handle(method, raw_path, headers, body, client_ip)
        with self._lock:
            self.latencies.append((time.perf_counter() - t0) * 1000.0)
        return status, payload

    def _handle(self, method, raw_path, headers, body, client_ip):
        url = urlparse(raw_path)
        path = url.path
        h = {k.lower(): v for k, v in headers.items()}
        client = (h.get("x-client-id") or client_ip or "unknown")[:40]
        token = h.get("x-demo-token")
        now = time.monotonic()
        tick = int(now)

        if path == "/_monitor" and method == "GET":
            return 200, self.monitor()

        self._count("requests")
        if self.cfg.ips and self.ips.is_blocked(client, now):
            self._count("blocked")
            self._log("BLOCKED", client, f"{method} {path}")
            return 403, {"error": "blocked by IPS"}
        if self.cfg.ids:
            a = self.ids.observe_request(client, tick)
            if a:
                self._alert(a, client, now)
        if self.cfg.rate_limit and not self.limiter.allow(client, now):
            self._count("rate_limited")
            self._log("RATE_LIMITED", client, f"{method} {path}")
            return 429, {"error": "rate limit exceeded"}

        def failed(reason: str, code: int):
            self._count("denied")
            self._log("DENIED", client, f"{method} {path}: {reason}")
            if self.cfg.ids:
                a = self.ids.observe_failed(client, tick)
                if a:
                    self._alert(a, client, now)
            return code, {"error": reason}

        def work():
            with self._sem:
                time.sleep(self.cfg.work_ms / 1000.0)

        if path == "/health" and method == "GET":
            work()
            self._count("ok")
            return 200, {"status": "ok", "service": "dummy-securebank (LOCAL LAB)"}

        if path == "/balance" and method == "GET":
            account = parse_qs(url.query).get("account", [""])[0]
            if not validate_account_id(account):
                self._count("bad_request")
                return 400, {"error": "invalid account id"}
            allowed, reason, data = self.acl.request_balance(token, account, enforce=self.cfg.access_control)
            if not allowed:
                return failed(reason, 401 if "authentication" in reason else 403 if "authoris" in reason else 404)
            work()
            self._count("ok")
            return 200, {**data, "note": "FICTIONAL DATA"}

        if path == "/transfer-simulated" and method == "POST":
            if len(body) > MAX_BODY_BYTES:
                self._count("bad_request")
                return 413, {"error": "body too large"}
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                self._count("bad_request")
                return 400, {"error": "invalid JSON"}
            if self.cfg.access_control and self.acl.authenticate(token) is None:
                return failed("authentication failed", 401)
            mac = payload.pop("mac", None) if isinstance(payload, dict) else None
            ok, why = validate_transfer(payload)
            if not ok:
                self._count("bad_request")
                return 400, {"error": why}
            if self.cfg.integrity:
                if not mac or not verify_message(payload, mac):
                    self._count("denied")
                    self._log("INTEGRITY_FAILURE", client, "HMAC verification failed")
                    if self.cfg.ids:  # repeated failures (not a single one) trigger the IDS/IPS policy
                        a = self.ids.observe_failed(client, tick)
                        if a:
                            self._alert(a, client, now)
                    return 400, {"error": "integrity check failed"}
            work()
            self._count("ok")
            return 200, {"status": "SIMULATED transfer accepted", "note": "No money moves; nothing is stored."}

        self._count("bad_request")
        return 404, {"error": "not found"}


def make_server(service: BankingService, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    if host not in LOOPBACK and os.environ.get("LAB_CONTAINER") != "1":
        raise ValueError("Refusing to bind to a non-loopback address. Set LAB_CONTAINER=1 only inside the "
                         "isolated Docker lab.")

    class Handler(BaseHTTPRequestHandler):
        def _serve(self, method: str):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(length, MAX_BODY_BYTES + 1)) if length else b""
            status, payload = service.handle(method, self.path, dict(self.headers), body, self.client_address[0])
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._serve("GET")

        def do_POST(self):
            self._serve("POST")

        def log_message(self, *a):  # keep console quiet; events go to the service log
            pass

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv


def main() -> None:
    ap = argparse.ArgumentParser(description="Local DUMMY banking service (teaching only)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--no-rate-limit", action="store_true")
    ap.add_argument("--no-ids", action="store_true")
    ap.add_argument("--no-ips", action="store_true")
    ap.add_argument("--no-auth", action="store_true")
    ap.add_argument("--no-integrity", action="store_true")
    ap.add_argument("--rate-limit", type=int, default=20, help="requests per second per client")
    ap.add_argument("--work-ms", type=int, default=25)
    ap.add_argument("--capacity", type=int, default=2)
    ap.add_argument("--log", default=str(Path(__file__).parent / "logs" / "events.jsonl"))
    a = ap.parse_args()
    Path(a.log).parent.mkdir(parents=True, exist_ok=True)
    cfg = ServiceConfig(access_control=not a.no_auth, integrity=not a.no_integrity,
                        rate_limit=not a.no_rate_limit, ids=not a.no_ids, ips=not a.no_ips,
                        rate_limit_per_sec=a.rate_limit, work_ms=a.work_ms, capacity=a.capacity,
                        log_path=a.log)
    srv = make_server(BankingService(cfg), a.host, a.port)
    print(f"Dummy banking service on http://{a.host}:{a.port}  (LOCAL LAB, fictional data)")
    print(f"Monitor: http://{a.host}:{a.port}/_monitor   Event log: {a.log}   Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
