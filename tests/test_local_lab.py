"""Tests for the LOCAL dummy service (in-process, loopback only, small request counts)."""
import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from local_lab import test_harness as th  # noqa: E402
from local_lab.banking_service import BankingService, ServiceConfig, make_server  # noqa: E402
from src.controls import sign_message  # noqa: E402

TOKEN = {"X-Demo-Token": "DEMO-TOKEN-ALICE"}


def call(svc, method, path, headers=None, body=None, client="c1"):
    h = dict(headers or {}, **{"X-Client-Id": client})
    return svc.handle(method, path, h, json.dumps(body).encode() if body is not None else b"", "127.0.0.1")


class TestService(unittest.TestCase):
    def svc(self, **kw):
        kw.setdefault("work_ms", 0)
        return BankingService(ServiceConfig(**kw))

    def test_access_control(self):
        s = self.svc()
        self.assertEqual(call(s, "GET", "/balance?account=ACC-1001", TOKEN)[0], 200)
        self.assertEqual(call(s, "GET", "/balance?account=ACC-1001")[0], 401)
        self.assertEqual(call(s, "GET", "/balance?account=ACC-1002", TOKEN)[0], 403)
        self.assertEqual(call(s, "GET", "/balance?account=../etc")[0], 400)

    def test_integrity_and_validation(self):
        s = self.svc()
        msg = {"from": "ACC-1001", "to": "ACC-1002", "amount": 5, "memo": "hi"}
        self.assertEqual(call(s, "POST", "/transfer-simulated", TOKEN, dict(msg, mac=sign_message(msg)))[0], 200)
        self.assertEqual(call(s, "POST", "/transfer-simulated", TOKEN, dict(msg, mac=sign_message(msg), amount=999))[0], 400)
        self.assertEqual(call(s, "POST", "/transfer-simulated", TOKEN, dict(msg, amount=-5))[0], 400)

    def test_rate_limit_then_ids_ips(self):
        s = self.svc(rate_limit_per_sec=1000, ids_rate_threshold=5, ips_block_seconds=60)
        codes = [call(s, "GET", "/health", client="bot")[0] for _ in range(10)]
        self.assertEqual(codes[:6], [200] * 6)       # 6th request triggers IDS alert but is served
        self.assertTrue(all(c == 403 for c in codes[6:]))   # IPS blocks the rest
        self.assertEqual(call(s, "GET", "/health", client="other")[0], 200)
        mon = s.monitor()
        self.assertEqual(mon["detections"], 1)
        self.assertEqual(mon["blocked"], 4)

    def test_rate_limit_429(self):
        s = self.svc(rate_limit_per_sec=3, ids=False, ips=False)
        codes = [call(s, "GET", "/health")[0] for _ in range(6)]
        self.assertEqual(codes[:3], [200, 200, 200])
        self.assertIn(429, codes[3:])

    def test_failed_requests_trigger_block(self):
        s = self.svc(ids_failed_threshold=3, rate_limit=False)
        for _ in range(3):
            call(s, "GET", "/balance?account=ACC-1001", client="guesser")
        self.assertEqual(call(s, "GET", "/balance?account=ACC-1001", TOKEN, client="guesser")[0], 403)

    def test_refuses_non_loopback_bind(self):
        with self.assertRaises(ValueError):
            make_server(self.svc(), "0.0.0.0", 0)


class TestHarnessSafety(unittest.TestCase):
    def test_clamps(self):
        burst, legit, secs, threads = th.clamp_plan(10 ** 9, 10 ** 9, 10 ** 9, 10 ** 9)
        self.assertLessEqual(burst + legit, th.HARD_MAX_REQUESTS)
        self.assertLessEqual(secs, th.HARD_MAX_SECONDS)
        self.assertLessEqual(threads, th.HARD_MAX_THREADS)

    def test_non_local_target_refused(self):
        for url in ("http://example.com", "http://192.168.1.10:8080", "https://bank.real"):
            with self.assertRaises(SystemExit):
                th.check_target(url)

    def test_stop_event_halts_run(self):
        svc = BankingService(ServiceConfig(work_ms=0, rate_limit=False))
        srv = make_server(svc, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            stop = threading.Event()
            stop.set()
            m = th.run_load_phase(f"http://127.0.0.1:{srv.server_address[1]}", 400, 40, 10, 4, stop=stop)
            self.assertEqual(m["total_requests_sent"], 0)
            self.assertTrue(m["stopped_early"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_bounded_real_run_and_csv(self):
        svc = BankingService(ServiceConfig(work_ms=1))
        srv = make_server(svc, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            m = th.run_load_phase(f"http://127.0.0.1:{srv.server_address[1]}", 60, 5, 10, 2, legit_interval=0.01)
            self.assertLessEqual(m["total_requests_sent"], 65)
            rows = th.to_rows(m, "with_controls", "all", "t")
            self.assertEqual({r["mode"] for r in rows}, {"LOCAL MEASURED"})
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
