"""Unit tests for defensive controls. Run: python -m unittest discover -s tests -v  (or pytest)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.controls import (AccessControl, ArpGuard, Firewall, IDS, IPS, RateLimiter, Segmentation,  # noqa: E402
                          detect_arp_conflicts, sign_message, validate_transfer, verify_message)


class TestAccessControl(unittest.TestCase):
    def setUp(self):
        self.acl = AccessControl()

    def test_unauthorized_access_denied(self):
        ok, reason, data = self.acl.request_balance(None, "ACC-1001")
        self.assertFalse(ok)
        self.assertIsNone(data)
        ok, _, data = self.acl.request_balance("DEMO-TOKEN-ALICE", "ACC-1002")  # someone else's account
        self.assertFalse(ok)
        self.assertIsNone(data)

    def test_valid_dummy_access_succeeds(self):
        ok, _, data = self.acl.request_balance("DEMO-TOKEN-ALICE", "ACC-1001")
        self.assertTrue(ok)
        self.assertEqual(data["account_id"], "ACC-1001")


class TestIntegrity(unittest.TestCase):
    def test_tampered_message_fails(self):
        msg = {"from": "ACC-1001", "to": "ACC-1002", "amount": 10, "memo": "x"}
        mac = sign_message(msg)
        self.assertTrue(verify_message(msg, mac))
        self.assertFalse(verify_message(dict(msg, amount=11), mac))

    def test_wrong_key_fails(self):
        msg = {"a": 1}
        self.assertFalse(verify_message(msg, sign_message(msg, key=b"other"), key=b"mine"))


class TestRateLimiter(unittest.TestCase):
    def test_limit_activates_after_threshold(self):
        rl = RateLimiter(3, window=1.0)
        results = [rl.allow("s", 0.0) for _ in range(5)]
        self.assertEqual(results, [True, True, True, False, False])
        self.assertTrue(rl.allow("s", 1.0))          # new window
        self.assertTrue(rl.allow("other", 0.0))      # independent source


class TestIDSIPS(unittest.TestCase):
    def test_rate_alert_expected(self):
        ids = IDS(rate_threshold=3)
        alerts = [ids.observe_request("bot", 0) for _ in range(5)]
        self.assertEqual([a is not None for a in alerts], [False, False, False, True, False])
        self.assertEqual(alerts[3].signature, "RATE_EXCEEDED")

    def test_repeated_failures_alert(self):
        ids = IDS(failed_threshold=3)
        out = [ids.observe_failed("u", t) for t in range(3)]
        self.assertIsNone(out[0])
        self.assertEqual(out[2].signature, "REPEATED_FAILURES")

    def test_ips_blocks_then_expires(self):
        ips = IPS(default_duration=10)
        self.assertFalse(ips.is_blocked("x", 0))
        ips.block("x", 0, "RATE_EXCEEDED")
        self.assertTrue(ips.is_blocked("x", 5))
        self.assertFalse(ips.is_blocked("x", 10))

    def test_arp_conflict_detected(self):
        ids = IDS()
        trusted = {"10.0.0.1": "aa:aa:aa:aa:aa:01"}
        self.assertEqual(ids.observe_arp("10.0.0.1", "AA:AA:AA:AA:AA:01", trusted), (False, None))
        conflict, alert = ids.observe_arp("10.0.0.1", "de:ad:be:ef:00:66", trusted)
        self.assertTrue(conflict)
        self.assertEqual(alert.signature, "ARP_MAPPING_CONFLICT")
        self.assertEqual(ids.observe_arp("10.0.0.1", "de:ad:be:ef:00:66", trusted)[1], None)  # alert once

    def test_detect_arp_conflicts_function(self):
        obs = [("10.0.0.1", "aa:01"), ("10.0.0.2", "aa:02"), ("10.0.0.1", "de:66")]
        self.assertEqual(detect_arp_conflicts(obs), {"10.0.0.1": ["aa:01", "de:66"]})
        self.assertEqual(detect_arp_conflicts(obs[:2]), {})

    def test_arp_guard(self):
        g = ArpGuard({"10.0.0.1": "aa:bb"})
        self.assertTrue(g.accept("10.0.0.1", "AA:BB"))
        self.assertFalse(g.accept("10.0.0.1", "de:ad"))


class TestFirewallSegmentation(unittest.TestCase):
    def test_rules_and_default_deny(self):
        fw = Firewall()
        self.assertTrue(fw.evaluate("internet", "dmz", "/balance").allowed)
        self.assertFalse(fw.evaluate("internet", "dmz", "/admin").allowed)
        d = fw.evaluate("internet", "db-zone", "/db-query")
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule_id, "FW-05")

    def test_segmentation_paths(self):
        s = Segmentation()
        self.assertTrue(s.permits("internet", "dmz"))
        self.assertFalse(s.permits("internet", "db-zone"))
        self.assertTrue(s.permits("user-lan", "user-lan"))


class TestValidation(unittest.TestCase):
    def test_transfer_validation(self):
        good = {"from": "ACC-1001", "to": "ACC-1002", "amount": 5, "memo": "ok"}
        self.assertTrue(validate_transfer(good)[0])
        for bad in (dict(good, amount=-1), dict(good, amount=10 ** 6), dict(good, to="ACC-1001"),
                    dict(good, memo="<script>"), dict(good, **{"from": "x"}), {"from": "ACC-1001"}, [], dict(good, amount=True)):
            self.assertFalse(validate_transfer(bad)[0], bad)


if __name__ == "__main__":
    unittest.main()
