import csv
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.metrics import compare_results, percentile, result_to_rows, rows_to_csv, summarize_requests, validate_csv_header  # noqa: E402
from src.schemas import CSV_COLUMNS, ControlConfig, MODE_SIM, SCENARIOS  # noqa: E402
from src.simulator import MAX_REQUESTS, MAX_TICKS, run_before_after, run_ddos, run_layer_ablation, run_scenario  # noqa: E402


class TestDeterminism(unittest.TestCase):
    def test_same_seed_same_result(self):
        for s in SCENARIOS:
            a = run_scenario(s, ControlConfig.all_on(), seed=7)
            b = run_scenario(s, ControlConfig.all_on(), seed=7)
            self.assertEqual(a.metrics, b.metrics)
            self.assertEqual([e.to_dict() for e in a.events], [e.to_dict() for e in b.events])

    def test_different_seed_changes_ddos_latency(self):
        a = run_ddos(ControlConfig.none(), seed=1).metrics["avg_latency_ms_legit"]
        b = run_ddos(ControlConfig.none(), seed=2).metrics["avg_latency_ms_legit"]
        self.assertNotEqual(a, b)

    def test_everything_labelled_simulated(self):
        for s in SCENARIOS:
            r = run_scenario(s, ControlConfig.all_on())
            self.assertEqual(r.mode, MODE_SIM)
            self.assertTrue(all(e.mode == MODE_SIM for e in r.events))


class TestARP(unittest.TestCase):
    def test_baseline_poisoned_and_conflict_detected(self):
        base, post = run_before_after("arp_spoofing", ControlConfig(ids=True))
        self.assertEqual(base.metrics["caches_poisoned"], 4)
        self.assertEqual(base.metrics["detection_count"], 0)
        self.assertGreaterEqual(post.metrics["detection_count"], 1)   # conflict detected
        self.assertEqual(post.metrics["caches_poisoned"], 4)          # IDS alone does not prevent

    def test_ids_plus_ips_prevents(self):
        r = run_scenario("arp_spoofing", ControlConfig(ids=True, ips=True))
        self.assertEqual(r.metrics["caches_poisoned"], 0)
        self.assertGreater(r.metrics["block_count"], 0)

    def test_arp_guard_and_segmentation(self):
        self.assertEqual(run_scenario("arp_spoofing", ControlConfig(arp_protection=True)).metrics["caches_poisoned"], 0)
        seg = run_scenario("arp_spoofing", ControlConfig(segmentation=True)).metrics
        self.assertEqual(seg["caches_poisoned"], 2)  # only same-zone hosts remain exposed
        self.assertGreater(seg["frames_dropped_segmentation"], 0)


class TestMITM(unittest.TestCase):
    def test_hmac_detects_tampering(self):
        base, post = run_before_after("mitm", ControlConfig(hmac_integrity=True))
        self.assertGreater(base.metrics["tampered_accepted"], 0)
        self.assertEqual(base.metrics["integrity_check_outcome"], "FAIL")
        self.assertEqual(post.metrics["tampered_accepted"], 0)
        self.assertEqual(post.metrics["tampered_detected"], post.metrics["messages_tampered"])
        self.assertEqual(post.metrics["integrity_check_outcome"], "PASS")

    def test_encryption_flag_stops_reading_only(self):
        m = run_scenario("mitm", ControlConfig(encryption=True)).metrics
        self.assertEqual(m["messages_read_by_attacker"], 0)
        self.assertGreater(m["tampered_accepted"], 0)

    def test_ids_ips_on_integrity_failures(self):
        m = run_scenario("mitm", ControlConfig(hmac_integrity=True, ids=True, ips=True)).metrics
        self.assertEqual(m["detection_count"], m["messages_tampered"])
        self.assertEqual(m["block_count"], m["messages_tampered"])


class TestDDoS(unittest.TestCase):
    def test_burst_degrades_then_rate_limit_restores(self):
        normal = run_ddos(ControlConfig.none(), attack=False).metrics
        burst = run_ddos(ControlConfig.none()).metrics
        limited = run_ddos(ControlConfig(rate_limit=True)).metrics
        self.assertEqual(normal["legit_success_rate_pct"], 100.0)
        self.assertLess(burst["legit_success_rate_pct"], 90.0)
        self.assertGreaterEqual(limited["legit_success_rate_pct"], 90.0)
        self.assertGreater(limited["requests_rejected_by_controls"], 0)
        self.assertLess(limited["avg_latency_ms_legit"], burst["avg_latency_ms_legit"])

    def test_rate_limit_activates_after_threshold(self):
        r = run_ddos(ControlConfig(rate_limit=True, rate_limit_per_tick=5), bots=1, bot_rate=40, ticks=10,
                     attack_start=2, attack_end=3)
        # one bot, one burst tick: first 5 pass, remaining 35 are rate limited
        self.assertEqual(r.metrics["count_rejected_rate_limit"], 35)

    def test_ids_ips_blocks_by_documented_rules(self):
        r = run_ddos(ControlConfig(ids=True, ips=True, ids_rate_threshold=30), bots=2, bot_rate=40,
                     attack_start=2, attack_end=6)
        self.assertEqual(r.metrics["sources_blocked"], 2)                 # both bots blocked
        self.assertEqual(r.metrics["detection_count"], 2)                 # one RATE_EXCEEDED alert each
        # tick 2: 30 requests pass before alert (the 31st triggers). 4 attack ticks x 40 = 160 per bot.
        # the triggering request itself is processed; everything after is blocked => 160 - 31 = 129 per bot
        self.assertEqual(r.metrics["block_count"], 2 * (160 - 31))
        self.assertTrue(any(e.layer == "ips" and e.action == "block" for e in r.events))

    def test_request_cap_prevents_runaway(self):
        r = run_ddos(ControlConfig.none(), bots=10 ** 6, bot_rate=10 ** 12, ticks=10 ** 6, legit_clients=10 ** 6,
                     legit_rate=10 ** 6)
        self.assertLessEqual(r.metrics["total_requests"], MAX_REQUESTS)
        self.assertLessEqual(r.metrics["ticks_simulated"], MAX_TICKS)
        self.assertTrue(r.metrics["request_cap_applied"])

    def test_layer_attribution_and_ablation(self):
        rows = run_layer_ablation("ddos")
        by = {r["controls"]: r for r in rows}
        self.assertLess(by["none"]["legit_success_rate_pct"], by["ALL layers"]["legit_success_rate_pct"])
        self.assertGreater(by["ids"]["detection_count"], 0)
        self.assertEqual(by["ids"]["block_count"], 0)       # IDS alone never blocks


class TestMetricsAndCSV(unittest.TestCase):
    def test_metrics_derived_from_records(self):
        recs = [{"tick": 0, "legit": True, "outcome": "served", "latency_ms": 10.0},
                {"tick": 0, "legit": True, "outcome": "served", "latency_ms": 30.0},
                {"tick": 0, "legit": True, "outcome": "timeout", "latency_ms": None},
                {"tick": 0, "legit": False, "outcome": "blocked_ips", "latency_ms": None}]
        m = summarize_requests(recs, 1)
        self.assertEqual(m["total_requests"], 4)
        self.assertEqual(m["legit_success_rate_pct"], round(100 * 2 / 3, 2))
        self.assertEqual(m["avg_latency_ms_legit"], 20.0)
        self.assertEqual(m["count_blocked_ips"], 1)
        self.assertAlmostEqual(percentile([10, 30], 95), 29.0)

    def test_before_after_comparison_uses_runs(self):
        base, post = run_before_after("ddos", ControlConfig.all_on())
        rows = {r["metric"]: r for r in compare_results(base, post)}
        self.assertEqual(rows["legit_success_rate_pct"]["baseline"], base.metrics["legit_success_rate_pct"])
        self.assertEqual(rows["legit_success_rate_pct"]["with_controls"], post.metrics["legit_success_rate_pct"])
        self.assertAlmostEqual(rows["legit_success_rate_pct"]["change"],
                               round(post.metrics["legit_success_rate_pct"] - base.metrics["legit_success_rate_pct"], 2))

    def test_csv_export_schema(self):
        base, post = run_before_after("mitm", ControlConfig.all_on())
        text = rows_to_csv(result_to_rows(base, "r1") + result_to_rows(post, "r1"))
        reader = csv.DictReader(io.StringIO(text))
        self.assertTrue(validate_csv_header(reader.fieldnames))
        self.assertEqual(reader.fieldnames, CSV_COLUMNS)
        rows = list(reader)
        self.assertTrue(rows)
        self.assertEqual({r["mode"] for r in rows}, {MODE_SIM})
        self.assertTrue(all(r["source"] for r in rows))
        self.assertEqual({r["phase"] for r in rows}, {"baseline", "with_controls"})


if __name__ == "__main__":
    unittest.main()
