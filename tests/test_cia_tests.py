import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import cia_tests  # noqa: E402
from src.schemas import CSV_COLUMNS  # noqa: E402


class TestCIA(unittest.TestCase):
    def test_confidentiality(self):
        r = cia_tests.run_confidentiality_check()
        self.assertTrue(r["passed"])
        self.assertEqual(r["phases"]["with_controls"]["unauthorized_data_leaks"], 0)
        self.assertGreater(r["phases"]["baseline"]["unauthorized_data_leaks"], 0)

    def test_integrity(self):
        r = cia_tests.run_integrity_check()
        self.assertTrue(r["passed"])
        self.assertEqual(r["phases"]["with_controls"]["tampered_accepted"], 0)
        self.assertGreater(r["phases"]["baseline"]["tampered_accepted"], 0)

    def test_availability_uses_simulated_runs(self):
        r = cia_tests.run_availability_check(seed=42)
        self.assertTrue(r["passed"])
        p = r["phases"]
        self.assertGreater(p["normal_load"]["legit_success_rate_pct"], p["burst_baseline"]["legit_success_rate_pct"])
        self.assertGreater(p["burst_with_rate_limit"]["legit_success_rate_pct"], p["burst_baseline"]["legit_success_rate_pct"])
        self.assertGreater(p["burst_with_rate_limit"]["requests_rejected_by_controls"], 0)

    def test_rows_follow_schema(self):
        rows = cia_tests.cia_rows(cia_tests.run_integrity_check(), "x")
        self.assertTrue(rows)
        self.assertTrue(all(set(r) == set(CSV_COLUMNS) for r in rows))
        self.assertTrue(all(r["mode"] == "SIMULATED" for r in rows))


if __name__ == "__main__":
    unittest.main()
