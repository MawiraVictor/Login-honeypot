import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from analyze import analyze, to_markdown  # noqa: E402
from generate_sample_logs import generate  # noqa: E402


class AnalyzeTests(unittest.TestCase):
    def test_counts_and_bruteforce(self):
        events = [{"event": "login_attempt", "service": "telnet", "src_ip": "1.1.1.1",
                   "username": "root", "password": "toor", "timestamp": "2025-01-01T10:00:00"}] * 5
        events.append({"event": "login_attempt", "service": "http", "src_ip": "2.2.2.2",
                       "username": "a|b", "password": "x", "timestamp": "2025-01-01T11:00:00"})
        r = analyze(events, brute_threshold=5)
        self.assertEqual(r["login_attempts"], 6)
        self.assertEqual(r["unique_ips"], 2)
        self.assertEqual(r["brute_force_ips"], {"1.1.1.1": 5})
        self.assertIn("a\\|b", to_markdown(r))  # table characters are escaped

    def test_empty_log(self):
        self.assertIn("None detected", to_markdown(analyze([])))

    def test_sample_generator(self):
        events = generate(count=50)
        self.assertGreaterEqual(len(events), 50)
        self.assertTrue(all(e["src_ip"].startswith(("203.0.113.", "198.51.100.")) for e in events))


if __name__ == "__main__":
    unittest.main()
