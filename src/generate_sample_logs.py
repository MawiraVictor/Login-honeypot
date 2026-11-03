#!/usr/bin/env python3
"""Create FAKE honeypot events so you can try the analyser without exposing anything.
Uses only reserved documentation IP ranges (RFC 5737)."""
import argparse
import json
import random
from datetime import datetime, timedelta, timezone

USERS = ["root", "admin", "user", "test", "pi", "ubuntu", "support", "guest"]
PASSWORDS = ["123456", "admin", "password", "root", "12345678", "toor", "1234", "qwerty"]
PATHS = ["/", "/admin", "/login", "/.env", "/wp-login.php", "/phpmyadmin"]
AGENTS = ["curl/8.4.0", "Mozilla/5.0 (X11; Linux x86_64)", "python-requests/2.31", "Go-http-client/1.1"]


def generate(seed=42, count=300, start="2025-01-15"):
    rng = random.Random(seed)
    base = datetime.fromisoformat(start).replace(tzinfo=timezone.utc)
    ips = [f"203.0.113.{i}" for i in range(1, 12)] + [f"198.51.100.{i}" for i in range(1, 6)]
    weights = [10 if i < 3 else 1 for i in range(len(ips))]  # a few noisy attackers
    events = []
    for _ in range(count):
        ip = rng.choices(ips, weights)[0]
        ts = (base + timedelta(seconds=rng.randint(0, 72 * 3600))).isoformat(timespec="seconds")
        if rng.random() < 0.6:
            events.append({"timestamp": ts, "service": "telnet", "event": "login_attempt",
                           "src_ip": ip, "username": rng.choice(USERS),
                           "password": rng.choice(PASSWORDS)})
        else:
            events.append({"timestamp": ts, "service": "http", "event": "http_request",
                           "src_ip": ip, "method": "GET", "path": rng.choice(PATHS),
                           "user_agent": rng.choice(AGENTS)})
            if rng.random() < 0.5:
                events.append({"timestamp": ts, "service": "http", "event": "login_attempt",
                               "src_ip": ip, "username": rng.choice(USERS),
                               "password": rng.choice(PASSWORDS)})
    return sorted(events, key=lambda e: e["timestamp"])


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="data/sample_events.jsonl")
    p.add_argument("--count", type=int, default=300)
    a = p.parse_args()
    with open(a.out, "w", encoding="utf-8") as f:
        for e in generate(count=a.count):
            f.write(json.dumps(e) + "\n")
    print(f"Wrote sample events to {a.out}")
