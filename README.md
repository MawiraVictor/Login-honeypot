# Login Honeypot

A low-interaction honeypot written in pure Python (no dependencies) that imitates a
router's **Telnet login** and **HTTP admin panel**, records every login attempt, and
includes an **analyser** that turns the logs into a threat report.

> **Educational / defensive use only.** Run it only on systems and networks you own or
> are authorised to test.

## Features
- Fake Telnet login (port 2323) and fake router admin page (port 8080)
- Captures source IP, username, password, HTTP path and User-Agent
- Always rejects logins, never gives a shell, never executes input
- Safety limits: input length caps, timeouts, connection limit
- JSON Lines logs, plus an analyser that reports top IPs, credentials, probed
  paths, activity per hour and likely brute-force sources (MITRE ATT&CK T1110, T1595)
- Unit tests and a Dockerfile

## Project structure
```
src/honeypot.py             the honeypot
src/analyze.py              log analyser -> Markdown/JSON report
src/generate_sample_logs.py fake data for demos (documentation IP ranges only)
tests/                      unit tests
data/sample_events.jsonl    sample events
docs/sample_report.md       example analyser output
```

## Quick start
```bash
python src/honeypot.py                      # listens on 127.0.0.1 only
```
Try it from another terminal:
```bash
telnet 127.0.0.1 2323
curl -d "username=admin&password=test" http://127.0.0.1:8080/login
```
Analyse the log:
```bash
python src/analyze.py logs/events.jsonl --output report.md
```
No logs yet? Try the demo data:
```bash
python src/analyze.py data/sample_events.jsonl
```

## Running with Docker
```bash
docker build -t login-honeypot .
docker run --rm -p 2323:2323 -p 8080:8080 -v "$PWD/logs:/app/logs" login-honeypot
```

## Tests
```bash
python -m unittest discover -s tests -v
```

## Safe deployment checklist
- Use a disposable VM or container, separate from your personal machine and network
- Keep the default high ports; never run it as root or on a real service port without isolation
- Never type your real passwords into it
- Logs contain attacker-supplied text: treat it as untrusted and never execute it
- Only expose it to the internet if you understand your provider's rules

## Ideas to extend
- GeoIP and ASN lookup for source IPs
- Fake SSH service with `asyncssh`
- Alerts to Discord/Telegram or email for brute-force bursts
- Dashboard with Streamlit
- Auto-generate a blocklist from `brute_force_ips`

## License
MIT
