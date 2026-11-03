#!/usr/bin/env python3
"""Analyse honeypot JSONL logs and produce a Markdown (and optional JSON) report."""
import argparse
import json
from collections import Counter
from pathlib import Path

from geoip import GeoResolver, asn_label, country_label


def load_events(path):
    events = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip corrupted lines
    return events


def analyze(events, brute_threshold=5, top=10, geo=None):
    attempts = [e for e in events if e.get("event") == "login_attempt"]
    http = [e for e in events if e.get("event") == "http_request"]
    ips = {e["src_ip"] for e in events if "src_ip" in e}
    per_ip = Counter(e["src_ip"] for e in attempts)
    pairs = Counter(f'{e.get("username", "")}:{e.get("password", "")}' for e in attempts)
    report = {
        "total_events": len(events),
        "login_attempts": len(attempts),
        "unique_ips": len(ips),
        "services": dict(Counter(e.get("service", "?") for e in attempts)),
        "top_ips": per_ip.most_common(top),
        "top_usernames": Counter(e.get("username", "") for e in attempts).most_common(top),
        "top_passwords": Counter(e.get("password", "") for e in attempts).most_common(top),
        "top_pairs": pairs.most_common(top),
        "top_paths": Counter(e.get("path", "") for e in http).most_common(top),
        "attempts_per_hour": sorted(
            Counter(e.get("timestamp", "")[:13] for e in attempts).items()),
        "brute_force_ips": {ip: n for ip, n in per_ip.items() if n >= brute_threshold},
        "brute_threshold": brute_threshold,
    }
    if geo is not None:
        info = {ip: geo.lookup(ip) for ip in ips}
        report["ip_info"] = info
        countries, asns = Counter(), Counter()
        for ip, n in per_ip.items():
            countries[country_label(info[ip])] += n
            asns[asn_label(info[ip])] += n
        report["top_countries"] = countries.most_common(top)
        report["top_asns"] = asns.most_common(top)
    return report


def _md(value):
    return str(value).replace("|", "\\|").replace("`", "'") or "(empty)"


def _table(title, rows, headers=("Value", "Count")):
    out = [f"### {title}", "", f"| {headers[0]} | {headers[1]} |", "|---|---|"]
    out += [f"| `{_md(k)}` | {v} |" for k, v in rows] or ["| (none) | 0 |"]
    return "\n".join(out) + "\n"


def _ip_table(r):
    info = r["ip_info"]
    out = ["### Top source IPs", "", "| IP | Attempts | Country | ASN |", "|---|---|---|---|"]
    out += [f"| `{_md(ip)}` | {n} | {_md(country_label(info[ip]))} | "
            f"{_md(asn_label(info[ip]))} |" for ip, n in r["top_ips"]] or ["| (none) | 0 | | |"]
    return "\n".join(out) + "\n"


def to_markdown(r):
    geo = "ip_info" in r
    parts = [
        "# Honeypot Report\n",
        f"- **Total events:** {r['total_events']}",
        f"- **Login attempts:** {r['login_attempts']}",
        f"- **Unique source IPs:** {r['unique_ips']}",
        f"- **Attempts by service:** {r['services']}\n",
        _ip_table(r) if geo else _table("Top source IPs", r["top_ips"], ("IP", "Attempts")),
        *([_table("Top source countries", r["top_countries"], ("Country", "Attempts")),
           _table("Top source networks (ASN)", r["top_asns"], ("ASN", "Attempts"))]
          if geo else []),
        _table("Top usernames", r["top_usernames"], ("Username", "Attempts")),
        _table("Top passwords", r["top_passwords"], ("Password", "Attempts")),
        _table("Top username:password pairs", r["top_pairs"], ("Pair", "Attempts")),
        _table("Most requested HTTP paths", r["top_paths"], ("Path", "Requests")),
        _table("Attempts per hour (UTC)", r["attempts_per_hour"], ("Hour", "Attempts")),
        f"### Likely brute-force sources (>= {r['brute_threshold']} attempts)\n",
    ]
    bf = r["brute_force_ips"]
    def _bf_line(ip, n):
        extra = f" ({country_label(r['ip_info'][ip])}, {asn_label(r['ip_info'][ip])})" if geo else ""
        return f"- `{ip}`: {n} attempts{extra}"
    parts.append("\n".join(_bf_line(ip, n) for ip, n in
                           sorted(bf.items(), key=lambda x: -x[1])) or "- None detected")
    parts.append("\n\n*Mapped to MITRE ATT&CK: T1110 (Brute Force), T1595 (Active Scanning).*")
    return "\n".join(parts) + "\n"


def main():
    p = argparse.ArgumentParser(description="Analyse honeypot logs")
    p.add_argument("logfile")
    p.add_argument("--threshold", type=int, default=5)
    p.add_argument("--output", help="write Markdown report to this file")
    p.add_argument("--json", help="write raw stats as JSON to this file")
    g = p.add_argument_group("GeoIP / ASN enrichment (optional, offline lookups)")
    g.add_argument("--geoip-db", help="MaxMind GeoLite2 City or Country .mmdb "
                                      "(needs: pip install maxminddb)")
    g.add_argument("--asn-db", help="MaxMind GeoLite2 ASN .mmdb (needs: pip install maxminddb)")
    g.add_argument("--ip2asn", help="iptoasn.com ip2asn-combined.tsv[.gz] (no extra packages)")
    args = p.parse_args()

    geo = None
    if args.geoip_db or args.asn_db or args.ip2asn:
        try:
            geo = GeoResolver.from_paths(args.geoip_db, args.asn_db, args.ip2asn)
        except (RuntimeError, OSError, ValueError) as exc:
            p.error(f"could not open GeoIP database: {exc}")

    report = analyze(load_events(args.logfile), args.threshold, geo=geo)
    if geo:
        geo.close()
    md = to_markdown(report)
    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(md)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
