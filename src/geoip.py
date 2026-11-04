"""GeoIP and ASN enrichment for source IPs.

Lookups are done offline against local database files, so no attacker-controlled
data is ever sent to a third-party service. Two backends can be combined:

* MaxMind GeoLite2 ``.mmdb`` files (City/Country and/or ASN). Needs the optional
  ``maxminddb`` package (``pip install maxminddb``).
* An iptoasn.com TSV (``ip2asn-combined.tsv[.gz]``). Standard library only; gives
  country + ASN number + AS name, but no city.

Every lookup returns a dict with the same keys (values are ``None`` when unknown)
so callers never need to branch on the backend.
"""
import bisect
import gzip
import ipaddress
from pathlib import Path

FIELDS = ("country_code", "country", "city", "asn", "as_org")


def _blank():
    return dict.fromkeys(FIELDS)


def _open_text(path):
    path = Path(path)
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open(encoding="utf-8", errors="replace")


class Ip2AsnDb:
    """iptoasn.com TSV: range_start, range_end, AS number, country, AS description."""

    def __init__(self, path):
        # one sorted table per IP version: (starts, ends, rows)
        self._tables = {4: ([], [], []), 6: ([], [], [])}
        rows = {4: [], 6: []}
        with _open_text(path) as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5:
                    continue
                try:
                    start = ipaddress.ip_address(parts[0])
                    end = ipaddress.ip_address(parts[1])
                    asn = int(parts[2])
                except ValueError:
                    continue
                rows[start.version].append(
                    (int(start), int(end), asn, parts[3], parts[4]))
        for version, items in rows.items():
            items.sort()
            self._tables[version] = ([r[0] for r in items], [r[1] for r in items], items)

    def lookup(self, ip):
        addr = ipaddress.ip_address(ip)
        starts, ends, items = self._tables[addr.version]
        n = int(addr)
        i = bisect.bisect_right(starts, n) - 1
        out = _blank()
        if i < 0 or n > ends[i]:
            return out
        _, _, asn, country, desc = items[i]
        if asn == 0:  # iptoasn marks unrouted space as AS0
            return out
        out["asn"] = asn
        out["as_org"] = desc
        if country and country not in ("None", "ZZ"):
            out["country_code"] = country
        return out

    def close(self):
        pass


class MaxMindDb:
    """Thin wrapper over a GeoLite2 City/Country or ASN .mmdb file."""

    def __init__(self, path):
        try:
            import maxminddb
        except ImportError as exc:
            raise RuntimeError(
                "MaxMind databases need the 'maxminddb' package: pip install maxminddb"
            ) from exc
        self._reader = maxminddb.open_database(str(path))

    def lookup(self, ip):
        rec = self._reader.get(ip) or {}
        out = _blank()
        country = rec.get("country") or rec.get("registered_country") or {}
        out["country_code"] = country.get("iso_code")
        out["country"] = (country.get("names") or {}).get("en")
        out["city"] = ((rec.get("city") or {}).get("names") or {}).get("en")
        if rec.get("autonomous_system_number") is not None:
            out["asn"] = rec["autonomous_system_number"]
            out["as_org"] = rec.get("autonomous_system_organization")
        return out

    def close(self):
        self._reader.close()


class GeoResolver:
    """Combines any number of backends; the first non-empty value per field wins.

    Results are cached per IP. Private, loopback and other non-global addresses are
    never looked up and are labelled via ``scope`` instead.
    """

    def __init__(self, backends=()):
        self.backends = list(backends)
        self._cache = {}

    @classmethod
    def from_paths(cls, city=None, asn=None, ip2asn=None):
        backends = []
        if city:
            backends.append(MaxMindDb(city))
        if asn:
            backends.append(MaxMindDb(asn))
        if ip2asn:
            backends.append(Ip2AsnDb(ip2asn))
        return cls(backends)

    def lookup(self, ip):
        if ip in self._cache:
            return self._cache[ip]
        result = _blank()
        result["scope"] = "global"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            result["scope"] = "invalid"
        else:
            if not addr.is_global:
                result["scope"] = "private/reserved"
            else:
                for backend in self.backends:
                    try:
                        found = backend.lookup(ip)
                    except (ValueError, KeyError):
                        continue
                    for key in FIELDS:
                        if result[key] is None and found.get(key) is not None:
                            result[key] = found[key]
        self._cache[ip] = result
        return result

    def close(self):
        for backend in self.backends:
            backend.close()


def _fallback(info):
    scope = info.get("scope", "global")
    return {"private/reserved": "Private/Reserved", "invalid": "Invalid"}.get(scope, "Unknown")


def country_label(info):
    return info.get("country_code") or _fallback(info)


def asn_label(info):
    if info.get("asn") is None:
        return _fallback(info)
    return f"AS{info['asn']} {info.get('as_org') or ''}".strip()
