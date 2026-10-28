"""Offline MaxMind MMDB enrichments; no per-flow Internet requests.

The GeoLite2 city location is approximate, and describes an allocated IP range.
It must never be presented as an exact address or an attacker's physical location.
"""
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Any


def _reader(path: str | None):
    if not path:
        return None
    if not Path(path).is_file():
        raise FileNotFoundError(path)
    try:
        import geoip2.database
    except ImportError as exc:
        raise RuntimeError('Para ASN/geo, instale pip install geoip2 e obtenha bases GeoLite2 MMDB') from exc
    return geoip2.database.Reader(path)


class Enricher:
    def __init__(self, asn_mmdb: str | None = None, city_mmdb: str | None = None, asn_reader=None, city_reader=None):
        self.asn_reader = asn_reader if asn_reader is not None else _reader(asn_mmdb)
        self.city_reader = city_reader if city_reader is not None else _reader(city_mmdb)

    def close(self):
        for reader in (self.asn_reader, self.city_reader):
            if reader and hasattr(reader, 'close'):
                reader.close()

    @lru_cache(maxsize=8192)
    def lookup(self, ip: str) -> dict[str, Any]:
        try:
            address = ip_address(ip)
        except ValueError:
            return {}
        if not address.is_global:
            return {}
        out: dict[str, Any] = {}
        if self.asn_reader:
            try:
                record = self.asn_reader.asn(ip)
                if record.autonomous_system_number is not None:
                    out['asn'] = int(record.autonomous_system_number)
                if record.autonomous_system_organization:
                    out['asn_name'] = str(record.autonomous_system_organization)
            except Exception as exc:
                if exc.__class__.__name__ not in ('AddressNotFoundError',):
                    raise
        if self.city_reader:
            try:
                record = self.city_reader.city(ip)
                if record.country.iso_code:
                    out['country'] = record.country.iso_code.upper()
                if record.location.latitude is not None and record.location.longitude is not None:
                    out['latitude'] = round(float(record.location.latitude), 4)
                    out['longitude'] = round(float(record.location.longitude), 4)
            except Exception as exc:
                if exc.__class__.__name__ not in ('AddressNotFoundError',):
                    raise
        return out

    def enrich(self, raw: dict) -> dict:
        # Never overwrite exported values from a router with a conflicting lookup.
        row = dict(raw)
        for side, names in (('src', ('src_ip', 'src4_addr', 'src6_addr', 'srcip')),
                            ('dst', ('dst_ip', 'dst4_addr', 'dst6_addr', 'dstip'))):
            ip = next((str(row[k]) for k in names if row.get(k)), '')
            if not ip:
                continue
            data = self.lookup(ip)
            for key, value in data.items():
                row.setdefault(f'{side}_{key}', value)
        return row
