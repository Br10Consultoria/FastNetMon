"""Normalize ASN/GeoIP metadata before detection or telemetry aggregation.

Example: nfdump -r capture -o json | python -m fmn_filters.enrich_stream --format json --asn-mmdb /var/lib/GeoIP/GeoLite2-ASN.mmdb --city-mmdb /var/lib/GeoIP/GeoLite2-City.mmdb
"""
import argparse
import json
import sys
from .enrichment import Enricher
from .parsers import stream_records


def main(argv=None):
    ap = argparse.ArgumentParser(description='OrbyMon offline ASN e país (GeoLite2)')
    ap.add_argument('--asn-mmdb', required=False)
    ap.add_argument('--city-mmdb', required=False)
    ap.add_argument('--format', choices=('json', 'ndjson'), default='ndjson')
    a = ap.parse_args(argv)
    if not a.asn_mmdb and not a.city_mmdb:
        ap.error('informe --asn-mmdb e/ou --city-mmdb')
    enricher = Enricher(a.asn_mmdb, a.city_mmdb)
    try:
        for record in stream_records(sys.stdin, a.format):
            if not isinstance(record, dict):
                raise ValueError('registro precisa ser objeto JSON')
            print(json.dumps(enricher.enrich(record), ensure_ascii=False), flush=True)
    finally:
        enricher.close()


if __name__ == '__main__':
    main()
