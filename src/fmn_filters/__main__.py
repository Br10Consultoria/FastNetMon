from __future__ import annotations
import argparse
import json
import logging
import sys
import sqlite3
import time
from contextlib import ExitStack
from pathlib import Path

from .engine import Rule, Detector
from .parsers import parse_record, stream_records
from .watcher import scan
from .enrichment import Enricher


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description='FastNetMon Combined Filters - dry-run detector')
    cli.add_argument('--rules', default='rules/example-rules.json', help='JSON com regras')
    cli.add_argument('--input', action='append', default=[], help='arquivo(s) de entrada, ou - para stdin')
    cli.add_argument('--format', choices=('ndjson', 'json'), default='ndjson', help='json é array do nfdump -o json')
    cli.add_argument('--strict', action='store_true', help='encerrar na primeira linha inválida')
    cli.add_argument('--validate', action='store_true', help='validar regras e encerrar')
    cli.add_argument('--assume-utc', action='store_true', help='aceitar timestamps sem timezone como UTC')
    cli.add_argument('--watch-dir', help='diretorio com arquivos rotacionados nfcapd.*')
    cli.add_argument('--state-db', default='state/processed.db', help='SQLite para arquivos processados')
    cli.add_argument('--nfdump-bin', default='nfdump')
    cli.add_argument('--poll-seconds', type=int, default=5)
    cli.add_argument('--max-age-minutes', type=int, default=15)
    cli.add_argument('--once', action='store_true', help='escanear apenas uma vez')
    cli.add_argument('--asn-mmdb', help='caminho GeoLite2-ASN.mmdb (opcional)')
    cli.add_argument('--city-mmdb', help='caminho GeoLite2-City.mmdb (opcional)')
    args = cli.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s', stream=sys.stderr)
    try:
        spec = json.loads(Path(args.rules).read_text(encoding='utf-8'))
        if not isinstance(spec, dict) or not isinstance(spec.get('rules'), list) or not spec['rules']:
            raise ValueError('arquivo deve ter {"rules": [ ... ]}')
        rules = [Rule.from_dict(item) for item in spec['rules']]
        detector = Detector(rules)
        if args.validate:
            print(f'{len(rules)} regras válidas')
            return 0
        enricher = Enricher(args.asn_mmdb, args.city_mmdb) if (args.asn_mmdb or args.city_mmdb) else None
        if args.watch_dir:
            if args.poll_seconds < 1 or args.max_age_minutes < 1:
                raise ValueError('poll-seconds e max-age-minutes devem ser positivos')
            Path(args.state_db).parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(args.state_db) as db:
                while True:
                    scan(Path(args.watch_dir), db, detector, args.nfdump_bin,
                         args.max_age_minutes, emit=lambda item: print(json.dumps(item, ensure_ascii=False), flush=True),
                         enricher=enricher)
                    if args.once:
                        return 0
                    time.sleep(args.poll_seconds)
        inputs = args.input or ['-']
        with ExitStack() as stack:
            for filename in inputs:
                source = sys.stdin if filename == '-' else stack.enter_context(open(filename, encoding='utf-8'))
                for raw in stream_records(source, args.format):
                    try:
                        event = parse_record(enricher.enrich(raw) if enricher else raw, assume_utc=args.assume_utc)
                        if event is None:
                            continue
                        for alert in detector.process(event):
                            print(json.dumps(alert, ensure_ascii=False, separators=(',', ':')), flush=True)
                    except (ValueError, TypeError, KeyError) as exc:
                        logging.warning('registro descartado: %s', exc)
                        if args.strict:
                            return 2
        return 0
    except (ValueError, OSError, json.JSONDecodeError, RuntimeError) as exc:
        logging.error('%s', exc)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
