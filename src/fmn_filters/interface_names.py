"""Import verified Huawei IF-MIB ifName mappings without changing the router.

Supports header CSV (ifindex,ifname) or SNMP walk lines for
1.3.6.1.2.1.31.1.1.1.1 / IF-MIB::ifName. The caller obtains the walk
read-only, with credentials handled outside this module.
"""
from __future__ import annotations
import argparse
import csv
from pathlib import Path
import re
import sys
from .mysql_sink import connection_from_env

OID_RE = re.compile(
    r'(?:IF-MIB::ifName\.|(?:iso\.|\.)?1?\.?3\.6\.1\.2\.1\.31\.1\.1\.1\.1\.)(\d+)\s*=\s*(?:STRING:\s*)?(.+)',
    re.IGNORECASE,
)

def validated(index, name):
    try:
        idx = int(str(index).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f'ifIndex invalido: {index!r}') from exc
    if idx < 1 or idx > 4294967295:
        raise ValueError(f'ifIndex deve ser de 1 ate 4294967295: {idx}')
    val = str(name).strip().strip('"').strip()
    if not val or len(val) > 128 or any(ord(c) < 32 for c in val):
        raise ValueError(f'ifName invalido para ifIndex {idx}')
    return idx, val

def parse_text(content, fmt='auto'):
    if fmt == 'auto':
        fmt = 'snmpwalk' if '::ifName.' in content or re.search(
            r'(?:iso\.|\.)?1?\.?3\.6\.1\.2\.1\.31\.1\.1\.1\.1\.\d+\s*=', content
        ) else 'csv'
    mappings = {}
    if fmt == 'csv':
        reader = csv.DictReader(content.splitlines())
        if not reader.fieldnames or not {'ifindex','ifname'}.issubset(
            {c.strip().lower() for c in reader.fieldnames}
        ):
            raise ValueError('CSV exige cabecalho: ifindex,ifname')
        lookup = {c.strip().lower(): c for c in reader.fieldnames}
        rows = ((r[lookup['ifindex']],r[lookup['ifname']]) for r in reader)
    elif fmt == 'snmpwalk':
        matches = [m for line in content.splitlines() if (m := OID_RE.search(line))]
        if not matches:
            raise ValueError('SNMP walk nao contem IF-MIB::ifName OID 1.3.6.1.2.1.31.1.1.1.1')
        rows = ((m.group(1),m.group(2)) for m in matches)
    else:
        raise ValueError('Formato invalido')
    for index,name in rows:
        if index is None or name is None:
            raise ValueError('Linha sem ifindex/ifname')
        idx,label = validated(index,name)
        if idx in mappings and mappings[idx] != label:
            raise ValueError(f'ifIndex {idx} possui nomes conflitantes')
        mappings[idx] = label
    if not mappings:
        raise ValueError('Arquivo sem interfaces mapeaveis')
    return mappings

def main(argv=None):
    p=argparse.ArgumentParser(description='Importar ifName confirmado para dashboards OrbyMon')
    p.add_argument('--source',choices=('huawei','mikrotik'),default='huawei')
    p.add_argument('--file',required=True)
    p.add_argument('--format',choices=('auto','csv','snmpwalk'),default='auto')
    p.add_argument('--dry-run',action='store_true')
    a=p.parse_args(argv)
    try:
        path=Path(a.file)
        if not path.is_file():
            raise FileNotFoundError(path)
        mapping=parse_text(path.read_text(encoding='utf-8'),a.format)
        print(f'fonte={a.source} ifNames_validos={len(mapping)} dry_run={a.dry_run}')
        if a.dry_run:
            for k,v in sorted(mapping.items()):
                print(f'{k}: {v}')
            return 0
        db=connection_from_env()
        try:
            with db.cursor() as cur:
                cur.executemany(
                    'INSERT INTO orby_interface_names(source,if_index,if_name) VALUES (%s,%s,%s) '
                    'ON DUPLICATE KEY UPDATE if_name=VALUES(if_name)',
                    [(a.source,k,v) for k,v in sorted(mapping.items())]
                )
            db.commit()
            print(f'IF-MIB atualizado: {len(mapping)} interfaces para {a.source}')
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        return 0
    except Exception as exc:
        print('ERRO ifName: '+str(exc),file=sys.stderr)
        return 1

if __name__=='__main__':
    sys.exit(main())
