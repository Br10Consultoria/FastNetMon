"""Ingestao idempotente de arquivos NetFlow rotacionados; nao altera o coletor."""
import argparse
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from .mysql_sink import connection_from_env, process
from .parsers import parse_record

ROOT = Path("/var/lib/orbymon/flows")


def candidates(directory, now, min_age=45, max_age=3600):
    if not directory.is_dir():
        raise FileNotFoundError(directory)
    found = []
    for path in directory.glob("nfcapd.20*"):
        if not path.is_file() or not path.name.removeprefix("nfcapd.").isdigit():
            continue
        st = path.stat()
        if st.st_size > 0 and min_age <= now - st.st_mtime <= max_age:
            found.append((st.st_mtime, path))
    return [p for _, p in sorted(found)]


def decode_file(path, now, max_file_bytes=32 * 1024 * 1024):
    before = path.stat()
    if before.st_size > max_file_bytes:
        raise ValueError("Arquivo maior que limite configurado: " + path.name)
    # nfdump imprime timestamps sem offset; forcar UTC antes de usar assume_utc.
    env = dict(os.environ, TZ="UTC")
    cp = subprocess.run(["nfdump", "-r", str(path), "-o", "json"],
                        capture_output=True, text=True, check=True, timeout=90, env=env)
    after = path.stat()
    if (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size):
        raise ValueError("Arquivo foi alterado durante leitura: " + path.name)
    output = cp.stdout.strip()
    records = [] if "No matching flows" in output and output.startswith("[") else json.loads(output)
    if not isinstance(records, list):
        raise ValueError("Saida nfdump nao e uma lista JSON")
    count = 0
    for raw in records:
        event = parse_record(raw, assume_utc=True)
        if event is None or event.kind != "flow":
            continue
        if event.end > now + 300 or event.end < now - 4 * 3600:
            raise ValueError("Horario do fluxo fora da janela segura: " + path.name)
        count += 1
    return before, records, count


def save_file(db, source, path, stat, records, count):
    """Checkpoint e rollup na mesma transacao: rollback integral em erro."""
    with db.cursor() as cur:
        cur.execute("""INSERT IGNORE INTO orby_ingested_files
                     (source,file_name,file_size,file_mtime_ns,flow_count)
                     VALUES (%s,%s,%s,%s,%s)""",
                    (source, path.name, stat.st_size, stat.st_mtime_ns, count))
        if cur.rowcount == 0:
            cur.execute("""SELECT file_size,file_mtime_ns FROM orby_ingested_files
                        WHERE source=%s AND file_name=%s""", (source, path.name))
            previous = cur.fetchone()
            if previous is None or tuple(previous) != (stat.st_size, stat.st_mtime_ns):
                raise ValueError("Nome de arquivo reutilizado com conteudo diferente: " + path.name)
            db.rollback()
            return False
        # O sink existente agrega na mesma transacao. Evitar seus commits em lote.
        process(io.StringIO(json.dumps(records)), cur, "flows", fmt="json",
                commit=lambda: None)
    db.commit()
    return True


def run(source="huawei", *, dry_run=False, max_files=20,
        max_age_hours=1, min_age=45, directory=None):
    folder = directory if directory is not None else ROOT / source
    files = candidates(folder, time.time(), min_age, max_age_hours * 3600)[:max_files]
    print(f"fonte={source} arquivos_elegiveis={len(files)} dry_run={dry_run}", flush=True)
    if not files:
        return 0
    db = None if dry_run else connection_from_env()
    imported = 0
    failures = 0
    try:
        for path in files:
            try:
                st, records, count = decode_file(path, time.time())
                if dry_run:
                    print(f"DRY-RUN {path.name}: {count} fluxos", flush=True)
                else:
                    fresh = save_file(db, source, path, st, records, count)
                    print(f"{'IMPORTADO' if fresh else 'JA_IMPORTADO'} {path.name}: {count} fluxos", flush=True)
                    imported += int(fresh)
            except Exception as exc:
                if db is not None:
                    db.rollback()
                # Um arquivo legado com relogio incorreto nao deve impedir
                # a ingestao dos demais arquivos novos.
                print(f"IGNORADO {path.name}: {exc}", file=sys.stderr, flush=True)
                failures += 1
                continue
    finally:
        if db is not None:
            db.close()
    if failures:
        raise RuntimeError(f"{failures} arquivo(s) nao importado(s); verifique logs")
    return imported


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyMon: ingestao Huawei nfcapd para MariaDB")
    ap.add_argument("--source", choices=["huawei", "mikrotik"], default="huawei")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--max-files", type=int, default=20)
    ap.add_argument("--max-age-hours", type=int, default=1)
    ap.add_argument("--min-age", type=int, default=45)
    a = ap.parse_args(argv)
    if min(a.max_files, a.max_age_hours, a.min_age) < 1:
        ap.error("Os limites devem ser maiores que zero")
    try:
        run(a.source, dry_run=a.dry_run, max_files=a.max_files,
            max_age_hours=a.max_age_hours, min_age=a.min_age)
    except Exception as exc:
        print("ERRO ingestao: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
