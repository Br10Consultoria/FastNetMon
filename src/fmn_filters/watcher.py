"""Read rotated nfcapd files without binding privileged ports.

This is a proof-of-concept collector adapter, not a low-latency packet sensor.
"""
from __future__ import annotations
import json
import logging
import os
from pathlib import Path
import sqlite3
import subprocess
import time
from typing import Callable

from .engine import Detector
from .parsers import parse_record

LOG = logging.getLogger(__name__)


def scan(directory: Path, db: sqlite3.Connection, detector: Detector,
         nfdump_binary: str = 'nfdump', max_age_minutes: int = 15,
         min_age_seconds: int = 3, emit: Callable[[dict], None] = print,
         assume_utc: bool = True, enricher=None) -> int:
    db.execute('CREATE TABLE IF NOT EXISTS processed (path TEXT PRIMARY KEY, mtime_ns INTEGER, size INTEGER)')
    db.commit()
    now = time.time()
    processed = 0
    files = sorted(directory.glob('nfcapd.[0-9]*'))
    for candidate in files:
        if not candidate.is_file():
            continue
        stat = candidate.stat()
        age = now - stat.st_mtime
        if age < min_age_seconds or age > max_age_minutes * 60:
            continue
        previous = db.execute('SELECT mtime_ns, size FROM processed WHERE path=?', (str(candidate),)).fetchone()
        if previous == (stat.st_mtime_ns, stat.st_size):
            continue
        LOG.info('Analisando %s', candidate)
        # TZ=UTC makes nfdump timezone-free timestamps unambiguous.
        env = dict(os.environ, TZ='UTC')
        try:
            result = subprocess.run([nfdump_binary, '-r', str(candidate), '-o', 'json'],
                                    capture_output=True, text=True, timeout=120, env=env,
                                    check=True)
            raw_records = json.loads(result.stdout)
            if not isinstance(raw_records, list):
                raise ValueError('nfdump não retornou lista JSON')
            for raw in raw_records:
                try:
                    event = parse_record(enricher.enrich(raw) if enricher else raw, assume_utc=assume_utc)
                    if event is None:
                        continue
                    for alert in detector.process(event):
                        emit(alert)
                except (ValueError, TypeError) as exc:
                    LOG.warning('Registro inválido em %s: %s', candidate.name, exc)
        except (subprocess.SubprocessError, ValueError, OSError) as exc:
            LOG.error('Falha nfdump %s: %s', candidate, exc)
            continue
        db.execute('INSERT OR REPLACE INTO processed(path,mtime_ns,size) VALUES(?,?,?)',
                   (str(candidate), stat.st_mtime_ns, stat.st_size))
        db.commit()
        processed += 1
    return processed
