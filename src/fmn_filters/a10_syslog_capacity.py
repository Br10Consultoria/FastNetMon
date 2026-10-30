"""Estimate A10 CGNAT syslog raw volume without modifying collector or NAT.

Read-only: uses file metadata, measures growth between two snapshots and
reports capacity risk. Never prints private IPs, ports, or raw log entries.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time

DEFAULT_LOG = Path("/var/log/orbymon/a10/a10-current.ndjson")
SECONDS_PER_DAY = 86400
GIB = 1024 ** 3


def estimate(before, after, seconds, free_bytes):
    """Before/after: (device, inode, length). Never assume rotated log is monotonic."""
    if seconds <= 0 or free_bytes < 0:
        raise ValueError("intervalo ou disco invalido")
    result = {
        "intervalo_segundos": round(seconds, 3),
        "inode_trocou_durante_amostragem": before[:2] != after[:2],
        "tamanho_inicio_bytes": before[2],
        "tamanho_fim_bytes": after[2],
        "livres_gib": round(free_bytes / GIB, 2),
        "metodo": "arquivo ativo, taxa sem considerar compressao",
    }
    if before[:2] != after[:2] or after[2] < before[2]:
        result.update({
            "valido": False, "aviso": "Arquivo foi rotacionado/truncado durante medicao. Repita a amostra."
        })
        return result
    delta = after[2] - before[2]
    bytes_sec = delta / seconds
    bytes_day = bytes_sec * SECONDS_PER_DAY
    available_days = free_bytes / bytes_day if bytes_day else None
    result.update({
        "valido": True,
        "bytes_gravados": delta,
        "taxa_kib_por_segundo": round(bytes_sec / 1024, 2),
        "projecao_gib_por_dia": round(bytes_day / GIB, 2),
        "dias_livres_estimados_sem_compressao": (
            round(available_days, 2) if available_days is not None else None
        ),
        "alerta_capacidade": (
            "critico" if available_days is not None and available_days < 3
            else "atencao" if available_days is not None and available_days < 7
            else "indeterminado" if available_days is None
            else "normal"
        ),
        "aviso": (
            "Estimativa de crescimento de log ativo; nao substitui retencao, "
            "backup ou capacidade apos compressao. Nao apague historico CGNAT."
        ),
    })
    return result


def snapshot(path):
    st = path.stat()
    return (st.st_dev, st.st_ino, st.st_size)


def measure(path=DEFAULT_LOG, seconds=15):
    if not (5 <= seconds <= 120):
        raise ValueError("seconds precisa estar entre 5 e 120")
    before = snapshot(path)
    started = time.monotonic()
    time.sleep(seconds)
    after = snapshot(path)
    duration = time.monotonic() - started
    free = shutil.disk_usage(path.parent).free
    return estimate(before, after, duration, free)


def main(argv=None):
    p = argparse.ArgumentParser(description="OrbyMon: taxa de logs CGNAT A10 (read-only)")
    p.add_argument("--file", type=Path, default=DEFAULT_LOG)
    p.add_argument("--seconds", type=int, default=15)
    a = p.parse_args(argv)
    try:
        print(json.dumps(measure(a.file, a.seconds), ensure_ascii=False, indent=2))
    except (OSError, ValueError) as exc:
        print("Falha de capacidade A10: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
