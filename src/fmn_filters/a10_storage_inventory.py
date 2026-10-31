"""Read-only inventory of A10 rsyslog files and filesystem capacity.

Only file metadata is used; syslog event content, private IPs, subscriber
ports and raw filenames are NEVER printed. This is not a retention-policy
engine and cannot establish end-to-end CGNAT log integrity.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

DEFAULT_DIR = Path("/var/log/orbymon/a10")
PREFIX = "a10-current.ndjson"
GIB = 1024 ** 3


def _gib(value: int) -> float:
    return round(value / GIB, 3)


def inventory(directory: Path = DEFAULT_DIR, *, max_entries: int = 100000,
              expected_rotation_mib: int = 128, now: float | None = None) -> dict:
    """Inventory regular files without following symlinks or reading content."""
    if not 1 <= max_entries <= 1000000:
        raise ValueError("Limite de arquivos invalido")
    if not 1 <= expected_rotation_mib <= 10240:
        raise ValueError("Tamanho esperado de rotacao invalido")
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("Diretorio de logs regular obrigatorio, sem link simbolico")
    free, total = None, None
    usage = shutil.disk_usage(directory)
    total, free = usage.total, usage.free
    groups = {
        "arquivo_ativo": {"arquivos": 0, "bytes": 0},
        "rotacionados_comprimidos": {"arquivos": 0, "bytes": 0},
        "rotacionados_nao_comprimidos": {"arquivos": 0, "bytes": 0},
        "outros_regulares": {"arquivos": 0, "bytes": 0},
        "links_simbolicos_ignorados": {"arquivos": 0, "bytes": 0},
    }
    observed_at = time.time() if now is None else now
    active_mtime = None
    scanned = 0
    with os.scandir(directory) as entries:
        for item in entries:
            scanned += 1
            if scanned > max_entries:
                raise ValueError("Numero de entradas excedeu o limite configurado")
            info = item.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                group = "links_simbolicos_ignorados"
            elif not stat.S_ISREG(info.st_mode):
                continue
            elif item.name == PREFIX:
                group = "arquivo_ativo"
                active_mtime = info.st_mtime
            elif item.name.startswith(PREFIX) and item.name.endswith((".gz", ".zst", ".xz", ".bz2")):
                group = "rotacionados_comprimidos"
            elif item.name.startswith(PREFIX):
                group = "rotacionados_nao_comprimidos"
            else:
                group = "outros_regulares"
            groups[group]["arquivos"] += 1
            if group != "links_simbolicos_ignorados":
                groups[group]["bytes"] += info.st_size
    for value in groups.values():
        value["gib"] = _gib(value["bytes"])
    active_size = groups["arquivo_ativo"]["bytes"]
    timestamp = datetime.fromtimestamp(active_mtime, timezone.utc).isoformat() if active_mtime else None
    seconds_idle = max(0, observed_at - active_mtime) if active_mtime is not None else None
    return {
        "status": "ok" if groups["arquivo_ativo"]["arquivos"] == 1 else "sem_arquivo_ativo_unico",
        "observado_em_utc": datetime.fromtimestamp(observed_at, timezone.utc).isoformat(),
        "arquivo_ativo_existe": groups["arquivo_ativo"]["arquivos"] == 1,
        "grupos": groups,
        "total_de_arquivos_regulares_bytes": sum(v["bytes"] for v in groups.values()),
        "total_de_arquivos_regulares_gib": _gib(sum(v["bytes"] for v in groups.values())),
        "disco_total_gib": _gib(total),
        "disco_livre_gib": _gib(free),
        "disco_livre_percentual": round(100 * free / total, 2) if total else None,
        "arquivo_ativo_ultima_modificacao_utc": timestamp,
        "arquivo_ativo_sem_modificacao_segundos": round(seconds_idle, 1) if seconds_idle is not None else None,
        "arquivo_ativo_acima_limite_referencia": active_size > expected_rotation_mib * 1024 ** 2,
        "limite_referencia_rotacao_mib": expected_rotation_mib,
        "timer_e_ultima_rotacao_verificados": False,
        "retencao_homologada": False,
        "integridade_cgnat_comprovada": False,
        "observacao": (
            "maxsize no logrotate e avaliado apenas quando logrotate executa; "
            "arquivo ativo acima do tamanho nao prova falha do timer. "
            "Inventario sem leitura de payload e sem exclusao. "
            "Checar a execucao do timer e medir taxa de crescimento separadamente."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="A10 flow: inventario seguro dos logs (somente metadados)")
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_DIR)
    parser.add_argument("--expected-rotation-mib", type=int, default=128)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(inventory(args.log_dir, expected_rotation_mib=args.expected_rotation_mib),
                         indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError) as exc:
        print("Falha no inventario A10: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
