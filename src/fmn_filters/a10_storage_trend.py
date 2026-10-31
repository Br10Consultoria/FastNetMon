"""A10 storage trend between two metadata-only inventory snapshots.

This calculator never accesses private CGNAT log content, deletes files,
configures retention, restarts services or reads secrets.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys

GIB = 1024 ** 3
DAY_SECONDS = 86400


def compare_snapshots(before: dict, after: dict, *, min_seconds: int = 3600) -> dict:
    """Estimate *net directory* growth, not raw syslog production."""
    if not 300 <= min_seconds <= 86400:
        raise ValueError("Intervalo minimo invalido")
    for s in (before, after):
        if s.get("status") != "ok" or not s.get("arquivo_ativo_existe"):
            raise ValueError("Snapshot sem arquivo de log ativo valido")
        if not isinstance(s.get("total_de_arquivos_regulares_bytes"), int):
            raise ValueError("Snapshot sem total de bytes valido")
        if s["total_de_arquivos_regulares_bytes"] < 0:
            raise ValueError("Total de arquivos invalido")
        if not isinstance(s.get("disco_livre_gib"), (int, float)) or s["disco_livre_gib"] < 0:
            raise ValueError("Snapshot sem espaco livre")
    try:
        t1 = datetime.fromisoformat(before["observado_em_utc"].replace("Z", "+00:00"))
        t2 = datetime.fromisoformat(after["observado_em_utc"].replace("Z", "+00:00"))
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Snapshots sem horarios validos") from exc
    if t1.tzinfo is None or t2.tzinfo is None:
        raise ValueError("Horarios devem conter timezone")
    seconds = (t2 - t1).total_seconds()
    if seconds <= 0:
        raise ValueError("Segundo snapshot deve ser posterior")
    growth = after["total_de_arquivos_regulares_bytes"] - before["total_de_arquivos_regulares_bytes"]
    free_delta = after["disco_livre_gib"] - before["disco_livre_gib"]
    sound_window = seconds >= min_seconds
    positive = growth > 0
    if not sound_window:
        status = "intervalo_curto_para_projecao"
    elif not positive:
        status = "sem_crescimento_liquido_positivo"
    else:
        status = "crescimento_liquido_observado"
    net_gib_day = (growth * DAY_SECONDS / seconds / GIB) if sound_window else None
    days_from_free = (
        after["disco_livre_gib"] / net_gib_day
        if sound_window and positive and net_gib_day is not None and net_gib_day > 0 else None
    )
    return {
        "status": status,
        "intervalo_segundos": round(seconds, 2),
        "intervalo_minimo_recomendado_segundos": min_seconds,
        "diretorio_cgnat_delta_bytes": growth,
        "diretorio_cgnat_delta_gib": round(growth / GIB, 4),
        "disco_livre_variacao_gib": round(free_delta, 3),
        "crescimento_liquido_estimado_gib_dia": (
            round(net_gib_day, 3) if net_gib_day is not None else None
        ),
        "dias_livres_estimados_pelo_crescimento_liquido": (
            round(days_from_free, 2) if days_from_free is not None else None
        ),
        "rotacao_e_compressao_consideradas_indiretamente": sound_window,
        "integridade_logs_comprovada": False,
        "retencao_homologada": False,
        "aviso": (
            "Estimativa baseada na diferenca de tamanhos dos arquivos "
            "apos rotacao/compressao; difere do ritmo de producao bruto "
            "e pode variar muito entre janelas. Mudancas em outros usos "
            "do disco nao sao atribuidas aos logs. Nao autoriza apagar "
            "ou alterar retencao de registros CGNAT."
        ),
    }


def read_snapshot(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Arquivo JSON regular obrigatorio")
    if path.stat().st_size > 1048576:
        raise ValueError("Snapshot excede o limite de 1 MiB")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Snapshot JSON deve ser um objeto")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="A10: crescimento liquido da pasta de logs entre duas auditorias")
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = compare_snapshots(read_snapshot(args.before), read_snapshot(args.after))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print("Falha A10 tendencia: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
