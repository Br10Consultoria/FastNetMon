"""Format a scrubbed A10 receiver-health report for Zabbix trapper items.

Read-only offline converter. It does not connect to Zabbix, start a daemon,
alter rsyslog, read CGNAT event payloads, or send customer information.

Run the existing a10_receiver_health separately as root and convert its
aggregate-only JSON output. Zabbix sender input format: <host> <key> <value>.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

STATE = {
    "operacional_na_amostra": 0,
    "atencao": 1,
    "critico": 2,
    "inconclusivo": 3,
}
HOST = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
MAX_FILE_BYTES = 262144
METRIC_NAMES = {
    "health.state": lambda x: STATE[x["status"]],
    "rsyslog.active": lambda x: _boolean(x.get("rsyslog_ativo")),
    "tcp.listening": lambda x: _boolean(x.get("tcp_5514", {}).get("escutando")),
    "tcp.recvq": lambda x: _numeric(x.get("tcp_5514", {}).get("fila_recebimento_maxima"), whole=True),
    "rotate.timer.active": lambda x: _boolean(x.get("timer_rotacao_ativo")),
    "rotate.last.success": lambda x: _boolean(
        True if x.get("resultado_ultima_rotacao") == "success" else
        None if x.get("resultado_ultima_rotacao") is None else False
    ),
    "rotate.last.age": lambda x: _numeric(x.get("segundos_desde_ultima_rotacao")),
    "log.active.age": lambda x: _numeric(x.get("arquivo_ativo_modificado_ha_segundos")),
    "disk.free.pct": lambda x: _numeric(x.get("disco_livre_percentual")),
    "disk.free.gib": lambda x: _numeric(x.get("disco_livre_gib")),
    "logs.total.gib": lambda x: _numeric(x.get("total_logs_gib")),
    "logs.compressed.files": lambda x: _numeric(x.get("arquivos_compactados"), whole=True),
    "checks.critical": lambda x: len(x.get("alertas_criticos", [])),
    "checks.warning": lambda x: len(x.get("alertas_atencao", [])),
    "checks.unknown": lambda x: len(x.get("verificacoes_indisponiveis", [])),
}


def _boolean(value) -> int:
    return int(value) if value is not None else -1


def _numeric(value, *, whole=False) -> int | float:
    if value is None:
        return -1
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError("Campo numerico invalido no relatorio")
    if value < 0 or value != value or value == float("inf"):
        raise ValueError("Valor numerico invalido no relatorio")
    if whole:
        if not isinstance(value, int):
            raise ValueError("Campo de contagem deve ser inteiro")
        return value
    return round(value, 3)


def format_sender_lines(health: dict, hostname: str) -> str:
    """Only whitelisted numeric fields appear; no free-form data is emitted."""
    if not HOST.fullmatch(hostname):
        raise ValueError("Nome de host Zabbix invalido: usar letras, numeros, ., _ ou -")
    if not isinstance(health, dict) or health.get("status") not in STATE:
        raise ValueError("Relatorio de saude invalido")
    if health.get("homologacao_entrega_syslog") is not False:
        raise ValueError("Relatorio sem aviso explicito sobre integridade")
    metrics = []
    for suffix, mapper in METRIC_NAMES.items():
        value = mapper(health)
        metrics.append(f"{hostname} orbymon.a10.{suffix} {value}")
    return "\n".join(metrics) + "\n"


def read_health(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Arquivo regular de relatorio obrigatorio")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Relatorio excede o limite de leitura")
    with path.open("r", encoding="utf-8") as handle:
        health = json.load(handle)
    if not isinstance(health, dict):
        raise ValueError("Relatorio deve ser objeto JSON")
    return health


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="A10 receiver health -> entrada numerica Zabbix sender (sem enviar)")
    parser.add_argument("--input", type=Path, required=True, help="JSON agregado de a10_receiver_health")
    parser.add_argument("--host", required=True, help="Nome exato do host tecnico no Zabbix, sem espacos")
    args = parser.parse_args(argv)
    try:
        sys.stdout.write(format_sender_lines(read_health(args.input), args.host))
        return 0
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        print("Falha no conversor Zabbix A10: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
