"""A10 CGNAT: compare two cumulative logging-counter snapshots (read-only).

Parses only a fixed allowlist of aggregate counters. No credentials, subscriber
information, command execution, network access or database writes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

COUNTERS = (
    "TCP Port Allocated",
    "TCP Port Freed",
    "UDP Port Allocated",
    "UDP Port Freed",
    "ICMP Resource Allocated",
    "ICMP Resource Freed",
    "Log Packets Sent",
    "Log Packets Dropped",
    "TCP Connection Established",
    "TCP Connection Lost",
)
REQUIRED = (
    "Log Packets Sent",
    "Log Packets Dropped",
    "TCP Connection Established",
    "TCP Connection Lost",
)
KNOWN = frozenset(COUNTERS)
LINE = re.compile(r"^\s*(?P<name>.*?)\s{2,}(?P<value>[0-9]+)\s*$")
KEYS = {key: key.lower().replace(" ", "_") for key in COUNTERS}
EVENT_COUNTERS = (
    "tcp_port_allocated", "tcp_port_freed",
    "udp_port_allocated", "udp_port_freed",
    "icmp_resource_allocated", "icmp_resource_freed",
)


def reconcile_log_sent_with_events(delta: dict[str, int]) -> dict:
    """Compare internal A10 counters, without assuming end-to-end delivery."""
    missing = [name for name in EVENT_COUNTERS if name not in delta]
    if missing:
        return {
            "status": "inconclusivo_sem_todos_os_contadores",
            "contadores_ausentes": missing,
            "concordancia_contadores_internos": None,
            "entrega_ao_servidor_comprovada": False,
        }
    sent = delta["log_packets_sent"]
    tcp = delta["tcp_port_allocated"] + delta["tcp_port_freed"]
    udp = delta["udp_port_allocated"] + delta["udp_port_freed"]
    icmp = delta["icmp_resource_allocated"] + delta["icmp_resource_freed"]
    total = tcp + udp + icmp
    match = total == sent
    return {
        "status": "contadores_internos_coincidem" if match else "contadores_internos_divergem",
        "eventos_tcp": tcp,
        "eventos_udp": udp,
        "eventos_icmp": icmp,
        "soma_eventos_nat": total,
        "log_packets_sent_delta": sent,
        "diferenca_log_sent_menos_eventos": sent - total,
        "concordancia_contadores_internos": match,
        "entrega_ao_servidor_comprovada": False,
        "observacao": (
            "Concordancia numerica dos contadores do A10; nao comprova "
            "mensagens individuais entregues ao rsyslog nem bytes TCP no disco."
        ),
    }


def parse_snapshot(content: str) -> dict[str, int]:
    """Extract only known numerical counters, rejecting ambiguities."""
    result: dict[str, int] = {}
    for line in content.splitlines():
        match = LINE.fullmatch(line)
        if not match:
            continue
        name = match.group("name")
        if name not in KNOWN:
            continue
        if name in result:
            raise ValueError("Contador duplicado no snapshot: " + name)
        result[name] = int(match.group("value"))
    absent = [name for name in REQUIRED if name not in result]
    if absent:
        raise ValueError("Snapshot incompleto; faltando " + ", ".join(absent))
    return result


def compare(before: dict[str, int], after: dict[str, int], seconds: float) -> dict:
    """No estimates are emitted across counter resets or missing values."""
    if not 1 <= seconds <= 86400:
        raise ValueError("O intervalo deve estar entre 1 e 86400 segundos")
    available = [name for name in COUNTERS if name in before and name in after]
    differences: dict[str, int] = {}
    resets: list[str] = []
    for name in available:
        delta = after[name] - before[name]
        if delta < 0:
            resets.append(name)
        else:
            differences[KEYS[name]] = delta
    if resets:
        return {
            "status": "contadores_reiniciados_ou_wrap",
            "contadores_que_diminuiram": resets,
            "intervalo_informado_segundos": seconds,
            "taxas_validas": False,
            "integridade_do_logging_comprovada": False,
            "aviso": "Possivel reinicio/wrap: nao calcular taxas ou perdas a partir destes snapshots.",
        }
    sent = differences["log_packets_sent"]
    dropped = differences["log_packets_dropped"]
    lost = differences["tcp_connection_lost"]
    established = differences["tcp_connection_established"]
    observed = sent + dropped
    # This is a counter ratio, NOT a claim about missing NAT event records.
    pct = round(100 * dropped / observed, 6) if observed else None
    return {
        "status": "incrementos_de_erro" if dropped or lost else "sem_incremento_de_erro_nos_contadores",
        "intervalo_informado_segundos": seconds,
        "delta": differences,
        "reconciliacao_contadores_nat_e_log_sent": reconcile_log_sent_with_events(differences),
        "pacotes_log_enviados_por_segundo": round(sent / seconds, 2),
        "pacotes_log_descartados_por_segundo": round(dropped / seconds, 4),
        "proporcao_descartada_dos_pacotes_contabilizados_percentual": pct,
        "conexoes_tcp_de_logging_estabelecidas_no_intervalo": established,
        "conexoes_tcp_de_logging_perdidas_no_intervalo": lost,
        "framing_rfc6587_homologado": False,
        "integridade_do_logging_comprovada": False,
        "aviso": (
            "Os contadores sao acumulados do A10: pacotes log nao equivalem "
            "a eventos NAT individuais. Taxas usam o intervalo fornecido; "
            "nao demonstram entrega pelo rsyslog nem integridade juridica."
        ),
    }


def read_snapshot(path: Path) -> dict[str, int]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Arquivo de estatisticas regular obrigatorio")
    if path.stat().st_size > 1048576:
        raise ValueError("Arquivo de estatisticas excede 1 MiB")
    return parse_snapshot(path.read_text(encoding="utf-8"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="A10: comparar duas leituras de show cgnv6 logging statistics")
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--seconds", type=float, required=True, help="Intervalo medido entre os snapshots")
    args = parser.parse_args(argv)
    try:
        output = compare(read_snapshot(args.before), read_snapshot(args.after), args.seconds)
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print("Falha no diagnostico de contadores A10: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
